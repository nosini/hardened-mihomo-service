"""Real curl compatibility boundary for the exact socket-BIO observer profile."""
import base64
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess


def run_curl_matrix(*, call, api, wait, systemctl, application_user, listener,
                    run, prepare, cgroup, family, inbound, redirect_port=None, adapter=False):
    version_info = call('curl', '-q', '--version').stdout
    assert 'libcurl/8.22.0 OpenSSL/3.5.3' in version_info, version_info
    public_key = call('openssl', 'x509', '-in', str(run / 'peer.pem'), '-pubkey', '-noout').stdout
    der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'],
                         input=public_key.encode(), capture_output=True, check=True).stdout
    good_pin = 'sha256//' + base64.b64encode(hashlib.sha256(der).digest()).decode()
    bad_pin = 'sha256//' + base64.b64encode(bytes(32)).decode()
    threaded_library = run / 'curl-thread.so'
    if adapter:
        call('gcc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
             str(run / 'packaging/tests/hostname_curl_thread.c'), '-o', str(threaded_library))
    results = []
    errors = []
    try:
        for version in ('1.2', '1.3'):
            for case, host, expected_exit in (
                    ('named', 'route.invalid', 0), ('renamed', 'reuse.invalid', 0),
                    ('wrong-host', 'wrong.invalid', 60), ('wrong-pin', 'route.invalid', 90),
                    *((('observer-stopped', 'route.invalid', 0), ('threaded', 'route.invalid', 0)) if adapter else ())):
                assert not api('/connections')['connections']
                environment = {key: value for key, value in os.environ.items()
                               if key not in ('SSLKEYLOGFILE', 'CURL_SSL_BACKEND', 'LD_PRELOAD')}
                if case == 'threaded':
                    # Constructor creates and joins one thread before curl reads
                    # config. It does not interpose any socket or TLS function.
                    environment['LD_PRELOAD'] = str(threaded_library)
                proc = subprocess.Popen(['curl', '-q', '--config', '-'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, preexec_fn=application_user,
                    env=environment)
                accepted = None
                record = {'tls': version, 'case': case, 'hostname': host}
                results.append(record)
                try:
                    # curl waits for config EOF after loading its real libraries.
                    # Attach to that exact TGID before allowing any transfer.
                    library_paths = [prepare[prepare.index(flag) + 1]
                                     for flag in ('-libssl', '-libcrypto', '-libc')]
                    maps_path = Path(f'/proc/{proc.pid}/maps')
                    def loaded():
                        assert proc.poll() is None, 'curl exited before transfer configuration'
                        mappings = maps_path.read_text().splitlines()
                        return mappings if all(any(line.endswith(' ' + path) for line in mappings)
                                               for path in library_paths) else None
                    mappings = wait(loaded)
                    libraries = set(library_paths)
                    libraries.update(line.split()[5] for line in mappings
                                     if len(line.split()) == 6 and '/libcurl.so.' in line.split()[5])
                    assert len(libraries) == 4, libraries
                    record['library_sha256'] = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                                for path in sorted(libraries)}
                    (cgroup / 'cgroup.procs').write_text(str(proc.pid))
                    registration = list(prepare)
                    registration[registration.index('-target-pid') + 1] = str(proc.pid)
                    if adapter:
                        registration[registration.index('-profile') + 1] = 'openssl-3.5.3-curl-8.22.0-x86-64-v3'
                        registration[-1:-1] = ['-libcurl', str(Path('/usr/lib64/libcurl.so.4').resolve())]
                    call(*registration)
                    systemctl('reset-failed', 'mihomo-hostname-observer.service')
                    systemctl('start', 'mihomo-hostname-observer.service')
                    assert systemctl('is-active', 'mihomo-hostname-observer.service').stdout.strip() == 'active'
                    observer_pid = int(systemctl('show', '-p', 'MainPID', '--value',
                                                 'mihomo-hostname-observer.service').stdout)
                    assert 'mihomo_hostname_t' in Path(f'/proc/{observer_pid}/attr/current').read_text()
                    if case == 'observer-stopped':
                        systemctl('stop', 'mihomo-hostname-observer.service')
                    target, port = listener.getsockname()[:2]
                    address = f'[{target}]' if family == 6 else target
                    config = '\n'.join((
                        'silent', 'show-error', 'http1.1', 'noproxy = "*"',
                        'connect-timeout = 5', 'max-time = 10',
                        f'tlsv{version}', f'tls-max = "{version}"',
                        f'cacert = "{run / "peer.pem"}"',
                        f'pinnedpubkey = "{bad_pin if case == "wrong-pin" else good_pin}"',
                        f'resolve = "{host}:{port}:{address}"',
                        f'url = "https://{host}:{port}/curl/{case}"', ''))
                    proc.stdin.write(config)
                    proc.stdin.close()
                    accepted, _ = listener.accept()
                    accepted.settimeout(5)
                    # The upstream accept proves route commitment before the
                    # server handshake can let curl exit on a verification error.
                    connection = wait(lambda: next((entry for entry in (api('/connections')['connections'] or [])
                        if entry['metadata']['destinationIP'] == target
                        and entry['metadata']['destinationPort'] == str(port)), None))
                    metadata = connection['metadata']
                    assert metadata['type'] == inbound, connection
                    attributed = adapter and case != 'observer-stopped'
                    chain = {'route.invalid': 'NAMED', 'reuse.invalid': 'RENAMED'}.get(host, 'DIRECT') if attributed else 'DIRECT'
                    # Application evidence is used for matching while the real-IP
                    # metadata remains intact; the API host stays empty.
                    assert not metadata.get('host'), connection
                    expected_chains = ['DIRECT'] if chain == 'DIRECT' else ['DIRECT', chain]
                    assert connection['chains'] == expected_chains, connection
                    if chain != 'DIRECT':
                        assert connection['rule'] == 'Domain' and connection['rulePayload'] == host, connection
                    if redirect_port is not None:
                        assert int(metadata['inboundPort']) == redirect_port, connection
                    record['connection'] = connection
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = context.maximum_version = (
                        ssl.TLSVersion.TLSv1_2 if version == '1.2' else ssl.TLSVersion.TLSv1_3)
                    context.load_cert_chain(str(run / 'peer.pem'), str(run / 'peer.key'))
                    context.set_alpn_protocols(['http/1.1'])
                    names = []
                    context.set_servername_callback(lambda _sock, name, _ctx: names.append(name))
                    request = b''
                    try:
                        with context.wrap_socket(accepted, server_side=True) as peer:
                            assert peer.version() == f'TLSv{version}'
                            assert peer.selected_alpn_protocol() == 'http/1.1'
                            while b'\r\n\r\n' not in request:
                                data = peer.recv(2048)
                                if not data:
                                    break
                                request += data
                                assert len(request) <= 2048, 'oversized fixture request'
                            if expected_exit == 0:
                                lines = request.decode('ascii').split('\r\n')
                                assert lines[0] == f'GET /curl/{case} HTTP/1.1', lines
                                assert f'Host: {host}:{port}' in lines, lines
                                body = f'curl-{case}-TLSv{version}'.encode()
                                peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode()
                                             + b'\r\nConnection: close\r\n\r\n' + body)
                            else:
                                assert request == b'', request
                    except ssl.SSLError as error:
                        # Curl may abort during the handshake or after receiving
                        # tickets. The exact curl exit and zero request bytes
                        # below distinguish verification rejection from breakage.
                        assert expected_exit != 0 and request == b'', (error, request)
                        record['peer_tls_error'] = str(error)
                    assert names == [host], names
                    stdout, stderr = proc.stdout.read(), proc.stderr.read()
                    assert proc.wait(timeout=5) == expected_exit, (record, stdout, stderr)
                    if expected_exit == 0:
                        assert stdout == body.decode() and stderr == '', (stdout, stderr)
                    else:
                        assert stdout == '' and stderr.startswith(f'curl: ({expected_exit})'), (stdout, stderr)
                    record.update(exit=proc.returncode, request_bytes=len(request))
                    errors.append({'tls': version, 'case': case, 'stderr': stderr})
                finally:
                    if accepted is not None:
                        accepted.close()
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait()
                    for pipe in (proc.stdin, proc.stdout, proc.stderr):
                        pipe.close()
                    systemctl('stop', 'mihomo-hostname-observer.service', check=False)
                    systemctl('reset-failed', 'mihomo-hostname-observer.service')
                    wait(lambda: not api('/connections')['connections'])
            label = 'verified curl adapter routes, verification and observer-stop/threaded sends (6 connections)' if adapter else 'real curl custom-BIO remains unattributed; fallback, hostname and pin verification (4 connections)'
            print(f'PASS IPv{family} TLSv{version} {inbound} {label}', flush=True)
    finally:
        (run / ('curl-adapter-results.log' if adapter else 'curl-results.log')).write_text(json.dumps({'curl_version': version_info, 'cases': results}, indent=2) + '\n')
        (run / ('curl-adapter-stderr.log' if adapter else 'curl-stderr.log')).write_text(json.dumps(errors, indent=2) + '\n')
