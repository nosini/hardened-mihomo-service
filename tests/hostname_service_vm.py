#!/usr/bin/python3
"""Privileged disposable-VM integration test; see docs/hostname-development.md.

The run directory contains packaging/, mihomo, mihomo-hostname-observer and
client.c. Refuses existing production paths. Uses a dedicated network namespace
and removes only its own fixtures. Never run this on a deployed machine.
"""
import argparse
import hashlib
import json
import re
import os
from pathlib import Path
import pwd
import select
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

NS = 'mihomo-hostname-review'
RUN = None
PACK = None
FAMILY = 4


def call(*args, check=True, **kw):
    result = subprocess.run(args, check=False, text=True, capture_output=True, **kw)
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.stdout}{result.stderr}')
    return result


def wait(check, seconds=12):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = check()
        except OSError:
            result = None
        if result:
            return result
        time.sleep(.05)
    raise AssertionError('condition timed out')


def systemctl(*args, **kw):
    return call('systemctl', *args, **kw)


def api(path):
    with urllib.request.urlopen('http://127.0.0.1:18662' + path, timeout=2) as response:
        return json.load(response)


def wait_mihomo():
    wait(lambda: api('/version'))
    # The control API starts before inbound listeners. Avoid sending a SYN to
    # a not-yet-listening REDIRECT port immediately after a service restart.
    wait(lambda: call('ss', '-H', '-ltn', 'sport = :18661').stdout.strip())


def inside():
    assert call('/usr/sbin/getenforce').stdout.strip() == 'Enforcing'
    call('ip', 'link', 'set', 'lo', 'up')
    # An isolated non-loopback path proves the shipped kill-switch output drop
    # survives observer failure. It has no route to the guest or the LAN.
    call('ip', 'link', 'add', 'review0', 'type', 'dummy')
    call('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'review0')
    call('ip', 'link', 'set', 'review0', 'up')
    installed = []
    created_user = False
    client = None
    address = '127.0.0.1' if FAMILY == 4 else '::1'
    server = socket.socket(socket.AF_INET if FAMILY == 4 else socket.AF_INET6)
    server.bind((address, 0))
    server.listen()
    server.settimeout(5)
    port = server.getsockname()[1]
    cgroup = Path('/sys/fs/cgroup/hostname-review-target')
    audit_offset = Path('/var/log/audit/audit.log').stat().st_size
    try:
        try:
            account = pwd.getpwnam('mihomo')
        except KeyError:
            call('systemd-sysusers', str(PACK / 'mihomo.sysusers'))
            created_user = True
            account = pwd.getpwnam('mihomo')
        call('make', '-f', '/usr/share/selinux/devel/Makefile', 'mihomo.pp', cwd=RUN / 'packaging')
        call('semodule', '-i', str(PACK / 'mihomo.pp'))
        for binary in ('mihomo', 'mihomo-hostname-observer'):
            path = Path('/usr/local/bin') / binary
            call('install', '-m', '755', str(RUN / binary), str(path))
            installed.append(path)
            call('restorecon', str(path))
        call('gcc', '-O2', '-g', '-Wall', '-Wextra', '-Werror', str(RUN / 'client.c'), '-o', '/usr/local/bin/hostname-review-client', '-lssl', '-lcrypto', '-pthread')
        installed.append(Path('/usr/local/bin/hostname-review-client'))
        call('systemd-tmpfiles', '--create', str(PACK / 'mihomo.tmpfiles'), str(PACK / 'mihomo-hostname.tmpfiles'))
        config = Path('/etc/mihomo/config.yaml')
        config.write_text('''
redir-port: 18661
allow-lan: true
bind-address: '*'
external-controller: 127.0.0.1:18662
mode: rule
log-level: info
ipv6: true
find-process-mode: off
hostname-discovery:
  enable: true
  endpoint: /run/mihomo-hostname/bootstrap.sock
  wait-ms: 250
sniffer: {enable: false}
tun: {enable: false}
dns: {enable: false}
proxy-groups:
  - {name: NAMED, type: select, proxies: [DIRECT]}
rules:
  - DOMAIN,route.invalid,NAMED
  - MATCH,DIRECT
''')
        os.chown(config, 0, account.pw_gid)
        config.chmod(0o640)
        call('restorecon', '-R', '/etc/mihomo', '/run/mihomo-hostname', '/run/mihomo-hostname-target')
        for name in ('mihomo.service', 'mihomo-hostname-observer.service'):
            path = Path('/etc/systemd/system') / name
            text = (PACK / name).read_text()
            if name == 'mihomo.service':
                text = text.replace('After=network-online.target killswitch.service socketowner.service', 'After=killswitch.service')
                text = text.replace('Wants=network-online.target', '')
                text += f'\n[Service]\nNetworkNamespacePath=/run/netns/{NS}\n'
            path.write_text(text)
            installed.append(path)
        # Run the shipped fail-closed rules in our network namespace only.
        guard = Path('/etc/systemd/system/killswitch.service')
        guard.write_text((PACK / 'killswitch.service').read_text().replace(
            'After=firewalld.service\nBefore=network-pre.target\nWants=network-pre.target\n', '') +
            f'\n[Service]\nNetworkNamespacePath=/run/netns/{NS}\n')
        installed.append(guard)
        rules = Path('/etc/nftables-killswitch.conf')
        rules.write_text((PACK / rules.name).read_text().replace('include "/etc/nftables-killswitch.d/*.conf"', ''))
        installed.append(rules)
        generator = Path('/etc/systemd/system-generators/mihomo-process-generator')
        generator.parent.mkdir(exist_ok=True)
        shutil.copyfile(PACK / generator.name, generator)
        generator.chmod(0o755)
        installed.append(generator)
        call('restorecon', str(generator))
        cgroup.mkdir()
        def unprivileged():
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
        # Ephemeral fixture trust stays in this run directory and client only.
        for name in ('peer', 'untrusted'):
            call('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', str(RUN / (name + '.key')), '-out', str(RUN / (name + '.pem')),
                 '-days', '1', '-subj', '/CN=route.invalid',
                 '-addext', 'subjectAltName=DNS:route.invalid')
        certificate = ssl.PEM_cert_to_DER_cert((RUN / 'peer.pem').read_text())
        pin = hashlib.sha256(certificate).hexdigest()
        client = subprocess.Popen(['/usr/local/bin/hostname-review-client', str(FAMILY), address, str(port)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, preexec_fn=unprivileged)
        assert client.stdout.readline().strip() == 'ready'
        (cgroup / 'cgroup.procs').write_text(str(client.pid))
        observer = '/usr/local/bin/mihomo-hostname-observer'
        prepare = [observer, '-target-pid', str(client.pid), '-cgroup', str(cgroup),
                   '-profile', 'openssl-3.5.3-x86-64-v3',
                   '-libssl', str(Path('/usr/lib64/glibc-hwcaps/x86-64-v3/libssl.so.3').resolve()),
                   '-libcrypto', str(Path('/usr/lib64/glibc-hwcaps/x86-64-v3/libcrypto.so.3').resolve()),
                   '-libc', '/usr/lib64/libc.so.6', '-reader-user', 'mihomo', '-reader-group', 'mihomo', 'prepare']
        systemctl('daemon-reload')
        systemctl('start', 'mihomo.service')
        wait_mihomo()
        assert systemctl('is-active', 'mihomo-hostname-observer.service', check=False).stdout.strip() == 'inactive'
        print('PASS missing registration leaves real mihomo running', flush=True)
        call(*prepare)
        regfile = Path('/run/mihomo-hostname-target/target.json')
        original = regfile.read_text()
        # A forged birth is rejected before maps, links or an endpoint exist.
        reg = json.loads(original)
        reg['Target']['Inode'] += 1
        regfile.write_text(json.dumps(reg))
        systemctl('daemon-reload')
        systemctl('start', 'mihomo-hostname-observer.service', check=False)
        assert systemctl('is-active', 'mihomo.service').stdout.strip() == 'active'
        assert systemctl('show', '-p', 'Result', '--value', 'mihomo-hostname-observer.service').stdout.strip() == 'exit-code'
        print('PASS stale registration does not block mihomo', flush=True)
        systemctl('stop', 'mihomo-hostname-observer.service')
        regfile.write_text(original)
        systemctl('reset-failed', 'mihomo-hostname-observer.service')
        systemctl('start', 'mihomo-hostname-observer.service')
        pid = int(systemctl('show', '-p', 'MainPID', '--value', 'mihomo-hostname-observer.service').stdout)
        assert 'mihomo_hostname_t' in Path(f'/proc/{pid}/attr/current').read_text()
        observer_status = Path(f'/proc/{pid}/status').read_text()
        caps = int(next(line.split()[1] for line in observer_status.splitlines() if line.startswith('CapEff:')), 16)
        assert caps == sum(1 << bit for bit in (0, 12, 19, 38, 39)), hex(caps)
        mainpid = int(systemctl('show', '-p', 'MainPID', '--value', 'mihomo.service').stdout)
        assert 'mihomo_t' in Path(f'/proc/{mainpid}/attr/current').read_text()
        status = Path(f'/proc/{mainpid}/status').read_text()
        assert 'CapEff:\t0000000000001400' in status
        assert not Path(f'/proc/{mainpid}/root/run/mihomo-hostname-target').exists()
        assert not list(Path(f'/proc/{mainpid}/root/sys/fs/bpf/mihomo-hostname').iterdir())
        print('PASS separate enforcing domains and unchanged mihomo capabilities', flush=True)
        call('nft', '-f', '-', input=f'''table inet hostname_review {{
 chain output {{ type nat hook output priority dstnat; policy accept;
 meta skuid 1000 {'ip' if FAMILY == 4 else 'ip6'} daddr {address} tcp dport {port} redirect to :18661
 }}
}}''')

        def command(text):
            client.stdin.write(text + '\n')
            client.stdin.flush()
            ready, _, _ = select.select([client.stdout], [], [], 10)
            assert ready, text
            return client.stdout.readline().strip()

        def probe(named):
            opened = command('open route.invalid name-first fd')
            assert opened.startswith('socket '), opened
            slot = int(opened.split()[1])
            command(f'handshake {slot}')
            accepted, _ = server.accept()
            try:
                accepted.settimeout(5)
                data = accepted.recv(4096)
                assert data.startswith(b'\x16\x03') and b'route.invalid' in data, data
                connection = wait(lambda: next(iter(api('/connections')['connections'] or []), None))
                assert ('NAMED' in connection['chains']) == named, connection
            finally:
                command(f'close {slot}')
                accepted.close()
                wait(lambda: not api('/connections')['connections'])

        def tls_probe(named, version, failure=None):
            opened = command('open route.invalid name-first fd')
            assert opened.startswith('socket '), opened
            slot = int(opened.split()[1])
            trust = RUN / ('untrusted.pem' if failure == 'trust' else 'peer.pem')
            hostname = 'wrong.invalid' if failure == 'hostname' else 'route.invalid'
            expected_pin = '0' * 64 if failure == 'pin' else pin
            assert command(f'verify {slot} {trust} {hostname} {expected_pin} {version}') == 'ok'
            hello = command(f'handshake {slot}')
            assert hello == f'handshake {slot} -1 2', hello  # WANT_READ after ClientHello
            accepted, _ = server.accept()
            accepted.settimeout(5)
            connection = wait(lambda: next(iter(api('/connections')['connections'] or []), None))
            assert ('NAMED' in connection['chains']) == named, connection
            assert connection['metadata']['destinationIP'] == address, connection
            assert connection['metadata']['destinationPort'] == str(port), connection
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(RUN / 'peer.pem'), str(RUN / 'peer.key'))
            protocol = ssl.TLSVersion.TLSv1_2 if version == 12 else ssl.TLSVersion.TLSv1_3
            context.minimum_version = context.maximum_version = protocol
            result = {'names': [], 'request': b'', 'error': None}
            context.set_servername_callback(lambda _sock, name, _ctx: result['names'].append(name))

            def serve():
                try:
                    with context.wrap_socket(accepted, server_side=True) as peer:
                        result['version'] = peer.version()
                        request = b'hostname-fixture-request\n'
                        while len(result['request']) < len(request):
                            chunk = peer.recv(len(request) - len(result['request']))
                            if not chunk:
                                break
                            result['request'] += chunk
                        if result['request']:
                            assert result['request'] == request, result
                            peer.sendall(b'hostname-fixture-response\n')
                            # Keep the routed connection live for the post-TLS assertion.
                            assert peer.recv(1) == b''
                except Exception as error:
                    result['error'] = error

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                reply = command(f'exchange {slot}')
                if failure in ('trust', 'hostname'):
                    assert reply.startswith(f'exchange {slot} handshake-failed '), reply
                    expected_error = 18 if failure == 'trust' else 62
                    assert int(reply.split()[-1]) == expected_error, reply
                elif failure == 'pin':
                    assert reply == f'exchange {slot} pin-failed', reply
                else:
                    expected_version = 'TLSv1.2' if version == 12 else 'TLSv1.3'
                    assert reply == f'exchange {slot} ok {expected_version}', reply
                    assert result['request'] == b'hostname-fixture-request\n', result
                    # Later TLS sends revoke first-send evidence, but cannot move
                    # the already committed route or interrupt the relay.
                    live = api('/connections')['connections']
                    assert len(live) == 1 and live[0]['id'] == connection['id'], live
                    assert live[0]['chains'] == connection['chains'], live
            finally:
                assert command(f'close {slot}') == 'ok'
                worker.join(timeout=6)
                accepted.close()
            assert not worker.is_alive(), result
            assert result['names'] == ['route.invalid'], result
            if failure in ('trust', 'hostname'):
                assert isinstance(result['error'], ssl.SSLError), result
                assert result['request'] == b'', result
            else:
                assert result['error'] is None, result
                if failure == 'pin':
                    assert result['request'] == b'', result
            wait(lambda: not api('/connections')['connections'])

        for version in (12, 13):
            tls_probe(True, version)
            for failure in ('trust', 'hostname', 'pin'):
                tls_probe(True, version, failure)
        print(f'PASS IPv{FAMILY} TLS 1.2/1.3 certificate, hostname, pin and application exchange', flush=True)

        probe(True)
        print('PASS named routing with real destination and original ClientHello', flush=True)
        systemctl('stop', 'mihomo-hostname-observer.service')
        probe(False)
        for version in (12, 13):
            tls_probe(False, version)
        print(f'PASS IPv{FAMILY} completed TLS through ordinary fallback after observer stop', flush=True)
        assert systemctl('is-active', 'killswitch.service').stdout.strip() == 'active'
        assert systemctl('is-active', 'mihomo.service').stdout.strip() == 'active'
        systemctl('start', 'mihomo-hostname-observer.service')
        probe(True)
        tls_probe(True, 13)
        print('PASS stop fallback and fresh restart through stable endpoint mount', flush=True)
        oldpid = int(systemctl('show', '-p', 'MainPID', '--value', 'mihomo-hostname-observer.service').stdout)
        systemctl('kill', '--signal=SIGKILL', '--kill-whom=main', 'mihomo-hostname-observer.service')
        probe(False)
        wait(lambda: systemctl('is-active', 'mihomo-hostname-observer.service', check=False).stdout.strip() == 'active')
        assert oldpid != int(systemctl('show', '-p', 'MainPID', '--value', 'mihomo-hostname-observer.service').stdout)
        probe(True)
        tls_probe(True, 13)
        print('PASS SIGKILL cleanup, fallback and automatic fresh-instance recovery', flush=True)
        call('nft', '-a', 'list', 'table', 'inet', 'killswitch')
        # Probe blocked egress as the application user; the nft rules stay installed.
        call('nft', 'add', 'counter', 'inet', 'killswitch', 'review_blocked')
        call('nft', 'add', 'rule', 'inet', 'killswitch', 'output', 'ip', 'daddr', '192.0.2.2', 'counter', 'name', 'review_blocked', 'drop')
        call('runuser', '-u', 'nobody', '--', 'python3', '-c',
                       'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.2); s.sendto(b"probe",("192.0.2.2",9999))', check=False)
        counters = json.loads(call('nft', '-j', 'list', 'counter', 'inet', 'killswitch', 'review_blocked').stdout)
        assert next(item['counter']['packets'] for item in counters['nftables'] if 'counter' in item) > 0
        assert 'policy drop' in call('nft', 'list', 'chain', 'inet', 'killswitch', 'output').stdout
        print('PASS kill-switch rules remain active after observer failures', flush=True)
        # Disablement removes service coupling and the endpoint mount.
        config.write_text(config.read_text().replace('enable: true', 'enable: false'))
        systemctl('daemon-reload')
        generated = Path('/run/systemd/generator/mihomo.service.d/50-process-lookup.conf').read_text()
        assert 'hostname' not in generated
        systemctl('stop', 'mihomo-hostname-observer.service')
        systemctl('restart', 'mihomo.service')
        wait_mihomo()
        probe(False)
        for version in (12, 13):
            tls_probe(False, version)
        print(f'PASS IPv{FAMILY} completed TLS with hostname discovery disabled', flush=True)
        mainpid = int(systemctl('show', '-p', 'MainPID', '--value', 'mihomo.service').stdout)
        assert not Path(f'/proc/{mainpid}/root/run/mihomo-hostname').exists()
        assert 'CapEff:\t0000000000001400' in Path(f'/proc/{mainpid}/status').read_text()
        assert systemctl('is-active', 'killswitch.service').stdout.strip() == 'active'
        config.write_text(config.read_text().replace('enable: false', 'enable: true', 1))
        systemctl('daemon-reload')
        systemctl('reset-failed', 'mihomo-hostname-observer.service')
        systemctl('restart', 'mihomo.service')
        wait_mihomo()
        probe(True)
        print('PASS disable removes generated coupling/mount and re-enable restores it', flush=True)
        # Exit does not cause the service to attach to another numeric PID.
        client.stdin.close()
        client.wait(timeout=5)
        wait(lambda: systemctl('is-active', 'mihomo-hostname-observer.service', check=False).stdout.strip() == 'inactive')
        assert systemctl('start', 'mihomo-hostname-observer.service', check=False).returncode != 0
        assert systemctl('is-active', 'mihomo.service').stdout.strip() == 'active'
        print('PASS target exit revokes and stale restart refuses', flush=True)
    finally:
        for unit in ('mihomo-hostname-observer.service', 'mihomo.service', 'killswitch.service'):
            (RUN / (unit + '.journal')).write_text(call('journalctl', '-u', unit, '--no-pager', '-n', '160', check=False).stdout)
            systemctl('stop', unit, check=False)
            systemctl('reset-failed', unit, check=False)
        if client is not None:
            if client.poll() is None:
                client.kill()
            client.wait()
            (RUN / 'client-stderr.log').write_text(client.stderr.read())
        server.close()
        if cgroup.exists():
            cgroup.rmdir()
        for path in reversed(installed):
            path.unlink(missing_ok=True)
        for root in ('/etc/mihomo', '/run/mihomo-hostname', '/run/mihomo-hostname-target'):
            if Path(root).exists():
                shutil.rmtree(root)
        # The directory is kept stable during the run; only remove after stop.
        pins = Path('/sys/fs/bpf/mihomo-hostname')
        if pins.exists():
            assert not list(pins.iterdir()), 'observer pins remain; inspect before cleanup'
            pins.rmdir()
        systemctl('daemon-reload')
        call('semodule', '-r', 'mihomo', check=False)
        if created_user:
            call('userdel', 'mihomo')
            call('groupdel', 'mihomo', check=False)
        with Path('/var/log/audit/audit.log').open() as audit:
            audit.seek(audit_offset)
            denials = [line for line in audit if line.startswith('type=AVC') and 'denied' in line and re.search(r'scontext=\S*:mihomo(?:_hostname)?_t:', line)]
        (RUN / 'runtime-denials.log').write_text(''.join(denials))
        assert not denials, 'unexpected runtime SELinux denials; see runtime-denials.log'


def main():
    global RUN, PACK, FAMILY
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--family', type=int, choices=(4, 6), default=4)
    args = parser.parse_args()
    FAMILY = args.family
    RUN = args.run.resolve()
    PACK = RUN / 'packaging'
    assert os.geteuid() == 0
    if args.inside:
        inside()
        return
    for path in ('/etc/mihomo', '/usr/local/bin/mihomo', '/usr/local/bin/mihomo-hostname-observer',
                 '/usr/local/bin/hostname-review-client', '/etc/nftables-killswitch.conf',
                 '/etc/systemd/system/mihomo.service', '/etc/systemd/system/killswitch.service',
                 '/etc/systemd/system/mihomo-hostname-observer.service',
                 '/etc/systemd/system-generators/mihomo-process-generator',
                 '/run/mihomo-hostname', '/run/mihomo-hostname-target', '/sys/fs/bpf/mihomo-hostname'):
        assert not Path(path).exists() and not Path(path).is_symlink(), f'refusing existing path {path}'
    for unit in ('mihomo.service', 'mihomo-hostname-observer.service', 'killswitch.service'):
        assert systemctl('show', '-p', 'LoadState', '--value', unit).stdout.strip() == 'not-found', f'refusing existing unit {unit}'
    modules = call('semodule', '-l').stdout.splitlines()
    assert not any(line.split()[0] == 'mihomo' for line in modules)
    assert NS not in call('ip', 'netns', 'list').stdout
    call('ip', 'netns', 'add', NS)
    try:
        result = call('nsenter', '--net=/run/netns/' + NS, sys.executable, str(Path(__file__).resolve()), str(RUN), '--inside', '--family', str(FAMILY), check=False)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        assert result.returncode == 0, f'VM test failed ({result.returncode})'
    finally:
        call('ip', 'netns', 'delete', NS)


if __name__ == '__main__':
    main()
