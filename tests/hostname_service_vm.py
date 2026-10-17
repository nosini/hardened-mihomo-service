#!/usr/bin/python3
"""Privileged disposable-VM integration test; see docs/hostname-development.md.

The run directory contains packaging/, mihomo, mihomo-hostname-observer and
client.c. Refuses existing production paths. Uses a dedicated network namespace
and removes only its own fixtures. Never run this on a deployed machine.
"""
import argparse
from contextlib import contextmanager
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

from hostname_http2 import run_http2_matrix

NS = 'mihomo-hostname-review'
# Holds the TUN group's server, so its address is not local to NS.
REMOTE = 'mihomo-hostname-remote'
RUN = None
PACK = None
FAMILY = 4
AUTO_REDIRECT = False
INTERRUPT_RECOVERY_POLL = False


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


def application_user():
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)


@contextmanager
def interrupt_recovery_poll():
    if not INTERRUPT_RECOVERY_POLL:
        yield
        return
    pid = int(systemctl('show', '-p', 'MainPID', '--value', 'mihomo.service').stdout)
    trace = RUN / 'recovery-poll.trace'
    with (RUN / 'recovery-poll-tracer.log').open('w') as errors:
        tracer = subprocess.Popen(['strace', '-f', '-p', str(pid), '-o', str(trace),
            '-e', 'trace=ppoll', '-e', 'inject=ppoll:error=EINTR:when=1'],
            stdout=subprocess.DEVNULL, stderr=errors)
        try:
            def attached():
                if tracer.poll() is not None:
                    raise AssertionError('strace exited; see recovery-poll-tracer.log')
                tasks = list(Path(f'/proc/{pid}/task').iterdir())
                return tasks and all(
                    f'TracerPid:\t{tracer.pid}\n' in (task / 'status').read_text()
                    for task in tasks)
            wait(attached)
            yield
        finally:
            if tracer.poll() is None:
                tracer.send_signal(2)  # detach; leave the tracee running
            tracer.wait(timeout=5)
    assert 'INJECTED' in trace.read_text(), 'recovery poll was not interrupted'


def wait_mihomo():
    wait(lambda: api('/version'))
    # The control API starts before inbound listeners. Avoid sending a SYN to
    # a not-yet-listening REDIRECT port immediately after a service restart.
    wait(lambda: call('ss', '-H', '-ltn', 'sport = :18661').stdout.strip())
    # ApplyConfig creates listeners before tunnel.OnRunning. A listening port
    # alone can still accept and discard a connection during that interval.
    # Probe an independent unobserved flow, with its own destination/rule, so
    # readiness retries cannot consume or retry a matrix connection.
    address = '127.0.0.1' if FAMILY == 4 else '::1'
    with socket.socket(socket.AF_INET if FAMILY == 4 else socket.AF_INET6) as peer:
        peer.bind((address, 0))
        peer.listen()
        peer.settimeout(1)
        port = peer.getsockname()[1]
        call('nft', '-f', '-', input=f'''table inet hostname_ready {{
 chain output {{ type nat hook output priority dstnat; policy accept;
 meta skuid 1000 {'ip' if FAMILY == 4 else 'ip6'} daddr {address} tcp dport {port} redirect to :18661
 }}
}}''')
        try:
            def relay_ready():
                script = ('import socket; '
                          f's=socket.socket(socket.AF_INET{6 if FAMILY == 6 else ""}); '
                          's.settimeout(1); '
                          f's.connect(({address!r},{port})); '
                          's.sendall(b"ready"); assert s.recv(5)==b"ready"')
                child = subprocess.Popen([sys.executable, '-c', script],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    preexec_fn=application_user)
                try:
                    accepted, _ = peer.accept()
                    with accepted:
                        accepted.settimeout(1)
                        if accepted.recv(5) != b'ready':
                            return False
                        accepted.sendall(b'ready')
                    return child.wait(timeout=2) == 0
                except (OSError, subprocess.TimeoutExpired):
                    return False
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait()
            wait(relay_ready)
            wait(lambda: not api('/connections')['connections'])
        finally:
            call('nft', 'delete', 'table', 'inet', 'hostname_ready')


def inside():
    assert call('/usr/sbin/getenforce').stdout.strip() == 'Enforcing'
    call('ip', 'link', 'set', 'lo', 'up')
    # This fixture-owned netns uses small receive windows to force actual
    # nonblocking retries through the real redirect listener.
    receive_defaults = Path('/proc/sys/net/ipv4/tcp_rmem').read_text()
    Path('/proc/sys/net/ipv4/tcp_rmem').write_text('4096 4096 4096\n')
    # An isolated non-loopback path proves the shipped kill-switch output drop
    # survives observer failure. It has no route to the guest or the LAN.
    call('ip', 'link', 'add', 'review0', 'type', 'dummy')
    call('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'review0')
    call('ip', 'link', 'set', 'review0', 'up')
    installed = []
    created_user = False
    client = None
    tun_server = None
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
  - {name: RENAMED, type: select, proxies: [DIRECT]}
rules:
  - DOMAIN,route.invalid,NAMED
  - DOMAIN,reuse.invalid,RENAMED
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
        # Ephemeral fixture trust stays in this run directory and client only.
        for name in ('peer', 'untrusted'):
            call('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', str(RUN / (name + '.key')), '-out', str(RUN / (name + '.pem')),
                 '-days', '1', '-subj', '/CN=route.invalid',
                 '-addext', 'subjectAltName=DNS:route.invalid,DNS:reuse.invalid')
        certificate = ssl.PEM_cert_to_DER_cert((RUN / 'peer.pem').read_text())
        pin = hashlib.sha256(certificate).hexdigest()
        client = subprocess.Popen(['/usr/local/bin/hostname-review-client', str(FAMILY), address, str(port)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, preexec_fn=application_user)
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

        def probe(named, listener=None, inbound='Redir'):
            opened = command('open route.invalid name-first fd')
            assert opened.startswith('socket '), opened
            slot = int(opened.split()[1])
            hello = command(f'handshake {slot}')
            assert hello == f'handshake {slot} -1 2', hello
            try:
                accepted, _ = (listener or server).accept()
            except TimeoutError:
                (RUN / 'probe-sockets.log').write_text(call('ss', '-tinm').stdout)
                raise
            try:
                accepted.settimeout(5)
                data = accepted.recv(4096)
                assert data.startswith(b'\x16\x03') and b'route.invalid' in data, data
                connection = wait(lambda: next(iter(api('/connections')['connections'] or []), None))
                assert ('NAMED' in connection['chains']) == named, connection
                assert connection['metadata']['type'] == inbound, connection
                if AUTO_REDIRECT and listener is not None:
                    assert int(connection['metadata']['inboundPort']) == auto_redirect_port, connection
                # The real destination is kept, never replaced by the name.
                peer = accepted.getsockname()
                assert connection['metadata']['destinationIP'] == peer[0], connection
                assert connection['metadata']['destinationPort'] == str(peer[1]), connection
            finally:
                command(f'close {slot}')
                accepted.close()
                wait(lambda: not api('/connections')['connections'])

        def tls_probe(named, version, failure=None, window=None, listener=None, inbound='Redir'):
            if window == 'retry':
                assert command('tiny-send') == 'ok'
            opened = command('open route.invalid name-first fd')
            assert opened.startswith('socket '), opened
            slot = int(opened.split()[1])
            if window == 'retry':
                assert command('normal-send') == 'ok'
            trust = RUN / ('untrusted.pem' if failure == 'trust' else 'peer.pem')
            hostname = 'wrong.invalid' if failure == 'hostname' else 'route.invalid'
            expected_pin = '0' * 64 if failure == 'pin' else pin
            assert command(f'verify {slot} {trust} {hostname} {expected_pin} {version}') == 'ok'
            if window:
                shape = 'retry-alpn' if window == 'retry' else 'large-alpn'
                assert command(f'{shape} {slot}') == 'ok'
            hello = command(f'handshake {slot}')
            expected_error = 3 if window == 'retry' else 2
            assert hello == f'handshake {slot} -1 {expected_error}', hello
            # WANT_WRITE proves the live TLS exchange begins with a pending
            # nonblocking write, then exchange must drain it through TLS.
            accepted, _ = (listener or server).accept()
            accepted.settimeout(5)
            connection = wait(lambda: next(iter(api('/connections')['connections'] or []), None))
            assert ('NAMED' in connection['chains']) == named, connection
            assert connection['metadata']['type'] == inbound, connection
            if AUTO_REDIRECT and listener is not None:
                assert int(connection['metadata']['inboundPort']) == auto_redirect_port, connection
            expected = (listener or server).getsockname()
            assert connection['metadata']['destinationIP'] == expected[0], connection
            assert connection['metadata']['destinationPort'] == str(expected[1]), connection
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
            elif failure == 'pin':
                # The client closes after checking the certificate pin. A TLS
                # 1.3 session-ticket write can race that close on the server.
                assert result['error'] is None or isinstance(
                    result['error'], (BrokenPipeError, ConnectionResetError)), result
                assert result['request'] == b'', result
            else:
                assert result['error'] is None, result
            wait(lambda: not api('/connections')['connections'])

        for version in (12, 13):
            for window in ('large', 'retry'):
                tls_probe(True, version, window=window)
        print(f'PASS IPv{FAMILY} large ClientHello and short-write TLS 1.2/1.3', flush=True)
        # A 4 KiB total receive allocation can drop whole relay packets even
        # with an advertised window (skb overhead counts toward this limit).
        # Keep that pressure in the short-write cases, then recreate listeners
        # with normal buffers for the certificate/session matrices.
        Path('/proc/sys/net/ipv4/tcp_rmem').write_text(receive_defaults)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(receive_defaults.split()[1]))
        systemctl('restart', 'mihomo.service')
        wait_mihomo()
        systemctl('start', 'mihomo-hostname-observer.service')
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
        def restarted():
            # One state snapshot: separate is-active/MainPID queries can cross
            # a transition, and MainPID=0 is not a recovered observer.
            state = dict(line.split('=', 1) for line in systemctl('show', '-p',
                'ActiveState,SubState,MainPID', 'mihomo-hostname-observer.service').stdout.splitlines())
            return (state['ActiveState'] == 'active' and state['SubState'] == 'running'
                    and int(state['MainPID']) not in (0, oldpid))
        wait(restarted)
        with interrupt_recovery_poll():
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
        # The shipped default inbound: TUN system stack with auto-route. The
        # server sits behind a veth in another namespace, so the target's
        # connection is routed into the device while Mihomo dials out directly.
        # auto-route keeps connected subnets off the TUN, so the server's
        # address is only reachable through the default route.
        local, gateway, prefix, remote, host = ('198.51.100.1', '198.51.100.2', '/24', '203.0.113.2', '/32') if FAMILY == 4 else ('2001:db8:6::1', '2001:db8:6::2', '/64', '2001:db8:7::2', '/128')
        nodad = [] if FAMILY == 4 else ['nodad']
        call('ip', 'netns', 'add', REMOTE)
        call('ip', 'link', 'add', 'review1', 'type', 'veth', 'peer', 'name', 'review2')
        call('ip', 'link', 'set', 'review2', 'netns', REMOTE)
        call('ip', '-n', REMOTE, 'link', 'set', 'lo', 'up')
        call('ip', '-n', REMOTE, 'address', 'add', remote + host, 'dev', 'lo')
        call('ip', '-n', REMOTE, 'address', 'add', gateway + prefix, 'dev', 'review2', *nodad)
        call('ip', '-n', REMOTE, 'link', 'set', 'review2', 'up')
        call('ip', 'address', 'add', local + prefix, 'dev', 'review1', *nodad)
        call('ip', 'link', 'set', 'review1', 'up')
        call('ip', f'-{FAMILY}', 'route', 'add', 'default', 'via', gateway, 'dev', 'review1')
        own = os.open('/proc/self/ns/net', os.O_RDONLY)
        theirs = os.open(f'/run/netns/{REMOTE}', os.O_RDONLY)
        try:
            os.setns(theirs, os.CLONE_NEWNET)
            tun_server = socket.socket(socket.AF_INET if FAMILY == 4 else socket.AF_INET6)
            tun_server.bind((remote, 0))
            tun_server.listen()
            tun_server.settimeout(5)
        finally:
            os.setns(own, os.CLONE_NEWNET)
            os.close(own)
            os.close(theirs)
        config.write_text(config.read_text().replace('tun: {enable: false}', '''tun:
  enable: true
  device: Mihomo
  stack: system
  auto-route: true
  auto-detect-interface: true
  inet4-address: [198.18.0.1/30]
  inet6-address: [fdfe:dcba:9876::1/126]'''))
        if AUTO_REDIRECT:
            config.write_text(config.read_text().replace('  auto-route: true', '  auto-route: true\n  auto-redirect: true'))
        systemctl('restart', 'mihomo.service')
        wait_mihomo()
        # /sys/class/net still shows the guest's devices; ask this namespace.
        wait(lambda: call('ip', 'link', 'show', 'Mihomo', check=False).returncode == 0)

        def tun_ready():
            # Device creation precedes IPv6 DAD and the system stack's
            # listener. Starting a socket earlier can select a source/route
            # that bypasses the TUN even after startup finishes.
            tun_address = '198.18.0.1' if FAMILY == 4 else 'fdfe:dcba:9876::1'
            addresses = json.loads(call('ip', '-j', 'address', 'show', 'dev', 'Mihomo').stdout)
            if not any(item['local'] == tun_address and not item.get('tentative') and not item.get('dadfailed')
                       for link in addresses for item in link['addr_info']):
                return False
            if tun_address not in call('ss', '-H', '-ltn').stdout:
                return False
            routes = json.loads(call('ip', '-j', f'-{FAMILY}', 'route', 'get', remote, 'uid', '1000').stdout)
            return routes and routes[0]['dev'] == 'Mihomo'

        wait(tun_ready)
        if FAMILY == 6:
            # A connect without a source can choose the TUN while a connected
            # socket's later lookup bypasses it. Test both sourceful paths,
            # including the loopback input selector used for local output.
            def route_device(source, incoming):
                routes = json.loads(call('ip', '-j', '-6', 'route', 'get', remote,
                                         'from', source, 'iif', incoming).stdout)
                return routes[0]['dev']
            assert route_device('fdfe:dcba:9876::1', 'lo') == 'Mihomo'
            assert route_device(local, 'lo') == 'review1'
            assert route_device('fdfe:dcba:9876::1', 'Mihomo') == 'review1'
        inbound = 'Redir' if AUTO_REDIRECT else 'Tun'
        if AUTO_REDIRECT:
            auto_redirect_port = int(wait(lambda: re.search(r'redirect to :(\d+)',
                call('nft', 'list', 'table', 'inet', 'mihomo', check=False).stdout)).group(1))
        assert command('any-source') == 'ok'
        assert command(f'destination {remote} {tun_server.getsockname()[1]}') == 'ok'
        probe(True, tun_server, inbound)
        tls_probe(True, 13, listener=tun_server, inbound=inbound)
        if AUTO_REDIRECT:
            for version in (12, 13):
                tls_probe(True, version, listener=tun_server, inbound=inbound)
                for failure in ('trust', 'hostname', 'pin'):
                    tls_probe(True, version, failure, listener=tun_server, inbound=inbound)
            print(f'PASS IPv{FAMILY} auto-redirect TLS 1.2/1.3 certificate, hostname and pin verification', flush=True)
        systemctl('stop', 'mihomo-hostname-observer.service')
        probe(False, tun_server, inbound)
        systemctl('start', 'mihomo-hostname-observer.service')
        probe(True, tun_server, inbound)
        assert 'CapEff:\t0000000000001400' in Path(f'/proc/{int(systemctl("show", "-p", "MainPID", "--value", "mihomo.service").stdout)}/status').read_text()
        print(f'PASS IPv{FAMILY} {"auto-redirect" if AUTO_REDIRECT else "TUN system-stack"} named routing, completed TLS and fallback', flush=True)
        def session_context(version):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(RUN / 'peer.pem'), str(RUN / 'peer.key'))
            protocol = ssl.TLSVersion.TLSv1_2 if version == 12 else ssl.TLSVersion.TLSv1_3
            context.minimum_version = context.maximum_version = protocol
            return context

        def session_probe(context, version, *, previous=None, resume=False,
                          resumed=False, name='route.invalid', chain='NAMED',
                          rounds=1, pin_failure=False, groups=None, hrr=False, stop_after_route=False):
            # The server context persists between connections, including its
            # ticket keys. Each invocation still gets a new TCP lifetime.
            if previous is None:
                opened = command(f'open {name} name-first fd')
            else:
                opened = command(f'reopen {previous[1]} {name}')
            fields = opened.split()
            assert fields[0] == 'socket', opened
            slot = int(fields[1])
            if previous is not None:
                assert fields[1] == previous[1] and fields[2] != previous[2], (previous, fields)
            expected_pin = '0' * 64 if pin_failure else pin
            hostname = 'route.invalid' if name == '-' else name
            assert command(f'verify {slot} {RUN / "peer.pem"} {hostname} {expected_pin} {version}') == 'ok'
            if resume:
                assert command(f'resume {slot}') == 'ok'
            if groups:
                assert command(f'groups {slot} {groups}') == 'ok'
            assert command(f'handshake {slot}') == f'handshake {slot} -1 2'
            if groups:
                assert command(f'hello-state {slot}') == f'hello-state {slot} client-hellos 1 hello-retries 0'
            accepted, _ = tun_server.accept()
            accepted.settimeout(5)
            connection = wait(lambda: next(iter(api('/connections')['connections'] or []), None))
            assert connection['metadata']['type'] == inbound, connection
            if AUTO_REDIRECT:
                assert int(connection['metadata']['inboundPort']) == auto_redirect_port, connection
            assert connection['metadata']['destinationIP'] == remote, connection
            assert connection['metadata']['destinationPort'] == str(tun_server.getsockname()[1]), connection
            selected = next((item for item in connection['chains'] if item in ('NAMED', 'RENAMED')), 'DIRECT')
            assert selected == chain, connection
            # This route is committed before the server sends any HRR. Losing
            # discovery authority cannot change the relay already selected.
            if stop_after_route:
                systemctl('stop', 'mihomo-hostname-observer.service')
            result = {'names': [], 'requests': [], 'error': None}
            context.set_servername_callback(lambda _sock, value, _ctx: result['names'].append(value))

            def serve_session():
                try:
                    with context.wrap_socket(accepted, server_side=True) as peer:
                        result['resumed'] = peer.session_reused
                        result['version'] = peer.version()
                        request = b'hostname-fixture-request\n'
                        for _ in range(0 if pin_failure else rounds):
                            received = b''
                            while len(received) < len(request):
                                chunk = peer.recv(len(request) - len(received))
                                assert chunk, result
                                received += chunk
                            assert received == request, received
                            result['requests'].append(received)
                            peer.sendall(b'hostname-fixture-response\n')
                        # Reuse tests close TLS cleanly so the retained session
                        # is not invalidated by SSL_free or SSL_clear.
                        assert peer.recv(1) == b'', result
                        peer.unwrap().close()
                except Exception as error:
                    result['error'] = error

            worker = threading.Thread(target=serve_session, daemon=True)
            worker.start()
            complete = False
            try:
                for round_index in range(1 if pin_failure else rounds):
                    if FAMILY == 6 and round_index:
                        # Force a fresh route lookup on the same live TLS
                        # connection instead of relying on an intermittent
                        # socket-cache expiry to expose sourceful routing.
                        call('ip', '-6', 'route', 'flush', 'cache')
                    reply = command(f'exchange {slot}')
                    expected = 'pin-failed' if pin_failure else f'ok TLSv1.{version - 10}'
                    if reply != f'exchange {slot} {expected}':
                        (RUN / 'session-sockets.log').write_text(
                            call('ss', '-tinm').stdout + '\nREMOTE\n' +
                            call('ip', 'netns', 'exec', REMOTE, 'ss', '-tinm').stdout)
                        (RUN / 'session-routes.log').write_text(
                            call('ip', '-6', 'rule', 'show').stdout + '\nROUTES\n' +
                            call('ip', '-6', 'route', 'show', 'table', 'all').stdout +
                            '\nLOOKUP\n' + call('ip', f'-{FAMILY}', 'route', 'get', remote,
                                                  'uid', '1000').stdout)
                    assert reply == f'exchange {slot} {expected}', (reply, result)
                    live = api('/connections')['connections']
                    assert len(live) == 1 and live[0]['id'] == connection['id'], live
                    assert live[0]['chains'] == connection['chains'], live
                if groups:
                    state = command(f'hello-state {slot}')
                    expected_hellos = 2 if hrr else 1
                    assert state == f'hello-state {slot} client-hellos {expected_hellos} hello-retries {int(hrr)}', state
                state = command(f'session-state {slot}')
                assert state.startswith(f'session {slot} reused {int(resumed)} resumable '), state
                shutdown_reply = command(f'shutdown {slot}')
                assert shutdown_reply == f'shutdown {slot} ok', (shutdown_reply, result)
                worker.join(timeout=6)
                assert not worker.is_alive(), result
                assert result['error'] is None, result
                assert result['resumed'] == resumed, result
                assert result['version'] == f'TLSv1.{version - 10}', result
                assert result['names'] == [None if name == '-' else name] * (2 if hrr else 1), result
                assert len(result['requests']) == (0 if pin_failure else rounds), result
                if not pin_failure:
                    assert command(f'save-session {slot}') == 'ok'
                wait(lambda: not api('/connections')['connections'])
                complete = True
                print(f'  TLSv1.{version - 10} name={name} chain={chain} offered={resume} '
                      f'resumed={resumed} same_ssl={previous is not None} rounds={rounds} '
                      f'pin_rejected={pin_failure} hrr={hrr} groups={groups}', flush=True)
                return fields
            finally:
                if not complete and client.poll() is None:
                    command(f'close {slot}')
                accepted.close()
                worker.join(timeout=6)

        for version in (12, 13):
            context = session_context(version)
            # A seed and a different SSL object with its retained ticket.
            saved = session_probe(context, version)
            assert command(f'close {saved[1]}') == 'ok'
            current = session_probe(context, version, resume=True, resumed=True)
            assert current[2] != saved[2], (saved, current)
            # Then the exact same SSL object, reset onto successive sockets.
            current = session_probe(context, version, previous=current, resume=True, resumed=True, rounds=3)
            current = session_probe(context, version, previous=current, resume=True, resumed=True)
            # A new name must select a different rule; clearing the name must
            # not leave either old name authoritative on the next connection.
            current = session_probe(context, version, previous=current, name='reuse.invalid', chain='RENAMED')
            current = session_probe(context, version, previous=current, name='-', chain='DIRECT')
            current = session_probe(context, version, previous=current)
            # A different server context declines the offered ticket and does
            # a full handshake. This must not change hostname routing.
            context = session_context(version)
            current = session_probe(context, version, previous=current, resume=True)
            systemctl('stop', 'mihomo-hostname-observer.service')
            current = session_probe(context, version, previous=current, resume=True, resumed=True, chain='DIRECT')
            systemctl('reset-failed', 'mihomo-hostname-observer.service')
            systemctl('start', 'mihomo-hostname-observer.service')
            current = session_probe(context, version, previous=current, resume=True, resumed=True)
            # Pin checks still run on an actually resumed handshake, before
            # any application request, even when no certificate is resent.
            current = session_probe(context, version, previous=current, resume=True, resumed=True, pin_failure=True)
            assert command(f'close {current[1]}') == 'ok'
            print(f'PASS IPv{FAMILY} TLSv1.{version - 10} {"auto-redirect" if AUTO_REDIRECT else "TUN"} session resumption, SSL reuse and fallback', flush=True)

        # Advertise P-256 but initially share only X25519. The server's
        # P-256-only policy forces HRR; reversing client preference is the
        # negative control. Message counters prove the actual flight counts.
        def hrr_probe(*, retry=True, chain='NAMED', stop_after_route=False, pin_failure=False):
            context = session_context(13)
            context.set_ecdh_curve('prime256v1')
            fields = session_probe(context, 13,
                groups='X25519:P-256' if retry else 'P-256:X25519', hrr=retry,
                chain=chain, stop_after_route=stop_after_route,
                rounds=3, pin_failure=pin_failure)
            assert command(f'close {fields[1]}') == 'ok'

        hrr_probe(retry=False)
        hrr_probe()
        hrr_probe(stop_after_route=True)
        hrr_probe(chain='DIRECT')
        systemctl('reset-failed', 'mihomo-hostname-observer.service')
        systemctl('start', 'mihomo-hostname-observer.service')
        hrr_probe(pin_failure=True)
        print(f'PASS IPv{FAMILY} TLSv1.3 {"auto-redirect" if AUTO_REDIRECT else "TUN"} HelloRetryRequest and stable routes', flush=True)

        run_http2_matrix(command=command, api=api, wait=wait, systemctl=systemctl,
            listener=tun_server, run=RUN, pin=pin, family=FAMILY, inbound=inbound,
            redirect_port=auto_redirect_port if AUTO_REDIRECT else None)

        if AUTO_REDIRECT:
            # Two original destinations collapse onto the same redirect
            # listener. Hold both connections live and force the same source
            # port, so NAT must distinguish their accepted source ports.
            alternate = '203.0.113.3' if FAMILY == 4 else '2001:db8:7::3'
            call('ip', '-n', REMOTE, 'address', 'add', alternate + host, 'dev', 'lo')
            own = os.open('/proc/self/ns/net', os.O_RDONLY)
            theirs = os.open(f'/run/netns/{REMOTE}', os.O_RDONLY)
            try:
                os.setns(theirs, os.CLONE_NEWNET)
                second = socket.socket(socket.AF_INET if FAMILY == 4 else socket.AF_INET6)
                second.bind((alternate, tun_server.getsockname()[1]))
                second.listen()
                second.settimeout(5)
            finally:
                os.setns(own, os.CLONE_NEWNET)
                os.close(own)
                os.close(theirs)
            slots, peers, reports, routed = [], [], [], []
            try:
                cases = ((remote, 'route.invalid', 'NAMED', tun_server),
                         (alternate, 'reuse.invalid', 'RENAMED', second))
                for target, name, chain, listener in cases:
                    assert command(f'destination {target} {listener.getsockname()[1]}') == 'ok'
                    opened = command(f'open {name} name-first fd').split()
                    assert opened[0] == 'socket', opened
                    slot = int(opened[1])
                    slots.append(slot)
                    reports.append(opened)
                    if len(slots) == 1:
                        assert command(f'source {opened[4]}') == 'ok'
                    else:
                        assert opened[4] == reports[0][4] and opened[2] != reports[0][2], reports
                    assert command(f'handshake {slot}') == f'handshake {slot} -1 2'
                    peer, _ = listener.accept()
                    peers.append(peer)
                    peer.settimeout(5)
                    hello = peer.recv(4096)
                    assert hello.startswith(b'\x16\x03') and name.encode() in hello, hello
                    entry = wait(lambda: next((item for item in api('/connections')['connections'] or []
                                               if item['metadata']['destinationIP'] == target), None))
                    assert entry['metadata']['type'] == 'Redir', entry
                    assert int(entry['metadata']['inboundPort']) == auto_redirect_port, entry
                    assert entry['metadata']['destinationPort'] == str(listener.getsockname()[1]), entry
                    assert chain in entry['chains'] and ({'NAMED', 'RENAMED'} - {chain}).isdisjoint(entry['chains']), entry
                    routed.append(entry)
                ports = [int(item['metadata']['sourcePort']) for item in routed]
                assert ports[0] != ports[1] and any(value != int(reports[0][4]) for value in ports), (ports, reports)
                assert routed[0]['metadata']['sourceIP'] == routed[1]['metadata']['sourceIP'], routed
                assert len(api('/connections')['connections']) == 2
            finally:
                for slot in slots:
                    command(f'close {slot}')
                for peer in peers:
                    peer.close()
                second.close()
                command('source 0')
                command(f'destination {remote} {tun_server.getsockname()[1]}')
            wait(lambda: not api('/connections')['connections'])
            print(f'PASS IPv{FAMILY} auto-redirect source-port collision preserves distinct names and destinations', flush=True)

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
        if tun_server is not None:
            tun_server.close()
        if REMOTE in call('ip', 'netns', 'list').stdout:
            call('ip', 'netns', 'delete', REMOTE)
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
    global RUN, PACK, FAMILY, AUTO_REDIRECT, INTERRUPT_RECOVERY_POLL
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--family', type=int, choices=(4, 6), default=4)
    parser.add_argument('--auto-redirect', action='store_true')
    parser.add_argument('--interrupt-recovery-poll', action='store_true')
    args = parser.parse_args()
    FAMILY = args.family
    AUTO_REDIRECT = args.auto_redirect
    INTERRUPT_RECOVERY_POLL = args.interrupt_recovery_poll
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
    assert REMOTE not in call('ip', 'netns', 'list').stdout
    guest_tcp_rmem = Path('/proc/sys/net/ipv4/tcp_rmem').read_text()
    call('ip', 'netns', 'add', NS)
    try:
        result = call('nsenter', '--net=/run/netns/' + NS, sys.executable, str(Path(__file__).resolve()), str(RUN), '--inside', '--family', str(FAMILY), *(['--auto-redirect'] if AUTO_REDIRECT else []), *(['--interrupt-recovery-poll'] if INTERRUPT_RECOVERY_POLL else []), check=False)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        assert result.returncode == 0, f'VM test failed ({result.returncode})'
    finally:
        call('ip', 'netns', 'delete', NS)
        assert Path('/proc/sys/net/ipv4/tcp_rmem').read_text() == guest_tcp_rmem


if __name__ == '__main__':
    main()
