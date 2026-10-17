"""Controlled HTTP/2 peers over the VM fixture's verified OpenSSL transport."""
import ssl
import threading

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded


def run_http2_matrix(*, command, api, wait, systemctl, listener, run, pin,
                     family, inbound, redirect_port=None):
    for version in (12, 13):
        class Peer:
            def __init__(self, name, chain, *, held=False, wrong_pin=False):
                self.name = name
                self.release = threading.Event()
                self.two_open = threading.Event()
                self.result = {'requests': {}, 'authorities': {}, 'error': None, 'data_order': []}
                self.request_hosts = {}
                self.bytes_sent = 0
                self.closed = False
                if not held:
                    self.release.set()
                before = {entry['id'] for entry in (api('/connections')['connections'] or [])}
                fields = command(f'open {name} name-first fd').split()
                assert fields[0] == 'socket', fields
                self.slot, self.cookie = int(fields[1]), fields[2]
                expected_pin = '0' * 64 if wrong_pin else pin
                assert command(f'verify {self.slot} {run / "peer.pem"} {name} {expected_pin} {version}') == 'ok'
                assert command(f'h2-alpn {self.slot}') == 'ok'
                assert command(f'handshake {self.slot}') == f'handshake {self.slot} -1 2'
                accepted, _ = listener.accept()
                accepted.settimeout(5)
                self.connection = wait(lambda: next((entry for entry in (api('/connections')['connections'] or [])
                                                     if entry['id'] not in before), None))
                metadata = self.connection['metadata']
                assert metadata['type'] == inbound, self.connection
                assert metadata['destinationIP'] == listener.getsockname()[0], self.connection
                assert metadata['destinationPort'] == str(listener.getsockname()[1]), self.connection
                if redirect_port is not None:
                    assert int(metadata['inboundPort']) == redirect_port, self.connection
                selected = next((item for item in self.connection['chains'] if item in ('NAMED', 'RENAMED')), 'DIRECT')
                assert selected == chain, self.connection
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(run / 'peer.pem'), str(run / 'peer.key'))
                context.minimum_version = context.maximum_version = (
                    ssl.TLSVersion.TLSv1_2 if version == 12 else ssl.TLSVersion.TLSv1_3)
                context.set_alpn_protocols(['h2'])
                names = []
                context.set_servername_callback(lambda _sock, value, _ctx: names.append(value))

                def serve():
                    try:
                        with context.wrap_socket(accepted, server_side=True) as peer:
                            assert peer.selected_alpn_protocol() == 'h2'
                            assert peer.version() == f'TLSv1.{version - 10}'
                            assert names == [name], names
                            if wrong_pin:
                                assert peer.recv(1) == b'', 'unverified client sent HTTP/2 bytes'
                                peer.unwrap().close()
                                return
                            conn = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
                            conn.initiate_connection()
                            peer.sendall(conn.data_to_send())
                            pending = []
                            while data := peer.recv(4096):
                                for event in conn.receive_data(data):
                                    if isinstance(event, RequestReceived):
                                        headers = dict(event.headers)
                                        assert headers[':authority'] == self.authority(self.request_hosts[event.stream_id]), headers
                                        self.result['authorities'][event.stream_id] = headers[':authority']
                                        assert headers[':method'] == 'POST' and headers[':scheme'] == 'https', headers
                                        assert headers[':path'] == f'/stream/{event.stream_id}', headers
                                        self.result['requests'][event.stream_id] = b''
                                    elif isinstance(event, DataReceived):
                                        self.result['data_order'].append(event.stream_id)
                                        self.result['requests'][event.stream_id] += event.data
                                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                                    elif isinstance(event, StreamEnded):
                                        assert self.result['requests'][event.stream_id] == f'request-{event.stream_id}'.encode()
                                        pending.append(event.stream_id)
                                if len(pending) == 2:
                                    assert conn.open_inbound_streams == 2, 'streams did not overlap'
                                    self.two_open.set()
                                    assert self.release.wait(15), 'response barrier timed out'
                                    # Reply out of request order and interleave DATA on both streams.
                                    for stream in reversed(pending):
                                        conn.send_headers(stream, [(':status', '200'),
                                            ('x-fixture-authority', self.result['authorities'][stream])])
                                    for half in (0, 1):
                                        for stream in reversed(pending):
                                            body = f'response-{stream}'.encode()
                                            cut = len(body) // 2
                                            conn.send_data(stream, body[:cut] if half == 0 else body[cut:],
                                                           end_stream=half == 1)
                                    pending.clear()
                                outgoing = conn.data_to_send()
                                if outgoing:
                                    peer.sendall(outgoing)
                            assert not pending, pending
                            peer.unwrap().close()
                    except Exception as error:
                        self.result['error'] = error
                    finally:
                        accepted.close()

                self.worker = threading.Thread(target=serve, daemon=True)
                self.worker.start()
                reply = command(f'tls-ready {self.slot}')
                expected = 'pin-failed' if wrong_pin else f'ok TLSv1.{version - 10} h2'
                assert reply == f'tls-ready {self.slot} {expected}', (reply, self.result)
                self.h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
                self.responses, self.ended, self.response_order = {}, set(), []
                if not wrong_pin:
                    self.h2.initiate_connection()
                    self.flush()
                self.stable()

            def stable(self):
                entry = next(item for item in (api('/connections')['connections'] or []) if item['id'] == self.connection['id'])
                assert entry['chains'] == self.connection['chains'], entry
                for key in ('destinationIP', 'destinationPort', 'type'):
                    assert entry['metadata'][key] == self.connection['metadata'][key], entry

            def flush(self):
                data = self.h2.data_to_send()
                if data:
                    assert len(data) <= 2048, len(data)
                    assert command(f'tls-send {self.slot} {data.hex()}') == 'ok'
                    self.bytes_sent += len(data)

            def authority(self, hostname):
                return f'{hostname}:{listener.getsockname()[1]}'

            def start_pair(self, streams, hosts=None):
                hosts = hosts or {stream: self.name for stream in streams}
                # Controlled origin resolution: every candidate uses this same
                # test IP/port. Check the already pinned peer certificate for
                # every hostname before building even the first HEADERS frame.
                origins = {host: listener.getsockname() for host in
                           ('route.invalid', 'reuse.invalid', 'wrong.invalid')}
                for host in set(hosts.values()):
                    assert origins[host] == listener.getsockname()
                    reply = command(f'tls-authorize {self.slot} {host}')
                    if reply == f'tls-authorize {self.slot} hostname-failed':
                        return False
                    assert reply == f'tls-authorize {self.slot} ok', reply
                self.request_hosts.update(hosts)
                for stream in streams:
                    self.h2.send_headers(stream, [(':method', 'POST'), (':scheme', 'https'),
                        (':authority', self.authority(hosts[stream])), (':path', f'/stream/{stream}')])
                for half in (0, 1):
                    for stream in streams:
                        body = f'request-{stream}'.encode()
                        cut = len(body) // 2
                        self.h2.send_data(stream, body[:cut] if half == 0 else body[cut:], end_stream=half == 1)
                assert self.h2.open_outbound_streams == 2, 'client streams did not overlap'
                self.flush()
                return True

            def finish_pair(self, streams):
                while not set(streams) <= self.ended:
                    reply = command(f'tls-recv {self.slot}').split()
                    assert reply[:2] == ['tls-data', str(self.slot)], reply
                    for event in self.h2.receive_data(bytes.fromhex(reply[2])):
                        if isinstance(event, ResponseReceived):
                            headers = dict(event.headers)
                            assert headers[':status'] == '200', event
                            assert headers['x-fixture-authority'] == self.authority(self.request_hosts[event.stream_id]), event
                            self.responses[event.stream_id] = b''
                        elif isinstance(event, DataReceived):
                            self.response_order.append(event.stream_id)
                            self.responses[event.stream_id] += event.data
                            self.h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, StreamEnded):
                            self.ended.add(event.stream_id)
                    self.flush()
                for stream in streams:
                    assert self.responses[stream] == f'response-{stream}'.encode(), self.responses
                assert self.response_order[-4:] == [streams[1], streams[0]] * 2, self.response_order
                assert self.result['data_order'][-4:] == list(streams) * 2, self.result
                self.stable()

            def close(self, *, wrong_pin=False):
                if self.closed:
                    return
                self.release.set()
                if not wrong_pin:
                    self.h2.close_connection()
                    self.flush()
                assert command(f'shutdown {self.slot}') == f'shutdown {self.slot} ok'
                self.worker.join(timeout=6)
                assert not self.worker.is_alive(), self.result
                assert self.result['error'] is None, self.result
                assert command(f'close {self.slot}') == 'ok'
                self.closed = True
                wait(lambda: all(entry['id'] != self.connection['id'] for entry in (api('/connections')['connections'] or [])))

        peers = []
        try:
            primary = Peer('route.invalid', 'NAMED', held=True)
            peers.append(primary)
            primary.start_pair((1, 3))
            wait(primary.two_open.is_set)
            assert not primary.ended
            systemctl('stop', 'mihomo-hostname-observer.service')
            fallback = Peer('route.invalid', 'DIRECT')
            peers.append(fallback)
            assert fallback.cookie != primary.cookie
            fallback.start_pair((1, 3))
            fallback.finish_pair((1, 3))
            primary.release.set()
            primary.finish_pair((1, 3))
            systemctl('reset-failed', 'mihomo-hostname-observer.service')
            systemctl('start', 'mihomo-hostname-observer.service')
            renamed = Peer('reuse.invalid', 'RENAMED')
            peers.append(renamed)
            assert renamed.cookie not in (primary.cookie, fallback.cookie)
            renamed.start_pair((1, 3))
            renamed.finish_pair((1, 3))
            renamed.close()
            fallback.start_pair((5, 7))
            fallback.finish_pair((5, 7))
            assert fallback.start_pair((9, 11), {9: 'route.invalid', 11: 'reuse.invalid'})
            fallback.finish_pair((9, 11))
            fallback.close()
            primary.start_pair((5, 7))
            primary.finish_pair((5, 7))
            assert primary.start_pair((9, 11), {9: 'route.invalid', 11: 'reuse.invalid'})
            primary.finish_pair((9, 11))
            sent = primary.bytes_sent
            next_stream = primary.h2.get_next_available_stream_id()
            received = dict(primary.result['authorities'])
            assert not primary.start_pair((13, 15), {13: 'route.invalid', 15: 'wrong.invalid'})
            assert primary.bytes_sent == sent and primary.h2.data_to_send() == b''
            assert primary.h2.get_next_available_stream_id() == next_stream
            assert primary.result['authorities'] == received
            # Refusing an uncovered name does not poison the verified socket.
            assert primary.start_pair((13, 15), {13: 'reuse.invalid', 15: 'reuse.invalid'})
            primary.finish_pair((13, 15))
            assert primary.connection['chains'] != renamed.connection['chains']
            assert set(primary.result['authorities'].values()) == {
                primary.authority('route.invalid'), primary.authority('reuse.invalid')}
            primary.close()
            rejected = Peer('route.invalid', 'NAMED', wrong_pin=True)
            peers.append(rejected)
            rejected.close(wrong_pin=True)
            assert rejected.result['requests'] == {}, rejected.result
            print(f'PASS IPv{family} TLSv1.{version - 10} {inbound} HTTP/2 multiplexing, reuse and observer fallback (16 streams)', flush=True)
            print(f'PASS IPv{family} TLSv1.{version - 10} {inbound} HTTP/2 certificate-checked cross-origin reuse and uncovered-name refusal', flush=True)
        finally:
            for peer in peers:
                peer.release.set()
                if not peer.closed:
                    command(f'close {peer.slot}')
                    peer.worker.join(timeout=6)
