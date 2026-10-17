# Hostname service development

Run the generator checks in this checkout:

```sh
python3 -m unittest discover -s tests -v
```

They cover all three process modes, independent hostname enablement, nested
aliases/merges, boolean defaults and malformed settings. Bad configuration
leaves a deny-start drop-in without logging configuration contents.

Build the SELinux module with the distribution's development policy and check
units with `systemd-analyze verify`. The optional observer uses its own domain,
runtime/state/registration types and BPF map-creation label. The reader receives
Unix-socket, transferred-FD, read-only map and pidfs metadata permissions. Tests
must verify the actual running contexts, not only successful starts.

## Disposable VM integration

`tests/hostname_service_vm.py` requires root, systemd, enforcing SELinux, the
SELinux development package, Python/PyYAML, gcc/OpenSSL headers, iproute2,
nftables and the openssl CLI. Use a disposable Linux amd64 VM with the observer's
exact verified libraries, BPF LSM, cgroup v2, bpffs and packaged Python
`h2` (hyper-h2). Do not run it on a deployed machine.
It refuses existing Mihomo units, binaries, config, runtime/pin directories and
policy module rather than replacing them.

Prepare a run directory with:

- `packaging/`: this repository's files (without its .git directory).
- `mihomo`: a static (`CGO_ENABLED=0`) optional-reader Mihomo build with
  `hostname_discovery`, suitable for the unit's empty root.
- `mihomo-hostname-observer`: the independent observer build including registration.
- `client.c`: socketowner's controlled OpenSSL fixture from
  `experiments/hostname/testdata/client.c`.

Run, keeping logs in that directory:

```sh
sudo python3 tests/hostname_service_vm.py /absolute/path/to/run --family 4
sudo python3 tests/hostname_service_vm.py /absolute/path/to/run --family 6
# Repeat the service matrices with the actual local nftables auto-redirect listener:
sudo python3 tests/hostname_service_vm.py /absolute/path/to/run --family 4 --auto-redirect
sudo python3 tests/hostname_service_vm.py /absolute/path/to/run --family 6 --auto-redirect
```

The harness compiles/loads the shipped policy, temporarily installs the binaries,
units and actual generator, and selects a dedicated network namespace for Mihomo
and the shipped kill switch. Its target runs as UID 1000; the observer uses the
shipped private-network unit. `nsenter` changes only the harness's network
namespace, preserving the VM's selinuxfs mount for enforcing-state checks.
The fixture omits the unrelated network-online dependency and external kill-switch
include, enables a controlled dual-stack REDIRECT listener with sniffing/DNS/TUN
off, and adds only a target-specific local REDIRECT rule. A later group switches
to the shipped TUN shape (system stack, auto-route, auto-detect-interface,
device `Mihomo`) and reaches a server behind a veth in a second fixture
namespace. It does not modify guest uplinks or an existing network-protection
service. Only the fixture network namespace
uses reduced TCP receive-buffer defaults to force nonblocking ClientHello
retries; the harness checks that the guest defaults remain unchanged.

Checks include a stale registration with ordinary Mihomo startup; actual
`mihomo_t`/`mihomo_hostname_t` execution; the base Mihomo capability set; private
registration absent and hostname pins masked in the reader's root; a
DOMAIN-selected chain with original destination and ClientHello relay; ordinary fallback after stop
and crash; restart visibility through the same endpoint-directory bind; fresh
maps after automatic recovery; target exit/stale restart; disable/re-enable
without extra capabilities; no runtime SELinux denials; and a counted non-loopback
application packet dropped by the shipped kill switch.

The full-TLS matrix also fixes TLS 1.2/1.3, verifies the peer certificate and
hostname with a client-only test trust store, checks a SHA-256 certificate pin,
and exchanges known application bytes in both directions. Untrusted certificates,
wrong hostnames and wrong pins must fail without delivering application data.
In the default TUN mode, each family runs fifty-four TLS connections:
forty-three successful exchanges
(including large ClientHellos, actual short-write retries, observer stop/restart,
recovery after SIGKILL, feature disablement, TUN and session resumption) and eleven
intentional rejections. Both TLS versions exercise a ClientHello above 4 KiB and
a pending write that starts with
`SSL_ERROR_WANT_WRITE`, then completes through the real redirect listener. After
the handshake and application exchange, the same connection ID and chain must
remain live despite unsupported later sends revoking initial-window discovery
authority. The peer checks the unchanged SNI, and the API confirms the
original destination IP/port.

The TLS 1.3 HelloRetryRequest group adds five connections per family/mode.
The client supports X25519 and P-256, initially sharing X25519; a P-256-only
server forces a key-share retry. Reversed client preference is a no-retry
control. OpenSSL's message callback counts sent ClientHellos and identifies
received HRR by the fixed ServerHello Random in
[RFC 8446 section 4.1.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3).
Before the peer starts TLS, each case must have exactly one ClientHello and no
HRR; completion requires two ClientHellos/one HRR, or one/zero for the control.
The server sees the same SNI on both ClientHellos. Repeated application exchanges
preserve the connection ID, selected chain and original destination, including
observer stop after initial route commitment and new-socket fallback while it
is stopped. A wrong pin after HRR still delivers no application request.
Certificate and hostname verification stay enabled. These are full handshakes,
not ticket resumption, and use no added adapter/profile/runtime permissions.
Cookie-only HRR, malformed retry flights and other TLS implementations remain
unproved.

The HTTP/2 group negotiates `h2` ALPN over both TLS 1.2 and 1.3 using the
existing OpenSSL fixture. The test harness uses hyper-h2 to encode and validate
both peers' HTTP/2 and HPACK state, without adding a protocol parser or dependency
to Mihomo/observer/reader. New fixture commands expose only bounded application
byte I/O after certificate, hostname, pin and ALPN verification.

Each TLS version adds four connections: a named primary, ordinary fallback while
the observer is stopped, a new hostname selecting RENAMED after restart, and a
wrong-pin rejection that sends no HTTP/2 preface or request. Two streams are open
at once on both peers before any response is sent. Request DATA alternates
between stream IDs; response headers and DATA arrive in reverse/interleaved
order. Bodies and status are checked per stream. The primary survives observer
stop with responses held pending; both the named and fallback connections open
another pair of streams after observer restart on the same connection ID,
chain and destination. Sixteen successful streams per TLS version cover multiplexing and reuse.
The group adds eight TLS connections and thirty-two streams per mode/family.
This is controlled HTTP/2, not automatic browser coalescing, HTTP/2 proxying
inside Mihomo, load testing or a general HTTP/2 conformance suite.

Cross-origin reuse uses explicit fixture origin mappings to the same test IP
and port. Before building HEADERS, `tls-authorize` checks each hostname against
the already verified/pinned peer certificate's DNS SANs. Mixed-origin stream
pairs on both existing NAMED and DIRECT connections preserve their original
ID/chain/destination, while a fresh TLS connection for `reuse.invalid` selects
RENAMED. The peer echoes the received authority, including the test port, and
the client checks it independently for each response.
An uncovered `wrong.invalid` is refused by the fixture client before any frame
is built or sent: HTTP/2 byte count, next stream ID and peer request set
stay unchanged. Valid requests then reuse those same stream IDs on the existing
connection. No additional TLS connections are needed for these cases.
This demonstrates connection-based domain routing: a covered second HTTP origin
shares the route chosen for the initial TLS SNI. Origin-by-origin routing would
require separate client connections. The additional-hostname refusal belongs to
the test client; Mihomo continues relaying end-to-end encrypted application data.
Browser DNS, automatic coalescing decisions, ORIGIN frames and 421 recovery remain
unproved. See [RFC 9113 section 9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1).

The TUN resumption group adds eleven connections per TLS version. A persistent
server context accepts saved tickets on new SSL objects and on the same object
after `SSL_clear` and socket replacement. Both peers must confirm whether the
handshake actually resumed. Cases include successive resets, three requests on
one live connection, a new hostname selecting a different chain, a removed name
falling back to DIRECT, a ticket declined by a fresh server context, observer
stop/restart fallback and a wrong pin on a resumed session delivering no request.
Each new socket has a fresh cookie; the same connection ID and route survive
repeated application exchanges. The seed verifies the certificate and hostname;
every resumed connection still checks the peer certificate pin. Sessions remain
in client memory, and clean TLS shutdown preserves their eligibility for reuse.
No adapter, profile, service unit, capability or SELinux policy change is needed.
The fixture retries shutdown progress immediately, and polls only actual
WANT_READ/WANT_WRITE failures, so buffered close-notify data cannot stall reuse.
The socketowner fixture also has a deterministic regression for that API contract.
The 4 KiB receive-memory limit is scoped to the large/short-write group, then
normal defaults and fresh listeners are restored. Leaving that limit active
can drop relay packets despite an advertised window because skb overhead also
counts against receive memory; it is not a suitable baseline for session tests.
Unexpected session exchange failures save both namespaces’ socket states.

With `--auto-redirect`, each family runs sixty-two TLS connections:
forty-five successful exchanges and seventeen deliberate rejections. Eight
additional connections check both TLS versions' certificate, hostname and pin
behavior through the actual redirect listener; the loopback groups stay intact.
The remote-server and resumption groups enable
`auto-redirect: true` and assert REDIR metadata plus the port from the installed
nft redirect rule. A final collision group holds two ClientHellos with distinct
names/destination IPs and the same requested source port. It requires distinct
accepted source ports, correct routes and unchanged destinations/ClientHellos.
No service capability, policy or runtime change is needed. This validates local
nftables OUTPUT; forwarded/prerouting, bridge and iptables-fallback traffic remain
unproved. Earlier descriptions of auto-redirect as unknown were incorrect: the
listener already supplies REDIR metadata to the existing accepted-socket lookup.

Run both family selections and interception modes sequentially; they use the same temporary service
paths. The control API starts before inbound listeners, so the harness waits for
the REDIRECT listener too, then confirms a bidirectional relay using a separate
unobserved readiness flow. Listener creation precedes `tunnel.OnRunning`, so
a listening socket alone is insufficient. Readiness retries never retry a
matrix connection. The TUN group waits for its address to finish IPv6
duplicate-address detection, its system-stack listener and the application's
route into the device before opening the first connection. Empty connection
snapshots are retried. A wrong-pin client may close while the server writes a
TLS 1.3 session ticket; broken-pipe or connection-reset errors are accepted only
in that rejection case, which must still deliver no application request. Certificate
keys remain in the task run directory for its owner to remove after collecting
logs; no test trust enters the system store. The harness collects service
journals and client stderr before removing its own installations and policy.
Browser encrypted DNS/ECH, early data, cross-origin reuse,
performance and broader applications remain unproved. Resumption coverage is
limited to TLS tickets and the controlled OpenSSL socket-BIO fixture.

Socketowner's separate tagged VM suite covers journal ownership, pidfd/boot/PID
namespace identity rejection, malformed registrations, and the existing
publication, lifetime, bootstrap and routing matrices. Run it after changes to
observer initialization or link ownership, using a temporary three-module Go
workspace containing socketowner, socketowner/hostname and Mihomo.

The IPv6 route regression distinguishes initial connects from lookups with an
already selected source. A known TUN source with `iif lo` must still select
`Mihomo`; a physical source and reinjected TUN traffic must select the uplink.
Unpatched sing-tun 0.4.27 fails the first assertion. Mihomo's Linux TUN
constructor moves only its two blanket bypasses behind its existing source
lookups, retaining the backend's owned priority range and cleanup. No dependency
fork or extra module version is needed.
During the three-exchange TLS cases, IPv6 route-cache flushes force fresh
lookups on the same live connection. No test connection is retried and no
firewall exception bypasses the shipped kill switch. Failures retain socket
and route state for diagnosis.

The optional `--interrupt-recovery-poll` flag requires `strace` in the disposable
VM. After automatic observer restart is active/running with a new nonzero PID,
it attaches only to the fixture Mihomo and injects `EINTR` into its first pidfd
poll before the first named recovery connection. The tracer then detaches;
`recovery-poll.trace` records the injection. Run this option with each family
and interception mode. It changes no service unit, capability or SELinux policy.

Previously a zero-timeout pidfd check treated `EINTR` as observer death and
permanently revoked the reader. With this injection the old reader routes the
first recovery connection through ordinary fallback; bounded interruption
retries restore named routing. Actual exit and persistent errors still fail
closed. Restart readiness uses one state snapshot and rejects PID zero.
One earlier IPv6 loopback recovery failure had the same fallback symptom and
preserved the destination and ClientHello, but its logs lack a syscall-level
cause. The deterministic regression establishes a real cause of that symptom;
it does not prove the earlier event's exact trigger retrospectively.
