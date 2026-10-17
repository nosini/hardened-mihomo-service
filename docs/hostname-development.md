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
exact verified libraries, BPF LSM, cgroup v2 and bpffs. Do not run it on a deployed machine.
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
Each family runs forty-one TLS connections: thirty-three successful exchanges
(including large ClientHellos, actual short-write retries, observer stop/restart,
recovery after SIGKILL, feature disablement, TUN and session resumption) and eight
intentional rejections. Both TLS versions exercise a ClientHello above 4 KiB and
a pending write that starts with
`SSL_ERROR_WANT_WRITE`, then completes through the real redirect listener. After
the handshake and application exchange, the same connection ID and chain must
remain live despite unsupported later sends revoking initial-window discovery
authority. The peer checks the unchanged SNI, and the API confirms the
original destination IP/port.

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

Run both family selections sequentially; they use the same temporary service
paths. The control API starts before inbound listeners, so the harness waits for
the REDIRECT listener too. The TUN group waits for its address to finish IPv6
duplicate-address detection, its system-stack listener and the application's
route into the device before opening the first connection. Empty connection
snapshots are retried. A wrong-pin client may close while the server writes a
TLS 1.3 session ticket; broken-pipe or connection-reset errors are accepted only
in that rejection case, which must still deliver no application request. Certificate
keys remain in the task run directory for its owner to remove after collecting
logs; no test trust enters the system store. The harness collects service
journals and client stderr before removing its own installations and policy.
Browser encrypted DNS/ECH, early data, HelloRetryRequest, cross-origin reuse,
performance and broader applications remain unproved. Resumption coverage is
limited to TLS tickets and the controlled OpenSSL socket-BIO fixture.

Socketowner's separate tagged VM suite covers journal ownership, pidfd/boot/PID
namespace identity rejection, malformed registrations, and the existing
publication, lifetime, bootstrap and routing matrices. Run it after changes to
observer initialization or link ownership, using a temporary three-module Go
workspace containing socketowner, socketowner/hostname and Mihomo.
