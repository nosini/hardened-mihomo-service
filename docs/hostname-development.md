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
off, and adds only a target-specific local REDIRECT rule. It does not modify guest uplinks
or an existing network-protection service.

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
Each family runs fourteen TLS cases: eight successful exchanges (enabled,
observer stopped, restarted, recovered after SIGKILL, and disabled) and six
intentional rejections. After the handshake and application exchange, the same
connection ID and chain must remain live despite later sends revoking first-send
discovery authority. The peer checks the unchanged SNI, and the API confirms the
original destination IP/port.

Run both family selections sequentially; they use the same temporary service
paths. The control API starts before inbound listeners, so the harness waits for
the REDIRECT listener too. Empty connection snapshots are retried. Certificate
keys remain in the task run directory for its owner to remove after collecting
logs; no test trust enters the system store. The harness collects service
journals and client stderr before removing its own installations and policy.
Browser encrypted DNS/ECH, session resumption, performance and broader
applications remain unproved.

Socketowner's separate tagged VM suite covers journal ownership, pidfd/boot/PID
namespace identity rejection, malformed registrations, and the existing
publication, lifetime, bootstrap and routing matrices. Run it after changes to
observer initialization or link ownership, using a temporary three-module Go
workspace containing socketowner, socketowner/hostname and Mihomo.
