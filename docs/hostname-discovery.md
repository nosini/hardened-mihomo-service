# Optional application hostname discovery

The optional `mihomo-hostname-observer.service` observes one explicitly selected
OpenSSL process and supplies verified transport hostnames to an optional Mihomo
reader. Mihomo keeps its existing capabilities, process visibility and kill-switch
dependency. When observation is missing or unusable, it routes normally.

This is experimental. It supports one exact OpenSSL 3.5.3 x86-64-v3/library profile,
one initial ClientHello record of at most 16 KiB with verified same-SSL/name
retries inside its remaining bytes, and 256 concurrently retained socket guards
per observer instance; final release reclaims slots. Controlled TLS 1.2/1.3
certificate/hostname verification, certificate pinning and application exchange
pass for IPv4/IPv6; browser ECH, QUIC and broad application discovery remain
unsupported. Mihomo looks up real-IP TCP connections from REDIRECT and from the
shipped TUN configuration (`stack: system`; `mixed` behaves the same for TCP).
With fake-ip DNS, applications using the system resolver already reach Mihomo
with a fake IP and keep that behavior; discovery adds names for applications
that resolve names themselves. The `gvisor` stack and `auto-redirect` stay
unknown. This package does not change interception, DNS, TUN or firewall rules.
See the [observer requirements](https://github.com/nosini/socketowner/blob/ebpf-hostname-discovery/experiments/hostname/OBSERVER.md)
and [reader contract](https://github.com/nosini/socketowner/blob/ebpf-hostname-discovery/hostname/PROFILE3.md).

## Installing

Install a static (`CGO_ENABLED=0`) optional-reader Mihomo build and the independent observer binary from
socketowner. Both are opt-in builds; replacing ordinary Mihomo does not install
or update the privileged observer. No reader release is published yet; source
build instructions are in the respective repositories. The observer binary must
include `prepare` and `run-registered`. Rebuild both the observer and optional
Mihomo reader consumer when upgrading to hostname contract profile 3;
profile-1/profile-2 binaries cannot bootstrap this observer.

After installing the regular hardened service, build and install the updated
SELinux module and optional files from this checkout:

```sh
make -f /usr/share/selinux/devel/Makefile mihomo.pp
sudo semodule -i mihomo.pp
sudo restorecon -v /usr/local/bin/mihomo /usr/local/bin/mihomo-hostname-observer
sudo install -D -m 644 mihomo-hostname-observer.service \
    /usr/local/lib/systemd/system/mihomo-hostname-observer.service
sudo install -m 644 mihomo-hostname.tmpfiles /etc/tmpfiles.d/mihomo-hostname.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/mihomo-hostname.conf
sudo restorecon -Rv /run/mihomo-hostname /run/mihomo-hostname-target
sudo install -D -m 755 mihomo-process-generator \
    /etc/systemd/system-generators/mihomo-process-generator
sudo restorecon -v /etc/systemd/system-generators/mihomo-process-generator
```

bpffs must already be mounted at `/sys/fs/bpf`, cgroup v2 and BPF LSM must be
available, and the policy must support pidfs metadata. Do not create or expose
hostname pins through the process-owner map directory. The optional tmpfiles
configuration creates a stable root-owned `/run/mihomo-hostname` directory and
private state, registration and pin directories. Keeping that directory's inode
stable lets a running Mihomo see a replacement endpoint after observer restart.

## Selecting a target

Start the supported application first and identify its PID and the library files
it actually mapped. Use an explicit PID, not an executable-name pattern. For
example, with `pid` set to that running process:

```sh
grep -E 'libssl|libcrypto|libc\.so' "/proc/$pid/maps"
sudo /usr/local/bin/mihomo-hostname-observer \
    -target-pid "$pid" \
    -cgroup "/sys/fs/cgroup$(cut -d: -f3 "/proc/$pid/cgroup")" \
    -profile openssl-3.5.3-x86-64-v3 \
    -libssl /usr/lib64/glibc-hwcaps/x86-64-v3/libssl.so.3.5.3 \
    -libcrypto /usr/lib64/glibc-hwcaps/x86-64-v3/libcrypto.so.3.5.3 \
    -libc /usr/lib64/libc.so.6 \
    -reader-user mihomo -reader-group mihomo prepare
```

The paths are examples for the verified profile, not interchangeable library
versions. Preparation checks file hashes and mapped device/inode identity and
writes `/run/mihomo-hostname-target/target.json` as root, mode 0600, in a mode-0700
directory. It records the boot, PID namespace and target pidfd birth identity.
It loads no BPF and does not start a service. Keep the default runtime and pin
paths for the shipped unit; the registration is not an environment file or an
editable application configuration.

A reboot or a different application process needs explicit preparation again.
A stale registration fails before attachment. Guard exhaustion or a crash may
restart observation of the same still-living target, using fresh maps; a recycled
numeric PID cannot become the new target. Existing sockets stay unknown after
each restart. Target `exec` is not yet detected; mapped-library/frame checks
normally stop matching, but this is not a general executable-identity guarantee.

## Enabling and stopping

Set this independent configuration in `/etc/mihomo/config.yaml`:

```yaml
hostname-discovery:
  enable: true
  endpoint: /run/mihomo-hostname/bootstrap.sock
  wait-ms: 50
```

Choose an explicit budget from 1 through 250 ms. The example is not a latency
recommendation. The generator requires this exact endpoint and handles anchors,
merges, null defaults and boolean spellings as it does for process lookup.
The setting works independently of `find-process-mode`.

```sh
sudo systemctl daemon-reload
sudo systemctl restart mihomo.service
```

The generator adds `Wants` and ordering for the observer, plus an optional
read-only directory bind into Mihomo. There is no `Requires`, `BindsTo` or
`PartOf` relationship to the observer. Its missing executable, registration,
startup failure, stop or crash leaves Mihomo and its kill switch running. Startup
ordering may wait up to the observer's 10-second startup timeout. If the endpoint
directory was missing when Mihomo started, create it with tmpfiles and restart
Mihomo to add the mount. An API configuration reload alone cannot add a mount.

The observer runs as root in its own SELinux domain, with only BPF, perfmon,
network-administration, chown and read-only process-inspection capabilities.
Its writes to the host filesystem are limited to its runtime and private pin
subtree, with a separate private temporary directory;
network access is limited to Unix sockets in a private network namespace.
The seccomp filter denies direct ptrace and process_vm operations. Mihomo gains
only endpoint IPC and read-only map/pidfd metadata access in SELinux, without
BPF-loading or additional process-inspection capabilities. Its normal process
lookup sandbox is still selected separately.

Stop observation temporarily with:

```sh
sudo systemctl stop mihomo-hostname-observer.service
```

Graceful stop revokes before detaching; `ExecStopPost` also performs authenticated
journal cleanup after a crash or failed startup. Cleanup refuses live/foreign or
corrupt state. Pins remain private if cleanup cannot prove ownership. Unexpected
failure restarts after five seconds, with a limit of three starts per minute.
To retry after correcting a failed registration or a start-limit failure:

```sh
sudo systemctl reset-failed mihomo-hostname-observer.service
sudo systemctl start mihomo-hostname-observer.service
```

To disable permanently, set `hostname-discovery.enable: false`, reload the
manager, stop the observer and restart Mihomo. This removes the generated endpoint
mount on the next start and does not alter process lookup or firewall settings:

```sh
sudo systemctl daemon-reload
sudo systemctl stop mihomo-hostname-observer.service
sudo systemctl restart mihomo.service
```

Use `sudo journalctl -u mihomo-hostname-observer.service` for startup/cleanup
errors and `sudo systemctl cat mihomo.service` for the generated dependencies and
mount. The observer records no hostname history. Build and integration-test details
are in [hostname development](hostname-development.md).
