# hardened-mihomo-service

A sandboxed systemd service for [mihomo](https://github.com/MetaCubeX/mihomo) in TUN mode,
with an nftables kill switch and an SELinux policy.

- `mihomo.service` runs mihomo as an unprivileged `mihomo` user in an empty, read-only root.
  Only `/usr`, the trust stores and `/etc/mihomo` are visible. Of those, only `ruleset/`,
  `cache.db` and `geoip.metadb` are writable. `/etc/hosts` and `/etc/resolv.conf` are not,
  so configure mihomo's DNS servers explicitly. mihomo can't see other processes either;
  it learns which process owns a connection from mihomo-sockowner.
- `killswitch.service` loads `nftables-killswitch.conf` before the network comes up. It
  drops anything that doesn't go through the TUN device, except mihomo's own sockets and
  the local addresses you allow in `/etc/nftables-killswitch.d/`. If mihomo stops, nothing
  leaks. If the rules fail to load, everything but loopback stays blocked.
- `mihomo-sockowner.service` attaches small BPF programs that record which process opened
  each connection and which program each process runs, for `PROCESS-NAME` and
  `PROCESS-PATH` rules. It needs the kernel's BPF LSM; see
  [Process lookup](#process-lookup).
- `mihomo.te`, `mihomo.fc` and `mihomo.if` confine mihomo to `mihomo_t`, and
  mihomo-sockowner to `mihomo_sockowner_t`.
- `mihomo-v6-direct.service` and its two scripts are optional. They add source-based routing
  rules so that mihomo's direct IPv6 connections from the uplink's own prefixes use the main
  routing table instead of looping back into the TUN. The rules follow prefix changes.
  With several uplinks, each one's prefixes use a copy of the main table without the other
  uplinks' default routes, so replies that arrive on a secondary uplink, such as a VLAN,
  pass a strict reverse-path filter like firewalld's `IPv6_rpfilter=strict`.

## Installing

Install the mihomo binary as `/usr/local/bin/mihomo`.

Create the user, then the SELinux module, so that the directories created next get the
right labels:

```sh
sudo install -m 644 mihomo.sysusers /etc/sysusers.d/mihomo.conf
sudo systemd-sysusers /etc/sysusers.d/mihomo.conf

make -f /usr/share/selinux/devel/Makefile mihomo.pp
sudo semodule -i mihomo.pp
sudo restorecon -v /usr/local/bin/mihomo

sudo install -m 644 mihomo.tmpfiles /etc/tmpfiles.d/mihomo.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/mihomo.conf
```

Write the config. `config.example.yaml` matches the unit and the kill switch:

```sh
sudo install -m 640 -o root -g mihomo config.example.yaml /etc/mihomo/config.yaml
```

mihomo normally downloads `geoip.metadb` the first time a GEOIP rule is used. It can't do
that here, since `/etc/mihomo` is read-only to it. If you use GEOIP rules, fetch the file
once; after that, mihomo can update it in place:

```sh
sudo curl -fLo /etc/mihomo/geoip.metadb \
    https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb
sudo chown mihomo:mihomo /etc/mihomo/geoip.metadb
sudo chmod 600 /etc/mihomo/geoip.metadb
sudo restorecon -v /etc/mihomo/geoip.metadb
```

Put your LAN and any other addresses apps should reach directly in a file under
`/etc/nftables-killswitch.d/`. The kill switch includes every `*.conf` file there:

```sh
sudo mkdir -p /etc/nftables-killswitch.d
echo 'add element inet killswitch direct4 { 192.168.1.0/24 }' |
    sudo tee /etc/nftables-killswitch.d/lan.conf
```

IPv6 addresses go in `direct6` the same way, for example
`add element inet killswitch direct6 { fd00:1::/64 }`.

Then install the kill switch and the units:

```sh
sudo install -m 644 nftables-killswitch.conf /etc/nftables-killswitch.conf
sudo nft -c -f /etc/nftables-killswitch.conf
sudo install -m 644 killswitch.service mihomo.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now killswitch.service mihomo.service
```

For `PROCESS-NAME` and `PROCESS-PATH` rules, also install mihomo-sockowner as described
in [Process lookup](#process-lookup).

The kill switch blocks all traffic outside the tunnel as soon as it loads. Make sure mihomo
connects before enabling it on a remote machine.

After changing a file in `/etc/nftables-killswitch.d/`, swap the rules with
`sudo systemctl reload killswitch.service`. If the rules don't load, at boot or on a
reload, the previous table stays in place. At boot that's a table that blocks everything
but loopback, so the machine stays offline. `sudo journalctl -u killswitch.service` shows
the error. To get online without the kill switch, run
`sudo nft delete table inet killswitch`.

For the IPv6 direct routing:

```sh
sudo install -m 755 mihomo-v6-direct.sh mihomo-v6-watch.sh /usr/local/sbin/
sudo install -m 644 mihomo-v6-direct.service /etc/systemd/system/
sudo systemctl enable --now mihomo-v6-direct.service
```

The uplinks are the interfaces that hold a default route. To fix them instead, add the
interface names to `ExecStart=` in `mihomo-v6-direct.service`. Each uplink gets a routing
table, numbered 8999000 plus its interface index, holding that copy. The rules come at
priorities 8998 and 8999, ahead of mihomo's at 9000.

## Process lookup

`find-process-mode: always` lets rules match the process behind a connection
(`PROCESS-NAME`, `PROCESS-PATH`). mihomo.service gives mihomo no access to other
processes, so it gets that information from mihomo-sockowner.

### With mihomo-sockowner

`mihomo-sockowner.service` attaches BPF programs that record the process behind each TCP
and UDP connection and the program each process runs. mihomo reads both from tables that
`mihomo.service` binds into its sandbox read-only; it never looks at `/proc`. The tables
keep an entry after its connection closes and after its process exits, so a short UDP
exchange still matches its rule. Looking a connection up takes microseconds. When a
process passes a socket to another, the tables name the process that used it.

This needs the BPF LSM, which most distribution kernels build in but not all turn on.
Check that `bpf` is in the list of active LSMs:

```sh
cat /sys/kernel/security/lsm
```

If it's missing, look processes up [through /proc](#through-proc) instead. This setup has
been tested on Linux 7.2.

The loader needs `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` and `CAP_CHOWN`, and only while
it attaches the programs; it exits afterwards and the programs stay attached.
`CAP_PERFMON` lets BPF programs read kernel memory, which recording what each process runs
requires. The programs are built into the loader and checked by the kernel when they're
loaded, and the loader has no network access and takes no input but its command line. In
return, mihomo, which handles network traffic and serves its API, needs no capabilities
and no access to other processes for this.

mihomo-sockowner is built from mihomo's source, next to mihomo itself, and needs Go 1.25 or
later. In a mihomo checkout that has `component/process/ebpf`:

```sh
cd component/process/ebpf/loader
CGO_ENABLED=0 go build -o mihomo-sockowner .
sudo install -m 755 mihomo-sockowner /usr/local/bin/mihomo-sockowner
sudo restorecon -v /usr/local/bin/mihomo-sockowner
```

Then install and enable the unit:

```sh
sudo install -m 644 mihomo-sockowner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mihomo-sockowner.service
sudo systemctl restart mihomo.service
```

Once enabled, mihomo requires it. Otherwise process rules would silently stop matching
whenever the programs aren't attached. If they fail to attach, mihomo doesn't start, and
`sudo journalctl -u mihomo-sockowner.service` shows why. Restarting or stopping
mihomo-sockowner restarts or stops mihomo too.

`config.example.yaml` already points `find-process-bpf-map` at the tables and sets
`find-process-bpf-only: true`. When mihomo opens them, `sudo journalctl -u mihomo.service`
shows "Using socket owners and executables recorded in /run/mihomo-bpf".

Some processes can't be named:

- Connections opened before mihomo-sockowner started. Processes that were already running
  are filled in when it starts, but their earlier connections aren't.
- Programs whose path is longer than 1024 bytes.
- A process in a plain `chroot` is named by its path inside the chroot. Containers and
  sandboxes such as Flatpak show their in-sandbox path, as they do in `/proc`.

### Through /proc

Without the BPF LSM, mihomo can find the process by reading the `fd` and `exe` links under
`/proc/<pid>/` of other users' processes. That takes `CAP_SYS_PTRACE` and
`CAP_DAC_READ_SEARCH` and only works while the connection is still open. The SELinux policy
keeps mihomo from opening those processes' files, so it can't read their environment,
command line or memory. It can't stop mihomo from following their `root` and `cwd` links,
though, which work the same way as `exe`. Through them a compromised mihomo can reach files
outside its sandbox, as far as `mihomo_t` may read them.

To use it, set `find-process-bpf-only: false` in `config.yaml`, then turn on the SELinux
boolean and give mihomo the two capabilities:

```sh
sudo setsebool -P mihomo_find_process_proc on
sudo mkdir -p /etc/systemd/system/mihomo.service.d
printf '%s\n' '[Service]' \
    'CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH' \
    'AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH' |
    sudo tee /etc/systemd/system/mihomo.service.d/proc-lookup.conf
sudo systemctl daemon-reload
sudo systemctl restart mihomo.service
```

mihomo-sockowner can still record which process owns each connection, without the
programs that need the BPF LSM. That keeps short UDP exchanges matching their rules while
the process runs; mihomo then reads the path from `/proc`. Without the BPF LSM, though, a
connected socket that one process hands to another is still credited to the first. Install
it as above and run it without `-exec-paths`:

```sh
sudo mkdir -p /etc/systemd/system/mihomo-sockowner.service.d
printf '%s\n' '[Service]' 'ExecStart=' \
    'ExecStart=/usr/local/bin/mihomo-sockowner -reader-group mihomo attach' |
    sudo tee /etc/systemd/system/mihomo-sockowner.service.d/no-exec-paths.conf
sudo systemctl daemon-reload
sudo systemctl restart mihomo-sockowner.service
```

### Turning it off

If you don't use these rules, set `find-process-mode: off` in `config.yaml`, turn off the
SELinux boolean and disable mihomo-sockowner:

```sh
sudo setsebool -P mihomo_find_process off
sudo systemctl disable --now mihomo-sockowner.service
sudo systemctl restart mihomo.service
```

If you looked processes up through `/proc`, also turn off `mihomo_find_process_proc` and
remove `/etc/systemd/system/mihomo.service.d/proc-lookup.conf`.

## Updating

Rebuild and load the SELinux module, relabel `/etc/mihomo` (version 1.3 gave mihomo's
writable files a type of their own) and, if you use it, `/usr/local/bin/mihomo-sockowner`
(version 1.5 added its type). Then install the files again as above and reload:

```sh
make -f /usr/share/selinux/devel/Makefile mihomo.pp
sudo semodule -i mihomo.pp
sudo restorecon -Rv /etc/mihomo
sudo restorecon -v /usr/local/bin/mihomo-sockowner
sudo systemctl daemon-reload
sudo systemctl reload killswitch.service
sudo systemctl restart mihomo.service mihomo-v6-direct.service
```

Version 1.6 records what each process runs in mihomo-sockowner, so mihomo no longer reads
`/proc`. When updating to it, rebuild and install mihomo-sockowner too, add
`find-process-bpf-only: true` to `config.yaml` after `find-process-bpf-map`, and enable the
unit again so that mihomo requires it instead of merely wanting it:

```sh
sudo systemctl reenable mihomo-sockowner.service
sudo systemctl restart mihomo-sockowner.service
```

Without the BPF LSM, follow [Through /proc](#through-proc) instead; the policy now keeps
that access behind `mihomo_find_process_proc`.

If `restorecon` doesn't relabel `ruleset/` to `mihomo_data_t`, check
`sudo semanage fcontext -l -C` for local rules on `/etc/mihomo` and remove them with
`sudo semanage fcontext -d`; local rules override the module's.
