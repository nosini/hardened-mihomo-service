# hardened-mihomo-service

A sandboxed systemd service for [mihomo](https://github.com/MetaCubeX/mihomo) in TUN mode,
with an nftables kill switch and an SELinux policy.

- `mihomo.service` runs mihomo as an unprivileged `mihomo` user in an empty, read-only root.
  Only `/usr`, the trust stores and `/etc/mihomo` are visible. Of those, only `ruleset/`,
  `cache.db` and `geoip.metadb` are writable. `/etc/hosts` and `/etc/resolv.conf` are not,
  so configure mihomo's DNS servers explicitly. Process lookup is the exception; see
  [Process lookup](#process-lookup).
- `killswitch.service` loads `nftables-killswitch.conf` before the network comes up. It
  drops anything that doesn't go through the TUN device, except mihomo's own sockets and
  the local addresses you allow in `/etc/nftables-killswitch.d/`. If mihomo stops, nothing
  leaks. If the rules fail to load, everything but loopback stays blocked.
- `mihomo.te`, `mihomo.fc` and `mihomo.if` confine mihomo to `mihomo_t`.
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

The kill switch blocks all traffic outside the tunnel as soon as it loads. Make sure mihomo
connects before enabling it on a remote machine.

After changing a file in `/etc/nftables-killswitch.d/`, swap the rules with
`sudo systemctl reload killswitch.service`. If the rules don't load, at boot or on a
reload, the previous table stays in place. At boot that's a table that blocks everything
but loopback, so the machine stays offline. `journalctl -u killswitch.service` shows the
error. To get online without the kill switch, run `sudo nft delete table inet killswitch`.

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
(`PROCESS-NAME`, `PROCESS-PATH`). mihomo finds it by reading the `fd` and `exe` links under
`/proc/<pid>/` of other users' processes, which takes `CAP_SYS_PTRACE` and
`CAP_DAC_READ_SEARCH`. The SELinux policy keeps it from opening those processes' files, so
it can't read their environment, command line or memory. It can't stop mihomo from
following their `root` and `cwd` links, though, which work the same way as `exe`. Through
them a compromised mihomo can reach files outside its sandbox, as far as `mihomo_t` may
read them.

If you don't use these rules, turn the lookup off: set `find-process-mode: off` in
`config.yaml`, turn off the SELinux boolean, and drop the two capabilities:

```sh
sudo setsebool -P mihomo_find_process off
sudo mkdir -p /etc/systemd/system/mihomo.service.d
printf '%s\n' '[Service]' \
    'CapabilityBoundingSet=' 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' \
    'AmbientCapabilities=' 'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE' |
    sudo tee /etc/systemd/system/mihomo.service.d/no-process-lookup.conf
sudo systemctl daemon-reload
sudo systemctl restart mihomo.service
```

## Updating

Rebuild and load the SELinux module, relabel `/etc/mihomo` (version 1.3 gave mihomo's
writable files a type of their own), then install the files again as above and reload:

```sh
make -f /usr/share/selinux/devel/Makefile mihomo.pp
sudo semodule -i mihomo.pp
sudo restorecon -Rv /etc/mihomo
sudo systemctl daemon-reload
sudo systemctl reload killswitch.service
sudo systemctl restart mihomo.service mihomo-v6-direct.service
```
