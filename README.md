# hardened-mihomo-service

A sandboxed systemd service for [mihomo](https://github.com/MetaCubeX/mihomo) in TUN mode,
with an nftables kill switch and an SELinux policy.

- `mihomo.service` runs mihomo as an unprivileged `mihomo` user in an empty, read-only root.
  Only `/usr`, the trust stores and `/etc/mihomo` are visible. Of those, only `ruleset/`,
  `cache.db` and `geoip.metadb` are writable. `/etc/hosts` and `/etc/resolv.conf` are not,
  so configure mihomo's DNS servers explicitly.
- `killswitch.service` loads `nftables-killswitch.conf` before the network comes up. It
  drops anything that doesn't go through the TUN device, except mihomo's own sockets and
  the local addresses you allow in `/etc/nftables-killswitch.d/`. If mihomo stops, nothing
  leaks.
- `mihomo.te`, `mihomo.fc` and `mihomo.if` confine mihomo to `mihomo_t`.
- `mihomo-v6-direct.service` and its two scripts are optional. They add source-based routing
  rules so that mihomo's direct IPv6 connections from the uplink's own prefixes use the main
  routing table instead of looping back into the TUN. The rules follow prefix changes.

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

For the IPv6 direct routing:

```sh
sudo install -m 755 mihomo-v6-direct.sh mihomo-v6-watch.sh /usr/local/sbin/
sudo install -m 644 mihomo-v6-direct.service /etc/systemd/system/
sudo systemctl enable --now mihomo-v6-direct.service
```

The uplinks are the interfaces that hold a default route. To fix them instead, add the
interface names to `ExecStart=` in `mihomo-v6-direct.service`.
