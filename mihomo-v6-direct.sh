#!/bin/bash
# Keep mihomo's direct IPv6 traffic out of the TUN: one source-based rule per uplink prefix
# sends packets from the host's own global IPv6 addresses (GUA and ULA) to the main table,
# ahead of the rules mihomo installs for the TUN. Safe to re-run; only changed rules and
# routes are touched, so there's no window without them.
#
# With more than one uplink, the main table routes every source out of the uplink with the
# best default route. So each uplink also gets its own table, holding a copy of its routes
# from the main table, and a rule ahead of the main one sends its prefixes there. Otherwise
# a strict reverse-path filter (firewalld's IPv6_rpfilter=strict) drops the replies that
# arrive on the other uplinks. Destinations an uplink has no route to fall through to the
# main table.
#
# Usage: mihomo-v6-direct.sh [interface...]
# Without arguments the uplinks are the interfaces holding a default route in the main
# table, so VLANs, switching between Wi-Fi and Ethernet, and prefix rotation are handled.
set -euo pipefail

PRIO=8999
UPLINK_PRIO=$((PRIO - 1))
# An uplink's table is TABLE_BASE plus its interface index.
TABLE_BASE=8999000

if [ "$#" -gt 0 ]; then
  ifaces=("$@")
else
  mapfile -t ifaces < <(
    { ip -6 route show table main default; ip -4 route show table main default; } |
      awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }' | sort -u)
fi

# The networks of the uplink's global addresses, one per line
networks() {
  ip -6 -o addr show dev "$1" scope global | awk '{ print $4 }' | python3 -c '
import ipaddress, sys
for net in sorted({str(ipaddress.ip_interface(a).network) for a in sys.stdin.read().split()}):
    print(net)
'
}

# "add" and "del" arguments for ip -6 route that make the table (2) hold the routes the
# uplink (1) has in the main table
route_changes() {
  python3 - "$1" "$2" <<'EOF'
import json, subprocess, sys

dev, table = sys.argv[1:]

def routes(t):
    p = subprocess.run(["ip", "-6", "-j", "route", "show", "table", t, "dev", dev],
                       capture_output=True, text=True)
    # ip fails on a table that has never held a route
    if p.returncode != 0 and t != "main":
        return set()
    p.check_returncode()
    found = set()
    for r in json.loads(p.stdout or "[]"):
        if r.get("type", "unicast") != "unicast":
            continue
        # Equal-metric default routes from several routers show up as one multipath route
        for hop in r.get("nexthops") or [r]:
            found.add((r["dst"], hop.get("gateway", ""), str(r.get("metric", ""))))
    return found

def args(op, route):
    dst, gateway, metric = route
    a = [op, dst] + (["via", gateway] if gateway else []) + ["dev", dev, "table", table]
    return a + (["metric", metric] if metric else [])

want, have = routes("main"), routes(table)
for route in sorted(want - have):
    print(*args("add", route))
for route in sorted(have - want):
    print(*args("del", route))
EOF
}

# Make the "from NET lookup TABLE" rules at priority (1) match the "NET TABLE" lines in (2).
# Prints "+TABLE" for each rule added and "-TABLE" for each rule removed.
sync_rules() {
  local pref=$1 want=$2 have net table
  # ip prints a /128 source without its prefix length
  have=$(ip -6 rule show | awk -v pref="$pref:" '
    $1 == pref && $2 == "from" && $4 == "lookup" {
      p = $3; if (p !~ /\//) p = p "/128"; print p, $5 }')
  while read -r net table; do
    if [ -z "$net" ] || grep -qxF -- "$net $table" <<<"$want"; then continue; fi
    ip -6 rule del pref "$pref" from "$net" lookup "$table"
    echo "-$table"
  done <<<"$have"
  while read -r net table; do
    if [ -z "$net" ] || grep -qxF -- "$net $table" <<<"$have"; then continue; fi
    ip -6 rule add pref "$pref" from "$net" lookup "$table"
    echo "+$table"
  done <<<"$want"
}

changed=0
main_rules=""
uplink_rules=""
tables=""
for dev in "${ifaces[@]}"; do
  [ -e "/sys/class/net/$dev" ] || continue
  nets=$(networks "$dev")
  [ -n "$nets" ] || continue
  table=$((TABLE_BASE + $(<"/sys/class/net/$dev/ifindex")))
  tables+="$table"$'\n'
  while read -r -a cmd; do
    ip -6 route "${cmd[@]}"
    changed=1
  done < <(route_changes "$dev" "$table")
  while read -r net; do
    main_rules+="$net main"$'\n'
    uplink_rules+="$net $table"$'\n'
  done <<<"$nets"
done
main_rules=$(grep . <<<"$main_rules" | sort -u || true)

rule_changes=$(sync_rules "$UPLINK_PRIO" "$uplink_rules"; sync_rules "$PRIO" "$main_rules")
[ -z "$rule_changes" ] || changed=1
# Empty the tables of uplinks that are gone
while read -r table; do
  if [ -z "$table" ] || [ "$table" = main ] || grep -qxF -- "$table" <<<"$tables"; then
    continue
  fi
  ip -6 route flush table "$table"
done < <(sed -n 's/^-//p' <<<"$rule_changes" | sort -u)

if [ "$changed" = 1 ]; then
  sources=$(cut -d' ' -f1 <<<"$main_rules" | paste -sd' ')
  logger -t mihomo-v6-direct "direct IPv6 sources on ${ifaces[*]:-no uplink}: ${sources:-none}"
fi
