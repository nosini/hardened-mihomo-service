#!/bin/bash
# Keep mihomo's direct IPv6 traffic out of the TUN: one source-based rule per uplink prefix
# sends packets from the host's own global IPv6 addresses (GUA and ULA) to the main table,
# ahead of the rules mihomo installs for the TUN. Safe to re-run; only changed rules are
# touched, so there's no window without them.
#
# Usage: mihomo-v6-direct.sh [interface...]
# Without arguments the uplinks are the interfaces holding a default route in the main
# table, so VLANs, switching between Wi-Fi and Ethernet, and prefix rotation are handled.
set -euo pipefail

PRIO=8999

if [ "$#" -gt 0 ]; then
  ifaces=("$@")
else
  mapfile -t ifaces < <(
    { ip -6 route show table main default; ip -4 route show table main default; } |
      awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }' | sort -u)
fi

addrs=()
for dev in "${ifaces[@]}"; do
  mapfile -t -O "${#addrs[@]}" addrs < <(ip -6 -o addr show dev "$dev" scope global | awk '{ print $4 }')
done

want=$(python3 -c '
import ipaddress, sys
print("\n".join(sorted({str(ipaddress.ip_interface(a).network) for a in sys.argv[1:]})))
' "${addrs[@]}")
# ip prints a /128 source without its prefix length
have=$(ip -6 rule show | awk -v pref="$PRIO:" '
  $1 == pref && $2 == "from" { p = $3; if (p !~ /\//) p = p "/128"; print p }')

changed=0
while read -r net; do
  if [ -z "$net" ] || grep -qxF -- "$net" <<<"$want"; then continue; fi
  ip -6 rule del pref "$PRIO" from "$net" lookup main
  changed=1
done <<<"$have"
while read -r net; do
  if [ -z "$net" ] || grep -qxF -- "$net" <<<"$have"; then continue; fi
  ip -6 rule add pref "$PRIO" from "$net" lookup main
  changed=1
done <<<"$want"

if [ "$changed" = 1 ]; then
  sources=${want//$'\n'/ }
  logger -t mihomo-v6-direct "direct IPv6 sources on ${ifaces[*]:-no uplink}: ${sources:-none}"
fi
