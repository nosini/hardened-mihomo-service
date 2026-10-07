#!/bin/bash
# Keep mihomo's direct IPv6 traffic out of the TUN: source-based rules for each uplink prefix
# send packets from the host's own global IPv6 addresses (GUA and ULA) to the main table,
# ahead of the rules mihomo installs for the TUN. Safe to re-run; only changed rules and
# routes are touched, so there's no window without them.
#
# With more than one uplink, the main table's default route sends every source out of the
# same uplink, and a strict reverse-path filter (firewalld's IPv6_rpfilter=strict) then
# drops the replies that arrive on the others. So each uplink's prefixes first look up the
# uplink's own table: a copy of the main table without the other uplinks' default routes.
# Its specific routes (on-link prefixes, other interfaces, unreachable and prohibit routes)
# still apply. A rule after it falls back to the main table, for an uplink without a default
# route of its own. (A main-table rule with suppress_prefixlength 0 would avoid the copy,
# but the lookup nftables' fib expression does ignores suppress_prefixlength.)
#
# Usage: mihomo-v6-direct.sh [interface...]
# Without arguments the uplinks are the interfaces holding a default route in the main
# table, so VLANs, switching between Wi-Fi and Ethernet, and prefix rotation are handled.
set -euo pipefail

PRIO=8999
UPLINK_PRIO=$((PRIO - 1))
# Held "lookup main suppress_prefixlength 0" rules in an earlier version
OLD_PRIO=$((PRIO - 2))
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

# Arguments for ip -6 route, one command per line, that make the table (2) a copy of the
# main table without the default routes through other interfaces than the uplink (1); a
# multipath default route keeps only its nexthops through the uplink. Routes are copied
# from ip's own output, which ip route accepts back, so attributes such as source prefixes,
# onlink, preferred sources and locked metrics are kept. A route that changes is replaced
# in place where it's the only one with its destination and metric; otherwise the new one
# is added before the old one is removed.
route_changes() {
  python3 - "$1" "$2" <<'EOF'
import subprocess, sys

dev, table = sys.argv[1:]

TYPES = {"unicast", "unreachable", "prohibit", "blackhole", "throw"}
# Options ip prints without a value
FLAGS = {"onlink", "pervasive", "notify"}
# What ip reports about a route's state; it doesn't take these back
STATUS = {"dead", "linkdown", "offload", "offload_failed", "rt_offload",
          "rt_offload_failed", "rt_trap", "trap", "unresolved"}


def dump(t):
    p = subprocess.run(["ip", "-6", "-o", "route", "show", "table", t],
                       capture_output=True, text=True)
    # ip fails on a table that has never held a route
    if p.returncode != 0 and t != "main":
        return []
    p.check_returncode()
    # -o puts a multipath route's nexthops on one line, separated by backslashes
    return [line.replace("\\", " ").split() for line in p.stdout.splitlines()]


def options(tokens):
    """Group tokens into options: ("onlink",), ("via", gw), ("mtu", "lock", "1280")"""
    out, i = [], 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in STATUS:
            i += 1
        elif tok in FLAGS or i + 1 == len(tokens):
            out.append((tok,))
            i += 1
        elif tokens[i + 1] == "lock" and i + 2 < len(tokens):
            out.append(tuple(tokens[i:i + 3]))
            i += 3
        else:
            out.append(tuple(tokens[i:i + 2]))
            i += 2
    return out


def get(opts, name):
    return next((o[-1] for o in opts if o[0] == name and len(o) > 1), None)


def drop(opts, *names):
    return [o for o in opts if o[0] not in names]


class Route:
    def __init__(self, tokens):
        self.type = tokens[0] if tokens[0] in TYPES else "unicast"
        if tokens[0] in TYPES:
            tokens = tokens[1:]
        self.dst = tokens[0]
        head, hops = [], []
        for tok in tokens[1:]:
            if tok == "nexthop":
                hops.append([])
            else:
                (hops[-1] if hops else head).append(tok)
        self.head = drop(options(head), "expires", "table")
        self.hops = [options(h) for h in hops]
        self.devs = {get(h, "dev") for h in self.hops} or {get(self.head, "dev")}
        self.nhid = get(self.head, "nhid")
        if self.nhid:
            # A nexthop object; ip also prints what it resolves to, which isn't set
            self.head, self.hops = drop(self.head, "via", "dev"), []

    def key(self):
        """What replace matches a route by, as ip takes it"""
        k = [self.type] if self.type != "unicast" else []
        k.append(self.dst)
        for name in ("from", "metric"):
            if get(self.head, name) is not None:
                k += [name, get(self.head, name)]
        return k

    def path(self):
        """Which route this is among those with the same key, as ip takes it"""
        if self.nhid:
            return ["nhid", self.nhid]
        if self.hops:
            return [tok for h in sorted(self.hops) for tok in
                    ("nexthop", "via", get(h, "via") or "", "dev", get(h, "dev") or "")]
        return [tok for name in ("via", "dev") if get(self.head, name)
                for tok in (name, get(self.head, name))]

    def ident(self):
        return self.key() + self.path()

    def same(self, other):
        return (self.type, self.dst, sorted(self.head), sorted(map(sorted, self.hops))) == \
            (other.type, other.dst, sorted(other.head), sorted(map(sorted, other.hops)))

    def args(self):
        a = [self.type, self.dst, "table", table]
        a += [tok for o in self.head for tok in o]
        return a + [tok for h in self.hops for tok in ("nexthop",) + sum(h, ())]

    def del_args(self):
        # Without nexthops, del removes a multipath route whole
        return self.key() + (self.path() if not self.hops else []) + ["table", table]

    def for_uplink(self):
        """The part of this main-table route to copy, or None"""
        if self.dst != "default" or self.type != "unicast":
            return self
        if self.nhid or not self.hops:
            return self if self.devs == {dev} else None
        self.hops = [h for h in self.hops if get(h, "dev") == dev]
        if not self.hops:
            return None
        if len(self.hops) == 1:
            # A single nexthop is stored as an ordinary route, without its weight
            self.head += drop(self.hops.pop(), "weight")
        return self


want = [r for r in (Route(t).for_uplink() for t in dump("main")) if r]
have = [Route(t) for t in dump(table)]
done = set()
for r in want:
    match = next((h for h in have if h.ident() == r.ident()), None)
    if match and r.same(match):
        done.add(id(match))
        continue
    others = [h for h in have if h.key() == r.key()]
    if len(others) == 1 and [w.key() for w in want].count(r.key()) == 1:
        # The only route with this key, so replace swaps it in place
        print("replace", *r.args())
        done.add(id(others[0]))
    else:
        if match:
            print("del", *match.del_args())
            done.add(id(match))
        print("append", *r.args())
for h in have:
    if id(h) not in done and not any(h.ident() == r.ident() for r in want):
        print("del", *h.del_args())
EOF
}

# Make the rules at priority (1) match the "from NET lookup TABLE ..." lines in (2).
# Prints "+TABLE" for each rule added and "-TABLE" for each rule removed.
sync_rules() {
  local pref=$1 want=$2 have rule
  # ip prints a /128 source without its prefix length
  have=$(ip -6 rule show | awk -v pref="$pref:" '
    $1 == pref && $2 == "from" {
      if ($3 !~ /\//) $3 = $3 "/128"; $1 = ""; sub(/^ /, ""); print }')
  while read -r rule; do
    if [ -z "$rule" ] || grep -qxF -- "$rule" <<<"$want"; then continue; fi
    # shellcheck disable=SC2086 # the rule is split into ip's arguments
    ip -6 rule del pref "$pref" $rule
    echo "-$(awk '{ print $4 }' <<<"$rule")"
  done <<<"$have"
  while read -r rule; do
    if [ -z "$rule" ] || grep -qxF -- "$rule" <<<"$have"; then continue; fi
    # shellcheck disable=SC2086
    ip -6 rule add pref "$pref" $rule
    echo "+$(awk '{ print $4 }' <<<"$rule")"
  done <<<"$want"
}

status=0
changed=0
nets_all=""
uplink_rules=""
tables=""
for dev in "${ifaces[@]}"; do
  [ -e "/sys/class/net/$dev" ] || continue
  nets=$(networks "$dev")
  [ -n "$nets" ] || continue
  table=$((TABLE_BASE + $(<"/sys/class/net/$dev/ifindex")))
  tables+="$table"$'\n'
  while read -r -a cmd; do
    # A route can vanish between the dump and the change; the next run catches up
    ip -6 route "${cmd[@]}" || status=1
    changed=1
  done < <(route_changes "$dev" "$table")
  while read -r net; do
    nets_all+="$net"$'\n'
    uplink_rules+="from $net lookup $table"$'\n'
  done <<<"$nets"
done
nets_all=$(grep . <<<"$nets_all" | sort -u || true)
main_rules=$(awk 'NF { print "from", $1, "lookup main" }' <<<"$nets_all")

rule_changes=$(
  sync_rules "$OLD_PRIO" ""
  sync_rules "$UPLINK_PRIO" "$uplink_rules"
  sync_rules "$PRIO" "$main_rules"
)
[ -z "$rule_changes" ] || changed=1
# Empty the tables of uplinks that are gone
while read -r table; do
  if [ -z "$table" ] || [ "$table" = main ] || grep -qxF -- "$table" <<<"$tables"; then
    continue
  fi
  ip -6 route flush table "$table"
done < <(sed -n 's/^-//p' <<<"$rule_changes" | sort -u)

if [ "$changed" = 1 ]; then
  sources=$(paste -sd' ' <<<"$nets_all")
  logger -t mihomo-v6-direct "direct IPv6 sources on ${ifaces[*]:-no uplink}: ${sources:-none}"
fi
exit "$status"
