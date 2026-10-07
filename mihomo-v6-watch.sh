#!/bin/bash
# Re-run mihomo-v6-direct.sh whenever addresses or routes change. Changes arrive in bursts
# (a router advertisement adds addresses and routes together, mihomo adds its own routes
# on start), so wait until events stop for a second before re-running. A failed run is
# retried every RETRY seconds until one succeeds, even if no further events arrive.
# Arguments are passed on to mihomo-v6-direct.sh.
DIRECT=/usr/local/sbin/mihomo-v6-direct.sh
RETRY=10

ip monitor address route | {
  ok=0
  "$DIRECT" "$@" && ok=1
  while :; do
    if [ "$ok" = 1 ]; then
      read -r _ || break
    else
      read -r -t "$RETRY" _
      # 1 is the end of the monitor's output; above 128 is the timeout
      [ "$?" != 1 ] || break
    fi
    while read -r -t 1 _; do :; done
    ok=0
    "$DIRECT" "$@" && ok=1
  done
}
