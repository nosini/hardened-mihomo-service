#!/bin/bash
# Re-run mihomo-v6-direct.sh whenever addresses or routes change. Changes arrive in bursts
# (a router advertisement adds addresses and routes together, mihomo adds its own routes
# on start), so wait until events stop for a second before re-running.
# Arguments are passed on to mihomo-v6-direct.sh.
DIRECT=/usr/local/sbin/mihomo-v6-direct.sh

ip monitor address route | {
  "$DIRECT" "$@"
  while read -r _; do
    while read -r -t 1 _; do :; done
    "$DIRECT" "$@"
  done
}
