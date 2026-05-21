#!/usr/bin/env bash
set -euo pipefail

# Apply dataplane delay/rate to the FRR container interfaces. The SRv6 setup
# script uses different primary paths for the two customer VPNs; this script
# makes those path differences visible to packet probes as well.

apply() {
  local node="$1"
  local iface="$2"
  local delay="$3"
  local rate="$4"

  if ! docker ps --format '{{.Names}}' | grep -qx "$node"; then
    echo "skip $node:$iface; container is not running" >&2
    return 0
  fi

  docker exec "$node" bash -lc "tc qdisc replace dev $iface root netem delay $delay rate $rate" \
    && echo "$node:$iface delay=$delay rate=$rate"
}

# Low-delay, lower-bandwidth path: pe1-p1-p2-pe2.
apply pe1 eth1 1ms 100mbit
apply p1  eth1 1ms 100mbit
apply p1  eth2 1ms 100mbit
apply p2  eth1 1ms 100mbit
apply p2  eth2 1ms 100mbit
apply pe2 eth1 1ms 100mbit

# High-bandwidth, higher-delay path: pe1-p3-p4-pe2.
apply pe1 eth2 15ms 1000mbit
apply p3  eth1 15ms 1000mbit
apply p3  eth2 15ms 1000mbit
apply p4  eth1 15ms 1000mbit
apply p4  eth2 15ms 1000mbit
apply pe2 eth2 15ms 1000mbit

# Cross-links: medium quality backup paths.
apply p1 eth3 8ms 400mbit
apply p4 eth3 8ms 400mbit
apply p3 eth3 8ms 400mbit
apply p2 eth3 8ms 400mbit
