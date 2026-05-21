#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  ./vtysh.sh <node>
  ./vtysh.sh <node> <vtysh-command>

examples:
  ./vtysh.sh pe1
  ./vtysh.sh pe1 "show running-config"
  ./vtysh.sh p1 "show ipv6 ospf6 neighbor"
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

node="$1"
shift

if ! docker inspect "$node" >/dev/null 2>&1; then
  echo "container not found: $node" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  exec docker exec -it "$node" vtysh
fi

exec docker exec "$node" vtysh -c "$*"
