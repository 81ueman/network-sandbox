#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: ./wireshark-docker.sh <container> <interface> [tcpdump-filter...]

Examples:
  ./wireshark-docker.sh dc1-leaf1 e1-1
  ./wireshark-docker.sh dc1-leaf1 e1-1 icmp
  ./wireshark-docker.sh dc1-spine1 e1-49 tcp port 179

Environment:
  WIRESHARK=/path/to/Wireshark  Override Wireshark executable.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -lt 2 ]; then
  usage
  exit 1
fi

container="$1"
interface="$2"
shift 2

wireshark="${WIRESHARK:-/Applications/Wireshark.app/Contents/MacOS/Wireshark}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command not found" >&2
  exit 1
fi

if [ ! -x "$wireshark" ]; then
  echo "Wireshark executable not found: $wireshark" >&2
  echo "Set WIRESHARK=/path/to/Wireshark if it is installed elsewhere." >&2
  exit 1
fi

if ! docker inspect "$container" >/dev/null 2>&1; then
  echo "container not found: $container" >&2
  exit 1
fi

echo "Starting live capture: container=$container interface=$interface filter=${*:-<none>}" >&2
echo "Press Ctrl-C in this terminal to stop the capture." >&2

docker exec -i "$container" tcpdump -U -s 0 -ni "$interface" -w - "$@" \
  | "$wireshark" -k -i -
