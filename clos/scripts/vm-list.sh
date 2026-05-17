#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <dc1-client1|dc1-client2|dc2-client1|dc2-client2|dc3-client1|dc3-client2>" >&2
}

if [ "$#" -ne 1 ]; then usage; exit 1; fi
client="$1"
case "$client" in dc1-client1|dc1-client2|dc2-client1|dc2-client2|dc3-client1|dc3-client2) ;; *) usage; exit 1 ;; esac

docker exec -it "$client" sh -lc "ip -brief address show type dummy || true"
