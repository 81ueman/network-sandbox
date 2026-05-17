#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <dc1-client1|dc1-client2|dc2-client1|dc2-client2|dc3-client1|dc3-client2> <vm-id 1-254>" >&2
}

if [ "$#" -ne 2 ]; then usage; exit 1; fi
client="$1"
vm_id="$2"
case "$client" in dc1-client1|dc1-client2|dc2-client1|dc2-client2|dc3-client1|dc3-client2) ;; *) usage; exit 1 ;; esac
case "$vm_id" in ''|*[!0-9]*) usage; exit 1 ;; esac
if [ "$vm_id" -lt 1 ] || [ "$vm_id" -gt 254 ]; then usage; exit 1; fi

docker exec -it "$client" sh -lc "ip link show 'vm${vm_id}' >/dev/null 2>&1 && ip link delete 'vm${vm_id}' || true"
