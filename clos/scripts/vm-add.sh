#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <dc1-client1|dc1-client2|dc2-client1|dc2-client2|dc3-client1|dc3-client2> <vm-id 1-254>" >&2
}

if [ "$#" -ne 2 ]; then usage; exit 1; fi
client="$1"
vm_id="$2"

case "$client" in
  dc1-client1) third=1 ;;
  dc1-client2) third=2 ;;
  dc2-client1) third=1 ;;
  dc2-client2) third=2 ;;
  dc3-client1) third=1 ;;
  dc3-client2) third=2 ;;
  *) usage; exit 1 ;;
esac
case "$client" in
  dc1-*) second=201 ;;
  dc2-*) second=202 ;;
  dc3-*) second=203 ;;
esac
case "$vm_id" in ''|*[!0-9]*) usage; exit 1 ;; esac
if [ "$vm_id" -lt 1 ] || [ "$vm_id" -gt 254 ]; then usage; exit 1; fi

iface="vm${vm_id}"
addr="10.${second}.${third}.${vm_id}/32"

docker exec -it "$client" sh -lc "
  ip link show '$iface' >/dev/null 2>&1 || ip link add '$iface' type dummy
  ip address replace '$addr' dev '$iface'
  ip link set '$iface' up
  ip -brief address show '$iface'
"
