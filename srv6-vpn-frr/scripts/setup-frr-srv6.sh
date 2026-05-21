#!/usr/bin/env bash
set -euo pipefail

run() {
  local node="$1"
  shift
  docker exec "$node" sh -lc "$*"
}

# Enable the Linux forwarding knobs needed by transit routers and PEs. The
# P nodes need IPv6 forwarding/SRH handling; the PEs also need IPv4 forwarding
# inside customer VRFs.
base_sysctl() {
  local node="$1"
  run "$node" '
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null
    sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null
    sysctl -w net.ipv6.conf.default.seg6_enabled=1 >/dev/null
    for f in /proc/sys/net/ipv6/conf/*/seg6_enabled; do echo 1 > "$f"; done
    for f in /proc/sys/net/ipv6/conf/*/forwarding; do echo 1 > "$f"; done
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip link set lo up
  '
}

# Assign an address to an interface and bring it up. This is used for both
# underlay IPv6 links and loopbacks that FRR advertises into OSPFv3.
addr() {
  run "$1" "ip address replace $3 dev $2; ip link set $2 up"
}

# Install a customer IPv4 route in a VRF table with SRv6 encapsulation. The
# segment list is the explicit path plus the remote End.DT4 service SID.
route4_srv6() {
  run "$1" "ip route del $2 table $3 encap seg6 mode encap segs $4 dev $5 metric $6 2>/dev/null || true; ip route add $2 table $3 encap seg6 mode encap segs $4 dev $5 metric $6"
}

# Create or reuse a Linux VRF, bind the customer-facing interface to it, and
# assign the PE gateway address for that customer site.
vrf() {
  local node="$1"
  local name="$2"
  local table="$3"
  local iface="$4"
  local ipaddr="$5"

  run "$node" "
    sysctl -w net.vrf.strict_mode=1 >/dev/null
    ip link show $name >/dev/null 2>&1 || ip link add $name type vrf table $table
    ip link set $name up
    ip link set $iface master $name
    ip address flush dev $iface
    ip address add $ipaddr dev $iface
    ip link set $iface up
  "
}

for node in pe1 pe2 p1 p2 p3 p4; do
  base_sysctl "$node"
  run "$node" 'ip -6 route flush proto boot 2>/dev/null || true'
done

for node in pe1 pe2; do
  run "$node" '
    ip route flush table 100 2>/dev/null || true
    ip route flush table 200 2>/dev/null || true
  '
done

# Underlay IPv6 links.
addr pe1 eth1 2001:db8:10:1::1/64
addr p1  eth1 2001:db8:10:1::2/64
addr p1  eth2 2001:db8:10:2::1/64
addr p2  eth1 2001:db8:10:2::2/64
addr p2  eth2 2001:db8:10:3::1/64
addr pe2 eth1 2001:db8:10:3::2/64

addr pe1 eth2 2001:db8:20:1::1/64
addr p3  eth1 2001:db8:20:1::2/64
addr p3  eth2 2001:db8:20:2::1/64
addr p4  eth1 2001:db8:20:2::2/64
addr p4  eth2 2001:db8:20:3::1/64
addr pe2 eth2 2001:db8:20:3::2/64

addr p1 eth3 2001:db8:30:1::1/64
addr p4 eth3 2001:db8:30:1::2/64
addr p3 eth3 2001:db8:30:2::1/64
addr p2 eth3 2001:db8:30:2::2/64

# Loopbacks for FRR OSPFv3 visibility.
addr pe1 lo 2001:db8:0:1::1/128
addr pe2 lo 2001:db8:0:2::2/128
addr p1  lo 2001:db8:0:11::11/128
addr p2  lo 2001:db8:0:12::12/128
addr p3  lo 2001:db8:0:13::13/128
addr p4  lo 2001:db8:0:14::14/128

# SRv6 locator prefixes are attached to PE loopback interfaces and advertised
# by FRR OSPFv3 through "redistribute connected" in the PE configs. Transit
# nodes learn locator reachability dynamically instead of receiving static
# locator routes from this script.
addr pe1 lo 2001:db8:128:1::1/64
addr pe1 lo 2001:db8:129:1::1/64
addr pe2 lo 2001:db8:128:2::1/64
addr pe2 lo 2001:db8:129:2::1/64

# Customer VRFs on the PEs.
vrf pe1 vrf-a 100 eth3 10.10.1.1/24
vrf pe1 vrf-b 200 eth4 10.20.1.1/24
vrf pe2 vrf-a 100 eth3 10.10.2.1/24
vrf pe2 vrf-b 200 eth4 10.20.2.1/24

# SRv6 service SIDs.
run pe1 'ip -6 route replace 2001:db8:128:1::a/128 encap seg6local action End.DT4 vrftable 100 dev vrf-a'
run pe1 'ip -6 route replace 2001:db8:129:1::b/128 encap seg6local action End.DT4 vrftable 200 dev vrf-b'
run pe2 'ip -6 route replace 2001:db8:128:2::a/128 encap seg6local action End.DT4 vrftable 100 dev vrf-a'
run pe2 'ip -6 route replace 2001:db8:129:2::b/128 encap seg6local action End.DT4 vrftable 200 dev vrf-b'

# VPN routes. Primary and backup segment lists intentionally use different
# underlay paths so A and B can be inspected independently.
route4_srv6 pe1 10.10.2.0/24 100 2001:db8:10:1::2,2001:db8:10:2::2,2001:db8:128:2::a eth1 10
route4_srv6 pe1 10.10.2.0/24 100 2001:db8:20:1::2,2001:db8:30:2::2,2001:db8:128:2::a eth2 100
route4_srv6 pe1 10.20.2.0/24 200 2001:db8:20:1::2,2001:db8:20:2::2,2001:db8:129:2::b eth2 10
route4_srv6 pe1 10.20.2.0/24 200 2001:db8:10:1::2,2001:db8:30:1::2,2001:db8:129:2::b eth1 100

route4_srv6 pe2 10.10.1.0/24 100 2001:db8:10:3::1,2001:db8:10:2::1,2001:db8:128:1::a eth1 10
route4_srv6 pe2 10.10.1.0/24 100 2001:db8:20:3::1,2001:db8:30:1::1,2001:db8:128:1::a eth2 100
route4_srv6 pe2 10.20.1.0/24 200 2001:db8:20:3::1,2001:db8:20:2::1,2001:db8:129:1::b eth2 10
route4_srv6 pe2 10.20.1.0/24 200 2001:db8:10:3::1,2001:db8:30:2::1,2001:db8:129:1::b eth1 100

echo "FRR underlay and Linux SRv6 VPN routes installed."
