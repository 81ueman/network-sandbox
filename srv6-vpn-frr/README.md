# FRR SRv6 VPN Lab

This lab uses FRR containers for every node. FRR runs the IPv6 underlay with
OSPFv3, and Linux kernel SRv6 routes provide the VPN data plane between the two
PE routers.

The PE routers attach SRv6 locator prefixes to their loopbacks and advertise
them with OSPFv3 `redistribute connected`. Transit nodes learn locator
reachability from FRR instead of receiving static locator routes from the setup
script.

Customer A uses the low-delay path. Customer B uses the high-bandwidth path.
Both VPNs have backup SRv6 routes with higher metrics so link failures can be
tested without changing the topology.

## Topology

```text
              low delay / 100 Mbit
        +---- p1 ---- p2 ----+
        |      \      /      |
a1 -- pe1      \    /      pe2 -- a2
        |        \  /        |
        +---- p3 ---- p4 ----+
             high bandwidth / 1 Gbit

b1 -- pe1                    pe2 -- b2
```

Customer VPNs:

| VPN | Site 1 | Site 2 | Primary transport |
| --- | --- | --- | --- |
| `vrf-a` | `a1` `10.10.1.10/24` | `a2` `10.10.2.10/24` | `pe1-p1-p2-pe2` |
| `vrf-b` | `b1` `10.20.1.10/24` | `b2` `10.20.2.10/24` | `pe1-p3-p4-pe2` |

## Deploy

```bash
cd srv6-vpn-frr
containerlab deploy --reconfigure
./scripts/setup-frr-srv6.sh
./scripts/apply-link-impairment.sh
```

To remove the lab:

```bash
containerlab destroy --cleanup
```

## Verify

Check the FRR underlay:

```bash
docker exec -it pe1 vtysh -c "show ipv6 ospf6 neighbor"
docker exec -it pe1 vtysh -c "show ipv6 route ospf6"
docker exec -it pe2 vtysh -c "show ipv6 ospf6 neighbor"
```

Check SRv6 service routes:

```bash
docker exec -it pe1 ip -d -6 route show 2001:db8:128:1::a/128
docker exec -it pe1 ip -d route show table 100
docker exec -it pe1 ip -d route show table 200
docker exec -it pe2 ip -d route show table 100
docker exec -it pe2 ip -d route show table 200
```

Test customer reachability:

```bash
docker exec -it a1 ping -c 3 10.10.2.10
docker exec -it b1 ping -c 3 10.20.2.10
docker exec -it a1 traceroute 10.10.2.10
docker exec -it b1 traceroute 10.20.2.10
```

Expected behavior:

- `vrf-a` uses SRv6 segment list
  `2001:db8:10:1::2,2001:db8:10:2::2,2001:db8:128:2::a`.
- `vrf-b` uses SRv6 segment list
  `2001:db8:20:1::2,2001:db8:20:2::2,2001:db8:129:2::b`.
- Customer A sees the lower-delay path.
- Customer B sees the higher-bandwidth path.

## Failure Checks

Remove the low-delay primary VPN routes and confirm customer A uses the backup
route:

```bash
docker exec -it pe1 ip route del 10.10.2.0/24 table 100 \
  encap seg6 mode encap segs 2001:db8:10:1::2,2001:db8:10:2::2,2001:db8:128:2::a \
  dev eth1 metric 10
docker exec -it pe2 ip route del 10.10.1.0/24 table 100 \
  encap seg6 mode encap segs 2001:db8:10:3::1,2001:db8:10:2::1,2001:db8:128:1::a \
  dev eth1 metric 10
docker exec -it a1 ping -c 3 10.10.2.10
./scripts/setup-frr-srv6.sh
./scripts/apply-link-impairment.sh
```

Remove the high-bandwidth primary VPN routes and confirm customer B uses the
backup route:

```bash
docker exec -it pe1 ip route del 10.20.2.0/24 table 200 \
  encap seg6 mode encap segs 2001:db8:20:1::2,2001:db8:20:2::2,2001:db8:129:2::b \
  dev eth2 metric 10
docker exec -it pe2 ip route del 10.20.1.0/24 table 200 \
  encap seg6 mode encap segs 2001:db8:20:3::1,2001:db8:20:2::1,2001:db8:129:1::b \
  dev eth2 metric 10
docker exec -it b1 ping -c 3 10.20.2.10
./scripts/setup-frr-srv6.sh
./scripts/apply-link-impairment.sh
```

## Notes

- This is no longer an SR Linux lab; every node runs
  `quay.io/frrouting/frr:10.6.1`.
- FRR is used for the underlay routing process. The SRv6 encap and End.DT4
  service behavior are Linux kernel routes configured by
  `scripts/setup-frr-srv6.sh`.
- The setup script still installs the customer VPN routes and service SIDs in
  Linux, but underlay reachability to remote locator prefixes is learned through
  OSPFv3.
- The kernel must support `seg6` and `seg6local`; recent Docker Desktop,
  OrbStack, and Linux hosts generally expose these route types.
