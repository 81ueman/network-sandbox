# Multi-DC IP CLOS Lab

This lab builds three small data centers. Each DC has one FRR external router, one Nokia SR Linux spine, two Nokia SR Linux leaves, and two FRR clients. Leaf-client and spine-leaf links use BGP unnumbered. Each external router is the DC exit point; external routers run OSPF with each other and advertise only aggregated DC prefixes.

## Topology

```text
       dc1-external ----- dc2-external
          |   \             |
          |    \            |
       dc1-spine1       dc2-spine1
        /      \        /      \
   dc1-leaf1 dc1-leaf2 dc2-leaf1 dc2-leaf2
      |          |        |          |
 dc1-client1 dc1-client2 dc2-client1 dc2-client2

       dc3-external connects to dc1-external and dc2-external
       dc3 has the same spine/leaf/client shape.
```

## Deploy

```bash
cd clos
containerlab deploy --reconfigure
```

To remove the lab:

```bash
containerlab destroy --cleanup
```

## Verify

Check OSPF between external switches:

```bash
docker exec -it dc1-external vtysh -c "show ip ospf neighbor"
docker exec -it dc1-external vtysh -c "show ip route ospf"
```

Check BGP unnumbered inside a DC:

```bash
ssh admin@dc1-leaf1
show network-instance default protocols bgp neighbor
```

Create VM prefixes and test inter-DC reachability:

```bash
./scripts/vm-add.sh dc1-client1 11
./scripts/vm-add.sh dc2-client1 21
./scripts/vm-add.sh dc3-client2 32

docker exec -it dc1-client1 ping -c 3 10.202.1.21
docker exec -it dc2-client1 ping -c 3 10.203.2.32
docker exec -it dc3-client2 ping -c 3 10.201.1.11
```

Delete a VM prefix and confirm it is withdrawn:

```bash
./scripts/vm-del.sh dc1-client1 11
docker exec -it dc2-client1 vtysh -c "show bgp ipv4 unicast 10.201.1.11/32"
```

## Addressing and ASNs

| DC | Aggregate | External AS | Spine AS | Leaf AS range | Client AS range |
| --- | --- | ---: | ---: | --- | --- |
| DC1 | 10.201.0.0/16 | 4200000010 | 4200000011 | 4200001011-4200001012 | 4200002011-4200002012 |
| DC2 | 10.202.0.0/16 | 4200000020 | 4200000021 | 4200001021-4200001022 | 4200002021-4200002022 |
| DC3 | 10.203.0.0/16 | 4200000030 | 4200000031 | 4200001031-4200001032 | 4200002031-4200002032 |

External-to-external links use OSPF area `0.0.0.0`. OSPF should carry only the three `/16` DC aggregates, not VM `/32` routes.
