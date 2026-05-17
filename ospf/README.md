# Nokia SR Linux OSPF Lab

This lab builds a simple three-router OSPFv2 topology with one Linux client behind each router.

## Topology

```text
client1 -- r1 ----- r2 -- client2
            \       /
             \     /
               r3 -- client3
```

## Deploy

```bash
cd ospf
containerlab deploy --reconfigure
```

To remove the lab:

```bash
containerlab destroy --cleanup
```

## Verify

Check OSPF neighbors from a router:

```bash
ssh admin@r1
show network-instance default protocols ospf neighbor
```

Check learned routes:

```bash
show network-instance default route-table ipv4-unicast
```

Test client-to-client reachability:

```bash
docker exec -it client1 ping -c 3 172.16.2.10
docker exec -it client1 ping -c 3 172.16.3.10
docker exec -it client2 traceroute 172.16.3.10
```

## Addressing

| Link | Addresses |
| --- | --- |
| r1-r2 | r1 `192.0.2.0/31`, r2 `192.0.2.1/31` |
| r2-r3 | r2 `192.0.2.2/31`, r3 `192.0.2.3/31` |
| r3-r1 | r3 `192.0.2.4/31`, r1 `192.0.2.5/31` |
| client1 LAN | r1 `172.16.1.1/24`, client1 `172.16.1.10/24` |
| client2 LAN | r2 `172.16.2.1/24`, client2 `172.16.2.10/24` |
| client3 LAN | r3 `172.16.3.1/24`, client3 `172.16.3.10/24` |
