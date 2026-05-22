# Batfish BGP CLOS Lab

This lab builds a small cEOS and FRR L3 CLOS fabric for Batfish validation of client reachability and ECMP.

## Topology

```text
              spine1(cEOS)        spine2(cEOS)
              /        \          /        \
         leaf1(cEOS)             leaf2(cEOS)
             |                       |
        client1(FRR)            client2(FRR)
        10.10.1.1/32            10.10.2.1/32
```

Fabric and client links use numbered eBGP over `/31` point-to-point links. The client loopbacks are advertised with eBGP, and each leaf should learn the remote client loopback through both spines.

## Deploy

```bash
cd batfish-clos-lab
containerlab deploy --reconfigure
```

Destroy the lab:

```bash
containerlab destroy --cleanup
```

## Live Checks

Check BGP sessions and ECMP routes:

```bash
docker exec -it leaf1 Cli -p 15 -c "show ip bgp summary"
docker exec -it leaf1 Cli -p 15 -c "show ip route 10.10.2.1/32"
docker exec -it leaf2 Cli -p 15 -c "show ip route 10.10.1.1/32"
docker exec -it client1 vtysh -c "show bgp ipv4 unicast"
docker exec -it client2 vtysh -c "show bgp ipv4 unicast"
```

Try client loopback reachability:

```bash
docker exec -it client1 ping -I 10.10.1.1 -c 3 10.10.2.1
docker exec -it client2 ping -I 10.10.2.1 -c 3 10.10.1.1
```

## Batfish Validation

Start Batfish:

```bash
docker compose up -d batfish
```

Install dependencies, collect a fresh snapshot from the running lab, and run validation:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
uv run python scripts/collect_snapshot.py
uv run python scripts/validate.py
```

The script validates:

- All snapshot files parse successfully.
- L3 and BGP edges include the expected spine, leaf, and client nodes.
- `client1` loopback `10.10.1.1` reaches `client2` loopback `10.10.2.1`.
- `client2` loopback `10.10.2.1` reaches `client1` loopback `10.10.1.1`.
- `leaf1` has ECMP toward `10.10.2.1/32` via two spine-side next-hops.
- `leaf2` has ECMP toward `10.10.1.1/32` via two spine-side next-hops.

To validate a single-link failure, generate a failure snapshot before running validation:

```bash
uv run python scripts/collect_snapshot.py --failure spine1-leaf1
uv run python scripts/validate.py
```

Supported failure names are:

- `spine1-leaf1`
- `spine2-leaf1`
- `spine1-leaf2`
- `spine2-leaf2`

When a failure snapshot exists, `validate.py` also checks that client loopback reachability still works and that the affected leaf route shrinks from two spine-side next-hops to the expected surviving next-hop.

`scripts/collect_snapshot.py` rebuilds `snapshot/` from the running containers:

- cEOS fabric nodes: `show running-config`.
- FRR clients: `/etc/frr/frr.conf` plus live interface and loopback addresses.
- Layer1 topology: generated from the containerlab topology file, with cEOS interface names normalized for Batfish.
