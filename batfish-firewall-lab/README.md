# Batfish Firewall Validation Lab

This lab builds a small cEOS, FRR, and Linux firewall topology for trying Batfish validation against a concrete network intent.

## Topology

```text
client(FRR) --- r1(cEOS) --- fw(Linux iptables) --- r2(cEOS) --- server(FRR)
10.10.10.10     .1       10.0.12.0/30       10.0.23.0/30       10.20.20.10
```

The intended policy is:

- `client` can reach `server` on TCP/80.
- `client` cannot reach `server` on TCP/22.
- Allowed traffic must traverse `fw`.

## Deploy

```bash
cd batfish-firewall-lab
containerlab deploy --reconfigure
```

Destroy the lab:

```bash
containerlab destroy --cleanup
```

## Live Checks

Check the Linux firewall:

```bash
docker exec -it fw sysctl net.ipv4.ip_forward
docker exec -it fw iptables-save
docker exec -it fw ip route
```

Check routing:

```bash
docker exec -it r1 Cli -c "show ip route"
docker exec -it r2 Cli -c "show ip route"
docker exec -it client vtysh -c "show ip route"
docker exec -it server vtysh -c "show ip route"
```

Try basic reachability:

```bash
docker exec -it client ping -c 3 10.20.20.10
docker exec -it client bash -lc "timeout 3 bash -c '</dev/tcp/10.20.20.10/80' || true"
docker exec -it client bash -lc "timeout 3 bash -c '</dev/tcp/10.20.20.10/22' || true"
```

The TCP checks only prove packet forwarding if a service is listening on the destination port. Batfish is the primary validation mechanism for policy behavior.

## Batfish Validation

Start Batfish:

```bash
docker compose up -d batfish
```

Install dependencies, collect a fresh snapshot from the running lab, and run the checks with `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
uv run python scripts/collect_snapshot.py
uv run python scripts/validate.py
```

The script validates:

- All snapshot files parse successfully.
- L3 edges include `client`, `r1`, `fw`, `r2`, and `server`.
- `client -> server` TCP/80 is accepted and traverses `fw`.
- The Linux firewall's `filter::FORWARD` policy permits TCP/80.
- The Linux firewall's `filter::FORWARD` policy denies TCP/22.
- `r1` routes `10.20.20.0/24` toward `fw`.

Batfish currently reports `Do not support complicated iptables rules yet` for the host that carries the `FORWARD` chain. Because of that, this lab validates transit forwarding through `fw` and iptables policy matching as separate Batfish checks.

`scripts/collect_snapshot.py` rebuilds `snapshot/` from the running containers as much as possible:

- cEOS `r1` and `r2`: `show running-config` from the containers.
- FRR `client` and `server`: `/etc/frr/frr.conf` plus live interface addresses.
- Linux `fw`: live interface addresses, routes, and the `iptables-save` filter table.
- Layer1 topology: generated from the containerlab topology file, with cEOS interface names normalized for Batfish.

## Files

- `batfish-firewall.clab.yml`: containerlab topology.
- `live/frr/`: FRR configs mounted into live FRR containers.
- `snapshot/configs/`: cEOS and Cumulus-style FRR configs loaded by Batfish.
- `snapshot/hosts/fw.json`: Batfish host model used to parse the Linux firewall iptables policy.
- `snapshot/iptables/fw.iptables`: iptables-save policy for the firewall.
- `snapshot/batfish/layer1_topology.json`: explicit physical topology for Batfish.
- `scripts/collect_snapshot.py`: rebuilds the Batfish snapshot from the running lab.
- `scripts/validate.py`: Pybatfish validation script.
