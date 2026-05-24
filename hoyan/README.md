# Hoyan-Style WAN Verifier Lab

This directory contains a medium-size WAN sandbox inspired by the Hoyan
SIGCOMM 2020 paper. The lab uses containerlab for the runnable topology and a
Go verifier for offline route, packet, and failure reachability checks.

The verifier treats `hoyan.clab.yml` plus the referenced device configs as the
source of truth. `hoyan.clab.yml` provides containerlab inventory and physical
links; FRR, cEOS, and SR Linux startup configs provide interfaces, BGP ASN,
router-id, neighbors, and advertised prefixes. The verifier builds a Hoyan-style
network model from those configs: each device has control-plane and data-plane
pipelines made of ingress policy, route selector, and egress policy. BGP route
updates populate an extended RIB with topology conditions, and the FIB is
derived from the ranked RIB rules.

## Verify

```bash
cd hoyan
go run ./cmd/hoyan-verify
```

Checks are defined in `intent/queries.yml`:

- route reachability to advertised prefixes
- packet reachability to host prefixes
- failure-budget checks that print concrete link-failure counterexamples

Verifier-only policies that are not present in startup configs live in
`intent/policies.yml`.

The normal build uses a small enumerating solver for failure sets. With Z3:

```bash
go run -tags z3 ./cmd/hoyan-verify
```

## Compare Modeled RIBs With FRR

To run the full live integration check, including deploy, convergence wait,
modeled-vs-live FRR RIB comparison, and cleanup:

```bash
go run ./cmd/hoyan-live-check
```

By default, the command collects FRR BGP JSON up to three times with a 25s
interval. This keeps polling bounded while leaving enough room for the SR Linux
BGP sessions to come up after a fresh deploy. If expected routes are still
missing, it prints modeled-vs-live diffs instead of waiting for the full
timeout:

```bash
go run ./cmd/hoyan-live-check -max-polls 3 -poll-interval 25s
```

For debugging, keep the lab running if the comparison fails:

```bash
go run ./cmd/hoyan-live-check -keep-on-failure
```

To keep the lab running even on success:

```bash
go run ./cmd/hoyan-live-check -skip-destroy
```

If the lab is already deployed, compare the modeled best paths with live FRR
BGP RIBs directly:

```bash
go run ./cmd/hoyan-rib-compare
```

The command currently collects FRR nodes with:

```bash
docker exec <node> vtysh -c "show ip bgp json"
```

and reports prefix/next-hop mismatches. FRR ECMP candidates are treated as an
allowed next-hop set because FRR's displayed best path can depend on which
equivalent path was received first. cEOS and SR Linux collection are left as
future collectors; they are still included in the modeled control plane and
lab.

## Deploy

```bash
containerlab deploy --reconfigure
```

Destroy with:

```bash
containerlab destroy --cleanup
```

Useful FRR checks:

```bash
docker exec -it bj-edge1 vtysh -c "show ip bgp summary"
docker exec -it bj-edge1 vtysh -c "show ip route bgp"
docker exec -it cust-bj ping -c 3 10.4.1.10
```

## Z3

The default verifier backend enumerates small failure sets so normal tests work
without native libraries. A Z3-backed solver is available behind the `z3` build
tag and uses cgo against `libz3`.

On Debian:

```bash
sudo apt-get update
sudo apt-get install -y libz3-dev
go test -tags z3 ./...
```

## Tests

```bash
go test ./...
go test -tags z3 ./...
```
