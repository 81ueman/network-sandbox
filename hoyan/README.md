# Hoyan-Style WAN Verifier Lab

This directory contains a medium-size WAN sandbox inspired by the Hoyan
SIGCOMM 2020 paper. The lab uses containerlab for the runnable topology and a
Go verifier for offline route, packet, and failure reachability checks.

The verifier treats `hoyan.clab.yml` plus the referenced device configs as the
source of truth. `hoyan.clab.yml` provides containerlab inventory and physical
links; FRR, cEOS, and SR Linux startup configs provide interfaces, BGP ASN,
router-id, neighbors, and advertised prefixes. Containers use containerlab's
default `clab-<lab-name>-<node-name>` names. The verifier builds a Hoyan-style
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

## Compare Modeled BGP RIBs With Live Nodes

When running Hoyan from multiple git worktrees, render an isolated topology per
worktree first. The suffix is appended to the lab name and Docker management
network name, derives a separate `172.86.<n>.0/24` management subnet, keeps
containerlab's default naming, and keeps the relative config paths valid from
this directory. Keep the generated topology in the `hoyan` directory so
startup-config handling for cEOS and SR Linux matches the source topology:

```bash
go run ./cmd/hoyan-render-topology -suffix issue-21 -output hoyan.issue-21.clab.yml
```

For `-suffix issue-21`, containers use containerlab's default names such as
`clab-hoyan-wan-issue-21-bj-edge1`. Use the generated topology with live
commands:

```bash
go run ./cmd/hoyan-live-check -topology hoyan.issue-21.clab.yml
go run ./cmd/hoyan-rib-compare -topology hoyan.issue-21.clab.yml
```

To run the full live integration check, including deploy, convergence wait,
modeled-vs-live BGP RIB comparison, and cleanup:

```bash
go run ./cmd/hoyan-live-check
```

By default, the command polls live BGP RIB state up to three times with a 25s
interval. This keeps polling bounded while leaving enough room for all BGP
sessions to come up after a fresh deploy. If expected routes are still missing
or attributes do not match, it prints modeled-vs-live diffs instead of waiting
for the full timeout:

```bash
go run ./cmd/hoyan-live-check -max-polls 3 -poll-interval 25s
```

Live BGP RIB comparison is exact. It requires modeled and live RIBs to match on
prefixes, paths, best flag, valid flag, next-hop, AS path, origin, local-pref,
and MED. Unexpected live prefixes or paths are reported as diffs.

For debugging, keep the lab running if the comparison fails:

```bash
go run ./cmd/hoyan-live-check -keep-on-failure
```

To keep the lab running even on success:

```bash
go run ./cmd/hoyan-live-check -skip-destroy
```

If the lab is already deployed, compare the modeled BGP RIB with live nodes
directly:

```bash
go run ./cmd/hoyan-rib-compare
```

The live comparison reads BGP table state from FRR, cEOS, and SR Linux nodes,
not kernel routes, installed route tables, or dataplane forwarding state. It
collects:

```bash
docker exec -i <frr-node> vtysh -c "show ip bgp json"
docker exec -i <ceos-node> Cli -p 15 -c "show ip bgp | json"
docker exec -i <srlinux-node> sr_cli --output-format json --pagination off -- show network-instance default protocols bgp routes ipv4 summary
docker exec -i <srlinux-node> sr_cli --output-format json --pagination off -- show network-instance default protocols bgp routes ipv4 prefix <prefix> detail
```

Routes are normalized by node, network-instance, AFI, prefix, and BGP path.
Vendor-specific formatting differences such as local next-hop representation,
origin spelling, and omitted default local-pref are normalized before exact
comparison.

Vendor-specific BGP RIB behavior is modeled where it affects live comparison.
cEOS can keep paths with unresolved next-hops in the BGP table as invalid
paths, and SR Linux can retain AS-loop paths as invalid BGP RIB entries. Those
paths are not used for forwarding, but they are represented in the modeled BGP
RIB so live table comparison stays aligned with the devices.

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
docker exec -it clab-hoyan-wan-bj-edge1 vtysh -c "show ip bgp summary"
docker exec -it clab-hoyan-wan-bj-edge1 vtysh -c "show ip route bgp"
docker exec -it clab-hoyan-wan-cust-bj ping -c 3 10.4.1.10
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
