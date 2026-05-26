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
go run ./cmd/hoyan verify
```

Use strict config mode when the containerlab topology and startup configs are
the verification source of truth and unsupported parser syntax should fail the
run instead of being reported as warnings:

```bash
go run ./cmd/hoyan verify --strict-config
go run ./cmd/hoyan live-check --strict-config
go run ./cmd/hoyan rib-compare --strict-config
go run ./cmd/hoyan model rib --strict-config
```

Strict config errors include the vendor, config file, line number, raw
statement, and unsupported reason so CI logs point at the config syntax that
needs parser support or an intentional non-strict run.

Checks are defined in `intent/queries.yml`:

- route reachability to advertised prefixes
- packet reachability to host prefixes
- failure-budget checks that print concrete link-failure counterexamples

To verify by prefix equivalence class, enable PrefixUniverse expansion:

```bash
go run ./cmd/hoyan verify --prefix-classes
go run ./cmd/hoyan verify --prefix-classes --no-collapse
go run ./cmd/hoyan verify --prefix-classes --format json
```

`--prefix-classes` builds prefix classes from advertised route prefixes,
prefix-list and policy predicates, query destinations, and modeled RIB/FIB
prefixes. Route, packet, and failure checks are expanded across matching
classes. The default output collapses classes with identical reachability,
expected result, counterexample, reason, and symbolic conditions; `--no-collapse`
prints each class result separately. JSON output includes `class_id` or
`class_ids`, `space` or `spaces`, `matched_predicates`, `reachable_condition`,
and `unreachable_condition`.

Data-plane policies are parsed from the device startup configs.
Linux/FRR data-plane ACLs are stored as nftables rulesets under
`configs/frr/<node>/nftables.conf`; `hoyan-live-check` builds the local
`hoyan-frr-nftables:10.6.1` image and applies those rulesets after deploy.

The normal build uses a small solver for failure sets. The legacy
`FailureProblem` path still passes already-enumerated bad combinations to the
backend; that mode does not encode reachability itself. Packet reachability can
also be converted to a symbolic BoolExpr goal (`NOT(reachable)`) and solved by
the symbolic backend without first materializing every bad combo. With Z3:

```bash
go run -tags z3 ./cmd/hoyan verify
```

## Compare Modeled BGP RIBs With Live Nodes

## Inspect Modeled RIB, FIB, and Symbolic Paths

Use `hoyan model` to inspect the offline model built from the containerlab
topology and device configs without collecting live device state:

```bash
go run ./cmd/hoyan model rib --node bj-edge1
go run ./cmd/hoyan model rib --node bj-edge1 --prefix 10.4.0.0/16 --format json
go run ./cmd/hoyan model fib --node bj-edge1
go run ./cmd/hoyan model fib --node bj-edge1 --prefix 10.4.0.0/16 --format json
go run ./cmd/hoyan model prefix-classes --prefix 10.4.0.0/16
go run ./cmd/hoyan model symbolic-packet --from cust-bj --to 10.4.1.10 --protocol tcp
go run ./cmd/hoyan model symbolic-route --from bj-edge1 --prefix 10.4.0.0/16 --format json
```

The RIB view includes route attributes, provenance, condition, and selected
condition. The FIB view includes next-hop, rank, equivalent-route group, path,
cost, and install condition. Use `--format json` when feeding the output to
`jq` or Codex.

The `prefix-classes` view shows the PrefixUniverse classes derived from
advertised route prefixes, prefix-list predicates, policy destination prefixes,
modeled RIB/FIB prefixes, and an optional `--prefix` request predicate.
`model symbolic-route --prefix` uses the same request-aware PrefixUniverse and
emits one symbolic route result per matching class, including `class_id`,
`space`, matched predicates, and reachable/unreachable conditions.
`model symbolic-packet` remains IP-address based.

Modeled FIB semantics use reachability OR for explicitly grouped ECMP /
equivalent candidates: entries with the same prefix, rank, and `group_id` do
not suppress each other, and packet reachability may use any live member in the
group. Lower-rank or shorter-prefix candidates remain suppressed while a
higher-priority group is selected. This is a safety-oriented abstraction; it
does not model per-flow hashing or sticky hash buckets. The default BGP
decision process treats routes as equivalent when local-pref, local-origin,
AS-path length, MED, and eBGP/iBGP status tie. FRR currently installs only one
such equivalent route in the modeled FIB, while the generic behavior can keep
multiple equivalent routes. cEOS and SR Linux do not currently expose
equivalent FIB install groups in this model.

When running Hoyan from multiple git worktrees, render an isolated topology per
worktree first. The suffix is appended to the lab name and Docker management
network name, derives a separate `172.86.<n>.0/24` management subnet, keeps
containerlab's default naming, and keeps the relative config paths valid from
this directory. Keep the generated topology in the `hoyan` directory so
startup-config handling for cEOS and SR Linux matches the source topology:

```bash
go run ./cmd/hoyan render-topology --suffix issue-21 --output hoyan.issue-21.clab.yml
```

For `-suffix issue-21`, containers use containerlab's default names such as
`clab-hoyan-wan-issue-21-bj-edge1`. Use the generated topology with live
commands:

```bash
go run ./cmd/hoyan live-check --topology hoyan.issue-21.clab.yml
go run ./cmd/hoyan rib-compare --topology hoyan.issue-21.clab.yml
```

To run the full live integration check, including deploy, convergence wait,
modeled-vs-live BGP RIB comparison, and cleanup:

```bash
go run ./cmd/hoyan live-check
```

By default, the command polls live BGP RIB state up to five times with a 25s
interval. This keeps polling bounded while leaving enough room for all BGP
sessions to come up after a fresh deploy. If expected routes are still missing
or attributes do not match, it prints modeled-vs-live diffs instead of waiting
for the full timeout:

```bash
go run ./cmd/hoyan live-check --max-polls 5 --poll-interval 25s
```

Live BGP RIB comparison is exact. It requires modeled and live RIBs to match on
prefixes, paths, best flag, valid flag, next-hop, AS path, origin, local-pref,
and MED. Unexpected live prefixes or paths are reported as diffs.

For debugging, keep the lab running if the comparison fails:

```bash
go run ./cmd/hoyan live-check --keep-on-failure
```

To keep the lab running even on success:

```bash
go run ./cmd/hoyan live-check --skip-destroy
```

If the lab is already deployed, compare the modeled BGP RIB with live nodes
directly:

```bash
go run ./cmd/hoyan rib-compare
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

### Modeled BGP Decision Process

`DefaultBGPDecisionProcess` is a Hoyan model approximation, not a complete
vendor implementation. It currently orders candidate BGP routes as follows:

1. Higher local-pref.
2. Locally originated route.
3. Shorter AS path.
4. Lower origin-code preference: IGP, then EGP, then incomplete.
5. Lower MED. The default model preserves the historical approximation and
   compares MED across neighboring ASNs; `BGPDecisionOptions.AlwaysCompareMED`
   documents this knob and can be disabled for same-neighbor-AS-only MED tests.
6. eBGP over iBGP.
7. Shorter modeled path length.
8. Stable lexical tie-break over modeled path nodes.

The modeled path length and lexical tie-break are deterministic simulator
tie-breaks, not vendor bestpath rules. FRR currently uses the same route
attributes but keeps a vendor-specific reverse lexical tie-break so live RIB
comparison remains stable for this lab.

Known unsupported or approximated bestpath knobs:

- Weight: unsupported.
- IGP cost to next-hop: unsupported.
- Router-id tie-break: documented in `BGPDecisionOptions`, unsupported until
  modeled routes carry router-id attributes.
- Originator-id and cluster-list length: unsupported.
- Deterministic MED: documented in `BGPDecisionOptions`, unsupported.
- Always-compare-MED: documented in `BGPDecisionOptions`; the default model
  currently uses the always-compare approximation for backward compatibility.
- Compare-routerid: documented in `BGPDecisionOptions`, unsupported.
- Multipath / ECMP install policy: documented in `BGPDecisionOptions`; route
  equivalence and FIB install semantics are tracked separately in #65.
- Vendor-specific invalid route retention: partially modeled in device
  behavior for cEOS unresolved next-hops and SR Linux AS-loop paths.
- Vendor-specific route-map / policy side effects: only the parsed policy
  actions represented in the model are applied.

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
