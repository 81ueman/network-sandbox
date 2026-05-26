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
go run ./cmd/hoyan verify --prefix-classes --show-prefix-universe-stats
go run ./cmd/hoyan verify --prefix-classes --max-prefix-classes 10000
go run ./cmd/hoyan verify --prefix-classes --format json
```

`--prefix-classes` builds prefix classes from advertised route prefixes,
prefix-list and policy predicates, query destinations, and modeled RIB/FIB
prefixes. Route, packet, and failure checks are expanded across matching
classes. The default output collapses classes with identical reachability,
expected result, counterexample, reason, and symbolic conditions; `--no-collapse`
prints each class result separately.

`--format json` emits a structured report object with `results`. Each result
has common `name`, `type`, and `metadata` fields, then stores query-specific
payload under `route`, `packet`, or `failure`. Prefix class information is kept
separately under `prefix_class`, so route, packet, failure, and prefix-class
semantics can evolve without overloading a single flat result object.

Data-plane policies are parsed from the device startup configs.
Linux/FRR data-plane ACLs are stored as nftables rulesets under
`configs/frr/<node>/nftables.conf`; `hoyan-live-check` builds the local
`hoyan-frr-nftables:10.6.1` image and applies those rulesets after deploy.

Failure search in the normal verifier path is symbolic-only. Route, packet,
prefix-set, and prefix-class targets must implement `sim.SymbolicTarget`, and
the verifier builds a symbolic `NOT(reachable)` goal for the solver instead of
falling back to pre-enumerated forbidden failure combinations. The legacy
enumerated `FailureProblem` helper remains as a small test/parity oracle for
solver regression coverage, not as the verify-time fallback. JSON verify output
for results that run failure search includes a `solver` trace with backend,
candidate element count, and maximum failure budget. With Z3:

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
go run ./cmd/hoyan model prefix-classes --prefix 10.4.0.0/16 --show-predicates
go run ./cmd/hoyan model packet-classes --prefix 10.4.0.0/16 --show-predicates
go run ./cmd/hoyan model packet-classes --queries intent/queries.yml --prefix 10.4.0.0/16 --show-predicates
go run ./cmd/hoyan model symbolic-packet --from cust-bj --to 10.4.1.10 --protocol tcp
go run ./cmd/hoyan model symbolic-route --from bj-edge1 --prefix 10.4.0.0/16 --format json
go run ./cmd/hoyan model symbolic-route --from bj-edge1 --prefix 10.4.0.0/16 --show-conditions
go run ./cmd/hoyan model symbolic-route --from bj-edge1 --prefix 10.4.0.0/16 --show-predicates
```

The default table views keep symbolic conditions hidden so route and prefix
splits stay readable. Add `--show-conditions` to `model rib`, `model fib`,
`model symbolic-packet`, or `model symbolic-route` when you need route
existence, selected-route, install, or reachability conditions. JSON output
still includes condition fields for `jq` or Codex.

The `prefix-classes` view shows the PrefixUniverse classes derived from
advertised route prefixes, prefix-list predicates, policy destination prefixes,
modeled RIB/FIB prefixes, and an optional `--prefix` request predicate.
Matched predicates are hidden in table output by default; add
`--show-predicates` to `model prefix-classes` or `model symbolic-route` when
you need to see which predicates matched each class.
The `packet-classes` view builds HeaderSpace classes over only the header
dimensions that have predicate boundaries: destination prefix class, protocol,
source/destination port, and ingress/egress interface. This keeps packet
predicate inspection tied to PrefixUniverse without creating unused cross
products. Add `--show-predicates` to see the ACL or request predicates that
matched each packet class.
The view also reads `--queries` and includes `PacketCheck` and `FailureCheck`
protocol, destination port, and destination predicates, so query-only packet
classes are visible even when no device ACL distinguishes them.
Packet and failure queries can specify either a single destination port with
`dst_port: 80` or a set of ports with `dst_ports: [80, 443]`; multi-port
queries are expanded into one result per port and therefore one packet class
per port boundary.
Add `--summary` to `model prefix-classes` to print PrefixUniverse build
statistics, including predicate count, unique predicate count, class count,
build duration, max CIDRs per class, and predicate source categories. Use
`--max-prefix-classes` with either `verify --prefix-classes` or
`model prefix-classes` to fail early when class expansion exceeds the requested
guard.
`model symbolic-route --prefix` uses the same request-aware PrefixUniverse and
emits one symbolic route result per matching class, including `class_id`,
`space`, and reachable/unreachable conditions. JSON output still includes
`matched_predicates`.
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
multiple equivalent routes. The FIB compare expected-state builder separately
normalizes selected FRR multipath RIB entries into an ECMP next-hop set for
live kernel FIB comparison. cEOS and SR Linux do not currently expose
equivalent FIB install groups in this model.

Connected routes are classified when the model derives routes from interface
addresses. `link` means the interface belongs to a containerlab topology link,
`loopback` means a loopback interface on an infrastructure node, `service`
means a loopback interface on a customer/service/host node, and `host` means a
non-loopback host-length connected prefix. `hoyan model rib --format json` and
`hoyan model fib --format json` include `connected_class` for connected routes.
Live RIB/FIB compare canonicalizes vendor protocol names such as `kernel`,
`local`, `direct`, and `connected` to `connected`; `link`, `loopback`, and
`service` connected routes are compared, while unclassified host connected
routes remain outside the strict compare set.

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

To run the full live integration check, including deploy, BGP convergence wait,
modeled-vs-live RIB comparison for BGP, connected, and static route sources,
and cleanup:

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

After BGP converges, `live-check` collects the first-class RIB route-table
view for non-BGP sources and compares modeled BGP, connected, and static routes.
The output includes a source summary such as `bgp=10, connected=4, static=2`.
BGP RIB comparison is exact on prefixes, paths, best flag, valid flag,
next-hop, AS path, origin, local-pref, and MED.

For debugging, keep the lab running if the comparison fails:

```bash
go run ./cmd/hoyan live-check --keep-on-failure
```

To keep the lab running even on success:

```bash
go run ./cmd/hoyan live-check --skip-destroy
```

If the lab is already deployed, compare the modeled RIB with live nodes
directly. This compares BGP, connected, and static route sources:

```bash
go run ./cmd/hoyan rib-compare
```

To compare the no-failure modeled FIB with live installed Linux kernel routes,
run:

```bash
go run ./cmd/hoyan fib-compare
```

`fib-compare` normalizes modeled BGP, next-hop static, and comparable connected
FIB entries with live installed FIB entries by node, VRF, AFI, protocol,
prefix, and next-hop set. Null0/blackhole static routes without a comparable
next-hop are outside the strict FIB set. It reports missing routes, unexpected
routes, missing next-hops, and unexpected next-hops, including ECMP group
differences. Live collectors currently use:

```bash
docker exec -i <frr-node> ip -j route show table main
docker exec -i <ceos-node> Cli -p 15 -c "show ip route vrf default | json"
docker exec -i <srlinux-node> sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast summary
docker exec -i <srlinux-node> sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast prefix <prefix> detail
```

`live-check` runs the same comparison after BGP RIB convergence by default:

```bash
go run ./cmd/hoyan live-check
```

Use `--no-check-fib` to skip the installed FIB comparison for a quick
control-plane/dataplane-only run.

Limitations: the modeled side uses the no-failure installed FIB only, Linux
kernel BGP routes are the FRR source of truth, cEOS compares programmed routes
from EOS route JSON, SR Linux compares active route-table entries from
`ipv4-unicast summary` and uses per-prefix `detail` output for SR Linux BGP and
static next-hop peer gateway addresses. Protocol/metric/preference fields are
normalized for inspection but the first comparison target is protocol plus
prefix plus next-hop address/interface set, default routes and unclassified
host connected routes are out of scope, and hardware ASIC FIB or per-flow ECMP
hashing is not verified. BGP routes whose live next-hop cannot be mapped to a
topology data-plane interface are skipped from the strict set comparison for
now; #97 tracks making those unresolved or management-fallback routes explicit
diagnostics.

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
