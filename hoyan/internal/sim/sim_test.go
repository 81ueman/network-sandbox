package sim

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func loadGraph(t *testing.T) *Graph {
	t.Helper()
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	return NewGraph(topo)
}

func TestRouteReachable(t *testing.T) {
	g := loadGraph(t)
	path, ok := g.RouteReachable("bj-edge1", "10.4.0.0/16", NoFailures())
	if !ok {
		t.Fatalf("route not reachable")
	}
	if path.Nodes[0] != "bj-edge1" || path.Nodes[len(path.Nodes)-1] != "hz-edge1" {
		t.Fatalf("path = %#v", path.Nodes)
	}
}

func TestBGPBuildsRankedExtendedRIB(t *testing.T) {
	g := loadGraph(t)
	rib := g.RIB("bj-edge1", "10.3.1.10/32")
	if len(rib) < 2 {
		t.Fatalf("RIB entries = %d, want multiple alternatives", len(rib))
	}
	if !rib[0].Condition.Eval(FailureContext{}) || !rib[0].SelectedCond.Eval(FailureContext{}) {
		t.Fatalf("best route should exist and be selected with no failures")
	}
	var fallback bool
	for _, link := range rib[0].Links {
		failed := g.FailureContext(LinkFailures(model.LinkID(link)))
		if rib[0].SelectedCond.Eval(failed) {
			continue
		}
		for _, r := range rib[1:] {
			if r.SelectedCond.Eval(failed) {
				fallback = true
				break
			}
		}
		if fallback {
			break
		}
	}
	if !fallback {
		t.Fatalf("no lower-priority RIB route selected after best-route failure")
	}
}

func TestRIBEntryKeepsOriginNodeAndBGPOriginCodeSeparate(t *testing.T) {
	g := loadGraph(t)

	local := g.RIB("hz-edge1", "10.4.0.0/16")
	if len(local) == 0 {
		t.Fatalf("local RIB entry missing")
	}
	if local[0].Provenance.OriginNode != "hz-edge1" || local[0].Attrs.OriginCode != "igp" {
		t.Fatalf("local route origin node/code = %q/%q, want hz-edge1/igp: %#v", local[0].Provenance.OriginNode, local[0].Attrs.OriginCode, local[0])
	}

	var propagated RIBEntry
	for _, r := range g.RIB("bj-edge1", "10.4.0.0/16") {
		if r.Provenance.OriginNode == "hz-edge1" && r.From != "" {
			propagated = r
			break
		}
	}
	if propagated.Provenance.OriginNode == "" {
		t.Fatalf("propagated hz route not found")
	}
	if propagated.Provenance.OriginNode == string(propagated.Attrs.OriginCode) {
		t.Fatalf("propagated route mixed provenance origin and BGP origin-code: %#v", propagated)
	}
	if !propagated.ForwardingNextHop.Valid() || propagated.ForwardingNextHop.Node == "" || propagated.ForwardingNextHop.Addr != "" {
		t.Fatalf("simulated next-hop should be a node before live address resolution: %#v", propagated.ForwardingNextHop)
	}
}

func TestBGPRejectsASLoops(t *testing.T) {
	g := loadGraph(t)
	for _, r := range g.RIB("gz-edge1", "10.3.1.10/32") {
		if len(r.ASPath) == 0 {
			continue
		}
		for _, asn := range r.ASPath {
			if asn == 65003 {
				t.Fatalf("AS loop route installed: %#v", r)
			}
		}
	}
}

func TestIBGPSplitHorizon(t *testing.T) {
	g := loadGraph(t)
	for _, r := range g.RIB("core-hz", "10.1.0.0/16") {
		if r.From == "core-gz" {
			t.Fatalf("iBGP learned route was re-advertised to another iBGP peer: %#v", r)
		}
	}
}

func TestSRLinuxExportPolicySetsMED(t *testing.T) {
	g := loadGraph(t)
	for _, r := range g.RIB("transit-south", "10.3.0.0/16") {
		if r.From != "core-gz" {
			continue
		}
		if r.MED != 55 {
			t.Fatalf("core-gz route MED = %d, want 55: %#v", r.MED, r)
		}
		return
	}
	t.Fatalf("transit-south did not learn 10.3.0.0/16 from core-gz")
}

func TestPacketPolicyDeny(t *testing.T) {
	g := loadGraph(t)
	_, ok, reason := g.PacketReachable("cust-bj", "10.4.1.10", "tcp", NoFailures())
	if ok {
		t.Fatalf("tcp packet unexpectedly reachable")
	}
	if reason != "denied by policy BLOCK-HTTP-TO-HZ" {
		t.Fatalf("reason = %q", reason)
	}
	_, ok, reason = g.PacketReachableSpec("cust-bj", "10.4.1.10", model.PacketSpec{Protocol: "tcp", DstPort: model.ExactPortSet{Port: 443}}, NoFailures())
	if !ok {
		t.Fatalf("tcp/443 packet not reachable: %s", reason)
	}
	_, ok, reason = g.PacketReachable("cust-bj", "10.4.1.10", "icmp", NoFailures())
	if !ok {
		t.Fatalf("icmp packet not reachable: %s", reason)
	}
}

func TestSingleFailureStillReachable(t *testing.T) {
	g := loadGraph(t)
	failed := LinkFailures("core-bj-sh")
	if _, ok := g.RouteReachable("bj-edge1", "10.4.0.0/16", failed); !ok {
		t.Fatalf("route should survive core-bj-sh failure")
	}
}

func TestFindBreakingFailures(t *testing.T) {
	g := loadGraph(t)
	cut, ok := g.FindBreakingFailures("cust-bj", PacketTarget{To: "10.4.1.10", Protocol: "icmp"}, 1)
	if !ok || len(cut) == 0 {
		t.Fatalf("expected one-link cut after iBGP split-horizon modeling, got %v %v", cut, ok)
	}
	cut, ok = g.FindBreakingFailures("cust-bj", PacketTarget{To: "10.4.1.10", Protocol: "icmp"}, 3)
	if !ok || len(cut) == 0 {
		t.Fatalf("expected a cut within three failures, got %v %v", cut, ok)
	}
}

func TestFailureSearchTargetsAreSymbolic(t *testing.T) {
	var _ SymbolicTarget = PacketTarget{}
	var _ SymbolicTarget = PacketPrefixTarget{}
	var _ SymbolicTarget = PacketClassTarget{}
	var _ SymbolicTarget = PrefixTarget("")
	var _ SymbolicTarget = RoutePrefixSetTarget{}
	var _ SymbolicTarget = RouteClassTarget{}
}

func TestFindBreakingFailuresSymbolicUnsatAndTrace(t *testing.T) {
	g := loadGraph(t)
	result, err := g.FindBreakingFailuresSymbolic("cust-bj", PacketTarget{To: "10.4.1.10", Protocol: "icmp"}, FailureSearchOptions{
		IncludeLinks: true,
		MaxFailures:  0,
	})
	if err != nil {
		t.Fatalf("FindBreakingFailuresSymbolic() error = %v", err)
	}
	if result.Sat {
		t.Fatalf("FindBreakingFailuresSymbolic() Sat = true, want false for zero-failure reachable packet")
	}
	if result.Solver.Backend == "" || result.Solver.Elements == 0 || result.Solver.MaxFailures != 0 {
		t.Fatalf("solver trace = %#v", result.Solver)
	}
}

func TestFindBreakingFailuresSymbolicSupportsBuiltInTargets(t *testing.T) {
	g := loadGraph(t)
	universe, err := model.BuildPrefixUniverse([]model.PrefixSet{
		model.ExactPrefixSet{Prefix: model.MustPrefix("10.4.0.0/16")},
	})
	if err != nil {
		t.Fatalf("BuildPrefixUniverse() error = %v", err)
	}
	if len(universe.Classes) == 0 {
		t.Fatalf("BuildPrefixUniverse() produced no classes")
	}
	targets := []SymbolicTarget{
		PacketTarget{To: "10.4.1.10", Protocol: "icmp"},
		PacketPrefixTarget{Prefix: model.MustPrefix("10.4.1.10/32"), Protocol: "icmp"},
		PacketClassTarget{Universe: universe, ClassID: universe.Classes[0].ID, Protocol: "icmp"},
		PrefixTarget("10.4.0.0/16"),
		RoutePrefixSetTarget{Space: model.ExactPrefixSet{Prefix: model.MustPrefix("10.4.0.0/16")}},
		RouteClassTarget{Universe: universe, ClassID: universe.Classes[0].ID},
	}
	for _, target := range targets {
		result, err := g.FindBreakingFailuresSymbolic("cust-bj", target, FailureSearchOptions{
			IncludeLinks: true,
			MaxFailures:  0,
		})
		if err != nil {
			t.Fatalf("FindBreakingFailuresSymbolic(%T) error = %v", target, err)
		}
		if result.Solver.Backend == "" || result.Solver.Elements == 0 {
			t.Fatalf("FindBreakingFailuresSymbolic(%T) trace = %#v", target, result.Solver)
		}
	}
}

func TestFindBreakingFailuresRejectsConcreteOnlyTarget(t *testing.T) {
	g := loadGraph(t)
	target := concreteOnlyTarget{}
	if _, ok := g.FindBreakingFailuresWithOptions("cust-bj", target, FailureSearchOptions{IncludeLinks: true, MaxFailures: 1}); ok {
		t.Fatalf("FindBreakingFailuresWithOptions() accepted concrete-only target")
	}
	_, err := g.FindBreakingFailuresTargetSymbolic("cust-bj", target, FailureSearchOptions{IncludeLinks: true, MaxFailures: 1})
	if err == nil || !strings.Contains(err.Error(), "does not implement sim.SymbolicTarget") {
		t.Fatalf("FindBreakingFailuresTargetSymbolic() error = %v", err)
	}
}

type concreteOnlyTarget struct{}

func (concreteOnlyTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	return false
}
