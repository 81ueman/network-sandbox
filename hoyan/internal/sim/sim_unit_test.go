package sim

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func testPrefix(t *testing.T, raw string) netip.Prefix {
	t.Helper()
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", raw, err)
	}
	return pfx
}

func testGraph(topo *model.Topology) *Graph {
	return &Graph{
		topo: topo,
		adj:  map[string][]edge{},
		rib:  map[string]map[string][]RIBEntry{},
		fib:  map[string][]FIBEntry{},
	}
}

func TestApplyAdvertisementConditionsPropagatesParentSelectedCond(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "origin", Kind: "frr", ASN: 65001},
			{Name: "mid", Kind: "frr", ASN: 65002},
			{Name: "down", Kind: "frr", ASN: 65003},
		},
	})
	parentSelected := Var("best")
	childBase := Var("mid-down")
	g.rib["mid"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{
				Prefix:       "10.0.0.0/24",
				Origin:       "origin",
				From:         "origin",
				Nodes:        []string{"origin", "mid"},
				Condition:    True(),
				SelectedCond: parentSelected,
			},
		},
	}
	g.rib["down"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{
				Prefix:    "10.0.0.0/24",
				Origin:    "origin",
				From:      "mid",
				Nodes:     []string{"origin", "mid", "down"},
				BaseCond:  childBase,
				Condition: childBase,
			},
		},
	}

	if !g.applyAdvertisementConditions() {
		t.Fatalf("applyAdvertisementConditions() did not report a change")
	}
	child := g.rib["down"]["10.0.0.0/24"][0]
	if child.Condition.Eval(map[string]bool{"best": true}) {
		t.Fatalf("child condition should depend on parent selected condition: %s", child.Condition.String())
	}
	if child.Condition.Eval(map[string]bool{"mid-down": true}) {
		t.Fatalf("child condition should depend on child base condition: %s", child.Condition.String())
	}
	if !child.Condition.Eval(nil) {
		t.Fatalf("child condition should be true when parent and child conditions are true")
	}
}

func TestApplyAdvertisementConditionsSuppressesBackupAdvertisement(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "best", Kind: "frr", ASN: 65001},
			{Name: "backup", Kind: "frr", ASN: 65002},
			{Name: "mid", Kind: "frr", ASN: 65003},
			{Name: "down", Kind: "frr", ASN: 65004},
		},
	})
	bestCond := Var("best-link")
	backupCond := Var("backup-link")
	g.rib["mid"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{
				Prefix:       "10.0.0.0/24",
				Origin:       "best",
				From:         "best",
				Nodes:        []string{"best", "mid"},
				Condition:    bestCond,
				SelectedCond: bestCond,
			},
			{
				Prefix:       "10.0.0.0/24",
				Origin:       "best",
				From:         "backup",
				Nodes:        []string{"best", "backup", "mid"},
				Condition:    backupCond,
				SelectedCond: And(backupCond, Not(bestCond)),
			},
		},
	}
	g.rib["down"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{
				Prefix:    "10.0.0.0/24",
				Origin:    "best",
				From:      "mid",
				Nodes:     []string{"best", "backup", "mid", "down"},
				BaseCond:  Var("mid-down"),
				Condition: Var("mid-down"),
			},
		},
	}

	g.applyAdvertisementConditions()
	child := g.rib["down"]["10.0.0.0/24"][0]
	if child.Condition.Eval(nil) {
		t.Fatalf("backup child route should not be advertised while higher-priority parent is selected: %s", child.Condition.String())
	}
	if !child.Condition.Eval(map[string]bool{"best-link": true}) {
		t.Fatalf("backup child route should be advertised when best parent is unavailable: %s", child.Condition.String())
	}
}

func TestParentRouteFindsPreviousHopRoute(t *testing.T) {
	g := testGraph(&model.Topology{})
	parent := RIBEntry{
		Prefix: "10.0.0.0/24",
		Origin: "origin",
		From:   "origin",
		Nodes:  []string{"origin", "mid"},
	}
	g.rib["mid"] = map[string][]RIBEntry{"10.0.0.0/24": {parent}}
	child := RIBEntry{
		Prefix: "10.0.0.0/24",
		Origin: "origin",
		From:   "mid",
		Nodes:  []string{"origin", "mid", "down"},
	}

	got, ok := g.parentRoute(child)
	if !ok {
		t.Fatalf("parentRoute() did not find previous-hop route")
	}
	if !reflect.DeepEqual(got.Nodes, parent.Nodes) {
		t.Fatalf("parent nodes = %v, want %v", got.Nodes, parent.Nodes)
	}
}

func TestSelectRoutesBuildsMutuallyExclusiveSelectedConditions(t *testing.T) {
	g := testGraph(&model.Topology{Nodes: []model.Node{{Name: "r1", Kind: "frr", ASN: 65000}}})
	g.rib["r1"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{Prefix: "10.0.0.0/24", Origin: "a", LocalPref: 200, Condition: Var("best")},
			{Prefix: "10.0.0.0/24", Origin: "b", LocalPref: 100, Condition: Var("backup")},
		},
	}

	g.selectRoutes()
	routes := g.rib["r1"]["10.0.0.0/24"]
	best := routes[0].SelectedCond
	fallback := routes[1].SelectedCond
	if !best.Eval(nil) {
		t.Fatalf("best route should be selected when its condition is true")
	}
	if fallback.Eval(nil) {
		t.Fatalf("fallback should not be selected while best route condition is true")
	}
	if !fallback.Eval(map[string]bool{"best": true}) {
		t.Fatalf("fallback should be selected when best condition is false and fallback is true")
	}
	if fallback.Eval(map[string]bool{"best": true, "backup": true}) {
		t.Fatalf("fallback should not be selected when its own condition is false")
	}
}

func TestLookupFIBLongestPrefixAndConditionalFallback(t *testing.T) {
	g := testGraph(&model.Topology{})
	g.fib["r1"] = []FIBEntry{
		{Prefix: testPrefix(t, "10.0.1.0/24"), NextHop: "specific", Condition: Var("specific")},
		{Prefix: testPrefix(t, "10.0.0.0/16"), NextHop: "aggregate", Condition: True()},
	}

	got, ok := g.lookupFIB("r1", "10.0.1.10", nil)
	if !ok || got.NextHop != "specific" {
		t.Fatalf("lookupFIB() = %#v %v, want specific route", got, ok)
	}
	got, ok = g.lookupFIB("r1", "10.0.1.10", map[string]bool{"specific": true})
	if !ok || got.NextHop != "aggregate" {
		t.Fatalf("lookupFIB() = %#v %v, want aggregate fallback", got, ok)
	}
}

func TestPacketReachableDetectsForwardingLoop(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "b", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: []string{"10.0.0.0/24"}},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})
	g.fib["a"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "b", Condition: True()}}
	g.fib["b"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "a", Condition: True()}}

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", nil)
	if ok || reason != "forwarding loop" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want forwarding loop", ok, reason)
	}
}

func TestPacketReachableNextHopLinkDown(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "b", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: []string{"10.0.0.0/24"}},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})
	g.fib["a"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "b", Condition: True()}}

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", map[string]bool{"a-b": true})
	if ok || reason != "next-hop link is down" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want next-hop link is down", ok, reason)
	}
}

func TestPacketReachableNoForwardingRoute(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: []string{"10.0.0.0/24"}},
		},
	})

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", nil)
	if ok || reason != "no forwarding route" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want no forwarding route", ok, reason)
	}
}

func TestRIBAndFIBHelpers(t *testing.T) {
	g := testGraph(&model.Topology{
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", Cost: 3, Subnet: "192.0.2.0/31"},
			{Name: "b-c", A: "b", B: "c", Cost: 5, Subnet: "192.0.2.2/31"},
		},
	})
	r1 := RIBEntry{Prefix: "10.0.0.0/24", Origin: "origin", Nodes: []string{"origin", "a"}, SelectedCond: Var("selected"), Links: []string{"a-b"}}
	duplicate := r1
	distinct := RIBEntry{Prefix: "10.0.0.0/24", Origin: "origin", Nodes: []string{"origin", "b", "a"}, SelectedCond: True(), Links: []string{"b-c", "a-b"}}

	g.addRIB("a", "10.0.0.0/24", r1)
	g.addRIB("a", "10.0.0.0/24", duplicate)
	g.addRIB("a", "10.0.0.0/24", distinct)
	if got := len(g.rib["a"]["10.0.0.0/24"]); got != 2 {
		t.Fatalf("RIB entries = %d, want duplicate skipped and distinct path kept", got)
	}

	g.deriveFIB()
	if len(g.fib["a"]) != 2 {
		t.Fatalf("FIB entries = %d, want 2", len(g.fib["a"]))
	}
	if g.fib["a"][0].Condition.String() != r1.SelectedCond.String() {
		t.Fatalf("FIB condition = %s, want %s", g.fib["a"][0].Condition.String(), r1.SelectedCond.String())
	}

	if _, ok := g.linkBetween("b", "a"); !ok {
		t.Fatalf("linkBetween() should treat links as undirected")
	}
	if got := g.pathCost([]string{"a-b", "b-c"}); got != 8 {
		t.Fatalf("pathCost() = %d, want 8", got)
	}
}

func TestFindBreakingFailuresFindsOneLinkCut(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{{PeerNode: "a", RemoteAS: 65001, Activated: true}}, Prefixes: []string{"10.0.0.0/24"}},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})

	cut, ok := g.FindBreakingFailures("a", PrefixTarget("10.0.0.0/24"), 1)
	if !ok || !reflect.DeepEqual(cut, []string{"a-b"}) {
		t.Fatalf("FindBreakingFailures() = %v %v, want a-b cut", cut, ok)
	}
}

func TestFindBreakingFailuresNoSingleLinkCutInRedundantTopology(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{
				{PeerNode: "b", RemoteAS: 65002, Activated: true},
				{PeerNode: "c", RemoteAS: 65003, Activated: true},
			}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{
				{PeerNode: "a", RemoteAS: 65001, Activated: true},
				{PeerNode: "d", RemoteAS: 65004, Activated: true},
			}},
			{Name: "c", Kind: "frr", ASN: 65003, Neighbors: []model.BGPNeighbor{
				{PeerNode: "a", RemoteAS: 65001, Activated: true},
				{PeerNode: "d", RemoteAS: 65004, Activated: true},
			}},
			{Name: "d", Kind: "frr", ASN: 65004, Neighbors: []model.BGPNeighbor{
				{PeerNode: "b", RemoteAS: 65002, Activated: true},
				{PeerNode: "c", RemoteAS: 65003, Activated: true},
			}, Prefixes: []string{"10.0.0.0/24"}},
		},
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"},
			{Name: "a-c", A: "a", B: "c", Cost: 1, Subnet: "192.0.2.2/31"},
			{Name: "b-d", A: "b", B: "d", Cost: 1, Subnet: "192.0.2.4/31"},
			{Name: "c-d", A: "c", B: "d", Cost: 1, Subnet: "192.0.2.6/31"},
		},
	})

	cut, ok := g.FindBreakingFailures("a", PrefixTarget("10.0.0.0/24"), 1)
	if ok {
		t.Fatalf("FindBreakingFailures() = %v %v, want no single-link cut", cut, ok)
	}
}

func TestConditionHelpers(t *testing.T) {
	if !True().Eval(map[string]bool{"x": true}) {
		t.Fatalf("True() should always evaluate true")
	}
	if False().Eval(nil) {
		t.Fatalf("False() should evaluate false")
	}
	if !Var("x").Eval(nil) || Var("x").Eval(map[string]bool{"x": true}) {
		t.Fatalf("Var() should mean link-up unless failed")
	}
	if !And(True(), Var("x")).Eval(nil) || And(True(), Var("x")).Eval(map[string]bool{"x": true}) {
		t.Fatalf("And() evaluation is wrong")
	}
	if !Or(False(), Var("x")).Eval(nil) || Or(False(), Var("x")).Eval(map[string]bool{"x": true}) {
		t.Fatalf("Or() evaluation is wrong")
	}
	if Not(Var("x")).Eval(nil) || !Not(Var("x")).Eval(map[string]bool{"x": true}) {
		t.Fatalf("Not() evaluation is wrong")
	}

	if _, ok := And(True(), And(Var("a"), Var("b"))).(andCond); !ok {
		t.Fatalf("And() should flatten nested and drop true")
	}
	if got := And(True()).String(); got != "true" {
		t.Fatalf("And(True()).String() = %q, want true", got)
	}
	if _, ok := Or(Or(Var("a"), Var("b")), Var("c")).(orCond); !ok {
		t.Fatalf("Or() should flatten nested or")
	}
	if Or().Eval(nil) {
		t.Fatalf("empty Or() should evaluate false")
	}
}

func TestPrefixesOverlap(t *testing.T) {
	if !prefixesOverlap(testPrefix(t, "10.0.0.0/16"), testPrefix(t, "10.0.1.0/24")) {
		t.Fatalf("expected overlapping prefixes")
	}
	if !prefixesOverlap(testPrefix(t, "10.0.1.0/24"), testPrefix(t, "10.0.0.0/16")) {
		t.Fatalf("expected overlapping prefixes regardless of argument order")
	}
	if prefixesOverlap(testPrefix(t, "10.0.0.0/24"), testPrefix(t, "10.0.1.0/24")) {
		t.Fatalf("expected non-overlapping prefixes")
	}
}
