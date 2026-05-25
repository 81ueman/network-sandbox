package sim

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
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
	g := &Graph{
		topo:        topo,
		adj:         map[string][]edge{},
		rib:         map[string]map[string][]RIBEntry{},
		fib:         map[string][]FIBEntry{},
		linksByName: map[string]model.Link{},
	}
	for _, link := range topo.Links {
		g.linksByName[link.Name] = link
	}
	return g
}

func TestFailureSetAndContext(t *testing.T) {
	failures := FailureSetFromMap(map[string]bool{
		"raw-link":      true,
		"link:prefixed": true,
		"node:a":        true,
		"ignored":       false,
	})
	if !failures.Links["raw-link"] || !failures.Links["prefixed"] || !failures.Nodes["a"] {
		t.Fatalf("FailureSetFromMap() = %#v", failures)
	}
	if failures.Links["ignored"] {
		t.Fatalf("false raw entries should be ignored")
	}

	ctx := FailureContext{
		Failures: failures,
		LinksByName: map[string]model.Link{
			"a-b":        {Name: "a-b", A: "a", B: "b"},
			"b-c":        {Name: "b-c", A: "b", B: "c"},
			"prefixed":   {Name: "prefixed", A: "x", B: "y"},
			"raw-link":   {Name: "raw-link", A: "x", B: "z"},
			"unaffected": {Name: "unaffected", A: "b", B: "c"},
		},
	}
	if !ctx.NodeFailed("a") || ctx.NodeFailed("b") {
		t.Fatalf("NodeFailed returned unexpected values")
	}
	for _, link := range []string{"raw-link", "prefixed", "a-b"} {
		if !ctx.LinkFailed(link) {
			t.Fatalf("LinkFailed(%q) = false, want true", link)
		}
	}
	if ctx.LinkFailed("unaffected") || ctx.LinkFailed("missing") {
		t.Fatalf("LinkFailed returned true for unaffected or missing link")
	}
}

func TestFailureSetFromElements(t *testing.T) {
	failures := FailureSetFromElements([]solver.FailureElement{
		{Kind: solver.FailureLink, Name: "a-b"},
		{Kind: solver.FailureNode, Name: "b"},
	})
	if !failures.Links["a-b"] || !failures.Nodes["b"] {
		t.Fatalf("FailureSetFromElements() = %#v", failures)
	}
}

func TestTypedConditionEvaluation(t *testing.T) {
	ctx := FailureContext{
		Failures: NodeFailures("a"),
		LinksByName: map[string]model.Link{
			"a-b": {Name: "a-b", A: "a", B: "b"},
			"b-c": {Name: "b-c", A: "b", B: "c"},
		},
	}
	if LinkVar("a-b").Eval(ctx) {
		t.Fatalf("LinkVar should be false when endpoint node is failed")
	}
	if !LinkVar("b-c").Eval(ctx) {
		t.Fatalf("LinkVar should be true when link and endpoints are up")
	}
	if NodeVar("a").Eval(ctx) || !NodeVar("b").Eval(ctx) {
		t.Fatalf("NodeVar returned unexpected values")
	}
	if Var("a-b").Eval(ctx) {
		t.Fatalf("Var should remain a backward-compatible link condition")
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
				Prefix:       model.MustPrefix("10.0.0.0/24"),
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
				Prefix:    model.MustPrefix("10.0.0.0/24"),
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
	if child.Condition.Eval(FailureContext{Failures: LinkFailures("best")}) {
		t.Fatalf("child condition should depend on parent selected condition: %s", child.Condition.String())
	}
	if child.Condition.Eval(FailureContext{Failures: LinkFailures("mid-down")}) {
		t.Fatalf("child condition should depend on child base condition: %s", child.Condition.String())
	}
	if !child.Condition.Eval(FailureContext{}) {
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
				Prefix:       model.MustPrefix("10.0.0.0/24"),
				Origin:       "best",
				From:         "best",
				Nodes:        []string{"best", "mid"},
				Condition:    bestCond,
				SelectedCond: bestCond,
			},
			{
				Prefix:       model.MustPrefix("10.0.0.0/24"),
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
				Prefix:    model.MustPrefix("10.0.0.0/24"),
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
	if child.Condition.Eval(FailureContext{}) {
		t.Fatalf("backup child route should not be advertised while higher-priority parent is selected: %s", child.Condition.String())
	}
	if !child.Condition.Eval(FailureContext{Failures: LinkFailures("best-link")}) {
		t.Fatalf("backup child route should be advertised when best parent is unavailable: %s", child.Condition.String())
	}
}

func TestAdvertisementConditionsFixedPointPropagatesMultipleHops(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "origin", Kind: "frr", ASN: 65001},
			{Name: "mid1", Kind: "frr", ASN: 65002},
			{Name: "mid2", Kind: "frr", ASN: 65003},
			{Name: "down", Kind: "frr", ASN: 65004},
		},
	})
	g.rib["origin"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "origin", Nodes: []string{"origin"}, LocalPref: 200, Condition: True(), SelectedCond: True()},
		},
	}
	g.rib["mid1"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "origin", From: "origin", Nodes: []string{"origin", "mid1"}, LocalPref: 200, Condition: Var("origin-mid1")},
		},
	}
	g.rib["mid2"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "origin", From: "mid1", Nodes: []string{"origin", "mid1", "mid2"}, BaseCond: Var("mid1-mid2"), Condition: Var("mid1-mid2")},
		},
	}
	g.rib["down"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "origin", From: "mid2", Nodes: []string{"origin", "mid1", "mid2", "down"}, BaseCond: Var("mid2-down"), Condition: Var("mid2-down")},
		},
	}

	g.selectRoutes()
	for i := 0; i < 8; i++ {
		if !g.applyAdvertisementConditions() {
			break
		}
		g.selectRoutes()
	}

	child := g.rib["down"]["10.0.0.0/24"][0]
	if !child.Condition.Eval(FailureContext{}) {
		t.Fatalf("downstream condition should be true with all parent conditions true: %s", child.Condition.String())
	}
	for _, failed := range []string{"origin-mid1", "mid1-mid2", "mid2-down"} {
		if child.Condition.Eval(FailureContext{Failures: LinkFailures(failed)}) {
			t.Fatalf("downstream condition should depend on %s: %s", failed, child.Condition.String())
		}
	}
}

func TestConvergeAdvertisementConditionsHandlesDeepRouteChain(t *testing.T) {
	const depth = 12
	topo := &model.Topology{}
	for i := 0; i < depth; i++ {
		topo.Nodes = append(topo.Nodes, model.Node{Name: string(rune('a' + i)), Kind: "frr", ASN: uint32(65000 + i)})
	}
	g := testGraph(topo)
	prefix := "10.0.0.0/24"
	g.rib["a"] = map[string][]RIBEntry{
		prefix: {
			{Prefix: model.MustPrefix(prefix), Origin: "a", Nodes: []string{"a"}, LocalPref: 200, Condition: True(), SelectedCond: True()},
		},
	}
	nodes := []string{"a"}
	for i := 1; i < depth; i++ {
		node := string(rune('a' + i))
		parent := string(rune('a' + i - 1))
		nodes = append(nodes, node)
		linkCond := Var(parent + "-" + node)
		g.rib[node] = map[string][]RIBEntry{
			prefix: {
				{
					Prefix:    model.MustPrefix(prefix),
					Origin:    "a",
					From:      parent,
					Nodes:     append([]string(nil), nodes...),
					BaseCond:  linkCond,
					Condition: linkCond,
				},
			},
		}
	}

	g.selectRoutes()
	g.convergeAdvertisementConditions()

	deepest := g.rib[string(rune('a'+depth-1))][prefix][0]
	if !deepest.Condition.Eval(FailureContext{}) {
		t.Fatalf("deep chain condition should converge true with no failures: %s", deepest.Condition.String())
	}
	for _, failed := range []string{"a-b", "f-g", "k-l"} {
		if deepest.Condition.Eval(FailureContext{Failures: LinkFailures(failed)}) {
			t.Fatalf("deep chain condition should include %s: %s", failed, deepest.Condition.String())
		}
	}
	if got := g.maxRouteDepth(); got != depth {
		t.Fatalf("maxRouteDepth() = %d, want %d", got, depth)
	}
}

func TestParentRouteFindsPreviousHopRoute(t *testing.T) {
	g := testGraph(&model.Topology{})
	parent := RIBEntry{
		Prefix: model.MustPrefix("10.0.0.0/24"),
		Origin: "origin",
		From:   "origin",
		Nodes:  []string{"origin", "mid"},
	}
	g.rib["mid"] = map[string][]RIBEntry{"10.0.0.0/24": {parent}}
	child := RIBEntry{
		Prefix: model.MustPrefix("10.0.0.0/24"),
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
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "a", LocalPref: 200, Condition: Var("best")},
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "b", LocalPref: 100, Condition: Var("backup")},
		},
	}

	g.selectRoutes()
	routes := g.rib["r1"]["10.0.0.0/24"]
	best := routes[0].SelectedCond
	fallback := routes[1].SelectedCond
	if !best.Eval(FailureContext{}) {
		t.Fatalf("best route should be selected when its condition is true")
	}
	if fallback.Eval(FailureContext{}) {
		t.Fatalf("fallback should not be selected while best route condition is true")
	}
	if !fallback.Eval(FailureContext{Failures: LinkFailures("best")}) {
		t.Fatalf("fallback should be selected when best condition is false and fallback is true")
	}
	if fallback.Eval(FailureContext{Failures: LinkFailures("best", "backup")}) {
		t.Fatalf("fallback should not be selected when its own condition is false")
	}
}

func TestSelectRoutesMarksEquivalentFRRRoutesSelected(t *testing.T) {
	g := testGraph(&model.Topology{Nodes: []model.Node{{Name: "r1", Kind: "frr", ASN: 65000}}})
	g.rib["r1"] = map[string][]RIBEntry{
		"10.0.0.0/24": {
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "a", LocalPref: 100, ASPath: []uint32{65100}, Condition: Var("path-a")},
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "b", LocalPref: 100, ASPath: []uint32{65200}, Condition: Var("path-b")},
			{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "c", LocalPref: 100, ASPath: []uint32{65300, 65400}, Condition: Var("backup")},
		},
	}

	g.selectRoutes()
	routes := g.rib["r1"]["10.0.0.0/24"]
	if !routes[0].SelectedCond.Eval(FailureContext{}) || !routes[1].SelectedCond.Eval(FailureContext{}) {
		t.Fatalf("equivalent routes should both be selected: %#v", routes)
	}
	if routes[2].SelectedCond.Eval(FailureContext{}) {
		t.Fatalf("non-equivalent backup should not be selected while equivalent best routes are available")
	}
	if !routes[2].SelectedCond.Eval(FailureContext{Failures: LinkFailures("path-a", "path-b")}) {
		t.Fatalf("backup should be selected when all better equivalent paths are unavailable")
	}
}

func TestImportRouteMapSetsLocalPrefInRIB(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "SET-LP"
	topo.Nodes[1].PrefixLists = []model.PrefixList{{Name: "PL", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24"}}}}
	lp := 250
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "SET-LP", Rules: []model.RoutePolicyRule{{Action: "permit", MatchPrefixList: "PL", SetLocalPref: &lp}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].LocalPref != 250 {
		t.Fatalf("rx RIB = %#v, want local-pref 250", routes)
	}
}

func TestRouteMapWithoutMatchMatchesAnyRoute(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "SET-LP"
	lp := 250
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "SET-LP", Rules: []model.RoutePolicyRule{{Action: "permit", SetLocalPref: &lp}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].LocalPref != 250 {
		t.Fatalf("rx RIB = %#v, want match-any local-pref 250", routes)
	}
}

func TestExportRouteMapSetsMEDInRIB(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[0].Neighbors[0].ExportPolicy = "SET-MED"
	topo.Nodes[0].PrefixLists = []model.PrefixList{{Name: "PL", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24"}}}}
	med := 77
	topo.Nodes[0].RoutePolicies = []model.RoutePolicy{{Name: "SET-MED", Rules: []model.RoutePolicyRule{{Action: "permit", MatchPrefixList: "PL", SetMED: &med}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].MED != 77 {
		t.Fatalf("rx RIB = %#v, want MED 77", routes)
	}
}

func TestRouteMapCommunitySetAndMatch(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[0].Neighbors[0].ExportPolicy = "TAG"
	topo.Nodes[0].RoutePolicies = []model.RoutePolicy{{Name: "TAG", Rules: []model.RoutePolicyRule{{Action: "permit", SetCommunities: []string{"65001:100"}, SetCommunityAdditive: true}}}}
	topo.Nodes[1].Neighbors[0].ImportPolicy = "MATCH-COMM"
	topo.Nodes[1].CommunityLists = []model.CommunityList{{Name: "BJ", Rules: []model.StringListRule{{Action: "permit", Pattern: "65001:100"}}}}
	lp := 275
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "MATCH-COMM", Rules: []model.RoutePolicyRule{{Action: "permit", MatchCommunityList: "BJ", SetLocalPref: &lp}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].LocalPref != 275 || !reflect.DeepEqual(routes[0].Communities, []string{"65001:100"}) {
		t.Fatalf("rx RIB = %#v, want community-driven local-pref 275", routes)
	}
}

func TestRouteMapASPathMatchAndPrepend(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[0].Neighbors[0].ExportPolicy = "PREPEND"
	topo.Nodes[0].RoutePolicies = []model.RoutePolicy{{Name: "PREPEND", Rules: []model.RoutePolicyRule{{Action: "permit", SetASPathPrepend: []uint32{65001, 65001}}}}}
	topo.Nodes[1].Neighbors[0].ImportPolicy = "MATCH-AS"
	topo.Nodes[1].ASPathLists = []model.ASPathList{{Name: "FROM-ORIGIN", Rules: []model.StringListRule{{Action: "permit", Pattern: "^65001 65001 65001$"}}}}
	lp := 280
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "MATCH-AS", Rules: []model.RoutePolicyRule{{Action: "permit", MatchASPathList: "FROM-ORIGIN", SetLocalPref: &lp}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].LocalPref != 280 || !reflect.DeepEqual(routes[0].ASPath, []uint32{65001, 65001, 65001}) {
		t.Fatalf("rx RIB = %#v, want prepended AS path and local-pref 280", routes)
	}
}

func TestRouteMapNextHopPrefixListMatch(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "MATCH-NH"
	topo.Nodes[1].PrefixLists = []model.PrefixList{{Name: "NH", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "192.0.2.0/31", Le: 32}}}}
	med := 44
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "MATCH-NH", Rules: []model.RoutePolicyRule{{Action: "permit", MatchNextHopPrefixList: "NH", SetMED: &med}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].MED != 44 {
		t.Fatalf("rx RIB = %#v, want next-hop matched MED 44", routes)
	}
}

func TestRouteMapDeltasAndOriginCode(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "DELTA"
	lpDelta := 25
	medDelta := 12
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "DELTA", Rules: []model.RoutePolicyRule{{Action: "permit", SetLocalPrefDelta: &lpDelta, SetMEDDelta: &medDelta, SetOriginCode: "incomplete"}}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].LocalPref != 125 || routes[0].MED != 12 || routes[0].OriginCode != "incomplete" {
		t.Fatalf("rx RIB = %#v, want local-pref 125 MED 12 origin incomplete", routes)
	}
}

func TestImportRouteMapDenySuppressesRoute(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "DENY"
	topo.Nodes[1].PrefixLists = []model.PrefixList{{Name: "PL", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24"}}}}
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "DENY", Rules: []model.RoutePolicyRule{{Action: "deny", MatchPrefixList: "PL"}}}}

	g := NewGraph(topo)
	if routes := g.RIB("rx", "10.0.0.0/24"); len(routes) != 0 {
		t.Fatalf("rx RIB = %#v, want denied route suppressed", routes)
	}
}

func TestExportRouteMapDenySuppressesAdvertisement(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[0].Neighbors[0].ExportPolicy = "DENY"
	topo.Nodes[0].PrefixLists = []model.PrefixList{{Name: "PL", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24"}}}}
	topo.Nodes[0].RoutePolicies = []model.RoutePolicy{{Name: "DENY", Rules: []model.RoutePolicyRule{{Action: "deny", MatchPrefixList: "PL"}}}}

	g := NewGraph(topo)
	if routes := g.RIB("rx", "10.0.0.0/24"); len(routes) != 0 {
		t.Fatalf("rx RIB = %#v, want export-denied route suppressed", routes)
	}
}

func TestRouteMapImplicitDenySuppressesRoute(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "SET-LP"
	topo.Nodes[1].PrefixLists = []model.PrefixList{{Name: "OTHER", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.1.0/24"}}}}
	lp := 250
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "SET-LP", Rules: []model.RoutePolicyRule{{Action: "permit", MatchPrefixList: "OTHER", SetLocalPref: &lp}}}}

	g := NewGraph(topo)
	if routes := g.RIB("rx", "10.0.0.0/24"); len(routes) != 0 {
		t.Fatalf("rx RIB = %#v, want implicit-denied route suppressed", routes)
	}
}

func TestRouteMapFallThroughPermitPassesUnchanged(t *testing.T) {
	topo := routePolicyTestTopology()
	topo.Nodes[1].Neighbors[0].ImportPolicy = "RM"
	topo.Nodes[1].PrefixLists = []model.PrefixList{{Name: "SOME-PREFIX", Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.1.0/24"}}}}
	lp := 200
	topo.Nodes[1].RoutePolicies = []model.RoutePolicy{{Name: "RM", Rules: []model.RoutePolicyRule{
		{Seq: 10, Action: "permit", MatchPrefixList: "SOME-PREFIX", SetLocalPref: &lp},
		{Seq: 20, Action: "permit"},
	}}}

	g := NewGraph(topo)
	routes := g.RIB("rx", "10.0.0.0/24")
	if len(routes) != 1 || routes[0].LocalPref != 100 {
		t.Fatalf("rx RIB = %#v, want fall-through permit unchanged local-pref 100", routes)
	}
}

func TestPrefixListPermitsEvaluatesOrderedRules(t *testing.T) {
	node := model.Node{PrefixLists: []model.PrefixList{{Name: "PL", Rules: []model.PrefixListRule{
		{Seq: 10, Action: "deny", Prefix: "10.0.0.0/8"},
		{Seq: 20, Action: "permit", Prefix: "10.0.0.0/8"},
		{Seq: 30, Action: "permit", Prefix: "10.1.0.0/16"},
		{Seq: 40, Action: "permit", Prefix: "10.2.0.0/16", Ge: 24, Le: 28},
	}}}}
	if prefixListPermits(node, "PL", "10.0.0.0/8") {
		t.Fatalf("deny rule before permit should deny exact 10.0.0.0/8")
	}
	if !prefixListPermits(node, "PL", "10.1.0.0/16") {
		t.Fatalf("permit exact prefix should allow route")
	}
	if prefixListPermits(node, "PL", "10.2.0.0/16") {
		t.Fatalf("no matching prefix-list rule should deny route")
	}
	if !prefixListPermits(node, "PL", "10.2.1.0/24") {
		t.Fatalf("ge/le prefix-list rule should allow /24")
	}
	if prefixListPermits(node, "PL", "10.2.1.0/29") {
		t.Fatalf("ge/le prefix-list rule should deny longer than le")
	}
}

func TestPrefixListPermitsUsesRulePredicate(t *testing.T) {
	node := model.Node{PrefixLists: []model.PrefixList{{Name: "PL", Rules: []model.PrefixListRule{
		{Seq: 10, Action: "permit", Match: model.PrefixRangeSet{Base: model.MustPrefix("10.0.0.0/8"), MinLen: 16, MaxLen: 24}},
	}}}}
	if !prefixListPermits(node, "PL", "10.1.0.0/16") {
		t.Fatalf("predicate prefix-list rule should allow matching prefix")
	}
	if prefixListPermits(node, "PL", "10.1.2.128/25") {
		t.Fatalf("predicate prefix-list rule should deny prefixes outside bounds")
	}
}

func routePolicyTestTopology() *model.Topology {
	return &model.Topology{
		Nodes: []model.Node{
			{
				Name:     "origin",
				Kind:     "frr",
				ASN:      65001,
				Prefixes: model.MustPrefixes("10.0.0.0/24"),
				Neighbors: []model.BGPNeighbor{{
					PeerNode:  "rx",
					RemoteAS:  65002,
					Activated: true,
				}},
			},
			{
				Name: "rx",
				Kind: "frr",
				ASN:  65002,
				Neighbors: []model.BGPNeighbor{{
					PeerNode:  "origin",
					RemoteAS:  65001,
					Activated: true,
				}},
			},
		},
		Links: []model.Link{{Name: "origin-rx", A: "origin", B: "rx", Cost: 1, Subnet: "192.0.2.0/31"}},
	}
}

func TestLookupFIBLongestPrefixAndConditionalFallback(t *testing.T) {
	g := testGraph(&model.Topology{})
	g.fib["r1"] = []FIBEntry{
		{Prefix: testPrefix(t, "10.0.1.0/24"), NextHop: "specific", Condition: Var("specific")},
		{Prefix: testPrefix(t, "10.0.0.0/16"), NextHop: "aggregate", Condition: True()},
	}

	got, ok := g.lookupFIB("r1", "10.0.1.10", g.FailureContext(NoFailures()))
	if !ok || got.NextHop != "specific" {
		t.Fatalf("lookupFIB() = %#v %v, want specific route", got, ok)
	}
	got, ok = g.lookupFIB("r1", "10.0.1.10", g.FailureContext(LinkFailures("specific")))
	if !ok || got.NextHop != "aggregate" {
		t.Fatalf("lookupFIB() = %#v %v, want aggregate fallback", got, ok)
	}
}

func TestRouteConditionsIncludeNodeLiveness(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{
				{PeerNode: "a", RemoteAS: 65001, Activated: true},
				{PeerNode: "c", RemoteAS: 65003, Activated: true},
			}},
			{Name: "c", Kind: "frr", ASN: 65003, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}, Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"},
			{Name: "b-c", A: "b", B: "c", Cost: 1, Subnet: "192.0.2.2/31"},
		},
	})

	origin := g.RIB("c", "10.0.0.0/24")[0]
	if !origin.Condition.Eval(g.FailureContext(NoFailures())) {
		t.Fatalf("origin route should be valid without failures")
	}
	if origin.Condition.Eval(g.FailureContext(NodeFailures("c"))) {
		t.Fatalf("origin route should be invalid when origin node fails: %s", origin.Condition.String())
	}
	if _, ok := g.RouteReachable("a", "10.0.0.0/24", NodeFailures("b")); ok {
		t.Fatalf("route should be unreachable when intermediate node fails")
	}
	if _, ok := g.RouteReachable("a", "10.0.0.0/24", NodeFailures("a")); ok {
		t.Fatalf("route should be unreachable when source node fails")
	}
}

func TestPacketReachableDetectsForwardingLoop(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "b", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})
	g.fib["a"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "b", Condition: True()}}
	g.fib["b"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "a", Condition: True()}}

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", NoFailures())
	if ok || reason != "forwarding loop" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want forwarding loop", ok, reason)
	}
}

func TestPacketReachableNodeFailures(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "b", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"},
			{Name: "b-dst", A: "b", B: "dst", Cost: 1, Subnet: "192.0.2.2/31"},
		},
	})
	g.fib["a"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "b", Condition: True()}}
	g.fib["b"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "dst", Condition: True()}}

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", NodeFailures("a"))
	if ok || reason != "source node is down" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want source node is down", ok, reason)
	}
	_, ok, reason = g.PacketReachable("a", "10.0.0.10", "icmp", NodeFailures("dst"))
	if ok || reason != "destination node is down" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want destination node is down", ok, reason)
	}
	_, ok, reason = g.PacketReachable("a", "10.0.0.10", "icmp", NodeFailures("b"))
	if ok || reason != "next-hop node is down" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want next-hop node is down", ok, reason)
	}
	if !g.FailureContext(NodeFailures("b")).LinkFailed("a-b") {
		t.Fatalf("node failure should make incident next-hop link failed")
	}
}

func TestPacketReachableNextHopLinkDown(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "b", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})
	g.fib["a"] = []FIBEntry{{Prefix: testPrefix(t, "10.0.0.0/24"), NextHop: "b", Condition: True()}}

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", LinkFailures("a-b"))
	if ok || reason != "next-hop link is down" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want next-hop link is down", ok, reason)
	}
}

func TestPacketReachableNoForwardingRoute(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr"},
			{Name: "dst", Kind: "frr", Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
	})

	_, ok, reason := g.PacketReachable("a", "10.0.0.10", "icmp", NoFailures())
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
	r1 := RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "origin", Nodes: []string{"origin", "a"}, SelectedCond: Var("selected"), Links: []string{"a-b"}}
	duplicate := r1
	distinct := RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), Origin: "origin", Nodes: []string{"origin", "b", "a"}, SelectedCond: True(), Links: []string{"b-c", "a-b"}}

	g.addRIB("a", model.MustPrefix("10.0.0.0/24"), r1)
	g.addRIB("a", model.MustPrefix("10.0.0.0/24"), duplicate)
	g.addRIB("a", model.MustPrefix("10.0.0.0/24"), distinct)
	if got := len(g.rib["a"]["10.0.0.0/24"]); got != 2 {
		t.Fatalf("RIB entries = %d, want duplicate skipped and distinct path kept", got)
	}

	g.deriveFIB()
	if len(g.fib["a"]) != 2 {
		t.Fatalf("FIB entries = %d, want 2", len(g.fib["a"]))
	}
	found := false
	for _, entry := range g.fib["a"] {
		if entry.Condition.String() == r1.SelectedCond.String() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("FIB did not preserve selected condition %s", r1.SelectedCond.String())
	}

	if _, ok := g.linkBetween("b", "a"); !ok {
		t.Fatalf("linkBetween() should treat links as undirected")
	}
	if got := g.pathCost([]string{"a-b", "b-c"}); got != 8 {
		t.Fatalf("pathCost() = %d, want 8", got)
	}
}

func TestFailureEligibleLinksExcludesCustomerLinks(t *testing.T) {
	links := []model.Link{
		{Name: "core-a-b", A: "a", B: "b"},
		{Name: "cust-a", A: "a", B: "cust-a"},
		{Name: "edge-b-c", A: "b", B: "c"},
	}

	got := failureEligibleLinks(links)

	var names []string
	for _, link := range got {
		names = append(names, link.Name)
	}

	want := []string{"core-a-b", "edge-b-c"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("failureEligibleLinks() = %v, want %v", names, want)
	}
}

func TestFailureEligibleNodesExcludesCustomerNodes(t *testing.T) {
	nodes := []model.Node{
		{Name: "core-a"},
		{Name: "cust-a"},
		{Name: "edge-b"},
	}

	got := failureEligibleNodes(nodes)

	var names []string
	for _, node := range got {
		names = append(names, node.Name)
	}

	want := []string{"core-a", "edge-b"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("failureEligibleNodes() = %v, want %v", names, want)
	}
}

func TestFindBreakingFailuresFindsOneLinkCut(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{{PeerNode: "a", RemoteAS: 65001, Activated: true}}, Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})

	cut, ok := g.FindBreakingFailures("a", PrefixTarget("10.0.0.0/24"), 1)
	if !ok || !reflect.DeepEqual(cut, []string{"a-b"}) {
		t.Fatalf("FindBreakingFailures() = %v %v, want a-b cut", cut, ok)
	}
}

func TestFindBreakingFailuresWithOptionsFindsOneNodeCut(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "cust-a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{
				{PeerNode: "cust-a", RemoteAS: 65001, Activated: true},
				{PeerNode: "cust-dst", RemoteAS: 65003, Activated: true},
			}},
			{Name: "cust-dst", Kind: "frr", ASN: 65003, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}, Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{
			{Name: "cust-a-b", A: "cust-a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"},
			{Name: "b-cust-dst", A: "b", B: "cust-dst", Cost: 1, Subnet: "192.0.2.2/31"},
		},
	})

	cut, ok := g.FindBreakingFailuresWithOptions("cust-a", PrefixTarget("10.0.0.0/24"), FailureSearchOptions{
		IncludeNodes: true,
		MaxFailures:  1,
	})
	if !ok || len(cut) != 1 || cut[0] != (solver.FailureElement{Kind: solver.FailureNode, Name: "b"}) {
		t.Fatalf("FindBreakingFailuresWithOptions() = %v %v, want node:b", cut, ok)
	}
	if _, reachable := g.RouteReachable("cust-a", "10.0.0.0/24", FailureSetFromElements(cut)); reachable {
		t.Fatalf("returned node failure should make target unreachable")
	}
	if len(cut) != 1 {
		t.Fatalf("node failure should count as one selected failure, got %d", len(cut))
	}
}

func TestFindBreakingFailuresWithOptionsRejectsInvalidOptions(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{{PeerNode: "a", RemoteAS: 65001, Activated: true}}, Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"}},
	})

	if cut, ok := g.FindBreakingFailuresWithOptions("a", PrefixTarget("10.0.0.0/24"), FailureSearchOptions{MaxFailures: 1}); ok || cut != nil {
		t.Fatalf("empty search options = %v %v, want nil false", cut, ok)
	}
	if cut, ok := g.FindBreakingFailuresWithOptions("a", PrefixTarget("10.0.0.0/24"), FailureSearchOptions{
		IncludeLinks: true,
		MaxFailures:  -1,
	}); ok || cut != nil {
		t.Fatalf("negative MaxFailures = %v %v, want nil false", cut, ok)
	}
}

func TestFailureSearchElementsRespectsOptionsAndEligibility(t *testing.T) {
	g := testGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a"},
			{Name: "cust-a"},
			{Name: "b"},
		},
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b"},
			{Name: "cust-a-b", A: "cust-a", B: "b"},
		},
	})

	assertKinds := func(name string, opts FailureSearchOptions, want []solver.FailureElement) {
		t.Helper()
		if got := g.failureSearchElements(opts); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s elements = %#v, want %#v", name, got, want)
		}
	}

	assertKinds("link-only", FailureSearchOptions{IncludeLinks: true}, []solver.FailureElement{
		{Kind: solver.FailureLink, Name: "a-b"},
	})
	assertKinds("node-only", FailureSearchOptions{IncludeNodes: true}, []solver.FailureElement{
		{Kind: solver.FailureNode, Name: "a"},
		{Kind: solver.FailureNode, Name: "b"},
	})
	assertKinds("mixed", FailureSearchOptions{IncludeLinks: true, IncludeNodes: true}, []solver.FailureElement{
		{Kind: solver.FailureLink, Name: "a-b"},
		{Kind: solver.FailureNode, Name: "a"},
		{Kind: solver.FailureNode, Name: "b"},
	})
}

func TestFindBreakingFailuresWithOptionsMixedElements(t *testing.T) {
	g := NewGraph(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: "frr", ASN: 65001, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}},
			{Name: "b", Kind: "frr", ASN: 65002, Neighbors: []model.BGPNeighbor{
				{PeerNode: "a", RemoteAS: 65001, Activated: true},
				{PeerNode: "d", RemoteAS: 65003, Activated: true},
			}},
			{Name: "d", Kind: "frr", ASN: 65003, Neighbors: []model.BGPNeighbor{{PeerNode: "b", RemoteAS: 65002, Activated: true}}, Prefixes: model.MustPrefixes("10.0.0.0/24")},
		},
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", Cost: 1, Subnet: "192.0.2.0/31"},
			{Name: "b-d", A: "b", B: "d", Cost: 1, Subnet: "192.0.2.2/31"},
		},
	})

	elements := g.failureSearchElements(FailureSearchOptions{IncludeLinks: true, IncludeNodes: true})
	var hasLink, hasNode bool
	for _, element := range elements {
		hasLink = hasLink || element.Kind == solver.FailureLink
		hasNode = hasNode || element.Kind == solver.FailureNode
	}
	if !hasLink || !hasNode {
		t.Fatalf("mixed elements = %#v, want both link and node candidates", elements)
	}

	cut, ok := g.FindBreakingFailuresWithOptions("a", PrefixTarget("10.0.0.0/24"), FailureSearchOptions{
		IncludeLinks: true,
		IncludeNodes: true,
		MaxFailures:  1,
	})
	if !ok || len(cut) != 1 {
		t.Fatalf("FindBreakingFailuresWithOptions() = %v %v, want one mixed candidate", cut, ok)
	}
	if _, reachable := g.RouteReachable("a", "10.0.0.0/24", FailureSetFromElements(cut)); reachable {
		t.Fatalf("returned failure should make target unreachable: %v", cut)
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
			}, Prefixes: model.MustPrefixes("10.0.0.0/24")},
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
	if !True().Eval(FailureContext{Failures: LinkFailures("x")}) {
		t.Fatalf("True() should always evaluate true")
	}
	if False().Eval(FailureContext{}) {
		t.Fatalf("False() should evaluate false")
	}
	if !Var("x").Eval(FailureContext{}) || Var("x").Eval(FailureContext{Failures: LinkFailures("x")}) {
		t.Fatalf("Var() should mean link-up unless failed")
	}
	if !And(True(), Var("x")).Eval(FailureContext{}) || And(True(), Var("x")).Eval(FailureContext{Failures: LinkFailures("x")}) {
		t.Fatalf("And() evaluation is wrong")
	}
	if !Or(False(), Var("x")).Eval(FailureContext{}) || Or(False(), Var("x")).Eval(FailureContext{Failures: LinkFailures("x")}) {
		t.Fatalf("Or() evaluation is wrong")
	}
	if Not(Var("x")).Eval(FailureContext{}) || !Not(Var("x")).Eval(FailureContext{Failures: LinkFailures("x")}) {
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
	if Or().Eval(FailureContext{}) {
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
