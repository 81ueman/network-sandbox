package dataplane

import (
	"strings"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestSymbolicUnreachableReasonsUseSelectedCandidateCondition(t *testing.T) {
	engine := samePrefixCandidatesEngine()
	result := engine.SymbolicPacketReachability("src", "10.0.0.10", "icmp")

	primaryLinkReason := findReason(t, result.UnreachableReasons, UnreachableLinkFailed, "src", "src-primary", "next-hop link is down")
	if !primaryLinkReason.Cond.Eval(engine.FailureContext(failure.Links("src-primary"))) {
		t.Fatalf("primary link failure reason should be true when primary candidate is selected and its link fails: %s", primaryLinkReason.Cond)
	}
	if primaryLinkReason.Cond.Eval(engine.FailureContext(failure.Links("prefer-primary", "src-primary"))) {
		t.Fatalf("primary link failure reason should be false when primary candidate is not selected: %s", primaryLinkReason.Cond)
	}
	if got := primaryLinkReason.Cond.String(); !strings.Contains(got, "prefer-primary") || !strings.Contains(got, "node:primary") || !strings.Contains(got, "link:src-primary") {
		t.Fatalf("primary link failure reason condition should include selected candidate and expanded link-up terms: %s", got)
	}

	primaryNodeReason := findReason(t, result.UnreachableReasons, UnreachableNodeFailed, "primary", "", "next-hop node is down")
	if !primaryNodeReason.Cond.Eval(engine.FailureContext(failure.Nodes("primary"))) {
		t.Fatalf("primary node failure reason should be true when primary candidate is selected and primary is down: %s", primaryNodeReason.Cond)
	}
	if primaryNodeReason.Cond.Eval(engine.FailureContext(failure.NewSet([]model.LinkID{"prefer-primary"}, []model.NodeID{"primary"}))) {
		t.Fatalf("primary node failure reason should be false when primary candidate is not selected: %s", primaryNodeReason.Cond)
	}
}

func TestSymbolicNoRouteReasonRequiresAllCandidatesUnavailable(t *testing.T) {
	engine := redundantPathEngine()
	result := engine.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	reason := findReason(t, result.UnreachableReasons, UnreachableNoRoute, "src", "", "no forwarding route")

	if reason.Cond.Eval(engine.FailureContext(failure.None())) {
		t.Fatalf("no-route reason should be false when a candidate is available: %s", reason.Cond)
	}
	if reason.Cond.Eval(engine.FailureContext(failure.Links("src-primary"))) {
		t.Fatalf("no-route reason should be false while backup candidate is available: %s", reason.Cond)
	}
	if !reason.Cond.Eval(engine.FailureContext(failure.Links("src-primary", "src-backup"))) {
		t.Fatalf("no-route reason should be true when all candidates are unavailable: %s", reason.Cond)
	}
}

func TestSymbolicNoNextHopAndMissingLinkReasonsUseSelectedCandidateCondition(t *testing.T) {
	noNextHopEngine := selectedProblemCandidateEngine("")
	noNextHop := noNextHopEngine.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	noNextHopReason := findReason(t, noNextHop.UnreachableReasons, UnreachableNoNextHop, "src", "", "selected route has no next-hop")
	if !noNextHopReason.Cond.Eval(noNextHopEngine.FailureContext(failure.None())) {
		t.Fatalf("no-next-hop reason should be true when the no-next-hop candidate is selected: %s", noNextHopReason.Cond)
	}
	if noNextHopReason.Cond.Eval(noNextHopEngine.FailureContext(failure.Links("prefer-problem"))) {
		t.Fatalf("no-next-hop reason should be false when the no-next-hop candidate is not selected: %s", noNextHopReason.Cond)
	}

	missingLinkEngine := selectedProblemCandidateEngine("orphan")
	missingLink := missingLinkEngine.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	missingLinkReason := findReason(t, missingLink.UnreachableReasons, UnreachableLinkFailed, "src", "src-orphan", "next-hop link is down")
	if !missingLinkReason.Cond.Eval(missingLinkEngine.FailureContext(failure.None())) {
		t.Fatalf("missing-link reason should be true when the missing-link candidate is selected: %s", missingLinkReason.Cond)
	}
	if missingLinkReason.Cond.Eval(missingLinkEngine.FailureContext(failure.Links("prefer-problem"))) {
		t.Fatalf("missing-link reason should be false when the missing-link candidate is not selected: %s", missingLinkReason.Cond)
	}
}

func TestSymbolicDiscardReasonUsesSelectedCandidateCondition(t *testing.T) {
	engine := selectedDiscardCandidateEngine()
	result := engine.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	reason := findReason(t, result.UnreachableReasons, UnreachableDiscard, "src", "", "discard route selected")
	if !reason.Cond.Eval(engine.FailureContext(failure.None())) {
		t.Fatalf("discard reason should be true when the discard candidate is selected: %s", reason.Cond)
	}
	if reason.Cond.Eval(engine.FailureContext(failure.Links("prefer-discard"))) {
		t.Fatalf("discard reason should be false when the discard candidate is not selected: %s", reason.Cond)
	}
	if noNextHop, ok := firstUnreachableReason(result, UnreachableNoNextHop); ok {
		t.Fatalf("discard route should not be reported as no-next-hop: %#v", noNextHop)
	}
	if noRoute, ok := firstUnreachableReason(result, UnreachableNoRoute); !ok || noRoute.Message != "no forwarding route" {
		t.Fatalf("no-route reason should remain distinct: %#v", result.UnreachableReasons)
	}
}

func TestSymbolicUnreachableReasonMatchesConcretePacketReachableReason(t *testing.T) {
	engine := redundantPathEngine()
	result := engine.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	cases := []failure.Set{
		failure.Links("src-primary", "src-backup"),
		failure.Links("primary-dst", "backup-dst"),
		failure.Nodes("primary", "backup"),
	}

	for _, failures := range cases {
		_, reachable, concreteReason := engine.PacketReachable("src", "10.0.0.10", "icmp", failures)
		if reachable {
			t.Fatalf("test case should be unreachable: failures=%s", formatFailureSet(failures))
		}
		if !hasMatchingTrueReason(engine, result.UnreachableReasons, failures, concreteReason) {
			t.Fatalf("no symbolic reason matched concrete reason %q for failures=%s\nreasons=%s", concreteReason, formatFailureSet(failures), formatUnreachableReasons(result.UnreachableReasons))
		}
	}
}

func selectedDiscardCandidateEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "backup", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-backup", A: "src", B: "backup", Cost: 1},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 1},
		},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), SourceKind: model.RouteSourceBlackhole, Discard: true, Condition: failure.LinkVar("prefer-discard")},
			{Prefix: pfx.NetIP(), NextHop: "backup", Condition: failure.True()},
		},
		"backup": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func selectedProblemCandidateEngine(problemNextHop string) *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	nodes := []model.Node{
		{Name: "src", Kind: model.KindFRR},
		{Name: "backup", Kind: model.KindFRR},
		{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
	}
	if problemNextHop != "" {
		nodes = append(nodes, model.Node{Name: problemNextHop, Kind: model.KindFRR})
	}
	idx := mustTopologyIndex(&model.Topology{
		Nodes: nodes,
		Links: []model.Link{
			{Name: "src-backup", A: "src", B: "backup", Cost: 1},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 1},
		},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: problemNextHop, Condition: failure.LinkVar("prefer-problem")},
			{Prefix: pfx.NetIP(), NextHop: "backup", Condition: failure.True()},
		},
		"backup": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func findReason(t *testing.T, reasons []SymbolicUnreachableReason, kind SymbolicUnreachableReasonKind, node, link, message string) SymbolicUnreachableReason {
	t.Helper()
	for _, reason := range reasons {
		if reason.Kind == kind && reason.Node == node && reason.Link == link && reason.Message == message {
			return reason
		}
	}
	t.Fatalf("reason not found: kind=%s node=%s link=%s message=%q\nreasons=%s", kind, node, link, message, formatUnreachableReasons(reasons))
	return SymbolicUnreachableReason{}
}

func hasMatchingTrueReason(engine *Engine, reasons []SymbolicUnreachableReason, failures failure.Set, message string) bool {
	ctx := engine.FailureContext(failures)
	for _, reason := range reasons {
		if reason.Message == message && reason.Cond.Eval(ctx) {
			return true
		}
	}
	return false
}

func formatUnreachableReasons(reasons []SymbolicUnreachableReason) string {
	var out []string
	for _, reason := range reasons {
		out = append(out, string(reason.Kind)+" node="+reason.Node+" link="+reason.Link+" message="+reason.Message+" cond="+reason.Cond.String())
	}
	return strings.Join(out, "\n")
}
