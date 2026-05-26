package dataplane

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

func AssertSymbolicConcreteParity(t *testing.T, engine *Engine, from, to, protocol string, cases []failure.Set) {
	t.Helper()

	result := engine.SymbolicPacketReachability(from, to, protocol)
	for _, failures := range cases {
		_, concrete, concreteReason := engine.PacketReachable(from, to, protocol, failures)
		symbolic := result.Reachable.Eval(engine.FailureContext(failures))
		if symbolic != concrete {
			t.Fatalf("symbolic/concrete packet reachability mismatch\nfrom=%s to=%s protocol=%s\nfailures=%s\nconcrete=%v reason=%q\nsymbolic=%v\nreachable=%s\nreachable_key=%s\nunreachable=%s\nsymbolic_reason=%q\npaths=%s",
				from, to, protocol,
				formatFailureSet(failures),
				concrete, concreteReason,
				symbolic,
				result.Reachable.String(),
				result.Reachable.Key(),
				result.Unreachable.String(),
				result.Reason,
				formatSymbolicPaths(result.Paths),
			)
		}
		if !concrete && len(result.UnreachableReasons) == 0 {
			t.Fatalf("concrete PacketReachable is false but symbolic result has no unreachable reasons\nfrom=%s to=%s protocol=%s\nfailures=%s\nconcrete_reason=%q",
				from, to, protocol, formatFailureSet(failures), concreteReason)
		}
	}
}

func AssertSymbolicConcreteRouteParity(t *testing.T, engine *Engine, from, prefix string, cases []failure.Set) {
	t.Helper()

	result := engine.SymbolicRouteReachability(from, prefix)
	for _, failures := range cases {
		_, concrete := engine.RouteReachable(from, prefix, failures)
		symbolic := result.Reachable.Eval(engine.FailureContext(failures))
		if symbolic != concrete {
			t.Fatalf("symbolic/concrete route reachability mismatch\nfrom=%s prefix=%s\nfailures=%s\nconcrete=%v\nsymbolic=%v\nreachable=%s\nreachable_key=%s\nunreachable=%s\nsymbolic_reason=%q\npaths=%s",
				from, prefix,
				formatFailureSet(failures),
				concrete,
				symbolic,
				result.Reachable.String(),
				result.Reachable.Key(),
				result.Unreachable.String(),
				result.Reason,
				formatSymbolicRoutePaths(result.Paths),
			)
		}
	}
}

func TestPacketReachabilityParityMatrix(t *testing.T) {
	tests := []struct {
		name     string
		engine   *Engine
		from     string
		to       string
		protocol string
		cases    []failure.Set
	}{
		{
			name:     "single path",
			engine:   singlePathEngine(),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases: []failure.Set{
				failure.None(),
				failure.Links("src-mid"),
				failure.Links("mid-dst"),
				failure.Nodes("src"),
				failure.Nodes("mid"),
				failure.Nodes("dst"),
			},
		},
		{
			name:     "redundant path",
			engine:   redundantPathEngine(),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases: []failure.Set{
				failure.None(),
				failure.Links("src-primary"),
				failure.Links("primary-dst"),
				failure.Links("src-backup"),
				failure.Links("backup-dst"),
				failure.Links("src-primary", "src-backup"),
				failure.Links("primary-dst", "backup-dst"),
				failure.Nodes("primary"),
				failure.Nodes("backup"),
				failure.Nodes("primary", "backup"),
			},
		},
		{
			name:     "longest prefix fallback",
			engine:   longestPrefixFallbackEngine(),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases: []failure.Set{
				failure.None(),
				failure.Links("prefer-specific"),
				failure.Links("src-specific"),
				failure.Links("src-fallback"),
				failure.Links("prefer-specific", "src-fallback"),
			},
		},
		{
			name:     "same prefix multiple FIB candidates",
			engine:   samePrefixCandidatesEngine(),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases: []failure.Set{
				failure.None(),
				failure.Links("prefer-primary"),
				failure.Links("prefer-primary", "src-backup"),
				failure.Nodes("primary"),
				failure.Nodes("backup"),
			},
		},
		{
			name:     "no route",
			engine:   noRouteEngine(),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases:    []failure.Set{failure.None(), failure.Nodes("src"), failure.Nodes("dst")},
		},
		{
			name:     "forwarding loop",
			engine:   forwardingLoopEngine(),
			from:     "a",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases:    []failure.Set{failure.None(), failure.Links("a-b"), failure.Nodes("b")},
		},
		{
			name:     "ingress ACL deny",
			engine:   ingressACLDenyEngine(),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "tcp",
			cases:    []failure.Set{failure.None(), failure.Nodes("mid"), failure.Links("src-mid")},
		},
		{
			name:     "egress ACL deny",
			engine:   egressACLDenyEngine("eth2", "tcp"),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "tcp",
			cases:    []failure.Set{failure.None(), failure.Nodes("mid"), failure.Links("mid-dst")},
		},
		{
			name:     "interface-specific ACL mismatch",
			engine:   egressACLDenyEngine("eth9", "tcp"),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "tcp",
			cases:    []failure.Set{failure.None(), failure.Links("src-mid"), failure.Nodes("dst")},
		},
		{
			name:     "protocol-specific ACL mismatch",
			engine:   egressACLDenyEngine("eth2", "tcp"),
			from:     "src",
			to:       "10.0.0.10",
			protocol: "icmp",
			cases:    []failure.Set{failure.None(), failure.Links("src-mid"), failure.Nodes("dst")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AssertSymbolicConcreteParity(t, tt.engine, tt.from, tt.to, tt.protocol, tt.cases)
		})
	}
}

func TestRouteReachabilityParityMatrix(t *testing.T) {
	engine := routeRedundantPathEngine()
	AssertSymbolicConcreteRouteParity(t, engine, "src", "10.0.0.0/24", []failure.Set{
		failure.None(),
		failure.Links("src-primary"),
		failure.Links("primary-dst"),
		failure.Links("src-backup"),
		failure.Links("backup-dst"),
		failure.Nodes("primary"),
		failure.Nodes("backup"),
		failure.Nodes("primary", "backup"),
		failure.NewSet([]model.LinkID{"src-primary"}, []model.NodeID{"backup"}),
	})
}

func TestPacketReachabilityFailureEnumerationMatchesSymbolicBackend(t *testing.T) {
	engine := redundantPathEngine()
	from, to, protocol := "src", "10.0.0.10", "icmp"
	maxFailures := 2
	elements := []solver.FailureElement{
		{Kind: solver.FailureLink, Name: "src-primary"},
		{Kind: solver.FailureLink, Name: "primary-dst"},
		{Kind: solver.FailureLink, Name: "src-backup"},
		{Kind: solver.FailureLink, Name: "backup-dst"},
		{Kind: solver.FailureNode, Name: "primary"},
		{Kind: solver.FailureNode, Name: "backup"},
	}

	forbidden := concreteBreakingFailureCombos(engine, from, to, protocol, elements, maxFailures)
	enumerated, err := (solver.EnumeratingBackend{}).Solve(solver.FailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Forbidden:   forbidden,
	})
	if err != nil {
		t.Fatalf("enumerated concrete Solve() error = %v", err)
	}
	symbolicResult := engine.SymbolicPacketReachability(from, to, protocol)
	symbolicAns, err := (solver.EnumeratingBackend{}).SolveSymbolic(solver.SymbolicFailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Goal:        failure.BoolExpr(symbolicResult.Unreachable),
	})
	if err != nil {
		t.Fatalf("symbolic SolveSymbolic() error = %v", err)
	}
	assertSolverParityAnswer(t, engine, from, to, protocol, maxFailures, enumerated, symbolicAns)
}

func TestRouteReachabilityFailureEnumerationMatchesSymbolicBackend(t *testing.T) {
	engine := routeRedundantPathEngine()
	from, prefix := "src", "10.0.0.0/24"
	maxFailures := 2
	elements := []solver.FailureElement{
		{Kind: solver.FailureLink, Name: "src-primary"},
		{Kind: solver.FailureLink, Name: "primary-dst"},
		{Kind: solver.FailureLink, Name: "src-backup"},
		{Kind: solver.FailureLink, Name: "backup-dst"},
		{Kind: solver.FailureNode, Name: "primary"},
		{Kind: solver.FailureNode, Name: "backup"},
	}

	forbidden := concreteBreakingRouteFailureCombos(engine, from, prefix, elements, maxFailures)
	enumerated, err := (solver.EnumeratingBackend{}).Solve(solver.FailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Forbidden:   forbidden,
	})
	if err != nil {
		t.Fatalf("enumerated route Solve() error = %v", err)
	}
	symbolicResult := engine.SymbolicRouteReachability(from, prefix)
	symbolicAns, err := (solver.EnumeratingBackend{}).SolveSymbolic(solver.SymbolicFailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Goal:        failure.BoolExpr(symbolicResult.Unreachable),
	})
	if err != nil {
		t.Fatalf("symbolic route SolveSymbolic() error = %v", err)
	}
	assertRouteSolverParityAnswer(t, engine, from, prefix, maxFailures, enumerated, symbolicAns)
}

func concreteBreakingFailureCombos(engine *Engine, from, to, protocol string, elements []solver.FailureElement, maxFailures int) [][]solver.FailureElement {
	var forbidden [][]solver.FailureElement
	for k := 0; k <= maxFailures; k++ {
		failure.FindElementCombo(elements, k, 0, nil, func(combo []solver.FailureElement) bool {
			_, ok, _ := engine.PacketReachable(from, to, protocol, failure.SetFromElements(combo))
			if !ok {
				forbidden = append(forbidden, append([]solver.FailureElement(nil), combo...))
			}
			return false
		})
	}
	return forbidden
}

func concreteBreakingRouteFailureCombos(engine *Engine, from, prefix string, elements []solver.FailureElement, maxFailures int) [][]solver.FailureElement {
	var forbidden [][]solver.FailureElement
	for k := 0; k <= maxFailures; k++ {
		failure.FindElementCombo(elements, k, 0, nil, func(combo []solver.FailureElement) bool {
			_, ok := engine.RouteReachable(from, prefix, failure.SetFromElements(combo))
			if !ok {
				forbidden = append(forbidden, append([]solver.FailureElement(nil), combo...))
			}
			return false
		})
	}
	return forbidden
}

func assertSolverParityAnswer(t *testing.T, engine *Engine, from, to, protocol string, maxFailures int, concrete, symbolic solver.Answer) {
	t.Helper()
	if concrete.Sat != symbolic.Sat {
		t.Fatalf("solver SAT mismatch: concrete=%#v symbolic=%#v", concrete, symbolic)
	}
	if !concrete.Sat {
		return
	}
	if len(concrete.Failures) > maxFailures || len(symbolic.Failures) > maxFailures {
		t.Fatalf("solver answer exceeds maxFailures=%d: concrete=%#v symbolic=%#v", maxFailures, concrete, symbolic)
	}
	if len(concrete.Failures) != len(symbolic.Failures) {
		t.Fatalf("solver answer size mismatch: concrete=%#v symbolic=%#v", concrete, symbolic)
	}
	for name, failures := range map[string][]solver.FailureElement{
		"concrete": concrete.Failures,
		"symbolic": symbolic.Failures,
	} {
		_, ok, reason := engine.PacketReachable(from, to, protocol, failure.SetFromElements(failures))
		if ok {
			t.Fatalf("%s solver answer does not break concrete reachability: answer=%v reason=%q", name, solverFailureStrings(failures), reason)
		}
	}
}

func assertRouteSolverParityAnswer(t *testing.T, engine *Engine, from, prefix string, maxFailures int, concrete, symbolic solver.Answer) {
	t.Helper()
	if concrete.Sat != symbolic.Sat {
		t.Fatalf("route solver SAT mismatch: concrete=%#v symbolic=%#v", concrete, symbolic)
	}
	if !concrete.Sat {
		return
	}
	if len(concrete.Failures) > maxFailures || len(symbolic.Failures) > maxFailures {
		t.Fatalf("route solver answer exceeds maxFailures=%d: concrete=%#v symbolic=%#v", maxFailures, concrete, symbolic)
	}
	if len(concrete.Failures) != len(symbolic.Failures) {
		t.Fatalf("route solver answer size mismatch: concrete=%#v symbolic=%#v", concrete, symbolic)
	}
	for name, failures := range map[string][]solver.FailureElement{
		"concrete": concrete.Failures,
		"symbolic": symbolic.Failures,
	} {
		if _, ok := engine.RouteReachable(from, prefix, failure.SetFromElements(failures)); ok {
			t.Fatalf("%s route solver answer does not break concrete reachability: answer=%v", name, solverFailureStrings(failures))
		}
	}
}

func singlePathEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func redundantPathEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "primary", Kind: model.KindFRR},
			{Name: "backup", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-primary", A: "src", B: "primary", Cost: 1},
			{Name: "primary-dst", A: "primary", B: "dst", Cost: 1},
			{Name: "src-backup", A: "src", B: "backup", Cost: 1},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 1},
		},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: "primary", Condition: failure.And(failure.LinkVar("src-primary"), failure.LinkVar("primary-dst"))},
			{Prefix: pfx.NetIP(), NextHop: "backup", Condition: failure.And(failure.LinkVar("src-backup"), failure.LinkVar("backup-dst"))},
		},
		"primary": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.LinkVar("primary-dst")}},
		"backup":  {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.LinkVar("backup-dst")}},
	})
}

func routeRedundantPathEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "primary", Kind: model.KindFRR},
			{Name: "backup", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-primary", A: "src", B: "primary", Cost: 1},
			{Name: "primary-dst", A: "primary", B: "dst", Cost: 1},
			{Name: "src-backup", A: "src", B: "backup", Cost: 1},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 1},
		},
	})
	rib := map[string]map[string][]controlplane.RIBEntry{
		"src": {
			pfx.String(): {
				{
					Prefix:       pfx,
					Origin:       "dst",
					Nodes:        []string{"dst", "primary", "src"},
					Links:        []string{"primary-dst", "src-primary"},
					SelectedCond: failure.And(failure.LinkVar("src-primary"), failure.LinkVar("primary-dst")),
				},
				{
					Prefix:       pfx,
					Origin:       "dst",
					Nodes:        []string{"dst", "backup", "src"},
					Links:        []string{"backup-dst", "src-backup"},
					SelectedCond: failure.And(failure.LinkVar("src-backup"), failure.LinkVar("backup-dst")),
				},
			},
		},
	}
	return NewEngine(idx, rib, nil)
}

func longestPrefixFallbackEngine() *Engine {
	dstPfx := model.MustPrefix("10.0.0.0/16")
	specificPfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "specific", Kind: model.KindFRR},
			{Name: "fallback", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{dstPfx}},
		},
		Links: []model.Link{
			{Name: "src-specific", A: "src", B: "specific", Cost: 1},
			{Name: "specific-dst", A: "specific", B: "dst", Cost: 1},
			{Name: "src-fallback", A: "src", B: "fallback", Cost: 5},
			{Name: "fallback-dst", A: "fallback", B: "dst", Cost: 5},
		},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: specificPfx.NetIP(), NextHop: "specific", Condition: failure.LinkVar("prefer-specific")},
			{Prefix: dstPfx.NetIP(), NextHop: "fallback", Condition: failure.True()},
		},
		"specific": {{Prefix: dstPfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
		"fallback": {{Prefix: dstPfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func samePrefixCandidatesEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.DeviceKind("generic")},
			{Name: "primary", Kind: model.KindFRR},
			{Name: "backup", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-primary", A: "src", B: "primary", Cost: 1},
			{Name: "primary-dst", A: "primary", B: "dst", Cost: 1},
			{Name: "src-backup", A: "src", B: "backup", Cost: 1},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 1},
		},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: "primary", Condition: failure.LinkVar("prefer-primary")},
			{Prefix: pfx.NetIP(), NextHop: "backup", Condition: failure.True()},
		},
		"primary": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
		"backup":  {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func noRouteEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{{Name: "src-dst", A: "src", B: "dst", Cost: 1}},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{})
}

func forwardingLoopEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: model.KindFRR},
			{Name: "b", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1}},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"a": {{Prefix: pfx.NetIP(), NextHop: "b", Condition: failure.True()}},
		"b": {{Prefix: pfx.NetIP(), NextHop: "a", Condition: failure.True()}},
	})
}

func ingressACLDenyEngine() *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
		Policies: []model.Policy{{
			Name:      "DENY-TCP-IN",
			Node:      "mid",
			Plane:     "data",
			Stage:     "ingress",
			Interface: "eth1",
			Action:    "deny",
			Protocol:  "tcp",
			DstPrefix: pfx,
		}},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func egressACLDenyEngine(policyInterface, policyProtocol string) *Engine {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
		Policies: []model.Policy{{
			Name:      "DENY-POLICY",
			Node:      "mid",
			Plane:     "data",
			Stage:     "egress",
			Interface: policyInterface,
			Action:    "deny",
			Protocol:  policyProtocol,
			DstPrefix: pfx,
		}},
	})
	return NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
}

func TestSymbolicPacketReachabilityForPacketClassMatchesRepresentativeSpec(t *testing.T) {
	engine := egressACLDenyEngine("eth2", "tcp")
	pfx := model.MustPrefix("10.0.0.0/24")
	class := model.PacketClass{
		ID:            0,
		PrefixClassID: 0,
		DstSet:        model.ExactPrefixSet{Prefix: pfx},
		Protocol:      "tcp",
		DstPort:       model.ExactPort(80),
	}
	classResult := engine.SymbolicPacketReachabilityForPacketClass("src", class)
	specResult := engine.SymbolicPacketReachabilityForPrefixSetSpec("src", class.DstSet, class.Spec())
	if classResult.Reachable.String() != specResult.Reachable.String() {
		t.Fatalf("reachable = %s, want %s", classResult.Reachable.String(), specResult.Reachable.String())
	}
	if classResult.Unreachable.String() != specResult.Unreachable.String() {
		t.Fatalf("unreachable = %s, want %s", classResult.Unreachable.String(), specResult.Unreachable.String())
	}
}

func mustTopologyIndex(topo *model.Topology) *model.TopologyIndex {
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		panic(err)
	}
	return idx
}

func formatSymbolicPaths(paths []SymbolicPacketPath) string {
	if len(paths) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, fmt.Sprintf("{path=%s links=%v cond=%s key=%s}", strings.Join(path.Path.Nodes, "->"), path.Path.Links, path.Cond.String(), path.Cond.Key()))
	}
	sort.Strings(out)
	return "[" + strings.Join(out, ", ") + "]"
}

func formatSymbolicRoutePaths(paths []SymbolicRoutePath) string {
	if len(paths) == 0 {
		return "[]"
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, fmt.Sprintf("{path=%s links=%v cond=%s key=%s}", strings.Join(path.Path.Nodes, "->"), path.Path.Links, path.Cond.String(), path.Cond.Key()))
	}
	sort.Strings(out)
	return "[" + strings.Join(out, ", ") + "]"
}

func formatFailureSet(set failure.Set) string {
	var parts []string
	for name, failed := range set.Links {
		if failed {
			parts = append(parts, "link:"+string(name))
		}
	}
	for name, failed := range set.Nodes {
		if failed {
			parts = append(parts, "node:"+string(name))
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func solverFailureStrings(elements []solver.FailureElement) []string {
	out := make([]string, 0, len(elements))
	for _, element := range elements {
		out = append(out, element.String())
	}
	sort.Strings(out)
	return out
}
