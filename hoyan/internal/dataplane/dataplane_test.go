package dataplane

import (
	"strings"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestRouteReachableUsesSelectedCondition(t *testing.T) {
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: model.KindFRR},
			{Name: "b", Kind: model.KindFRR, Prefixes: []model.Prefix{model.MustPrefix("10.0.0.0/24")}},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rib := map[string]map[string][]controlplane.RIBEntry{
		"a": {"10.0.0.0/24": {{Prefix: model.MustPrefix("10.0.0.0/24"), Nodes: []string{"b", "a"}, Links: []string{"a-b"}, SelectedCond: failure.LinkVar("a-b")}}},
	}
	e := NewEngine(idx, rib, map[string][]FIBEntry{})
	path, ok := e.RouteReachable("a", "10.0.0.0/24", failure.None())
	if !ok || path.Cost != 10 || path.Nodes[0] != "a" || path.Nodes[1] != "b" {
		t.Fatalf("RouteReachable() = %#v %v", path, ok)
	}
	if _, ok := e.RouteReachable("a", "10.0.0.0/24", failure.Links("a-b")); ok {
		t.Fatalf("RouteReachable() should fail when selected condition is false")
	}
}

func TestSymbolicPacketReachabilitySinglePathIncludesForwardingConditions(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", Cost: 10},
			{Name: "mid-dst", A: "mid", B: "dst", Cost: 20},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	result := e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	if len(result.Paths) != 1 {
		t.Fatalf("symbolic paths = %d, want 1: %#v", len(result.Paths), result)
	}
	if !result.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("reachable condition should evaluate true without failures: %s", result.Reachable)
	}
	for _, failed := range []model.LinkID{"src-mid", "mid-dst"} {
		if result.Reachable.Eval(e.FailureContext(failure.Links(failed))) {
			t.Fatalf("reachable condition should evaluate false with failed link %s: %s", failed, result.Reachable)
		}
	}
	for _, failed := range []model.NodeID{"src", "mid", "dst"} {
		if result.Reachable.Eval(e.FailureContext(failure.Nodes(failed))) {
			t.Fatalf("reachable condition should evaluate false with failed node %s: %s", failed, result.Reachable)
		}
	}
	text := result.Reachable.String()
	for _, want := range []string{"link:src-mid", "link:mid-dst", "node:src", "node:mid", "node:dst"} {
		if !strings.Contains(text, want) {
			t.Fatalf("reachable condition %q does not include %q", text, want)
		}
	}
}

func TestSymbolicPacketReachabilityForExactPrefixSetMatchesConcreteIP(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", Cost: 10},
			{Name: "mid-dst", A: "mid", B: "dst", Cost: 20},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	concrete := e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	prefixSet := e.SymbolicPacketReachabilityForPrefixSet("src", model.ExactPrefixSet{Prefix: pfx}, "icmp")
	if concrete.Reachable.Key() != prefixSet.Reachable.Key() {
		t.Fatalf("PrefixSet reachable key = %s, want concrete key %s", prefixSet.Reachable.Key(), concrete.Reachable.Key())
	}
	if got, want := len(prefixSet.Paths), len(concrete.Paths); got != want {
		t.Fatalf("PrefixSet paths = %d, want concrete paths %d", got, want)
	}
	universe, err := model.BuildPrefixUniverse([]model.PrefixSet{model.ExactPrefixSet{Prefix: pfx}})
	if err != nil {
		t.Fatal(err)
	}
	classResult := e.SymbolicPacketReachabilityForClass("src", universe, universe.Classes[0].ID, "icmp")
	if concrete.Reachable.Key() != classResult.Reachable.Key() {
		t.Fatalf("class reachable key = %s, want concrete key %s", classResult.Reachable.Key(), concrete.Reachable.Key())
	}
}

func TestSymbolicPacketReachabilityRedundantPathsAreORed(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "primary", Kind: model.KindFRR},
			{Name: "backup", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-primary", A: "src", B: "primary", Cost: 10},
			{Name: "primary-dst", A: "primary", B: "dst", Cost: 10},
			{Name: "src-backup", A: "src", B: "backup", Cost: 20},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 20},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: "primary", Condition: failure.LinkVar("src-primary")},
			{Prefix: pfx.NetIP(), NextHop: "backup", Condition: failure.True()},
		},
		"primary": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
		"backup":  {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	result := e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	if len(result.Paths) != 2 {
		t.Fatalf("symbolic paths = %d, want 2: %#v", len(result.Paths), result)
	}
	if !strings.Contains(result.Reachable.String(), "||") {
		t.Fatalf("reachable condition should OR redundant paths: %s", result.Reachable)
	}
	if !result.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("reachable condition should evaluate true without failures: %s", result.Reachable)
	}
	if !result.Reachable.Eval(e.FailureContext(failure.Links("src-primary"))) {
		t.Fatalf("backup path should be reachable when primary route condition is false: %s", result.Reachable)
	}
	if result.Reachable.Eval(e.FailureContext(failure.Links("src-primary", "src-backup"))) {
		t.Fatalf("reachable condition should evaluate false when both source links fail: %s", result.Reachable)
	}
}

func TestSymbolicLookupFIBAddsNotHigherMatchingConditions(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	defaultPfx := model.MustPrefix("0.0.0.0/0")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "specific", Kind: model.KindFRR},
			{Name: "fallback", Kind: model.KindFRR},
		},
		Links: []model.Link{
			{Name: "src-specific", A: "src", B: "specific", Cost: 1},
			{Name: "src-fallback", A: "src", B: "fallback", Cost: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: defaultPfx.NetIP(), NextHop: "fallback", Condition: failure.True()},
			{Prefix: pfx.NetIP(), NextHop: "specific", Condition: failure.LinkVar("prefer-specific")},
		},
	})
	candidates := e.SymbolicLookupFIB("src", "10.0.0.10")
	if len(candidates) != 2 {
		t.Fatalf("SymbolicLookupFIB candidates = %d, want 2", len(candidates))
	}
	if candidates[0].Entry.NextHop != "specific" {
		t.Fatalf("first candidate next-hop = %q, want longest-prefix match specific", candidates[0].Entry.NextHop)
	}
	if candidates[1].Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("fallback condition should be false while higher specific route is active: %s", candidates[1].Cond)
	}
	if !candidates[1].Cond.Eval(e.FailureContext(failure.Links("prefer-specific"))) {
		t.Fatalf("fallback condition should be true when higher specific route is inactive: %s", candidates[1].Cond)
	}
	if !strings.Contains(candidates[1].Cond.String(), "!(") {
		t.Fatalf("fallback condition should include NOT(higher condition): %s", candidates[1].Cond)
	}
}

func TestSymbolicLookupFIBForPrefixSetAddsNotHigherMatchingConditions(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	defaultPfx := model.MustPrefix("0.0.0.0/0")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "specific", Kind: model.KindFRR},
			{Name: "fallback", Kind: model.KindFRR},
		},
		Links: []model.Link{
			{Name: "src-specific", A: "src", B: "specific", Cost: 1},
			{Name: "src-fallback", A: "src", B: "fallback", Cost: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: defaultPfx.NetIP(), NextHop: "fallback", Condition: failure.True()},
			{Prefix: pfx.NetIP(), NextHop: "specific", Condition: failure.LinkVar("prefer-specific")},
		},
	})
	candidates := e.SymbolicLookupFIBForPrefixSet("src", model.ExactPrefixSet{Prefix: pfx})
	if len(candidates) != 2 {
		t.Fatalf("SymbolicLookupFIBForPrefixSet candidates = %d, want 2", len(candidates))
	}
	if candidates[0].Entry.NextHop != "specific" {
		t.Fatalf("first candidate next-hop = %q, want longest-prefix match specific", candidates[0].Entry.NextHop)
	}
	if candidates[1].Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("fallback condition should be false while higher specific route is active: %s", candidates[1].Cond)
	}
	if !candidates[1].Cond.Eval(e.FailureContext(failure.Links("prefer-specific"))) {
		t.Fatalf("fallback condition should be true when higher specific route is inactive: %s", candidates[1].Cond)
	}
}

func TestSymbolicLookupFIBKeepsEquivalentGroupCandidates(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	defaultPfx := model.MustPrefix("0.0.0.0/0")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "a", Kind: model.KindFRR},
			{Name: "b", Kind: model.KindFRR},
			{Name: "fallback", Kind: model.KindFRR},
		},
		Links: []model.Link{
			{Name: "src-a", A: "src", B: "a", Cost: 1},
			{Name: "src-b", A: "src", B: "b", Cost: 1},
			{Name: "src-fallback", A: "src", B: "fallback", Cost: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: "a", Condition: failure.LinkVar("src-a"), Rank: 0, GroupID: "ecmp-10.0.0.0/24", Equivalent: true},
			{Prefix: pfx.NetIP(), NextHop: "b", Condition: failure.LinkVar("src-b"), Rank: 0, GroupID: "ecmp-10.0.0.0/24", Equivalent: true},
			{Prefix: defaultPfx.NetIP(), NextHop: "fallback", Condition: failure.True(), Rank: 1, GroupID: "default"},
		},
	})
	candidates := e.SymbolicLookupFIB("src", "10.0.0.10")
	if len(candidates) != 3 {
		t.Fatalf("SymbolicLookupFIB candidates = %d, want 3", len(candidates))
	}
	if !candidates[1].Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("second ECMP member should not be suppressed by first member: %s", candidates[1].Cond)
	}
	if candidates[2].Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("fallback should be suppressed while either ECMP member is active: %s", candidates[2].Cond)
	}
	if !candidates[2].Cond.Eval(e.FailureContext(failure.Links("src-a", "src-b"))) {
		t.Fatalf("fallback should be usable only after all ECMP members are inactive: %s", candidates[2].Cond)
	}
}

func TestPacketReachableUsesAnyLiveEquivalentFIBMember(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "a", Kind: model.KindFRR},
			{Name: "b", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-a", A: "src", B: "a", Cost: 1},
			{Name: "a-dst", A: "a", B: "dst", Cost: 1},
			{Name: "src-b", A: "src", B: "b", Cost: 1},
			{Name: "b-dst", A: "b", B: "dst", Cost: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: "a", Condition: failure.True(), Rank: 0, GroupID: "ecmp", Equivalent: true},
			{Prefix: pfx.NetIP(), NextHop: "b", Condition: failure.True(), Rank: 0, GroupID: "ecmp", Equivalent: true},
		},
		"a": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
		"b": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	cases := []failure.Set{
		failure.None(),
		failure.Links("src-a"),
		failure.Links("a-dst"),
		failure.Nodes("a"),
	}
	for _, failures := range cases {
		if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "icmp", failures); !ok {
			t.Fatalf("PacketReachable(%v) ok=false reason=%q, want ECMP alternate reachable", failures, reason)
		}
	}
	if _, ok, _ := e.PacketReachable("src", "10.0.0.10", "icmp", failure.Links("src-a", "src-b")); ok {
		t.Fatalf("PacketReachable should fail when all ECMP member links fail")
	}
	AssertSymbolicConcreteParity(t, e, "src", "10.0.0.10", "icmp", []failure.Set{
		failure.None(),
		failure.Links("src-a"),
		failure.Links("src-b"),
		failure.Links("src-a", "src-b"),
		failure.Links("a-dst", "b-dst"),
		failure.Nodes("a"),
		failure.Nodes("b"),
		failure.Nodes("a", "b"),
	})
}

func TestSymbolicPacketReachabilityEvalMatchesConcretePacketReachable(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "primary", Kind: model.KindFRR},
			{Name: "backup", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-primary", A: "src", B: "primary", Cost: 10},
			{Name: "primary-dst", A: "primary", B: "dst", Cost: 10},
			{Name: "src-backup", A: "src", B: "backup", Cost: 20},
			{Name: "backup-dst", A: "backup", B: "dst", Cost: 20},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {
			{Prefix: pfx.NetIP(), NextHop: "primary", Condition: failure.LinkVar("src-primary")},
			{Prefix: pfx.NetIP(), NextHop: "backup", Condition: failure.True()},
		},
		"primary": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
		"backup":  {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	result := e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	cases := []failure.Set{
		failure.None(),
		failure.Links("src-primary"),
		failure.Links("src-backup"),
		failure.Links("primary-dst"),
		failure.Links("backup-dst"),
		failure.Links("src-primary", "src-backup"),
		failure.Nodes("src"),
		failure.Nodes("primary"),
		failure.Nodes("backup"),
		failure.Nodes("dst"),
	}
	for _, failures := range cases {
		_, concrete, _ := e.PacketReachable("src", "10.0.0.10", "icmp", failures)
		symbolic := result.Reachable.Eval(e.FailureContext(failures))
		if symbolic != concrete {
			t.Fatalf("symbolic Eval(%v) = %v, concrete PacketReachable = %v; cond=%s", failures, symbolic, concrete, result.Reachable)
		}
	}
}

func TestPacketReachableMatchesPolicyInterface(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
		ACLs: testACLs("NFT-DENY", "mid", model.ACLRule{
			Seq: 10, Action: model.ACLDeny, Match: model.PacketSpec{Protocol: "tcp", DstSet: model.ExactPrefixSet{Prefix: pfx}},
		}),
		ACLBindings: testACLBindings("NFT-DENY", "mid", "eth2", "egress"),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	_, ok, reason := e.PacketReachable("src", "10.0.0.10", "tcp", failure.None())
	if ok || reason != "denied by acl NFT-DENY" {
		t.Fatalf("tcp PacketReachable() ok=%v reason=%q, want nft deny", ok, reason)
	}
	if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "icmp", failure.None()); !ok {
		t.Fatalf("icmp PacketReachable() ok=false reason=%q, want reachable", reason)
	}
	idx.Topology.ACLBindings[0].Interface = "eth9"
	if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "tcp", failure.None()); !ok {
		t.Fatalf("tcp PacketReachable() with nonmatching interface ok=false reason=%q, want reachable", reason)
	}
}

func TestPacketReachableMatchesPolicyDstPort(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
		ACLs: testACLs("DENY-HTTP", "mid", model.ACLRule{
			Seq: 10, Action: model.ACLDeny, Match: model.PacketSpec{Protocol: "tcp", DstSet: model.ExactPrefixSet{Prefix: pfx}, DstPort: model.ExactPortSet{Port: 80}},
		}),
		ACLBindings: testACLBindings("DENY-HTTP", "mid", "eth2", "egress"),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	http := model.PacketSpec{Protocol: "tcp", DstPort: model.ExactPortSet{Port: 80}}
	if _, ok, reason := e.PacketReachableSpec("src", "10.0.0.10", http, failure.None()); ok || reason != "denied by acl DENY-HTTP" {
		t.Fatalf("tcp/80 PacketReachableSpec() ok=%v reason=%q, want policy deny", ok, reason)
	}
	https := model.PacketSpec{Protocol: "tcp", DstPort: model.ExactPortSet{Port: 443}}
	if _, ok, reason := e.PacketReachableSpec("src", "10.0.0.10", https, failure.None()); !ok {
		t.Fatalf("tcp/443 PacketReachableSpec() ok=false reason=%q, want reachable", reason)
	}
	if _, ok, reason := e.PacketReachableSpec("src", "10.0.0.10", model.PacketSpec{Protocol: "icmp"}, failure.None()); !ok {
		t.Fatalf("icmp PacketReachableSpec() ok=false reason=%q, want reachable", reason)
	}
	result := e.SymbolicPacketReachabilitySpec("src", "10.0.0.10", http)
	if got := result.Reachable.Eval(e.FailureContext(failure.None())); got {
		t.Fatalf("tcp/80 symbolic reachable = %v, want false", got)
	}
	result = e.SymbolicPacketReachabilitySpec("src", "10.0.0.10", https)
	if got := result.Reachable.Eval(e.FailureContext(failure.None())); !got {
		t.Fatalf("tcp/443 symbolic reachable = %v, want true", got)
	}
}

func TestPacketReachableUsesACLPermitAndDefaultAction(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindCEOS},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "Ethernet1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "Ethernet2", BIntf: "eth1", Cost: 1},
		},
		ACLs: []model.ACL{{
			Name:          "WEB",
			Node:          "mid",
			Vendor:        model.KindCEOS,
			DefaultAction: model.ACLDefaultDeny,
			Rules: []model.ACLRule{
				{Seq: 10, Action: model.ACLPermit, Match: model.PacketSpec{Protocol: "tcp", DstSet: model.ExactPrefixSet{Prefix: pfx}, DstPort: model.ExactPort(443)}},
				{Seq: 20, Action: model.ACLDeny, Match: model.PacketSpec{Protocol: "tcp", DstSet: model.ExactPrefixSet{Prefix: pfx}, DstPort: model.ExactPort(80)}},
			},
		}},
		ACLBindings: []model.ACLBinding{{Node: "mid", Interface: "Ethernet2", Direction: "egress", ACLName: "WEB"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	https := model.PacketSpec{Protocol: "tcp", DstPort: model.ExactPort(443)}
	if _, ok, reason := e.PacketReachableSpec("src", "10.0.0.10", https, failure.None()); !ok {
		t.Fatalf("tcp/443 PacketReachableSpec() ok=false reason=%q, want ACL permit", reason)
	}
	http := model.PacketSpec{Protocol: "tcp", DstPort: model.ExactPort(80)}
	if _, ok, reason := e.PacketReachableSpec("src", "10.0.0.10", http, failure.None()); ok || reason != "denied by acl WEB" {
		t.Fatalf("tcp/80 PacketReachableSpec() ok=%v reason=%q, want ACL deny", ok, reason)
	}
	ssh := model.PacketSpec{Protocol: "tcp", DstPort: model.ExactPort(22)}
	if _, ok, reason := e.PacketReachableSpec("src", "10.0.0.10", ssh, failure.None()); ok || reason != "default deny by acl WEB" {
		t.Fatalf("tcp/22 PacketReachableSpec() ok=%v reason=%q, want ACL default deny", ok, reason)
	}
}

func TestSymbolicPacketReachabilityForClassAppliesDstPrefixPolicy(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
		ACLs: testACLs("deny-tcp", "mid", model.ACLRule{
			Seq: 10, Action: model.ACLDeny, Match: model.PacketSpec{Protocol: "tcp", DstSet: model.ExactPrefixSet{Prefix: pfx}},
		}),
		ACLBindings: testACLBindings("deny-tcp", "mid", "eth2", "egress"),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	universe, err := model.BuildPrefixUniverse([]model.PrefixSet{model.ExactPrefixSet{Prefix: pfx}})
	if err != nil {
		t.Fatal(err)
	}
	tcpResult := e.SymbolicPacketReachabilityForClass("src", universe, universe.Classes[0].ID, "tcp")
	if tcpResult.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("tcp class reachability should be denied by dst_prefix policy: %s", tcpResult.Reachable)
	}
	icmpResult := e.SymbolicPacketReachabilityForClass("src", universe, universe.Classes[0].ID, "icmp")
	if !icmpResult.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("icmp class reachability should be allowed: %s", icmpResult.Reachable)
	}
}

func TestSymbolicPacketReachabilityRecordsPolicyDeny(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR},
			{Name: "mid", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "src-mid", A: "src", B: "mid", AIntf: "eth1", BIntf: "eth1", Cost: 1},
			{Name: "mid-dst", A: "mid", B: "dst", AIntf: "eth2", BIntf: "eth1", Cost: 1},
		},
		ACLs: testACLs("NFT-DENY-TCP", "mid", model.ACLRule{
			Seq:    10,
			Action: model.ACLDeny,
			Match:  model.PacketSpec{Protocol: "tcp", DstSet: model.ExactPrefixSet{Prefix: pfx}},
			Source: model.ConfigSource{
				Vendor: "nftables",
				File:   "configs/frr/mid/nftables.conf",
				Line:   12,
				Raw:    "tcp dport 80 drop",
			},
		}),
		ACLBindings: testACLBindings("NFT-DENY-TCP", "mid", "eth2", "egress"),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})

	result := e.SymbolicPacketReachability("src", "10.0.0.10", "tcp")
	if result.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("tcp reachable condition = %s, want false under no failures", result.Reachable)
	}
	if got := len(result.Blocked); got != 1 {
		t.Fatalf("blocked paths = %d, want 1: %#v", got, result.Blocked)
	}
	blocked := result.Blocked[0]
	if blocked.ACL != "NFT-DENY-TCP" || blocked.Node != "mid" || blocked.Interface != "eth2" || blocked.Stage != "egress" {
		t.Fatalf("unexpected blocked policy metadata: %#v", blocked)
	}
	if blocked.Source.Vendor != "nftables" || blocked.Source.File == "" || blocked.Source.Raw == "" {
		t.Fatalf("missing blocked config source: %#v", blocked.Source)
	}
	if !blocked.Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("blocked condition = %s, want true under no failures", blocked.Cond)
	}

	result = e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	if !result.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("icmp reachable condition = %s, want true under no failures", result.Reachable)
	}
	if len(result.Blocked) != 0 {
		t.Fatalf("icmp blocked paths = %#v, want none", result.Blocked)
	}
	if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "icmp", failure.None()); !ok {
		t.Fatalf("icmp concrete PacketReachable() ok=false reason=%q, want symbolic/concrete match", reason)
	}
	if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "tcp", failure.None()); ok || reason != "denied by acl NFT-DENY-TCP" {
		t.Fatalf("tcp concrete PacketReachable() ok=%v reason=%q, want policy deny", ok, reason)
	}
}

func TestSymbolicPacketReachabilityDoesNotExploreLoopsForever(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: model.KindFRR},
			{Name: "b", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{{Name: "a-b", A: "a", B: "b", Cost: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"a": {{Prefix: pfx.NetIP(), NextHop: "b", Condition: failure.True()}},
		"b": {{Prefix: pfx.NetIP(), NextHop: "a", Condition: failure.True()}},
	})
	result := e.SymbolicPacketReachability("a", "10.0.0.10", "icmp")
	if len(result.Paths) != 0 {
		t.Fatalf("symbolic loop should produce no reachable paths, got %#v", result.Paths)
	}
	if result.Reachable.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("loop-only forwarding should not be reachable: %s", result.Reachable)
	}
}

func TestSymbolicPacketReachabilityRecordsNoRouteReason(t *testing.T) {
	e := noRouteEngine()
	result := e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	reason, ok := firstUnreachableReason(result, UnreachableNoRoute)
	if !ok {
		t.Fatalf("missing no_route reason: %#v", result.UnreachableReasons)
	}
	if reason.Node != "src" {
		t.Fatalf("no_route node = %q, want src", reason.Node)
	}
	if !reason.Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("no_route condition should be true without failures: %s", reason.Cond)
	}
}

func TestSymbolicPacketReachabilityRecordsEgressPolicyReason(t *testing.T) {
	e := egressACLDenyEngine("eth2", "tcp")
	result := e.SymbolicPacketReachability("src", "10.0.0.10", "tcp")
	reason, ok := firstUnreachableReason(result, UnreachableEgressPolicy)
	if !ok {
		t.Fatalf("missing egress_policy reason: %#v", result.UnreachableReasons)
	}
	if reason.Node != "mid" || reason.Interface != "eth2" || reason.PolicyName != "DENY-POLICY" {
		t.Fatalf("egress reason = %#v, want node mid interface eth2 policy DENY-POLICY", reason)
	}
	if !reason.Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("egress policy condition should be true without failures: %s", reason.Cond)
	}
}

func TestSymbolicPacketReachabilityRecordsLinkFailureReason(t *testing.T) {
	e := singlePathEngine()
	result := e.SymbolicPacketReachability("src", "10.0.0.10", "icmp")
	reason, ok := firstUnreachableReasonByLink(result, "mid-dst")
	if !ok {
		t.Fatalf("missing link_failed reason for mid-dst: %#v", result.UnreachableReasons)
	}
	if reason.Kind != UnreachableLinkFailed || reason.Node != "mid" {
		t.Fatalf("link failure reason = %#v, want kind link_failed node mid", reason)
	}
	if !reason.Cond.Eval(e.FailureContext(failure.Links("mid-dst"))) {
		t.Fatalf("link_failed condition should be true when mid-dst is failed: %s", reason.Cond)
	}
}

func TestSymbolicPacketReachabilityRecordsLoopReason(t *testing.T) {
	e := forwardingLoopEngine()
	result := e.SymbolicPacketReachability("a", "10.0.0.10", "icmp")
	reason, ok := firstUnreachableReason(result, UnreachableLoop)
	if !ok {
		t.Fatalf("missing loop reason: %#v", result.UnreachableReasons)
	}
	if reason.Node != "a" || len(reason.Path.Nodes) != 3 {
		t.Fatalf("loop reason = %#v, want repeated path ending at a", reason)
	}
	if !reason.Cond.Eval(e.FailureContext(failure.None())) {
		t.Fatalf("loop condition should be true without failures: %s", reason.Cond)
	}
}

func TestPacketReachableDetectsForwardingLoop(t *testing.T) {
	pfx := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{Name: "a", Kind: model.KindFRR},
			{Name: "b", Kind: model.KindFRR},
			{Name: "dst", Kind: model.KindFRR, Prefixes: []model.Prefix{pfx}},
		},
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", Cost: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"a": {{Prefix: pfx.NetIP(), NextHop: "b", Condition: failure.True()}},
		"b": {{Prefix: pfx.NetIP(), NextHop: "a", Condition: failure.True()}},
	})
	_, ok, reason := e.PacketReachable("a", "10.0.0.10", "icmp", failure.None())
	if ok || reason != "forwarding loop" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want forwarding loop", ok, reason)
	}
}

func TestPacketReachableReportsDiscardRoute(t *testing.T) {
	engine := discardRouteEngine(failure.True())
	_, ok, reason := engine.PacketReachable("src", "10.0.0.10", "icmp", failure.None())
	if ok || reason != "discard route selected" {
		t.Fatalf("PacketReachable() = ok %v reason %q, want discard route selected", ok, reason)
	}
}

func firstUnreachableReason(result SymbolicReachabilityResult, kind SymbolicUnreachableReasonKind) (SymbolicUnreachableReason, bool) {
	for _, reason := range result.UnreachableReasons {
		if reason.Kind == kind {
			return reason, true
		}
	}
	return SymbolicUnreachableReason{}, false
}

func firstUnreachableReasonByLink(result SymbolicReachabilityResult, link string) (SymbolicUnreachableReason, bool) {
	for _, reason := range result.UnreachableReasons {
		if reason.Kind == UnreachableLinkFailed && reason.Link == link {
			return reason, true
		}
	}
	return SymbolicUnreachableReason{}, false
}

func testACLs(name, node string, rules ...model.ACLRule) []model.ACL {
	return []model.ACL{{
		Name:          name,
		Node:          node,
		Vendor:        model.KindFRR,
		DefaultAction: model.ACLDefaultPermit,
		Rules:         rules,
	}}
}

func testACLBindings(name, node, iface, direction string) []model.ACLBinding {
	return []model.ACLBinding{{Node: node, Interface: iface, Direction: direction, ACLName: name}}
}

func TestDeriveFIBUsesVendorInstallEligibility(t *testing.T) {
	prefix := model.MustPrefix("10.0.0.0/24")
	equivalentRoutes := []controlplane.RIBEntry{
		{Prefix: prefix, Origin: "a", LocalPref: 100, ASPath: []uint32{65100}, Nodes: []string{"a", "rx"}, SelectedCond: failure.LinkVar("path-a")},
		{Prefix: prefix, Origin: "b", LocalPref: 100, ASPath: []uint32{65200}, Nodes: []string{"b", "rx"}, SelectedCond: failure.LinkVar("path-b")},
	}

	frrIdx, err := model.BuildTopologyIndex(&model.Topology{Nodes: []model.Node{{Name: "rx", Kind: model.KindFRR, ASN: 65000}}})
	if err != nil {
		t.Fatal(err)
	}
	frrRIB := map[string]map[string][]controlplane.RIBEntry{"rx": {prefix.String(): append([]controlplane.RIBEntry(nil), equivalentRoutes...)}}
	frrFIB := map[string][]FIBEntry{}
	NewEngine(frrIdx, frrRIB, frrFIB).DeriveFIB()
	if got := len(frrFIB["rx"]); got != 1 {
		t.Fatalf("FRR FIB entries = %d, want equivalent route collapsed to 1", got)
	}

	genericKind := model.DeviceKind("generic")
	genericIdx, err := model.BuildTopologyIndex(&model.Topology{Nodes: []model.Node{{Name: "rx", Kind: genericKind, ASN: 65000}}})
	if err != nil {
		t.Fatal(err)
	}
	genericRIB := map[string]map[string][]controlplane.RIBEntry{"rx": {prefix.String(): append([]controlplane.RIBEntry(nil), equivalentRoutes...)}}
	genericFIB := map[string][]FIBEntry{}
	NewEngine(genericIdx, genericRIB, genericFIB).DeriveFIB()
	if got := len(genericFIB["rx"]); got != 2 {
		t.Fatalf("generic FIB entries = %d, want equivalent routes kept", got)
	}
	if genericFIB["rx"][0].Rank != genericFIB["rx"][1].Rank || genericFIB["rx"][0].GroupID == "" || genericFIB["rx"][0].GroupID != genericFIB["rx"][1].GroupID {
		t.Fatalf("generic equivalent routes should share rank/group: %#v", genericFIB["rx"])
	}
	if !genericFIB["rx"][0].Equivalent || !genericFIB["rx"][1].Equivalent {
		t.Fatalf("generic equivalent routes should be marked equivalent: %#v", genericFIB["rx"])
	}
}

func TestDeriveFIBMarksAddressOnlyNextHopUnresolved(t *testing.T) {
	prefix := model.MustPrefix("10.0.0.0/24")
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{{Name: "rx", Kind: model.KindFRR}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fib := map[string][]FIBEntry{}
	NewEngine(idx, map[string]map[string][]controlplane.RIBEntry{
		"rx": {prefix.String(): {{
			Prefix:            prefix,
			ForwardingNextHop: controlplane.RouteNextHop{Addr: "192.0.2.1"},
			SelectedCond:      failure.True(),
		}}},
	}, fib).DeriveFIB()
	if got := len(fib["rx"]); got != 1 {
		t.Fatalf("FIB entries = %d, want 1", got)
	}
	entry := fib["rx"][0]
	if entry.NextHop != "" || entry.NextHopAddress != "192.0.2.1" || entry.ResolutionStatus != NextHopResolutionUnresolvedRecursive {
		t.Fatalf("FIB next-hop resolution = %#v, want unresolved address-only next-hop", entry)
	}
}

func TestDeriveFIBMarksBlackholeRouteAsDiscard(t *testing.T) {
	prefix := model.MustPrefix("10.0.0.0/24")
	idx := mustTopologyIndex(&model.Topology{
		Nodes: []model.Node{{Name: "src", Kind: model.KindFRR}},
	})
	rib := map[string]map[string][]controlplane.RIBEntry{
		"src": {
			prefix.String(): {
				{
					Prefix:       prefix,
					SourceKind:   model.RouteSourceBlackhole,
					RouteSource:  model.ConfiguredRoute{Prefix: prefix, Kind: model.RouteSourceBlackhole, Interface: "Null0"},
					SelectedCond: failure.True(),
				},
				{
					Prefix:       prefix,
					SourceKind:   model.RouteSourceBGP,
					NextHop:      "remote",
					SelectedCond: failure.True(),
				},
			},
		},
	}
	fib := map[string][]FIBEntry{}
	NewEngine(idx, rib, fib).DeriveFIB()
	if len(fib["src"]) != 1 {
		t.Fatalf("FIB entries = %#v, want local blackhole selected over same-prefix BGP", fib["src"])
	}
	entry := fib["src"][0]
	if !entry.Discard || entry.SourceKind != model.RouteSourceBlackhole || entry.Interface != "Null0" {
		t.Fatalf("blackhole FIB entry = %#v, want discard blackhole via Null0", entry)
	}
}
