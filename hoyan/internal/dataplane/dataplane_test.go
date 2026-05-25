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
		Policies: []model.Policy{{
			Name:      "NFT-DENY",
			Node:      "mid",
			Plane:     "data",
			Stage:     "egress",
			Interface: "eth2",
			Action:    "deny",
			Protocol:  "tcp",
			DstPrefix: pfx,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(idx, nil, map[string][]FIBEntry{
		"src": {{Prefix: pfx.NetIP(), NextHop: "mid", Condition: failure.True()}},
		"mid": {{Prefix: pfx.NetIP(), NextHop: "dst", Condition: failure.True()}},
	})
	_, ok, reason := e.PacketReachable("src", "10.0.0.10", "tcp", failure.None())
	if ok || reason != "denied by policy NFT-DENY" {
		t.Fatalf("tcp PacketReachable() ok=%v reason=%q, want nft deny", ok, reason)
	}
	if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "icmp", failure.None()); !ok {
		t.Fatalf("icmp PacketReachable() ok=false reason=%q, want reachable", reason)
	}
	idx.Topology.Policies[0].Interface = "eth9"
	if _, ok, reason := e.PacketReachable("src", "10.0.0.10", "tcp", failure.None()); !ok {
		t.Fatalf("tcp PacketReachable() with nonmatching interface ok=false reason=%q, want reachable", reason)
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
}
