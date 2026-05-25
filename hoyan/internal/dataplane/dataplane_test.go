package dataplane

import (
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
