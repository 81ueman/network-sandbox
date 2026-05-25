package model

import "testing"

func TestBuildTopologyIndexDetectsDuplicateNode(t *testing.T) {
	_, err := BuildTopologyIndex(&Topology{
		Nodes: []Node{
			{Name: "a"},
			{Name: "a"},
		},
	})
	if err == nil {
		t.Fatalf("BuildTopologyIndex() should reject duplicate nodes")
	}
}

func TestBuildTopologyIndexDetectsUnknownEndpoint(t *testing.T) {
	_, err := BuildTopologyIndex(&Topology{
		Nodes: []Node{{Name: "a"}},
		Links: []Link{{Name: "a-b", A: "a", B: "b", Cost: 1}},
	})
	if err == nil {
		t.Fatalf("BuildTopologyIndex() should reject links with unknown endpoints")
	}
}

func TestTopologyIndexLinkBetweenIsUndirected(t *testing.T) {
	idx, err := BuildTopologyIndex(&Topology{
		Nodes: []Node{{Name: "a"}, {Name: "b"}},
		Links: []Link{{Name: "a-b", A: "a", B: "b", Cost: 1}},
	})
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	ab, ok := idx.LinkBetween("a", "b")
	if !ok {
		t.Fatalf("LinkBetween(a,b) not found")
	}
	ba, ok := idx.LinkBetween("b", "a")
	if !ok {
		t.Fatalf("LinkBetween(b,a) not found")
	}
	if ab.Name != ba.Name {
		t.Fatalf("LinkBetween returned different links: %s and %s", ab.Name, ba.Name)
	}
}

func TestTopologyIndexAdjacencyOrderIsDeterministic(t *testing.T) {
	idx, err := BuildTopologyIndex(&Topology{
		Nodes: []Node{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}},
		Links: []Link{
			{Name: "a-d", A: "a", B: "d", Cost: 20},
			{Name: "a-c", A: "a", B: "c", Cost: 10},
			{Name: "a-b", A: "a", B: "b", Cost: 10},
		},
	})
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	got := []NodeID{idx.Adj[NodeID("a")][0].To, idx.Adj[NodeID("a")][1].To, idx.Adj[NodeID("a")][2].To}
	want := []NodeID{"b", "c", "d"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Adj[a] = %v, want %v", got, want)
		}
	}
}

func TestTopologyIndexOriginLookups(t *testing.T) {
	idx, err := BuildTopologyIndex(&Topology{
		Nodes: []Node{
			{Name: "wide", Prefixes: MustPrefixes("10.0.0.0/16")},
			{Name: "specific", Prefixes: MustPrefixes("10.0.1.0/24")},
		},
	})
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	node, ok := idx.OriginForPrefix("10.0.1.0/24")
	if !ok || node != "specific" {
		t.Fatalf("OriginForPrefix() = %q, %v", node, ok)
	}
	node, pfx, ok := idx.OriginForIP("10.0.1.99")
	if !ok || node != "specific" || pfx.String() != "10.0.1.0/24" {
		t.Fatalf("OriginForIP() = %q %s %v", node, pfx, ok)
	}
}
