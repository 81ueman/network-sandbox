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

func TestTopologyIndexEndpointAddressLookupUsesInterfaceAliases(t *testing.T) {
	topo := &Topology{
		Nodes: []Node{
			{Name: "frr", Interfaces: []Interface{{Name: "eth1", Address: "192.0.2.11/24"}}},
			{Name: "ceos", Kind: KindCEOS, Interfaces: []Interface{{Name: "Ethernet1", Address: "192.0.2.22/24"}}},
			{Name: "srl", Kind: KindSRLinux, Interfaces: []Interface{{Name: "ethernet-1/3.0", Address: "198.51.100.33/24"}}},
			{Name: "peer", Interfaces: []Interface{{Name: "eth9", Address: "198.51.100.44/24"}}},
		},
		Links: []Link{
			{Name: "frr-ceos", A: "frr", B: "ceos", AIntf: "eth1", BIntf: "eth1", Cost: 1, Subnet: "192.0.2.0/24"},
			{Name: "srl-peer", A: "srl", B: "peer", AIntf: "e1-3", BIntf: "eth9", Cost: 1, Subnet: "198.51.100.0/24"},
		},
	}
	idx, err := BuildTopologyIndex(topo)
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	tests := []struct {
		node string
		peer string
		want string
	}{
		{node: "frr", peer: "ceos", want: "192.0.2.11"},
		{node: "ceos", peer: "frr", want: "192.0.2.22"},
		{node: "srl", peer: "peer", want: "198.51.100.33"},
	}
	for _, tt := range tests {
		t.Run(tt.node+"-"+tt.peer, func(t *testing.T) {
			got, ok := idx.AddressOnLink(tt.node, tt.peer)
			if !ok || got.String() != tt.want {
				t.Fatalf("AddressOnLink(%s,%s) = %s, %v; want %s, true", tt.node, tt.peer, got, ok, tt.want)
			}
		})
	}
	got, ok := idx.PeerAddressOnLink("frr", "ceos")
	if !ok || got.String() != "192.0.2.22" {
		t.Fatalf("PeerAddressOnLink(frr,ceos) = %s, %v; want 192.0.2.22, true", got, ok)
	}
	ref, ok := idx.InterfaceToPeer("srl", "peer")
	if !ok || ref.ClabName != "e1-3" || ref.ConfigName != "ethernet-1/3.0" || ref.Address.String() != "198.51.100.33/24" {
		t.Fatalf("InterfaceToPeer(srl,peer) = %#v, %v; want e1-3 ethernet-1/3.0 198.51.100.33/24", ref, ok)
	}
	peerRef, ok := idx.PeerInterfaceToNode("srl", "peer")
	if !ok || peerRef.ClabName != "eth9" || peerRef.ConfigName != "eth9" || peerRef.Address.String() != "198.51.100.44/24" {
		t.Fatalf("PeerInterfaceToNode(srl,peer) = %#v, %v; want peer eth9 198.51.100.44/24", peerRef, ok)
	}
	peerAddr, ok := idx.PeerAddress("srl", "peer")
	if !ok || peerAddr.String() != "198.51.100.44" {
		t.Fatalf("PeerAddress(srl,peer) = %s, %v; want 198.51.100.44, true", peerAddr, ok)
	}
}
