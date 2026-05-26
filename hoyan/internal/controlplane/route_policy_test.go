package controlplane

import (
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestRouteNextHopForPolicyUsesResolvedPeerAddress(t *testing.T) {
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{
				Name:       "local",
				Kind:       model.KindFRR,
				Interfaces: []model.Interface{{Name: "eth1", Address: "198.51.100.10/24"}},
			},
			{
				Name:       "peer",
				Kind:       model.KindCEOS,
				Interfaces: []model.Interface{{Name: "Ethernet1", Address: "198.51.100.20/24"}},
			},
		},
		Links: []model.Link{
			{Name: "local-peer", A: "local", B: "peer", AIntf: "eth1", BIntf: "eth1", Cost: 1, Subnet: "198.51.100.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	got := routeNextHopForPolicy(idx, "local", "", RIBEntry{NextHop: "peer"})
	if got != "198.51.100.20" {
		t.Fatalf("routeNextHopForPolicy() = %q, want resolved peer address 198.51.100.20", got)
	}
}

func TestRoutePolicyNextHopPrefixListUsesResolvedAddress(t *testing.T) {
	idx, err := model.BuildTopologyIndex(&model.Topology{
		Nodes: []model.Node{
			{
				Name:       "local",
				Kind:       model.KindFRR,
				Interfaces: []model.Interface{{Name: "eth1", Address: "198.51.100.10/24"}},
			},
			{
				Name:       "peer",
				Kind:       model.KindCEOS,
				Interfaces: []model.Interface{{Name: "Ethernet1", Address: "198.51.100.20/24"}},
			},
		},
		Links: []model.Link{
			{Name: "local-peer", A: "local", B: "peer", AIntf: "eth1", BIntf: "eth1", Cost: 1, Subnet: "198.51.100.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	node := model.Node{
		Name: "local",
		PrefixLists: []model.PrefixList{{
			Name:  "NH",
			Rules: []model.PrefixListRule{{Seq: 10, Action: "permit", Prefix: "198.51.100.20/32"}},
		}},
	}
	rule := model.RoutePolicyRule{MatchNextHopPrefixList: "NH"}
	if !routePolicyRuleMatches(idx, node, "", rule, RIBEntry{NextHop: "peer"}) {
		t.Fatalf("routePolicyRuleMatches() = false, want next-hop prefix-list to match resolved peer address")
	}
}

func TestPrefixListRuleMatchesUsesNLRILengthSemantics(t *testing.T) {
	rule := model.PrefixListRule{Seq: 10, Action: "permit", Prefix: "10.0.0.0/8", Ge: 16, Le: 24}
	if !prefixListRuleMatches(rule, model.MustPrefix("10.4.0.0/16")) {
		t.Fatalf("prefix-list range should match NLRI inside ge/le bounds")
	}
	if prefixListRuleMatches(rule, model.MustPrefix("10.4.1.10/32")) {
		t.Fatalf("prefix-list range should reject NLRI longer than le")
	}
	if prefixListRuleMatches(rule, model.MustPrefix("10.0.0.0/8")) {
		t.Fatalf("prefix-list range should reject NLRI shorter than ge")
	}
}
