package model

import (
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

type Topology struct {
	Name             string   `yaml:"name"`
	ManagementSubnet string   `yaml:"management_subnet"`
	Nodes            []Node   `yaml:"nodes"`
	Links            []Link   `yaml:"links"`
	Policies         []Policy `yaml:"policies"`
}

type Node struct {
	Name           string          `yaml:"name"`
	ContainerName  string          `yaml:"container_name"`
	Kind           string          `yaml:"kind"`
	Role           string          `yaml:"role"`
	ASN            uint32          `yaml:"asn"`
	MgmtIPv4       string          `yaml:"mgmt_ipv4"`
	Loopback       string          `yaml:"loopback"`
	ConfigPath     string          `yaml:"config_path"`
	Prefixes       []Prefix        `yaml:"prefixes"`
	Interfaces     []Interface     `yaml:"interfaces"`
	Neighbors      []BGPNeighbor   `yaml:"neighbors"`
	PrefixLists    []PrefixList    `yaml:"prefix_lists"`
	ASPathLists    []ASPathList    `yaml:"as_path_lists"`
	CommunityLists []CommunityList `yaml:"community_lists"`
	RoutePolicies  []RoutePolicy   `yaml:"route_policies"`
}

func (n Node) RuntimeName() string {
	if n.ContainerName != "" {
		return n.ContainerName
	}
	return n.Name
}

type Link struct {
	Name   string `yaml:"name"`
	A      string `yaml:"a"`
	B      string `yaml:"b"`
	Cost   int    `yaml:"cost"`
	Subnet string `yaml:"subnet"`
	AIntf  string `yaml:"a_intf"`
	BIntf  string `yaml:"b_intf"`
}

type Interface struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

type BGPNeighbor struct {
	Address      string `yaml:"address"`
	RemoteAS     uint32 `yaml:"remote_as"`
	Activated    bool   `yaml:"activated"`
	NextHopSelf  bool   `yaml:"next_hop_self"`
	PeerNode     string `yaml:"peer_node"`
	ImportPolicy string `yaml:"import_policy"`
	ExportPolicy string `yaml:"export_policy"`
}

type PrefixList struct {
	Name  string           `yaml:"name"`
	Rules []PrefixListRule `yaml:"rules"`
}

type PrefixListRule struct {
	Seq    int    `yaml:"seq"`
	Action string `yaml:"action"`
	Prefix string `yaml:"prefix"`
	Ge     int    `yaml:"ge,omitempty"`
	Le     int    `yaml:"le,omitempty"`
}

type ASPathList struct {
	Name  string           `yaml:"name"`
	Rules []StringListRule `yaml:"rules"`
}

type CommunityList struct {
	Name  string           `yaml:"name"`
	Rules []StringListRule `yaml:"rules"`
}

type StringListRule struct {
	Seq     int    `yaml:"seq"`
	Action  string `yaml:"action"`
	Pattern string `yaml:"pattern"`
}

type RoutePolicy struct {
	Name  string            `yaml:"name"`
	Rules []RoutePolicyRule `yaml:"rules"`
}

type RoutePolicyRule struct {
	Seq                    int      `yaml:"seq"`
	Action                 string   `yaml:"action"`
	MatchPrefixList        string   `yaml:"match_prefix_list"`
	MatchNextHopPrefixList string   `yaml:"match_next_hop_prefix_list"`
	MatchASPathList        string   `yaml:"match_as_path_list"`
	MatchCommunityList     string   `yaml:"match_community_list"`
	MatchCommunityExact    bool     `yaml:"match_community_exact,omitempty"`
	SetLocalPref           *int     `yaml:"set_local_pref,omitempty"`
	SetLocalPrefDelta      *int     `yaml:"set_local_pref_delta,omitempty"`
	SetMED                 *int     `yaml:"set_med,omitempty"`
	SetMEDDelta            *int     `yaml:"set_med_delta,omitempty"`
	SetASPathPrepend       []uint32 `yaml:"set_as_path_prepend,omitempty"`
	SetCommunities         []string `yaml:"set_communities,omitempty"`
	SetCommunityAdditive   bool     `yaml:"set_community_additive,omitempty"`
	SetOriginCode          string   `yaml:"set_origin_code,omitempty"`
}

type Policy struct {
	Name      string `yaml:"name"`
	Node      string `yaml:"node"`
	Plane     string `yaml:"plane"`
	Stage     string `yaml:"stage"`
	Peer      string `yaml:"peer"`
	Action    string `yaml:"action"`
	Protocol  string `yaml:"protocol"`
	DstPrefix Prefix `yaml:"dst_prefix"`
}

type Queries struct {
	RouteChecks   []RouteCheck   `yaml:"route_checks"`
	PacketChecks  []PacketCheck  `yaml:"packet_checks"`
	FailureChecks []FailureCheck `yaml:"failure_checks"`
}

type RouteCheck struct {
	Name        string `yaml:"name"`
	From        string `yaml:"from"`
	Prefix      Prefix `yaml:"prefix"`
	MaxFailures int    `yaml:"max_failures"`
}

type PacketCheck struct {
	Name            string `yaml:"name"`
	From            string `yaml:"from"`
	To              string `yaml:"to"`
	Protocol        string `yaml:"protocol"`
	ExpectReachable *bool  `yaml:"expect_reachable"`
	MaxFailures     int    `yaml:"max_failures"`
}

type FailureCheck struct {
	Name            string `yaml:"name"`
	From            string `yaml:"from"`
	To              string `yaml:"to"`
	Prefix          Prefix `yaml:"prefix"`
	Protocol        string `yaml:"protocol"`
	ExpectReachable *bool  `yaml:"expect_reachable"`
	MaxFailures     int    `yaml:"max_failures"`
}

func LoadQueries(path string) (*Queries, error) {
	var queries Queries
	if err := loadYAML(path, &queries); err != nil {
		return nil, err
	}
	return &queries, nil
}

func loadYAML(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func (t *Topology) Validate() error {
	seen := map[string]bool{}
	for _, n := range t.Nodes {
		if n.Name == "" {
			return fmt.Errorf("node name is required")
		}
		if seen[n.Name] {
			return fmt.Errorf("duplicate node %q", n.Name)
		}
		seen[n.Name] = true
		for _, p := range n.Prefixes {
			if p.IsZero() {
				return fmt.Errorf("node %s has invalid empty prefix", n.Name)
			}
		}
		if n.Loopback != "" {
			if _, err := netip.ParsePrefix(n.Loopback); err != nil {
				return fmt.Errorf("node %s loopback %s: %w", n.Name, n.Loopback, err)
			}
		}
		if err := validateRoutePolicyReferences(n); err != nil {
			return err
		}
	}
	for _, l := range t.Links {
		if l.Name == "" || l.A == "" || l.B == "" {
			return fmt.Errorf("link must have name, a, and b")
		}
		if !seen[l.A] || !seen[l.B] {
			return fmt.Errorf("link %s references unknown node %s-%s", l.Name, l.A, l.B)
		}
		if l.Cost <= 0 {
			return fmt.Errorf("link %s cost must be positive", l.Name)
		}
		if _, err := netip.ParsePrefix(l.Subnet); err != nil {
			return fmt.Errorf("link %s subnet %s: %w", l.Name, l.Subnet, err)
		}
	}
	for _, p := range t.Policies {
		if !seen[p.Node] {
			return fmt.Errorf("policy %s references unknown node %s", p.Name, p.Node)
		}
	}
	return nil
}

func validateRoutePolicyReferences(n Node) error {
	prefixLists := map[string]bool{}
	for _, list := range n.PrefixLists {
		prefixLists[list.Name] = true
	}
	asPathLists := map[string]bool{}
	for _, list := range n.ASPathLists {
		asPathLists[list.Name] = true
	}
	communityLists := map[string]bool{}
	for _, list := range n.CommunityLists {
		communityLists[list.Name] = true
	}
	routePolicies := map[string]bool{}
	for _, policy := range n.RoutePolicies {
		routePolicies[policy.Name] = true
		for _, rule := range policy.Rules {
			if rule.MatchPrefixList != "" && !prefixLists[rule.MatchPrefixList] {
				return fmt.Errorf("node %s route policy %s rule %d references missing prefix-list %s", n.Name, policy.Name, rule.Seq, rule.MatchPrefixList)
			}
			if rule.MatchNextHopPrefixList != "" && !prefixLists[rule.MatchNextHopPrefixList] {
				return fmt.Errorf("node %s route policy %s rule %d references missing next-hop prefix-list %s", n.Name, policy.Name, rule.Seq, rule.MatchNextHopPrefixList)
			}
			if rule.MatchASPathList != "" && !asPathLists[rule.MatchASPathList] {
				return fmt.Errorf("node %s route policy %s rule %d references missing as-path list %s", n.Name, policy.Name, rule.Seq, rule.MatchASPathList)
			}
			if rule.MatchCommunityList != "" && !communityLists[rule.MatchCommunityList] {
				return fmt.Errorf("node %s route policy %s rule %d references missing community-list %s", n.Name, policy.Name, rule.Seq, rule.MatchCommunityList)
			}
		}
	}
	for _, neighbor := range n.Neighbors {
		if neighbor.ImportPolicy != "" && !routePolicies[neighbor.ImportPolicy] {
			return fmt.Errorf("node %s neighbor %s import route policy %s not found", n.Name, neighbor.Address, neighbor.ImportPolicy)
		}
		if neighbor.ExportPolicy != "" && !routePolicies[neighbor.ExportPolicy] {
			return fmt.Errorf("node %s neighbor %s export route policy %s not found", n.Name, neighbor.Address, neighbor.ExportPolicy)
		}
	}
	return nil
}

func (t *Topology) Node(name string) (Node, bool) {
	for _, n := range t.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return Node{}, false
}

func (t *Topology) OriginForPrefix(prefix string) (string, bool) {
	want, err := ParsePrefix(prefix)
	if err != nil {
		return "", false
	}
	for _, n := range t.Nodes {
		for _, got := range n.Prefixes {
			if got.Equal(want) {
				return n.Name, true
			}
		}
	}
	return "", false
}

func (t *Topology) OriginForIP(addr string) (string, Prefix, bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", Prefix{}, false
	}
	var bestNode string
	var bestPrefix Prefix
	for _, n := range t.Nodes {
		for _, pfx := range n.Prefixes {
			if !pfx.Contains(ip) {
				continue
			}
			if bestNode == "" || pfx.Bits() > bestPrefix.Bits() {
				bestNode = n.Name
				bestPrefix = pfx
			}
		}
	}
	return bestNode, bestPrefix, bestNode != ""
}
