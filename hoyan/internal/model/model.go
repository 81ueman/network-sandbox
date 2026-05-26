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
	Name           string              `yaml:"name"`
	ContainerName  string              `yaml:"container_name"`
	Kind           DeviceKind          `yaml:"kind"`
	Role           string              `yaml:"role"`
	ASN            uint32              `yaml:"asn"`
	MgmtIPv4       string              `yaml:"mgmt_ipv4"`
	Loopback       string              `yaml:"loopback"`
	ConfigPath     string              `yaml:"config_path"`
	Prefixes       []Prefix            `yaml:"prefixes"`
	Routes         []ConfiguredRoute   `yaml:"routes,omitempty"`
	Interfaces     []Interface         `yaml:"interfaces"`
	Neighbors      []BGPNeighbor       `yaml:"neighbors"`
	Redistribute   []BGPRedistribution `yaml:"redistribute,omitempty"`
	PrefixLists    []PrefixList        `yaml:"prefix_lists"`
	ASPathLists    []ASPathList        `yaml:"as_path_lists"`
	CommunityLists []CommunityList     `yaml:"community_lists"`
	RoutePolicies  []RoutePolicy       `yaml:"route_policies"`
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
	Role   string `yaml:"role,omitempty"`
	Cost   int    `yaml:"cost"`
	Subnet string `yaml:"subnet"`
	AIntf  string `yaml:"a_intf"`
	BIntf  string `yaml:"b_intf"`
}

type Interface struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

type RouteSourceKind string

const (
	RouteSourceConnected RouteSourceKind = "connected"
	RouteSourceStatic    RouteSourceKind = "static"
	RouteSourceBGP       RouteSourceKind = "bgp"
	RouteSourceAggregate RouteSourceKind = "aggregate"
	RouteSourceBlackhole RouteSourceKind = "blackhole"
)

type ConnectedRouteClass string

const (
	ConnectedRouteClassLink     ConnectedRouteClass = "link"
	ConnectedRouteClassLoopback ConnectedRouteClass = "loopback"
	ConnectedRouteClassService  ConnectedRouteClass = "service"
	ConnectedRouteClassHost     ConnectedRouteClass = "host"
)

type ConfiguredRoute struct {
	Node            string              `yaml:"node,omitempty" json:"node,omitempty"`
	NetworkInstance NetworkInstanceID   `yaml:"network_instance,omitempty" json:"network_instance,omitempty"`
	AFI             AFI                 `yaml:"afi,omitempty" json:"afi,omitempty"`
	Prefix          Prefix              `yaml:"prefix" json:"prefix"`
	NextHop         string              `yaml:"next_hop,omitempty" json:"next_hop,omitempty"`
	Interface       string              `yaml:"interface,omitempty" json:"interface,omitempty"`
	Kind            RouteSourceKind     `yaml:"kind" json:"kind"`
	ConnectedClass  ConnectedRouteClass `yaml:"connected_class,omitempty" json:"connected_class,omitempty"`
	AdminDistance   int                 `yaml:"admin_distance,omitempty" json:"admin_distance,omitempty"`
	Metric          int                 `yaml:"metric,omitempty" json:"metric,omitempty"`
	SummaryOnly     bool                `yaml:"summary_only,omitempty" json:"summary_only,omitempty"`
	Source          PolicySource        `yaml:"source,omitempty" json:"source,omitempty"`
}

type BGPRedistribution struct {
	Kind     RouteSourceKind `yaml:"kind" json:"kind"`
	RouteMap string          `yaml:"route_map,omitempty" json:"route_map,omitempty"`
	Source   PolicySource    `yaml:"source,omitempty" json:"source,omitempty"`
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
	Seq    int       `yaml:"seq"`
	Action string    `yaml:"action"`
	Prefix string    `yaml:"prefix"`
	Ge     int       `yaml:"ge,omitempty"`
	Le     int       `yaml:"le,omitempty"`
	Match  PrefixSet `yaml:"-"`
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
	SetNextHopSelf         bool     `yaml:"set_next_hop_self,omitempty"`
}

type Policy struct {
	Name      string       `yaml:"name"`
	Node      string       `yaml:"node"`
	Plane     string       `yaml:"plane"`
	Stage     string       `yaml:"stage"`
	Interface string       `yaml:"interface,omitempty"`
	Peer      string       `yaml:"peer"`
	Action    string       `yaml:"action"`
	Protocol  string       `yaml:"protocol"`
	SrcPrefix Prefix       `yaml:"src_prefix"`
	DstPrefix Prefix       `yaml:"dst_prefix"`
	SrcPort   PortSet      `yaml:"-"`
	DstPort   PortSet      `yaml:"-"`
	Seq       int          `yaml:"seq,omitempty"`
	Source    PolicySource `yaml:"source,omitempty"`
}

type PolicySource struct {
	Vendor string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	File   string `yaml:"file,omitempty" json:"file,omitempty"`
	Line   int    `yaml:"line,omitempty" json:"line,omitempty"`
	Raw    string `yaml:"raw,omitempty" json:"raw,omitempty"`
}

type Queries struct {
	RouteChecks   []RouteCheck   `yaml:"route_checks"`
	PacketChecks  []PacketCheck  `yaml:"packet_checks"`
	FailureChecks []FailureCheck `yaml:"failure_checks"`
}

type FailureDomain struct {
	IncludeNodeRoles []string `yaml:"include_node_roles"`
	ExcludeNodeRoles []string `yaml:"exclude_node_roles"`
	IncludeLinkRoles []string `yaml:"include_link_roles"`
	ExcludeLinkRoles []string `yaml:"exclude_link_roles"`
	IncludeNodes     []string `yaml:"include_nodes"`
	ExcludeNodes     []string `yaml:"exclude_nodes"`
	IncludeLinks     []string `yaml:"include_links"`
	ExcludeLinks     []string `yaml:"exclude_links"`
}

func (d FailureDomain) IsZero() bool {
	return len(d.IncludeNodeRoles) == 0 &&
		len(d.ExcludeNodeRoles) == 0 &&
		len(d.IncludeLinkRoles) == 0 &&
		len(d.ExcludeLinkRoles) == 0 &&
		len(d.IncludeNodes) == 0 &&
		len(d.ExcludeNodes) == 0 &&
		len(d.IncludeLinks) == 0 &&
		len(d.ExcludeLinks) == 0
}

type RouteCheck struct {
	Name          string        `yaml:"name"`
	From          string        `yaml:"from"`
	Prefix        Prefix        `yaml:"prefix"`
	MaxFailures   int           `yaml:"max_failures"`
	FailureDomain FailureDomain `yaml:"failure_domain"`
}

type PacketCheck struct {
	Name            string        `yaml:"name"`
	From            string        `yaml:"from"`
	To              string        `yaml:"to"`
	Protocol        string        `yaml:"protocol"`
	DstPort         int           `yaml:"dst_port,omitempty"`
	DstPorts        []int         `yaml:"dst_ports,omitempty"`
	LiveProbe       *bool         `yaml:"live_probe,omitempty"`
	ExpectReachable *bool         `yaml:"expect_reachable"`
	MaxFailures     int           `yaml:"max_failures"`
	FailureDomain   FailureDomain `yaml:"failure_domain"`
}

func (c PacketCheck) DstPortValues() []int {
	return normalizedQueryPorts(c.DstPort, c.DstPorts)
}

type FailureCheck struct {
	Name            string        `yaml:"name"`
	From            string        `yaml:"from"`
	To              string        `yaml:"to"`
	Prefix          Prefix        `yaml:"prefix"`
	Protocol        string        `yaml:"protocol"`
	DstPort         int           `yaml:"dst_port,omitempty"`
	DstPorts        []int         `yaml:"dst_ports,omitempty"`
	ExpectReachable *bool         `yaml:"expect_reachable"`
	MaxFailures     int           `yaml:"max_failures"`
	FailureDomain   FailureDomain `yaml:"failure_domain"`
}

func (c FailureCheck) DstPortValues() []int {
	return normalizedQueryPorts(c.DstPort, c.DstPorts)
}

func normalizedQueryPorts(single int, many []int) []int {
	seen := map[int]bool{}
	var out []int
	add := func(port int) {
		if port <= 0 || port > 65535 || seen[port] {
			return
		}
		seen[port] = true
		out = append(out, port)
	}
	add(single)
	for _, port := range many {
		add(port)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
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
	nodes := map[string]Node{}
	for _, n := range t.Nodes {
		if n.Name == "" {
			return fmt.Errorf("node name is required")
		}
		if seen[n.Name] {
			return fmt.Errorf("duplicate node %q", n.Name)
		}
		seen[n.Name] = true
		nodes[n.Name] = n
	}
	for _, n := range t.Nodes {
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
		if err := validateBGPNeighborReferences(n, nodes); err != nil {
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
		if l.AIntf != "" && !hasInterface(nodes[l.A], l.AIntf) {
			return fmt.Errorf("link %s references unknown interface %s on node %s", l.Name, l.AIntf, l.A)
		}
		if l.BIntf != "" && !hasInterface(nodes[l.B], l.BIntf) {
			return fmt.Errorf("link %s references unknown interface %s on node %s", l.Name, l.BIntf, l.B)
		}
	}
	for _, p := range t.Policies {
		if !seen[p.Node] {
			return fmt.Errorf("policy %s references unknown node %s", p.Name, p.Node)
		}
		if p.Peer != "" && !seen[p.Peer] {
			return fmt.Errorf("policy %s references unknown peer node %s", p.Name, p.Peer)
		}
		if p.Interface != "" && !hasInterface(nodes[p.Node], p.Interface) {
			return fmt.Errorf("policy %s references unknown interface %s on node %s", p.Name, p.Interface, p.Node)
		}
		if err := validatePolicy(p); err != nil {
			return err
		}
	}
	return nil
}

func validateRoutePolicyReferences(n Node) error {
	prefixLists := map[string]bool{}
	for _, list := range n.PrefixLists {
		if list.Name == "" {
			return fmt.Errorf("node %s prefix-list name is required", n.Name)
		}
		if prefixLists[list.Name] {
			return fmt.Errorf("node %s has duplicate prefix-list %s", n.Name, list.Name)
		}
		prefixLists[list.Name] = true
		seqs := map[int]bool{}
		for _, rule := range list.Rules {
			if seqs[rule.Seq] {
				return fmt.Errorf("node %s prefix-list %s has duplicate seq %d", n.Name, list.Name, rule.Seq)
			}
			seqs[rule.Seq] = true
			if rule.Action != "permit" && rule.Action != "deny" {
				return fmt.Errorf("node %s prefix-list %s rule %d has invalid action %s", n.Name, list.Name, rule.Seq, rule.Action)
			}
		}
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
		if policy.Name == "" {
			return fmt.Errorf("node %s route policy name is required", n.Name)
		}
		if routePolicies[policy.Name] {
			return fmt.Errorf("node %s has duplicate route policy %s", n.Name, policy.Name)
		}
		routePolicies[policy.Name] = true
		seqs := map[int]bool{}
		for _, rule := range policy.Rules {
			if seqs[rule.Seq] {
				return fmt.Errorf("node %s route policy %s has duplicate seq %d", n.Name, policy.Name, rule.Seq)
			}
			seqs[rule.Seq] = true
			if rule.Action != "permit" && rule.Action != "deny" {
				return fmt.Errorf("node %s route policy %s rule %d has invalid action %s", n.Name, policy.Name, rule.Seq, rule.Action)
			}
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

func validateBGPNeighborReferences(n Node, nodes map[string]Node) error {
	neighborAddresses := map[string]bool{}
	neighborPeers := map[string]bool{}
	for _, neighbor := range n.Neighbors {
		if neighbor.Address != "" {
			if _, err := netip.ParseAddr(neighbor.Address); err != nil {
				return fmt.Errorf("node %s neighbor %s has invalid address: %w", n.Name, neighbor.Address, err)
			}
			if neighborAddresses[neighbor.Address] {
				return fmt.Errorf("node %s has duplicate neighbor address %s", n.Name, neighbor.Address)
			}
			neighborAddresses[neighbor.Address] = true
		}
		if neighbor.PeerNode != "" {
			peer, ok := nodes[neighbor.PeerNode]
			if !ok {
				return fmt.Errorf("node %s neighbor %s references unknown peer node %s", n.Name, neighborLabel(neighbor), neighbor.PeerNode)
			}
			if neighborPeers[neighbor.PeerNode] {
				return fmt.Errorf("node %s has duplicate neighbor peer node %s", n.Name, neighbor.PeerNode)
			}
			neighborPeers[neighbor.PeerNode] = true
			if neighbor.Address != "" && !nodeOwnsAddress(peer, neighbor.Address) {
				return fmt.Errorf("node %s neighbor %s address is not on peer node %s", n.Name, neighbor.Address, neighbor.PeerNode)
			}
		}
		if neighbor.Activated && neighbor.RemoteAS == 0 {
			return fmt.Errorf("node %s neighbor %s is activated with remote_as 0", n.Name, neighborLabel(neighbor))
		}
	}
	return nil
}

func validatePolicy(p Policy) error {
	if p.Action != "deny" {
		return fmt.Errorf("policy %s has invalid action %s", p.Name, p.Action)
	}
	if p.Plane != "" && p.Plane != "control" && p.Plane != "data" {
		return fmt.Errorf("policy %s has invalid plane %s", p.Name, p.Plane)
	}
	if p.Stage != "" && p.Stage != "ingress" && p.Stage != "egress" {
		return fmt.Errorf("policy %s has invalid stage %s", p.Name, p.Stage)
	}
	switch p.Protocol {
	case "", "bgp", "icmp", "tcp", "udp":
	default:
		return fmt.Errorf("policy %s has invalid protocol %s", p.Name, p.Protocol)
	}
	return nil
}

func hasInterface(n Node, name string) bool {
	for _, iface := range n.Interfaces {
		if EquivalentInterfaceName(n.Kind, iface.Name, name) {
			return true
		}
	}
	return false
}

func nodeOwnsAddress(n Node, addr string) bool {
	for _, iface := range n.Interfaces {
		pfx, err := netip.ParsePrefix(iface.Address)
		if err == nil && pfx.Addr().String() == addr {
			return true
		}
	}
	if n.Loopback != "" {
		pfx, err := netip.ParsePrefix(n.Loopback)
		if err == nil && pfx.Addr().String() == addr {
			return true
		}
	}
	return false
}

func neighborLabel(n BGPNeighbor) string {
	if n.Address != "" {
		return n.Address
	}
	if n.PeerNode != "" {
		return n.PeerNode
	}
	return "<unnamed>"
}

func (t *Topology) Node(name string) (Node, bool) {
	idx, err := BuildTopologyIndex(t)
	if err != nil {
		return Node{}, false
	}
	return idx.Node(name)
}

func (t *Topology) OriginForPrefix(prefix string) (string, bool) {
	idx, err := BuildTopologyIndex(t)
	if err != nil {
		return "", false
	}
	return idx.OriginForPrefix(prefix)
}

func (t *Topology) OriginForIP(addr string) (string, Prefix, bool) {
	idx, err := BuildTopologyIndex(t)
	if err != nil {
		return "", Prefix{}, false
	}
	return idx.OriginForIP(addr)
}
