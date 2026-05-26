package model

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadLabTopology(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	if len(topo.Nodes) != 18 {
		t.Fatalf("nodes = %d, want 18", len(topo.Nodes))
	}
	if len(topo.Links) < 25 {
		t.Fatalf("links = %d, want at least 25", len(topo.Links))
	}
	if _, ok := topo.Node("core-sh"); !ok {
		t.Fatalf("core-sh not found")
	}
	core, _ := topo.Node("core-bj")
	if core.ASN != 65100 {
		t.Fatalf("core-bj ASN = %d, want parsed 65100", core.ASN)
	}
	if len(core.Neighbors) == 0 {
		t.Fatalf("core-bj neighbors were not parsed from config")
	}
}

func TestLoadQueriesIncludesFailureDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queries.yml")
	if err := os.WriteFile(path, []byte(`
route_checks:
  - name: explicit-domain
    from: edge
    prefix: 10.0.0.0/24
    max_failures: 1
    failure_domain:
      include_node_roles: [core]
      exclude_node_roles: [customer]
      include_link_roles: [backbone]
      exclude_link_roles: [access]
      include_nodes: [core1]
      exclude_nodes: [client1]
      include_links: [core1-core2]
      exclude_links: [edge-client1]
packet_checks:
  - name: multi-port
    from: src
    to: 10.0.0.10
    protocol: tcp
    dst_ports: [80, 443]
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	queries, err := LoadQueries(path)
	if err != nil {
		t.Fatalf("LoadQueries() error = %v", err)
	}
	got := queries.RouteChecks[0].FailureDomain
	if !reflect.DeepEqual(got.IncludeNodeRoles, []string{"core"}) ||
		!reflect.DeepEqual(got.ExcludeNodeRoles, []string{"customer"}) ||
		!reflect.DeepEqual(got.IncludeLinkRoles, []string{"backbone"}) ||
		!reflect.DeepEqual(got.ExcludeLinkRoles, []string{"access"}) ||
		!reflect.DeepEqual(got.IncludeNodes, []string{"core1"}) ||
		!reflect.DeepEqual(got.ExcludeNodes, []string{"client1"}) ||
		!reflect.DeepEqual(got.IncludeLinks, []string{"core1-core2"}) ||
		!reflect.DeepEqual(got.ExcludeLinks, []string{"edge-client1"}) {
		t.Fatalf("FailureDomain = %#v", got)
	}
	if ports := queries.PacketChecks[0].DstPortValues(); !reflect.DeepEqual(ports, []int{80, 443}) {
		t.Fatalf("DstPortValues() = %#v, want [80 443]", ports)
	}
}

func TestLoadLabTopologyIncludesRouteMaps(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	coreBJ, ok := topo.Node("core-bj")
	if !ok {
		t.Fatalf("core-bj not found")
	}
	if prefixListByName(coreBJ.PrefixLists, "BJ-LOCAL") == nil {
		t.Fatalf("core-bj BJ-LOCAL prefix-list not loaded: %#v", coreBJ.PrefixLists)
	}
	if routePolicyByName(coreBJ.RoutePolicies, "PREFER-BJ-LOCAL") == nil {
		t.Fatalf("core-bj PREFER-BJ-LOCAL route policy not loaded: %#v", coreBJ.RoutePolicies)
	}
	for _, addr := range []string{"198.18.10.0", "198.18.10.2"} {
		neighbor := neighborByAddress(coreBJ.Neighbors, addr)
		if neighbor == nil || neighbor.ImportPolicy != "PREFER-BJ-LOCAL" {
			t.Fatalf("core-bj neighbor %s = %#v, want import policy PREFER-BJ-LOCAL", addr, neighbor)
		}
	}
	coreHZ, ok := topo.Node("core-hz")
	if !ok {
		t.Fatalf("core-hz not found")
	}
	if prefixListByName(coreHZ.PrefixLists, "HZ-LOCAL") == nil {
		t.Fatalf("core-hz HZ-LOCAL prefix-list not loaded: %#v", coreHZ.PrefixLists)
	}
	if routePolicyByName(coreHZ.RoutePolicies, "HZ-TRANSIT-OUT") == nil {
		t.Fatalf("core-hz HZ-TRANSIT-OUT route policy not loaded: %#v", coreHZ.RoutePolicies)
	}
	neighbor := neighborByAddress(coreHZ.Neighbors, "198.18.30.7")
	if neighbor == nil || neighbor.ExportPolicy != "HZ-TRANSIT-OUT" {
		t.Fatalf("core-hz neighbor 198.18.30.7 = %#v, want export policy HZ-TRANSIT-OUT", neighbor)
	}
	coreSH, ok := topo.Node("core-sh")
	if !ok {
		t.Fatalf("core-sh not found")
	}
	if prefixListByName(coreSH.PrefixLists, "SH-LOCAL") == nil {
		t.Fatalf("core-sh SH-LOCAL prefix-list not loaded: %#v", coreSH.PrefixLists)
	}
	if routePolicyByName(coreSH.RoutePolicies, "PREFER-SH-LOCAL") == nil || routePolicyByName(coreSH.RoutePolicies, "SH-TRANSIT-OUT") == nil {
		t.Fatalf("core-sh route policies not loaded: %#v", coreSH.RoutePolicies)
	}
	for _, addr := range []string{"198.18.10.4", "198.18.10.6"} {
		neighbor := neighborByAddress(coreSH.Neighbors, addr)
		if neighbor == nil || neighbor.ImportPolicy != "PREFER-SH-LOCAL" {
			t.Fatalf("core-sh neighbor %s = %#v, want import policy PREFER-SH-LOCAL", addr, neighbor)
		}
	}
	neighbor = neighborByAddress(coreSH.Neighbors, "198.18.30.3")
	if neighbor == nil || neighbor.ExportPolicy != "SH-TRANSIT-OUT" {
		t.Fatalf("core-sh neighbor 198.18.30.3 = %#v, want export policy SH-TRANSIT-OUT", neighbor)
	}
}

func TestLoadLabTopologyIncludesACLPoliciesWithoutPolicyFile(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	for _, tt := range []struct {
		node  string
		iface string
	}{
		{node: "core-hz", iface: "eth1"},
		{node: "core-hz", iface: "eth2"},
		{node: "core-sh", iface: "Ethernet5"},
		{node: "core-gz", iface: "ethernet-1/4.0"},
	} {
		acl, binding := aclByNodeInterface(topo, tt.node, tt.iface)
		if acl == nil || binding == nil {
			t.Fatalf("acl for %s %s not found in ACLs=%#v bindings=%#v", tt.node, tt.iface, topo.ACLs, topo.ACLBindings)
		}
		if acl.Name != "BLOCK-HTTP-TO-HZ" || binding.Direction != "egress" || len(acl.Rules) == 0 || acl.Rules[0].Action != ACLDeny || acl.Rules[0].Match.Protocol != "tcp" {
			t.Fatalf("acl for %s %s = %#v binding=%#v", tt.node, tt.iface, acl, binding)
		}
		if acl.Rules[0].Match.DstSet == nil || !acl.Rules[0].Match.DstPort.Contains(80) {
			t.Fatalf("acl first rule match = %#v, want dst 10.4.0.0/16 tcp/80", acl.Rules[0].Match)
		}
		if acl.Rules[0].Source.File == "" || acl.Rules[0].Source.Line == 0 || acl.Rules[0].Source.Raw == "" {
			t.Fatalf("acl rule source not populated: %#v", acl.Rules[0].Source)
		}
		if tt.node == "core-hz" && acl.Source.Vendor != "nftables" {
			t.Fatalf("core-hz acl source vendor = %q, want nftables", acl.Source.Vendor)
		}
	}
}

func TestOriginLookups(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	node, ok := topo.OriginForPrefix("10.4.0.0/16")
	if !ok || node != "hz-edge1" {
		t.Fatalf("OriginForPrefix() = %q, %v", node, ok)
	}
	node, pfx, ok := topo.OriginForIP("10.4.1.10")
	if !ok || node != "cust-hz" || pfx.String() != "10.4.1.10/32" {
		t.Fatalf("OriginForIP() = %q %s %v", node, pfx, ok)
	}
}

func TestOriginLookupsUseTypedCanonicalPrefixes(t *testing.T) {
	topo := &Topology{Nodes: []Node{
		{Name: "origin", Prefixes: MustPrefixes("10.0.0.1/24")},
	}}
	if err := topo.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	node, ok := topo.OriginForPrefix("10.0.0.0/24")
	if !ok || node != "origin" {
		t.Fatalf("OriginForPrefix() = %q, %v", node, ok)
	}
	node, pfx, ok := topo.OriginForIP("10.0.0.99")
	if !ok || node != "origin" || pfx.String() != "10.0.0.0/24" {
		t.Fatalf("OriginForIP() = %q %s %v", node, pfx, ok)
	}
}

func TestParseFRRConfig(t *testing.T) {
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "labs", "base-wan", "configs", "frr", "bj-edge1", "frr.conf"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65001 || cfg.RouterID != "10.255.1.1" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Interfaces) != 4 {
		t.Fatalf("interfaces = %d, want 4", len(cfg.Interfaces))
	}
	if len(cfg.Neighbors) != 3 {
		t.Fatalf("neighbors = %d, want 3", len(cfg.Neighbors))
	}
}

func TestParseNftablesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.WriteFile(path, []byte(`table inet BLOCK_HTTP_TO_HZ {
  chain forward {
    type filter hook forward priority 0; policy accept;
    oifname "eth1" ip protocol tcp ip daddr 10.4.0.0/16 tcp dport 80 drop
    iifname "eth2" ip protocol icmp ip daddr 10.5.0.0/16 drop
  }
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	acls, bindings, err := ParseNftablesACLConfig(path)
	if err != nil {
		t.Fatalf("ParseNftablesACLConfig() error = %v", err)
	}
	if len(acls) != 1 || len(acls[0].Rules) != 2 {
		t.Fatalf("ACLs = %#v, want one ACL with two rules", acls)
	}
	acl := acls[0]
	if acl.Name != "BLOCK-HTTP-TO-HZ" || acl.DefaultAction != ACLDefaultPermit {
		t.Fatalf("acl metadata = %#v", acl)
	}
	if acl.Rules[0].Match.Protocol != "tcp" || acl.Rules[0].Action != ACLDeny || !acl.Rules[0].Match.DstPort.Contains(80) {
		t.Fatalf("first rule = %#v", acl.Rules[0])
	}
	if len(bindings) != 2 || bindings[0].Direction != "egress" || bindings[0].Interface != "eth1" || bindings[1].Direction != "ingress" || bindings[1].Interface != "eth2" {
		t.Fatalf("bindings = %#v", bindings)
	}
	if acl.Rules[0].Source.Vendor != "nftables" || acl.Rules[0].Source.File != path || acl.Rules[0].Source.Raw == "" {
		t.Fatalf("source = %#v", acl.Rules[0].Source)
	}
}

func TestParseFRRLikeACLsBuildNormalizedIRWithPermitAndBinding(t *testing.T) {
	cfg := parseCEOSConfigText(t, `
hostname r1
interface Ethernet1
   no switchport
   ip address 192.0.2.1/31
   ip access-group WEB-FILTER out
!
ip access-list WEB-FILTER
   10 permit tcp any 10.0.0.0/24 eq 443
   20 deny tcp any 10.0.0.0/24 eq 80
!
`)
	if len(cfg.ACLs) != 1 {
		t.Fatalf("ACLs = %#v, want one ACL", cfg.ACLs)
	}
	acl := cfg.ACLs[0]
	if acl.Name != "WEB-FILTER" || acl.Vendor != KindCEOS || acl.DefaultAction != ACLDefaultDeny {
		t.Fatalf("ACL metadata = %#v", acl)
	}
	if len(acl.Rules) != 2 || acl.Rules[0].Action != ACLPermit || acl.Rules[0].Seq != 10 || acl.Rules[1].Action != ACLDeny || acl.Rules[1].Seq != 20 {
		t.Fatalf("ACL rules = %#v, want permit seq 10 then deny seq 20", acl.Rules)
	}
	if acl.Rules[0].Match.Protocol != "tcp" || !acl.Rules[0].Match.DstPort.Contains(443) {
		t.Fatalf("permit rule match = %#v, want tcp/443", acl.Rules[0].Match)
	}
	if len(cfg.ACLBindings) != 1 || cfg.ACLBindings[0].ACLName != "WEB-FILTER" || cfg.ACLBindings[0].Interface != "Ethernet1" || cfg.ACLBindings[0].Direction != "egress" {
		t.Fatalf("ACL bindings = %#v", cfg.ACLBindings)
	}
}

func TestParseNftablesRejectsUnsupportedStatement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.WriteFile(path, []byte(`table inet T {
  chain forward {
    type filter hook forward priority 0; policy accept;
    oifname "eth1" ip saddr 10.0.0.0/8 drop
  }
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, _, err := ParseNftablesACLConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported nftables ip match") {
		t.Fatalf("ParseNftablesACLConfig() error = %v", err)
	}
}

func TestParseCoreBJRouteMapConfig(t *testing.T) {
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "labs", "base-wan", "configs", "frr", "core-bj", "frr.conf"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if prefixListByName(cfg.PrefixLists, "BJ-LOCAL") == nil {
		t.Fatalf("BJ-LOCAL prefix-list not parsed: %#v", cfg.PrefixLists)
	}
	policy := routePolicyByName(cfg.RoutePolicies, "PREFER-BJ-LOCAL")
	if policy == nil || len(policy.Rules) != 3 || policy.Rules[0].SetLocalPrefDelta == nil || *policy.Rules[0].SetLocalPrefDelta != 125 || policy.Rules[1].SetLocalPref == nil || *policy.Rules[1].SetLocalPref != 200 {
		t.Fatalf("PREFER-BJ-LOCAL = %#v", policy)
	}
	if asPathListByName(cfg.ASPathLists, "FROM-BJ") == nil {
		t.Fatalf("FROM-BJ as-path list not parsed: %#v", cfg.ASPathLists)
	}
	if communityListByName(cfg.CommunityLists, "BJ-DIRECT") == nil {
		t.Fatalf("BJ-DIRECT community-list not parsed: %#v", cfg.CommunityLists)
	}
	for _, addr := range []string{"198.18.10.0", "198.18.10.2"} {
		neighbor := neighborByAddress(cfg.Neighbors, addr)
		if neighbor == nil || neighbor.ImportPolicy != "PREFER-BJ-LOCAL" {
			t.Fatalf("neighbor %s = %#v", addr, neighbor)
		}
	}
}

func TestParseFRRRouteMaps(t *testing.T) {
	config := `
hostname r1
ip prefix-list PL-IN seq 10 permit 10.0.0.0/24
ip prefix-list PL-OUT permit 10.0.1.0/24
route-map RM-IN permit 10
 match ip address prefix-list PL-IN
 set local-preference 250
route-map RM-OUT permit 20
 match ip address prefix-list PL-OUT
 set metric 77
 set as-path prepend 65002 65002
 set community 65001:100 additive
 set origin incomplete
route-map RM-DENY deny 30
 match ip address prefix-list PL-IN
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
 address-family ipv4 unicast
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.1 route-map RM-IN in
  neighbor 192.0.2.1 route-map RM-OUT out
 exit-address-family
`
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg, err := ParseConfig("frr", path)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if got, want := prefixListsWithoutMatches(cfg.PrefixLists), []PrefixList{
		{Name: "PL-IN", Rules: []PrefixListRule{{Seq: 10, Action: "permit", Prefix: "10.0.0.0/24"}}},
		{Name: "PL-OUT", Rules: []PrefixListRule{{Seq: 0, Action: "permit", Prefix: "10.0.1.0/24"}}},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PrefixLists = %#v, want %#v", got, want)
	}
	if len(cfg.RoutePolicies) != 3 {
		t.Fatalf("RoutePolicies = %#v, want 3 policies", cfg.RoutePolicies)
	}
	rmIn := routePolicyByName(cfg.RoutePolicies, "RM-IN")
	if rmIn == nil || len(rmIn.Rules) != 1 || rmIn.Rules[0].MatchPrefixList != "PL-IN" || rmIn.Rules[0].SetLocalPref == nil || *rmIn.Rules[0].SetLocalPref != 250 {
		t.Fatalf("RM-IN = %#v", rmIn)
	}
	rmOut := routePolicyByName(cfg.RoutePolicies, "RM-OUT")
	if rmOut == nil || len(rmOut.Rules) != 1 || rmOut.Rules[0].MatchPrefixList != "PL-OUT" || rmOut.Rules[0].SetMED == nil || *rmOut.Rules[0].SetMED != 77 || !reflect.DeepEqual(rmOut.Rules[0].SetASPathPrepend, []uint32{65002, 65002}) || !reflect.DeepEqual(rmOut.Rules[0].SetCommunities, []string{"65001:100"}) || !rmOut.Rules[0].SetCommunityAdditive || rmOut.Rules[0].SetOriginCode != "incomplete" {
		t.Fatalf("RM-OUT = %#v", rmOut)
	}
	rmDeny := routePolicyByName(cfg.RoutePolicies, "RM-DENY")
	if rmDeny == nil || len(rmDeny.Rules) != 1 || rmDeny.Rules[0].Action != "deny" || rmDeny.Rules[0].MatchPrefixList != "PL-IN" {
		t.Fatalf("RM-DENY = %#v", rmDeny)
	}
	if len(cfg.Neighbors) != 1 || cfg.Neighbors[0].ImportPolicy != "RM-IN" || cfg.Neighbors[0].ExportPolicy != "RM-OUT" {
		t.Fatalf("Neighbors = %#v", cfg.Neighbors)
	}
}

func TestParseFRRRouteMapWithoutMatchIsMatchAny(t *testing.T) {
	cfg := parseFRRConfigText(t, `
route-map RM permit 10
 set metric 12
`)
	policy := routePolicyByName(cfg.RoutePolicies, "RM")
	if policy == nil || len(policy.Rules) != 1 || policy.Rules[0].MatchPrefixList != "" || policy.Rules[0].SetMED == nil || *policy.Rules[0].SetMED != 12 {
		t.Fatalf("RM = %#v", policy)
	}
}

func TestParseFRRRouteMapRejectsUnsupportedMatch(t *testing.T) {
	for _, stmt := range []string{
		"match source-protocol bgp",
		"match ip next-hop address 192.0.2.1",
	} {
		t.Run(stmt, func(t *testing.T) {
			_, err := parseFRRConfigTextResult(t, "route-map RM permit 10\n "+stmt+"\n set local-preference 200\n")
			if err == nil || !strings.Contains(err.Error(), "unsupported FRR route-map match statement") {
				t.Fatalf("ParseConfig() error = %v, want unsupported match", err)
			}
		})
	}
}

func TestParseConfigWithWarningsReportsUnsupportedFRRRouteMapStatements(t *testing.T) {
	config := `
hostname r1
route-map RM permit 10
 match source-protocol bgp
 set weight 50
 set local-preference 200
`
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	result, err := ParseConfigWithWarnings("frr", path)
	if err != nil {
		t.Fatalf("ParseConfigWithWarnings() error = %v", err)
	}
	if result.Config.Hostname != "r1" {
		t.Fatalf("Hostname = %q, want r1", result.Config.Hostname)
	}
	policy := routePolicyByName(result.Config.RoutePolicies, "RM")
	if policy == nil || len(policy.Rules) != 1 || policy.Rules[0].SetLocalPref == nil || *policy.Rules[0].SetLocalPref != 200 {
		t.Fatalf("RM = %#v", policy)
	}
	want := []UnsupportedStatement{
		{Vendor: "frr", File: path, Line: 4, Text: "match source-protocol bgp", Reason: "unsupported FRR route-map match statement"},
		{Vendor: "frr", File: path, Line: 5, Text: "set weight 50", Reason: "unsupported FRR route-map statement"},
	}
	if !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("Warnings = %#v, want %#v", result.Warnings, want)
	}
}

func TestLoadLabTopologyStrictConfigRejectsUnsupportedStatements(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(configPath, []byte(`
hostname r1
route-map RM permit 10
 match source-protocol bgp
 set local-preference 200
`), 0o644); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	topologyPath := filepath.Join(dir, "lab.clab.yml")
	if err := os.WriteFile(topologyPath, []byte(`name: strict-test
topology:
  nodes:
    r1:
      kind: linux
      binds:
        - frr.conf:/etc/frr/frr.conf
`), 0o644); err != nil {
		t.Fatalf("WriteFile(topology) error = %v", err)
	}

	topo, warnings, err := LoadLabTopologyWithOptions(topologyPath, LoadLabTopologyOptions{CollectWarnings: true})
	if err != nil {
		t.Fatalf("LoadLabTopologyWithOptions(non-strict) error = %v", err)
	}
	if topo == nil || len(warnings) != 1 {
		t.Fatalf("non-strict topology=%#v warnings=%#v, want topology and one warning", topo, warnings)
	}

	_, warnings, err = LoadLabTopologyWithOptions(topologyPath, LoadLabTopologyOptions{StrictConfig: true})
	if err == nil {
		t.Fatalf("LoadLabTopologyWithOptions(strict) error = nil")
	}
	if len(warnings) != 1 {
		t.Fatalf("strict warnings = %#v, want one", warnings)
	}
	msg := err.Error()
	for _, want := range []string{"vendor=frr", "file=" + configPath, "line=4", `raw="match source-protocol bgp"`, "reason=unsupported FRR route-map match statement"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("strict error missing %q:\n%s", want, msg)
		}
	}
}

func TestParseSRLinuxRoutingPolicies(t *testing.T) {
	config := `
set / system name host-name core1
set / network-instance default protocols bgp autonomous-system 65100
set / routing-policy prefix-set LOCAL prefix 10.0.0.0/24 mask-length-range 24..32
set / routing-policy policy IMPORT statement 10 match prefix prefix-set LOCAL
set / routing-policy policy IMPORT statement 10 action bgp local-preference set 250
set / routing-policy policy IMPORT statement 10 action policy-result accept
set / routing-policy policy EXPORT statement 20 action bgp med operation set value 77
set / routing-policy policy EXPORT statement 20 action policy-result accept
set / routing-policy policy REJECT-ALL default-action policy-result reject
set / network-instance default protocols bgp group edge import-policy [ IMPORT ]
set / network-instance default protocols bgp group edge export-policy [ EXPORT ]
set / network-instance default protocols bgp group edge peer-as 65001
set / network-instance default protocols bgp neighbor 192.0.2.1 peer-group edge
set / network-instance default protocols bgp neighbor 192.0.2.1 export-policy [ REJECT-ALL ]
`
	path := filepath.Join(t.TempDir(), "core.cfg")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg, err := ParseConfig("srlinux", path)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.Hostname != "core1" || cfg.ASN != 65100 {
		t.Fatalf("Config = %#v", cfg)
	}
	if got, want := prefixListsWithoutMatches(cfg.PrefixLists), []PrefixList{{Name: "LOCAL", Rules: []PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24", Le: 32}}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PrefixLists = %#v, want %#v", got, want)
	}
	importPolicy := routePolicyByName(cfg.RoutePolicies, "IMPORT")
	if importPolicy == nil || len(importPolicy.Rules) != 2 || importPolicy.Rules[0].Action != "permit" || importPolicy.Rules[0].MatchPrefixList != "LOCAL" || importPolicy.Rules[0].SetLocalPref == nil || *importPolicy.Rules[0].SetLocalPref != 250 || importPolicy.Rules[1].Action != "permit" {
		t.Fatalf("IMPORT = %#v", importPolicy)
	}
	exportPolicy := routePolicyByName(cfg.RoutePolicies, "EXPORT")
	if exportPolicy == nil || len(exportPolicy.Rules) != 2 || exportPolicy.Rules[0].Action != "permit" || exportPolicy.Rules[0].SetMED == nil || *exportPolicy.Rules[0].SetMED != 77 || exportPolicy.Rules[1].Action != "permit" {
		t.Fatalf("EXPORT = %#v", exportPolicy)
	}
	rejectPolicy := routePolicyByName(cfg.RoutePolicies, "REJECT-ALL")
	if rejectPolicy == nil || len(rejectPolicy.Rules) != 1 || rejectPolicy.Rules[0].Action != "deny" {
		t.Fatalf("REJECT-ALL = %#v", rejectPolicy)
	}
	if len(cfg.Neighbors) != 1 || cfg.Neighbors[0].ImportPolicy != "IMPORT" || cfg.Neighbors[0].ExportPolicy != "REJECT-ALL" {
		t.Fatalf("Neighbors = %#v, want group import and neighbor export override", cfg.Neighbors)
	}
}

func TestParseSRLinuxRoutingPolicyRejectsUnsupportedMatch(t *testing.T) {
	config := `
set / routing-policy policy IMPORT statement 10 match protocol bgp
set / routing-policy policy IMPORT statement 10 action policy-result accept
`
	path := filepath.Join(t.TempDir(), "core.cfg")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := ParseConfig("srlinux", path)
	if err == nil || !strings.Contains(err.Error(), "unsupported SR Linux routing-policy statement") {
		t.Fatalf("ParseConfig() error = %v, want unsupported SR Linux routing-policy statement", err)
	}
	result, err := ParseConfigWithWarnings("srlinux", path)
	if err != nil {
		t.Fatalf("ParseConfigWithWarnings() error = %v", err)
	}
	want := []UnsupportedStatement{{Vendor: "srlinux", File: path, Line: 2, Text: "set / routing-policy policy IMPORT statement 10 match protocol bgp", Reason: "unsupported SR Linux routing-policy statement"}}
	if !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("Warnings = %#v, want %#v", result.Warnings, want)
	}
	policy := routePolicyByName(result.Config.RoutePolicies, "IMPORT")
	if policy == nil || len(policy.Rules) != 2 || policy.Rules[0].MatchPrefixList == "" {
		t.Fatalf("unsupported match should not become match-any: %#v", policy)
	}
}

func TestParseConfigWithWarningsCurrentLabConfigs(t *testing.T) {
	tests := []struct {
		kind DeviceKind
		glob string
	}{
		{kind: KindFRR, glob: filepath.Join("..", "..", "labs", "base-wan", "configs", "frr", "*", "frr.conf")},
		{kind: KindCEOS, glob: filepath.Join("..", "..", "labs", "base-wan", "configs", "ceos", "*.cfg")},
		{kind: KindSRLinux, glob: filepath.Join("..", "..", "labs", "base-wan", "configs", "srlinux", "*.cfg")},
	}
	for _, tt := range tests {
		paths, err := filepath.Glob(tt.glob)
		if err != nil {
			t.Fatalf("Glob(%q) error = %v", tt.glob, err)
		}
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				result, err := ParseConfigWithWarnings(tt.kind, path)
				if err != nil {
					t.Fatalf("ParseConfigWithWarnings() error = %v", err)
				}
				if len(result.Warnings) != 0 {
					t.Fatalf("Warnings = %#v, want none", result.Warnings)
				}
			})
		}
	}
}

func TestParseFRRRouteMapMatchExtensions(t *testing.T) {
	cfg := parseFRRConfigText(t, `
bgp as-path access-list FROM-BJ permit ^65001$
bgp community-list standard BJ-COMM permit 65001:100
ip prefix-list NH seq 10 permit 198.18.10.0/30
route-map RM permit 10
 match as-path FROM-BJ
 match community BJ-COMM exact-match
 match ip next-hop prefix-list NH
 set local-preference +50
 set metric -10
`)
	if got, want := cfg.ASPathLists, []ASPathList{{Name: "FROM-BJ", Rules: []StringListRule{{Action: "permit", Pattern: "^65001$"}}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ASPathLists = %#v, want %#v", got, want)
	}
	if got, want := cfg.CommunityLists, []CommunityList{{Name: "BJ-COMM", Rules: []StringListRule{{Action: "permit", Pattern: "65001:100"}}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CommunityLists = %#v, want %#v", got, want)
	}
	policy := routePolicyByName(cfg.RoutePolicies, "RM")
	if policy == nil || len(policy.Rules) != 1 {
		t.Fatalf("RM = %#v", policy)
	}
	rule := policy.Rules[0]
	if rule.MatchASPathList != "FROM-BJ" || rule.MatchCommunityList != "BJ-COMM" || !rule.MatchCommunityExact || rule.MatchNextHopPrefixList != "NH" {
		t.Fatalf("match fields = %#v", rule)
	}
	if rule.SetLocalPrefDelta == nil || *rule.SetLocalPrefDelta != 50 || rule.SetMEDDelta == nil || *rule.SetMEDDelta != -10 {
		t.Fatalf("delta fields = %#v", rule)
	}
}

func TestParseFRRRouteMapSetIPAddressNextHop(t *testing.T) {
	cfg := parseFRRConfigText(t, `
route-map RM permit 10
 set ip next-hop 192.0.2.1
`)
	policy := routePolicyByName(cfg.RoutePolicies, "RM")
	if policy == nil || len(policy.Rules) != 1 {
		t.Fatalf("RM = %#v", policy)
	}
	if got := policy.Rules[0].SetNextHop; got != "192.0.2.1" {
		t.Fatalf("SetNextHop = %q, want 192.0.2.1", got)
	}
}

func TestParseFRRPrefixListDenyAndOrder(t *testing.T) {
	cfg := parseFRRConfigText(t, `
ip prefix-list PL seq 20 permit 10.1.0.0/16
ip prefix-list PL seq 10 deny 10.0.0.0/8
`)
	got := prefixListsWithoutMatches(cfg.PrefixLists)
	want := []PrefixList{{Name: "PL", Rules: []PrefixListRule{
		{Seq: 10, Action: "deny", Prefix: "10.0.0.0/8"},
		{Seq: 20, Action: "permit", Prefix: "10.1.0.0/16"},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PrefixLists = %#v, want %#v", got, want)
	}
}

func TestParseFRRPrefixListLeGe(t *testing.T) {
	cfg := parseFRRConfigText(t, `
ip prefix-list PL permit any
ip prefix-list PL seq 10 permit 10.0.0.0/8 ge 16 le 24
`)
	got := prefixListsWithoutMatches(cfg.PrefixLists)
	want := []PrefixList{{Name: "PL", Rules: []PrefixListRule{
		{Seq: 0, Action: "permit", Prefix: "any"},
		{Seq: 10, Action: "permit", Prefix: "10.0.0.0/8", Ge: 16, Le: 24},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PrefixLists = %#v, want %#v", got, want)
	}
}

func prefixListsWithoutMatches(in []PrefixList) []PrefixList {
	out := make([]PrefixList, len(in))
	for i, prefixList := range in {
		out[i] = prefixList
		out[i].Rules = append([]PrefixListRule(nil), prefixList.Rules...)
		for j := range out[i].Rules {
			out[i].Rules[j].Match = nil
		}
	}
	return out
}

func TestValidateRejectsMissingRoutePolicyReferences(t *testing.T) {
	tests := []struct {
		name     string
		neighbor BGPNeighbor
		want     string
	}{
		{
			name:     "import",
			neighbor: BGPNeighbor{Address: "192.0.2.1", ImportPolicy: "MISSING"},
			want:     "node r1 neighbor 192.0.2.1 import route policy MISSING not found",
		},
		{
			name:     "export",
			neighbor: BGPNeighbor{Address: "192.0.2.1", ExportPolicy: "MISSING"},
			want:     "node r1 neighbor 192.0.2.1 export route policy MISSING not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := &Topology{
				Nodes: []Node{{Name: "r1", Neighbors: []BGPNeighbor{tt.neighbor}}},
			}
			err := topo.Validate()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsMissingRouteMapMatchReferences(t *testing.T) {
	tests := []struct {
		name string
		rule RoutePolicyRule
		want string
	}{
		{
			name: "prefix-list",
			rule: RoutePolicyRule{Seq: 10, Action: "permit", MatchPrefixList: "MISSING"},
			want: "node r1 route policy RM rule 10 references missing prefix-list MISSING",
		},
		{
			name: "next-hop-prefix-list",
			rule: RoutePolicyRule{Seq: 10, Action: "permit", MatchNextHopPrefixList: "MISSING"},
			want: "node r1 route policy RM rule 10 references missing next-hop prefix-list MISSING",
		},
		{
			name: "as-path",
			rule: RoutePolicyRule{Seq: 10, Action: "permit", MatchASPathList: "MISSING"},
			want: "node r1 route policy RM rule 10 references missing as-path list MISSING",
		},
		{
			name: "community",
			rule: RoutePolicyRule{Seq: 10, Action: "permit", MatchCommunityList: "MISSING"},
			want: "node r1 route policy RM rule 10 references missing community-list MISSING",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := &Topology{Nodes: []Node{{Name: "r1", RoutePolicies: []RoutePolicy{{Name: "RM", Rules: []RoutePolicyRule{tt.rule}}}}}}
			err := topo.Validate()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsInvalidACLFields(t *testing.T) {
	tests := []struct {
		name string
		acl  ACL
		want string
	}{
		{
			name: "default action",
			acl:  ACL{Name: "a1", Node: "r1", DefaultAction: "drop"},
			want: "acl a1 has invalid default action drop",
		},
		{
			name: "rule action",
			acl:  ACL{Name: "a1", Node: "r1", DefaultAction: ACLDefaultPermit, Rules: []ACLRule{{Seq: 10, Action: "drop"}}},
			want: "acl a1 rule 10 has invalid action drop",
		},
		{
			name: "protocol",
			acl:  ACL{Name: "a1", Node: "r1", DefaultAction: ACLDefaultPermit, Rules: []ACLRule{{Seq: 10, Action: ACLDeny, Match: PacketSpec{Protocol: "gre"}}}},
			want: "acl a1 rule 10 has invalid protocol gre",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := &Topology{
				Nodes: []Node{{Name: "r1"}},
				ACLs:  []ACL{tt.acl},
			}
			err := topo.Validate()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsUnknownACLBindingNode(t *testing.T) {
	topo := &Topology{
		Nodes:       []Node{{Name: "r1"}},
		ACLBindings: []ACLBinding{{Node: "missing", ACLName: "a1", Direction: "egress"}},
	}
	err := topo.Validate()
	if err == nil || err.Error() != "acl binding a1 references unknown node missing" {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInvalidBGPNeighbors(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want string
	}{
		{
			name: "unknown-peer",
			node: Node{Name: "r1", Neighbors: []BGPNeighbor{{PeerNode: "missing", RemoteAS: 65002, Activated: true}}},
			want: "node r1 neighbor missing references unknown peer node missing",
		},
		{
			name: "activated-zero-remote-as",
			node: Node{Name: "r1", Neighbors: []BGPNeighbor{{Address: "192.0.2.1", Activated: true}}},
			want: "node r1 neighbor 192.0.2.1 is activated with remote_as 0",
		},
		{
			name: "duplicate-address",
			node: Node{Name: "r1", Neighbors: []BGPNeighbor{
				{Address: "192.0.2.1", RemoteAS: 65002},
				{Address: "192.0.2.1", RemoteAS: 65002},
			}},
			want: "node r1 has duplicate neighbor address 192.0.2.1",
		},
		{
			name: "duplicate-peer-node",
			node: Node{Name: "r1", Neighbors: []BGPNeighbor{
				{PeerNode: "r2", RemoteAS: 65002},
				{PeerNode: "r2", RemoteAS: 65002},
			}},
			want: "node r1 has duplicate neighbor peer node r2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := &Topology{
				Nodes: []Node{
					tt.node,
					{Name: "r2", Interfaces: []Interface{{Name: "eth1", Address: "192.0.2.1/31"}}},
				},
			}
			err := topo.Validate()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsDuplicatePolicyAndListState(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want string
	}{
		{
			name: "duplicate-prefix-list",
			node: Node{Name: "r1", PrefixLists: []PrefixList{{Name: "PL"}, {Name: "PL"}}},
			want: "node r1 has duplicate prefix-list PL",
		},
		{
			name: "duplicate-prefix-list-seq",
			node: Node{Name: "r1", PrefixLists: []PrefixList{{Name: "PL", Rules: []PrefixListRule{{Seq: 10, Action: "permit"}, {Seq: 10, Action: "deny"}}}}},
			want: "node r1 prefix-list PL has duplicate seq 10",
		},
		{
			name: "duplicate-route-policy",
			node: Node{Name: "r1", RoutePolicies: []RoutePolicy{{Name: "RM"}, {Name: "RM"}}},
			want: "node r1 has duplicate route policy RM",
		},
		{
			name: "duplicate-route-policy-seq",
			node: Node{Name: "r1", RoutePolicies: []RoutePolicy{{Name: "RM", Rules: []RoutePolicyRule{{Seq: 10, Action: "permit"}, {Seq: 10, Action: "deny"}}}}},
			want: "node r1 route policy RM has duplicate seq 10",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := &Topology{Nodes: []Node{tt.node}}
			err := topo.Validate()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsUnknownLinkInterface(t *testing.T) {
	topo := &Topology{
		Nodes: []Node{
			{Name: "r1", Interfaces: []Interface{{Name: "eth1", Address: "192.0.2.0/31"}}},
			{Name: "r2", Interfaces: []Interface{{Name: "eth1", Address: "192.0.2.1/31"}}},
		},
		Links: []Link{{Name: "r1-r2", A: "r1", B: "r2", AIntf: "eth9", BIntf: "eth1", Cost: 1, Subnet: "192.0.2.0/31"}},
	}
	err := topo.Validate()
	if err == nil || err.Error() != "link r1-r2 references unknown interface eth9 on node r1" {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestParseCoreHZEgressRouteMapConfig(t *testing.T) {
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "labs", "base-wan", "configs", "frr", "core-hz", "frr.conf"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if prefixListByName(cfg.PrefixLists, "HZ-LOCAL") == nil {
		t.Fatalf("HZ-LOCAL prefix-list not parsed: %#v", cfg.PrefixLists)
	}
	policy := routePolicyByName(cfg.RoutePolicies, "HZ-TRANSIT-OUT")
	if policy == nil || len(policy.Rules) != 2 || policy.Rules[0].SetMEDDelta == nil || *policy.Rules[0].SetMEDDelta != 7 || !reflect.DeepEqual(policy.Rules[0].SetASPathPrepend, []uint32{65100, 65100}) || policy.Rules[0].SetOriginCode != "incomplete" {
		t.Fatalf("HZ-TRANSIT-OUT = %#v", policy)
	}
	neighbor := neighborByAddress(cfg.Neighbors, "198.18.30.7")
	if neighbor == nil || neighbor.ExportPolicy != "HZ-TRANSIT-OUT" {
		t.Fatalf("neighbor 198.18.30.7 = %#v", neighbor)
	}
}

func TestParseCEOSConfig(t *testing.T) {
	cfg, err := ParseConfig("ceos", filepath.Join("..", "..", "labs", "base-wan", "configs", "ceos", "core-sh.cfg"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65100 || cfg.RouterID != "10.255.100.2" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Neighbors) != 6 {
		t.Fatalf("neighbors = %d, want 6", len(cfg.Neighbors))
	}
	if prefixListByName(cfg.PrefixLists, "SH-LOCAL") == nil {
		t.Fatalf("SH-LOCAL prefix-list not parsed: %#v", cfg.PrefixLists)
	}
	policy := routePolicyByName(cfg.RoutePolicies, "PREFER-SH-LOCAL")
	if policy == nil || len(policy.Rules) != 2 || policy.Rules[0].MatchPrefixList != "SH-LOCAL" || policy.Rules[0].SetLocalPref == nil || *policy.Rules[0].SetLocalPref != 225 {
		t.Fatalf("PREFER-SH-LOCAL = %#v", policy)
	}
	policy = routePolicyByName(cfg.RoutePolicies, "SH-TRANSIT-OUT")
	if policy == nil || len(policy.Rules) != 2 || policy.Rules[0].MatchPrefixList != "SH-LOCAL" || policy.Rules[0].SetMED == nil || *policy.Rules[0].SetMED != 9 {
		t.Fatalf("SH-TRANSIT-OUT = %#v", policy)
	}
	neighbor := neighborByAddress(cfg.Neighbors, "198.18.10.4")
	if neighbor == nil || neighbor.ImportPolicy != "PREFER-SH-LOCAL" {
		t.Fatalf("neighbor 198.18.10.4 = %#v", neighbor)
	}
	neighbor = neighborByAddress(cfg.Neighbors, "198.18.30.3")
	if neighbor == nil || neighbor.ExportPolicy != "SH-TRANSIT-OUT" {
		t.Fatalf("neighbor 198.18.30.3 = %#v", neighbor)
	}
	var found bool
	for _, iface := range cfg.Interfaces {
		if iface.Name == "Ethernet1" && iface.Address == "198.18.10.5/31" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Ethernet1 address not parsed: %#v", cfg.Interfaces)
	}
}

func TestParseCEOSRouteMaps(t *testing.T) {
	config := `
hostname ceos1
ip prefix-list PL-IN seq 10 permit 10.0.0.0/24
ip prefix-list PL-IN seq 20 deny 10.0.1.0/24
ip prefix-list PL-OUT permit 10.0.2.0/24 ge 25 le 28
route-map RM-IN permit 10
   match ip address prefix-list PL-IN
   set local-preference 250
route-map RM-OUT permit 20
   match ip address prefix-list PL-OUT
   set metric 77
route-map RM-DENY deny 30
   match ip address prefix-list PL-IN
router bgp 65001
   router-id 10.255.0.1
   neighbor 192.0.2.1 remote-as 65002
   address-family ipv4
      neighbor 192.0.2.1 activate
      neighbor 192.0.2.1 route-map RM-IN in
      neighbor 192.0.2.1 route-map RM-OUT out
`
	cfg := parseCEOSConfigText(t, config)
	if got, want := prefixListsWithoutMatches(cfg.PrefixLists), []PrefixList{
		{Name: "PL-IN", Rules: []PrefixListRule{
			{Seq: 10, Action: "permit", Prefix: "10.0.0.0/24"},
			{Seq: 20, Action: "deny", Prefix: "10.0.1.0/24"},
		}},
		{Name: "PL-OUT", Rules: []PrefixListRule{{Seq: 0, Action: "permit", Prefix: "10.0.2.0/24", Ge: 25, Le: 28}}},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PrefixLists = %#v, want %#v", got, want)
	}
	rmIn := routePolicyByName(cfg.RoutePolicies, "RM-IN")
	if rmIn == nil || len(rmIn.Rules) != 1 || rmIn.Rules[0].MatchPrefixList != "PL-IN" || rmIn.Rules[0].SetLocalPref == nil || *rmIn.Rules[0].SetLocalPref != 250 {
		t.Fatalf("RM-IN = %#v", rmIn)
	}
	rmOut := routePolicyByName(cfg.RoutePolicies, "RM-OUT")
	if rmOut == nil || len(rmOut.Rules) != 1 || rmOut.Rules[0].MatchPrefixList != "PL-OUT" || rmOut.Rules[0].SetMED == nil || *rmOut.Rules[0].SetMED != 77 {
		t.Fatalf("RM-OUT = %#v", rmOut)
	}
	rmDeny := routePolicyByName(cfg.RoutePolicies, "RM-DENY")
	if rmDeny == nil || len(rmDeny.Rules) != 1 || rmDeny.Rules[0].Action != "deny" || rmDeny.Rules[0].MatchPrefixList != "PL-IN" {
		t.Fatalf("RM-DENY = %#v", rmDeny)
	}
	if len(cfg.Neighbors) != 1 || cfg.Neighbors[0].ImportPolicy != "RM-IN" || cfg.Neighbors[0].ExportPolicy != "RM-OUT" {
		t.Fatalf("Neighbors = %#v", cfg.Neighbors)
	}
}

func TestLoadLabTopologyIncludesCEOSRouteMaps(t *testing.T) {
	dir := t.TempDir()
	config := `
hostname ceos1
ip prefix-list PL seq 10 permit 10.0.0.0/24
route-map RM-IN permit 10
   match ip address prefix-list PL
   set local-preference 250
route-map RM-OUT permit 20
   set metric 77
router bgp 65001
   router-id 10.255.0.1
   neighbor 192.0.2.1 remote-as 65002
   address-family ipv4
      neighbor 192.0.2.1 activate
      neighbor 192.0.2.1 route-map RM-IN in
      neighbor 192.0.2.1 route-map RM-OUT out
`
	if err := os.WriteFile(filepath.Join(dir, "ceos.cfg"), []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	topology := `
name: ceos-policy
topology:
  nodes:
    ceos1:
      kind: arista_ceos
      startup-config: ceos.cfg
`
	topologyPath := filepath.Join(dir, "lab.clab.yml")
	if err := os.WriteFile(topologyPath, []byte(topology), 0o644); err != nil {
		t.Fatalf("WriteFile(topology) error = %v", err)
	}
	topo, err := LoadLabTopology(topologyPath)
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	node, ok := topo.Node("ceos1")
	if !ok {
		t.Fatalf("ceos1 not found")
	}
	if prefixListByName(node.PrefixLists, "PL") == nil {
		t.Fatalf("PL prefix-list not propagated: %#v", node.PrefixLists)
	}
	if routePolicyByName(node.RoutePolicies, "RM-IN") == nil || routePolicyByName(node.RoutePolicies, "RM-OUT") == nil {
		t.Fatalf("route policies not propagated: %#v", node.RoutePolicies)
	}
	neighbor := neighborByAddress(node.Neighbors, "192.0.2.1")
	if neighbor == nil || neighbor.ImportPolicy != "RM-IN" || neighbor.ExportPolicy != "RM-OUT" {
		t.Fatalf("neighbor = %#v, want route-map bindings", neighbor)
	}
}

func TestParseFRRStaticRoutesAndRedistribution(t *testing.T) {
	cfg := parseFRRConfigText(t, `
hostname r1
ip route 0.0.0.0/0 192.0.2.254
ip route 203.0.113.0/24 Null0
router bgp 65001
 address-family ipv4 unicast
  network 198.51.100.0/24
  redistribute static route-map STATIC-OUT
 exit-address-family
!
`)
	if got, want := len(cfg.Routes), 2; got != want {
		t.Fatalf("routes = %d, want %d: %#v", got, want, cfg.Routes)
	}
	if cfg.Routes[0].Prefix.String() != "0.0.0.0/0" || cfg.Routes[0].NextHop != "192.0.2.254" || cfg.Routes[0].Kind != RouteSourceStatic {
		t.Fatalf("default static route not parsed: %#v", cfg.Routes[0])
	}
	if cfg.Routes[1].Kind != RouteSourceBlackhole || cfg.Routes[1].Interface != "Null0" {
		t.Fatalf("blackhole route not parsed: %#v", cfg.Routes[1])
	}
	if len(cfg.Redistribute) != 1 || cfg.Redistribute[0].Kind != RouteSourceStatic || cfg.Redistribute[0].RouteMap != "STATIC-OUT" {
		t.Fatalf("redistribute static not parsed: %#v", cfg.Redistribute)
	}
	if len(cfg.Prefixes) != 1 || cfg.Prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("BGP network prefixes = %#v", cfg.Prefixes)
	}
}

func TestParseFRRAggregateAddressSummaryOnly(t *testing.T) {
	cfg := parseFRRConfigText(t, `
hostname r1
router bgp 65001
 address-family ipv4 unicast
  aggregate-address 10.0.0.0/16 summary-only
 exit-address-family
!
`)
	if len(cfg.Routes) != 1 {
		t.Fatalf("routes = %#v, want one aggregate route", cfg.Routes)
	}
	route := cfg.Routes[0]
	if route.Kind != RouteSourceAggregate || route.Prefix.String() != "10.0.0.0/16" || !route.SummaryOnly || route.AdminDistance != 200 {
		t.Fatalf("aggregate route = %#v", route)
	}
	if len(cfg.Prefixes) != 0 {
		t.Fatalf("aggregate-address should not be parsed as unconditional BGP network prefix: %#v", cfg.Prefixes)
	}
}

func TestParseFRRAggregateAddressRejectsUnsupportedOptions(t *testing.T) {
	config := `
router bgp 65001
 address-family ipv4 unicast
  aggregate-address 10.0.0.0/16 as-set
 exit-address-family
`
	_, err := parseFRRConfigTextResult(t, config)
	if err == nil || !strings.Contains(err.Error(), `unsupported FRR aggregate-address option "as-set"`) {
		t.Fatalf("ParseConfig() error = %v, want unsupported aggregate-address option", err)
	}
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	result, err := ParseConfigWithWarnings(KindFRR, path)
	if err != nil {
		t.Fatalf("ParseConfigWithWarnings() error = %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0].Reason, "unsupported FRR aggregate-address option") {
		t.Fatalf("warnings = %#v, want aggregate option warning", result.Warnings)
	}
}

func TestParseSRLinuxBGPAggregateWarnsUnsupported(t *testing.T) {
	config := `set / network-instance default protocols bgp aggregate-routes route 10.0.0.0/16`
	path := filepath.Join(t.TempDir(), "core.cfg")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := ParseConfig(KindSRLinux, path)
	if err == nil || !strings.Contains(err.Error(), "unsupported SR Linux BGP aggregate route statement") {
		t.Fatalf("ParseConfig() error = %v, want unsupported SR Linux aggregate", err)
	}
	result, err := ParseConfigWithWarnings(KindSRLinux, path)
	if err != nil {
		t.Fatalf("ParseConfigWithWarnings() error = %v", err)
	}
	want := []UnsupportedStatement{{Vendor: "srlinux", File: path, Line: 1, Text: config, Reason: "unsupported SR Linux BGP aggregate route statement"}}
	if !reflect.DeepEqual(result.Warnings, want) {
		t.Fatalf("Warnings = %#v, want %#v", result.Warnings, want)
	}
}

func TestParseUnsupportedStaticRouteWarningAndStrictError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte("ip route 10.0.0.0/24 192.0.2.1 250\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ParseConfigWithWarnings(KindFRR, path)
	if err != nil {
		t.Fatalf("ParseConfigWithWarnings() error = %v", err)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one unsupported static route warning", result.Warnings)
	}
	_, err = ParseConfig(KindFRR, path)
	if err == nil {
		t.Fatalf("ParseConfig() error = nil, want strict unsupported static route error")
	}
}

func TestParseCEOSRouteMapRejectsUnsupportedMatch(t *testing.T) {
	_, err := parseCEOSConfigTextResult(t, `
route-map RM permit 10
   match as-path ASPATH
   set local-preference 200
`)
	if err == nil || !strings.Contains(err.Error(), "unsupported cEOS route-map match statement") {
		t.Fatalf("ParseConfig() error = %v, want unsupported cEOS match", err)
	}
}

func TestParseSRLinuxConfig(t *testing.T) {
	cfg, err := ParseConfig("srlinux", filepath.Join("..", "..", "labs", "base-wan", "configs", "srlinux", "core-gz.cfg"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65100 || cfg.RouterID != "10.255.100.3" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Interfaces) != 6 || len(cfg.Neighbors) != 6 {
		t.Fatalf("interfaces/neighbors = %d/%d, want 6/6", len(cfg.Interfaces), len(cfg.Neighbors))
	}
	policy := routePolicyByName(cfg.RoutePolicies, "GZ-NH-SELF")
	if policy == nil || len(policy.Rules) < 1 || !policy.Rules[0].SetNextHopSelf {
		t.Fatalf("GZ-NH-SELF policy = %#v, want set next-hop self", policy)
	}
	neighbor := neighborByAddress(cfg.Neighbors, "198.18.20.8")
	if neighbor == nil || neighbor.ExportPolicy != "GZ-NH-SELF" {
		t.Fatalf("neighbor 198.18.20.8 = %#v, want export policy GZ-NH-SELF", neighbor)
	}
	for _, addr := range []string{"198.18.20.5", "198.18.20.2"} {
		neighbor := neighborByAddress(cfg.Neighbors, addr)
		if neighbor == nil || neighbor.ExportPolicy != "" {
			t.Fatalf("neighbor %s = %#v, want no export policy", addr, neighbor)
		}
	}
}

func TestParseSRLinuxNextHopSelf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "srl.cfg")
	if err := os.WriteFile(path, []byte(`
set / network-instance default protocols bgp autonomous-system 65100
set / network-instance default protocols bgp group core peer-as 65100
set / network-instance default protocols bgp group core afi-safi ipv4-unicast ipv4-unicast next-hop-self true
set / network-instance default protocols bgp neighbor 198.18.20.8 peer-group core
set / network-instance default protocols bgp neighbor 198.18.20.8 admin-state enable
set / network-instance default protocols bgp neighbor 198.18.20.9 peer-group core
set / network-instance default protocols bgp neighbor 198.18.20.9 afi-safi ipv4-unicast ipv4-unicast next-hop-self true
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg, err := ParseConfig("srlinux", path)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if len(cfg.Neighbors) != 2 {
		t.Fatalf("neighbors = %#v", cfg.Neighbors)
	}
	for _, neighbor := range cfg.Neighbors {
		if !neighbor.NextHopSelf {
			t.Fatalf("neighbor %s NextHopSelf = false", neighbor.Address)
		}
	}
}

func routePolicyByName(policies []RoutePolicy, name string) *RoutePolicy {
	for i := range policies {
		if policies[i].Name == name {
			return &policies[i]
		}
	}
	return nil
}

func prefixListByName(prefixLists []PrefixList, name string) *PrefixList {
	for i := range prefixLists {
		if prefixLists[i].Name == name {
			return &prefixLists[i]
		}
	}
	return nil
}

func asPathListByName(lists []ASPathList, name string) *ASPathList {
	for i := range lists {
		if lists[i].Name == name {
			return &lists[i]
		}
	}
	return nil
}

func communityListByName(lists []CommunityList, name string) *CommunityList {
	for i := range lists {
		if lists[i].Name == name {
			return &lists[i]
		}
	}
	return nil
}

func aclByNodeInterface(topo *Topology, node, iface string) (*ACL, *ACLBinding) {
	for i := range topo.ACLBindings {
		binding := &topo.ACLBindings[i]
		if binding.Node != node || binding.Interface != iface {
			continue
		}
		for j := range topo.ACLs {
			if topo.ACLs[j].Node == node && topo.ACLs[j].Name == binding.ACLName {
				return &topo.ACLs[j], binding
			}
		}
	}
	return nil, nil
}

func neighborByAddress(neighbors []BGPNeighbor, addr string) *BGPNeighbor {
	for i := range neighbors {
		if neighbors[i].Address == addr {
			return &neighbors[i]
		}
	}
	return nil
}

func parseFRRConfigText(t *testing.T, config string) ParsedConfig {
	t.Helper()
	cfg, err := parseFRRConfigTextResult(t, config)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	return cfg
}

func parseFRRConfigTextResult(t *testing.T, config string) (ParsedConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return ParseConfig("frr", path)
}

func parseCEOSConfigText(t *testing.T, config string) ParsedConfig {
	t.Helper()
	cfg, err := parseCEOSConfigTextResult(t, config)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	return cfg
}

func parseCEOSConfigTextResult(t *testing.T, config string) (ParsedConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ceos.cfg")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return ParseConfig("ceos", path)
}
