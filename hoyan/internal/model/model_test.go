package model

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadLabTopology(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
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

func TestLoadLabTopologyIncludesRouteMaps(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
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
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), "")
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
		policy := policyByNodeInterface(topo.Policies, tt.node, tt.iface)
		if policy == nil {
			t.Fatalf("policy for %s %s not found in %#v", tt.node, tt.iface, topo.Policies)
		}
		if policy.Name != "BLOCK-HTTP-TO-HZ" || policy.Plane != "data" || policy.Stage != "egress" || policy.Action != "deny" || policy.Protocol != "tcp" || policy.DstPrefix.String() != "10.4.0.0/16" {
			t.Fatalf("policy for %s %s = %#v", tt.node, tt.iface, policy)
		}
		if policy.Source.File == "" || policy.Source.Line == 0 || policy.Source.Raw == "" {
			t.Fatalf("policy source not populated: %#v", policy.Source)
		}
	}
}

func TestOriginLookups(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
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
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "configs", "frr", "bj-edge1", "frr.conf"))
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

func TestParseCoreBJRouteMapConfig(t *testing.T) {
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "configs", "frr", "core-bj", "frr.conf"))
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
		{kind: KindFRR, glob: filepath.Join("..", "..", "configs", "frr", "*", "frr.conf")},
		{kind: KindCEOS, glob: filepath.Join("..", "..", "configs", "ceos", "*.cfg")},
		{kind: KindSRLinux, glob: filepath.Join("..", "..", "configs", "srlinux", "*.cfg")},
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

func TestValidateRejectsInvalidPolicyFields(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   string
	}{
		{
			name:   "action",
			policy: Policy{Name: "p1", Node: "r1", Action: "drop"},
			want:   "policy p1 has invalid action drop",
		},
		{
			name:   "plane",
			policy: Policy{Name: "p1", Node: "r1", Action: "deny", Plane: "mgmt"},
			want:   "policy p1 has invalid plane mgmt",
		},
		{
			name:   "stage",
			policy: Policy{Name: "p1", Node: "r1", Action: "deny", Stage: "pre"},
			want:   "policy p1 has invalid stage pre",
		},
		{
			name:   "protocol",
			policy: Policy{Name: "p1", Node: "r1", Action: "deny", Protocol: "gre"},
			want:   "policy p1 has invalid protocol gre",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := &Topology{
				Nodes:    []Node{{Name: "r1"}},
				Policies: []Policy{tt.policy},
			}
			err := topo.Validate()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateRejectsUnknownPolicyPeer(t *testing.T) {
	topo := &Topology{
		Nodes:    []Node{{Name: "r1"}},
		Policies: []Policy{{Name: "p1", Node: "r1", Peer: "missing", Action: "deny"}},
	}
	err := topo.Validate()
	if err == nil || err.Error() != "policy p1 references unknown peer node missing" {
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
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "configs", "frr", "core-hz", "frr.conf"))
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
	cfg, err := ParseConfig("ceos", filepath.Join("..", "..", "configs", "ceos", "core-sh.cfg"))
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
	topo, err := LoadLabTopology(topologyPath, "")
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
	cfg, err := ParseConfig("srlinux", filepath.Join("..", "..", "configs", "srlinux", "core-gz.cfg"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65100 || cfg.RouterID != "10.255.100.3" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Interfaces) != 6 || len(cfg.Neighbors) != 6 {
		t.Fatalf("interfaces/neighbors = %d/%d, want 6/6", len(cfg.Interfaces), len(cfg.Neighbors))
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

func policyByNodeInterface(policies []Policy, node, iface string) *Policy {
	for i := range policies {
		if policies[i].Node == node && policies[i].Interface == iface {
			return &policies[i]
		}
	}
	return nil
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
