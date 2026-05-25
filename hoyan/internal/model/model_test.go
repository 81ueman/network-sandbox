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
	if policy == nil || len(policy.Rules) != 2 || policy.Rules[0].SetLocalPref == nil || *policy.Rules[0].SetLocalPref != 200 {
		t.Fatalf("PREFER-BJ-LOCAL = %#v", policy)
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
	if got, want := cfg.PrefixLists, []PrefixList{
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
		"match community FOO",
		"match as-path ASPATH",
		"match ip next-hop prefix-list NH",
		"match source-protocol bgp",
	} {
		t.Run(stmt, func(t *testing.T) {
			_, err := parseFRRConfigTextResult(t, "route-map RM permit 10\n "+stmt+"\n set local-preference 200\n")
			if err == nil || !strings.Contains(err.Error(), "unsupported FRR route-map match statement") {
				t.Fatalf("ParseConfig() error = %v, want unsupported match", err)
			}
		})
	}
}

func TestParseFRRPrefixListDenyAndOrder(t *testing.T) {
	cfg := parseFRRConfigText(t, `
ip prefix-list PL seq 20 permit 10.1.0.0/16
ip prefix-list PL seq 10 deny 10.0.0.0/8
`)
	got := cfg.PrefixLists
	want := []PrefixList{{Name: "PL", Rules: []PrefixListRule{
		{Seq: 10, Action: "deny", Prefix: "10.0.0.0/8"},
		{Seq: 20, Action: "permit", Prefix: "10.1.0.0/16"},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PrefixLists = %#v, want %#v", got, want)
	}
}

func TestParseFRRPrefixListRejectsLeGe(t *testing.T) {
	for _, line := range []string{
		"ip prefix-list PL permit 10.0.0.0/8 le 24",
		"ip prefix-list PL seq 10 permit 10.0.0.0/8 ge 16",
	} {
		t.Run(line, func(t *testing.T) {
			_, err := parseFRRConfigTextResult(t, line+"\n")
			if err == nil || !strings.Contains(err.Error(), "unsupported FRR prefix-list le/ge") {
				t.Fatalf("ParseConfig() error = %v, want le/ge unsupported", err)
			}
		})
	}
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

func TestParseCoreHZEgressRouteMapConfig(t *testing.T) {
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "configs", "frr", "core-hz", "frr.conf"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if prefixListByName(cfg.PrefixLists, "HZ-LOCAL") == nil {
		t.Fatalf("HZ-LOCAL prefix-list not parsed: %#v", cfg.PrefixLists)
	}
	policy := routePolicyByName(cfg.RoutePolicies, "HZ-TRANSIT-OUT")
	if policy == nil || len(policy.Rules) != 2 || policy.Rules[0].SetMED == nil || *policy.Rules[0].SetMED != 0 {
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
