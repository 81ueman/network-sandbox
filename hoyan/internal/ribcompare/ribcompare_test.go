package ribcompare

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

func TestExpectedRoutesIncludesMultipleBgpPaths(t *testing.T) {
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	routes := Expected(topo)
	if len(routes) == 0 {
		t.Fatalf("Expected() returned no routes")
	}
	for _, r := range routes {
		if r.Node == "bj-edge1" && r.Prefix == "10.4.1.10/32" {
			if len(r.Paths) < 2 {
				t.Fatalf("bj-edge1 route paths = %#v, want multiple BGP paths", r.Paths)
			}
			return
		}
	}
	t.Fatalf("expected bj-edge1 route to hz customer host")
}

func TestParseFRR(t *testing.T) {
	data := []byte(`{
	  "totalPrefixCounter": 1,
	  "routes": {
	    "10.4.1.10/32": [
	      {"valid": true, "bestpath": false, "nexthops": [{"ip": "198.18.20.7"}], "path": "65100 4200001004", "origin":"i", "locPrf": 100, "metric": 0, "peerId": "198.18.20.7"},
	      {"valid": true, "bestpath": true, "nexthops": [{"ip": "198.18.10.1"}], "path": "65100 4200001004", "origin":"i", "locPrf": 100}
	    ],
	    "10.1.0.0/16": [
	      {"valid": true, "bestpath": true, "nexthops": [{"ip": "0.0.0.0"}], "path": "", "origin":"i"}
	    ]
	  }
	}`)
	routes, err := ParseFRR("bj-edge1", data)
	if err != nil {
		t.Fatalf("ParseFRR() error = %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	var foundRemote, foundLocal bool
	for _, route := range routes {
		for _, path := range route.Paths {
			if route.Prefix == "10.4.1.10/32" && path.NextHop == "198.18.10.1" && path.Best && len(path.ASPath) == 2 {
				foundRemote = true
			}
			if route.Prefix == "10.1.0.0/16" && path.NextHop == "" && path.Best {
				foundLocal = true
			}
		}
	}
	if !foundRemote || !foundLocal {
		t.Fatalf("routes = %#v", routes)
	}
}

func TestParseCEOS(t *testing.T) {
	data := []byte(`{
	  "vrfs": {
	    "default": {
	      "bgpRouteEntries": {
	        "10.0.0.0/24": {
	          "bgpRoutePaths": [
	            {
	              "routeType": {"active": true, "valid": true},
	              "localPreference": 150,
	              "med": 10,
	              "weight": 0,
	              "nextHop": "192.0.2.1",
	              "peerEntry": {"peerAddr": "192.0.2.1", "peerAS": 65001},
	              "asPathEntry": {"asPath": "65001 65002", "largeCommunityList": ["65000:100:1"]},
	              "communityList": ["65000:1", "no-export"],
	              "routeOrigin": "igp"
	            },
	            {
	              "routeType": {"active": false, "valid": true},
	              "localPreference": 120,
	              "med": 20,
	              "nextHop": "192.0.2.2",
	              "peerEntry": {"peerAddr": "192.0.2.2", "peerAS": 65003},
	              "asPathEntry": {"asPath": "65003 65004"},
	              "routeOrigin": "egp"
	            }
	          ]
	        },
	        "10.0.1.0/24": {
	          "bgpRoutePaths": [{
	            "routeType": {"active": true, "valid": true},
	            "nextHop": "0.0.0.0",
	            "asPathEntry": {"asPath": ""},
	            "routeOrigin": "igp"
	          }]
	        }
	      }
	    }
	  }
	}`)
	routes, err := ParseCEOS("core-sh", data)
	if err != nil {
		t.Fatalf("ParseCEOS() error = %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	remote := routeByPrefix(routes, "10.0.0.0/24")
	if remote == nil || len(remote.Paths) != 2 {
		t.Fatalf("remote route = %#v", remote)
	}
	best := pathByNextHop(remote.Paths, "192.0.2.1")
	if best == nil {
		t.Fatalf("paths = %#v, want next-hop 192.0.2.1", remote.Paths)
	}
	if !best.Best || !best.Valid || best.LocalPref != 150 || best.MED != 10 || !reflect.DeepEqual(best.ASPath, []uint32{65001, 65002}) || best.Peer != "192.0.2.1" || best.PeerAS != 65001 {
		t.Fatalf("best path = %#v", best)
	}
	if !reflect.DeepEqual(best.Communities, []string{"65000:1", "no-export"}) || !reflect.DeepEqual(best.LargeCommunities, []string{"65000:100:1"}) {
		t.Fatalf("best path communities = %#v large=%#v", best.Communities, best.LargeCommunities)
	}
	backup := pathByNextHop(remote.Paths, "192.0.2.2")
	if backup == nil || backup.Best || backup.LocalPref != 120 || backup.MED != 20 || !reflect.DeepEqual(backup.ASPath, []uint32{65003, 65004}) || backup.PeerAS != 65003 {
		t.Fatalf("backup path = %#v", backup)
	}
	local := routeByPrefix(routes, "10.0.1.0/24")
	if local == nil || len(local.Paths) != 1 || local.Paths[0].NextHop != "" {
		t.Fatalf("local route = %#v", local)
	}
}

func TestParseSRLinux(t *testing.T) {
	summary := []byte(`{"network-instance":[{"routes":[{"prefix":"10.0.1.0/24"},{"prefix":"10.0.0.0/24"}]}]}`)
	prefixes, err := ParseSRLinuxSummary(summary)
	if err != nil {
		t.Fatalf("ParseSRLinuxSummary() error = %v", err)
	}
	if got, want := prefixes, []string{"10.0.0.0/24", "10.0.1.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %#v", prefixes)
	}
	detail := []byte(`{
	  "routes": [
	    {"status":"<Best,Valid,Used>","next-hop":"192.0.2.1","neighbor":"192.0.2.1","peer-as":"65001","local pref":"150","med":"-","communities":["65000:1","no-export"],"as path":"65001 65002","origin":"igp"},
	    {"status":"<Valid>","next-hop":"192.0.2.2","peer":"192.0.2.2","peerAS":65003,"local-pref":120,"med":30,"community":"65000:2","as-path":"65003 65004","origin":"incomplete"}
	  ],
	  "advertised": {"routes":[{"status":"<Best,Valid>","next-hop":"203.0.113.1","as-path":"64512"}]},
	  "non-route": {"routes":[{"status":"<Best,Valid>","next-hop":"203.0.113.2","as-path":"64513"}]}
	}`)
	routes, err := ParseSRLinuxDetail("core-gz", "10.0.0.0/24", detail)
	if err != nil {
		t.Fatalf("ParseSRLinuxDetail() error = %v", err)
	}
	if len(routes) != 1 || len(routes[0].Paths) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	best := pathByNextHop(routes[0].Paths, "192.0.2.1")
	if best == nil || !best.Best || !best.Valid || best.LocalPref != 150 || best.MED != 0 || !reflect.DeepEqual(best.ASPath, []uint32{65001, 65002}) || best.Peer != "192.0.2.1" || best.PeerAS != 65001 {
		t.Fatalf("best path = %#v", best)
	}
	if !reflect.DeepEqual(best.Communities, []string{"65000:1", "no-export"}) {
		t.Fatalf("best communities = %#v", best.Communities)
	}
	backup := pathByNextHop(routes[0].Paths, "192.0.2.2")
	if backup == nil || backup.Best || !backup.Valid || backup.LocalPref != 120 || backup.MED != 30 || !reflect.DeepEqual(backup.ASPath, []uint32{65003, 65004}) || backup.Peer != "192.0.2.2" || backup.PeerAS != 65003 {
		t.Fatalf("backup path = %#v", backup)
	}
	if pathByNextHop(routes[0].Paths, "203.0.113.1") != nil || pathByNextHop(routes[0].Paths, "203.0.113.2") != nil {
		t.Fatalf("advertised/non-route sections were parsed: %#v", routes[0].Paths)
	}
}

func TestExpectedPathUsesModeledAttributes(t *testing.T) {
	topo := &model.Topology{}
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		t.Fatalf("BuildTopologyIndex() error = %v", err)
	}
	node := model.Node{Name: "r1", Kind: "frr"}
	ctx := sim.FailureContext{}
	path := expectedPath(idx, node, sim.RIBEntry{
		ASPath:       []uint32{65001},
		LocalPref:    175,
		MED:          42,
		Condition:    sim.True(),
		SelectedCond: sim.True(),
	}, ctx)
	if !path.Best || path.LocalPref != 175 || path.MED != 42 || path.Origin != "igp" || !reflect.DeepEqual(path.ASPath, []uint32{65001}) {
		t.Fatalf("path = %#v", path)
	}
}

func TestExpectedReflectsRouteMapAttributes(t *testing.T) {
	lp := 225
	med := 33
	topo := &model.Topology{
		Nodes: []model.Node{
			{
				Name:     "origin",
				Kind:     "frr",
				ASN:      65001,
				Prefixes: model.MustPrefixes("10.0.0.0/24"),
				PrefixLists: []model.PrefixList{{
					Name:  "PL-OUT",
					Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24"}},
				}},
				RoutePolicies: []model.RoutePolicy{{
					Name:  "SET-MED",
					Rules: []model.RoutePolicyRule{{Action: "permit", MatchPrefixList: "PL-OUT", SetMED: &med}},
				}},
				Neighbors: []model.BGPNeighbor{{
					PeerNode:     "rx",
					RemoteAS:     65002,
					Activated:    true,
					ExportPolicy: "SET-MED",
				}},
			},
			{
				Name: "rx",
				Kind: "frr",
				ASN:  65002,
				PrefixLists: []model.PrefixList{{
					Name:  "PL-IN",
					Rules: []model.PrefixListRule{{Action: "permit", Prefix: "10.0.0.0/24"}},
				}},
				RoutePolicies: []model.RoutePolicy{{
					Name:  "SET-LP",
					Rules: []model.RoutePolicyRule{{Action: "permit", MatchPrefixList: "PL-IN", SetLocalPref: &lp}},
				}},
				Neighbors: []model.BGPNeighbor{{
					PeerNode:     "origin",
					RemoteAS:     65001,
					Activated:    true,
					ImportPolicy: "SET-LP",
				}},
			},
		},
		Links: []model.Link{{Name: "origin-rx", A: "origin", B: "rx", Cost: 1, Subnet: "192.0.2.0/31"}},
	}
	routes := ExpectedForNodes(topo, []model.Node{{Name: "rx", Kind: "frr"}})
	route := routeByPrefix(routes, "10.0.0.0/24")
	if route == nil || len(route.Paths) != 1 {
		t.Fatalf("routes = %#v", routes)
	}
	if route.Paths[0].LocalPref != 225 || route.Paths[0].MED != 33 {
		t.Fatalf("path = %#v, want local-pref 225 MED 33", route.Paths[0])
	}
}

func TestCompareBgpRib(t *testing.T) {
	base := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(true, true, "192.0.2.1", []uint32{65001}, 100, 0),
		path(false, true, "192.0.2.2", []uint32{65002}, 100, 0),
	)}
	tests := []struct {
		name string
		exp  []NormalizedBgpRoute
		act  []NormalizedBgpRoute
		want func(BgpRibCompareResult) bool
	}{
		{"exact", base, base, func(r BgpRibCompareResult) bool { return r.OK }},
		{"missing prefix", base, nil, func(r BgpRibCompareResult) bool { return len(r.MissingPrefixes) == 1 }},
		{"unexpected prefix", nil, base, func(r BgpRibCompareResult) bool { return len(r.UnexpectedPrefixes) == 1 }},
		{"missing path", base, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", base[0].Paths[0])}, func(r BgpRibCompareResult) bool { return len(r.MissingPaths) == 1 }},
		{"unexpected path", []NormalizedBgpRoute{route("r1", "10.0.0.0/24", base[0].Paths[0])}, base, func(r BgpRibCompareResult) bool { return len(r.UnexpectedPaths) == 1 }},
		{"as path mismatch", []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 100, 0))}, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65009}, 100, 0))}, func(r BgpRibCompareResult) bool { return len(r.MissingPaths) == 1 && len(r.UnexpectedPaths) == 1 }},
		{"local-pref mismatch", []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 200, 0))}, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 100, 0))}, mismatch("local_pref")},
		{"med mismatch", []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 100, 10))}, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 100, 20))}, mismatch("med")},
		{"best mismatch", []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 100, 0))}, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(false, true, "192.0.2.1", []uint32{65001}, 100, 0))}, mismatch("best")},
		{"valid mismatch", []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, true, "192.0.2.1", []uint32{65001}, 100, 0))}, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", path(true, false, "192.0.2.1", []uint32{65001}, 100, 0))}, mismatch("valid")},
		{"path order ignored", base, []NormalizedBgpRoute{route("r1", "10.0.0.0/24", base[0].Paths[1], base[0].Paths[0])}, func(r BgpRibCompareResult) bool { return r.OK }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.exp, tt.act); !tt.want(got) {
				t.Fatalf("Compare() = %#v", got)
			}
		})
	}
}

func TestDefaultCompareRejectsBestPathMismatch(t *testing.T) {
	expected := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(true, true, "192.0.2.1", []uint32{65001}, 100, 0),
	)}
	actual := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(false, true, "192.0.2.1", []uint32{65001}, 100, 0),
	)}
	result := CompareBgpRib(expected, actual, DefaultBgpRibCompareOptions())
	if result.OK || len(result.Mismatched) != 1 || result.Mismatched[0].Field != "best" {
		t.Fatalf("CompareBgpRib() = %#v, want best mismatch", result)
	}
}

func TestDefaultCompareRejectsUnexpectedExtraPath(t *testing.T) {
	expected := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(true, true, "192.0.2.1", []uint32{65001}, 100, 0),
	)}
	actual := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(true, true, "192.0.2.1", []uint32{65001}, 100, 0),
		path(false, true, "192.0.2.2", []uint32{65002}, 100, 0),
	)}
	result := CompareBgpRib(expected, actual, DefaultBgpRibCompareOptions())
	if result.OK || len(result.UnexpectedPaths) != 1 {
		t.Fatalf("CompareBgpRib() = %#v, want unexpected path", result)
	}
}

func TestCompareMergesDuplicateVisiblePaths(t *testing.T) {
	expected := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(true, true, "192.0.2.1", []uint32{65001}, 100, 0),
		path(false, true, "192.0.2.1", []uint32{65001}, 100, 0),
	)}
	actual := []NormalizedBgpRoute{route("r1", "10.0.0.0/24",
		path(true, true, "192.0.2.1", []uint32{65001}, 100, 0),
	)}
	if result := CompareBgpRib(expected, actual, DefaultBgpRibCompareOptions()); !result.OK {
		t.Fatalf("CompareBgpRib() = %#v, want duplicate visible paths merged", result)
	}
}

func mismatch(field string) func(BgpRibCompareResult) bool {
	return func(r BgpRibCompareResult) bool {
		return len(r.Mismatched) == 1 && r.Mismatched[0].Field == field
	}
}

func route(node, prefix string, paths ...NormalizedBgpPath) NormalizedBgpRoute {
	return NormalizedBgpRoute{Node: node, NetworkInstance: "default", AFI: "ipv4", Prefix: prefix, Paths: paths}
}

func path(best, valid bool, nextHop string, asPath []uint32, localPref, med int) NormalizedBgpPath {
	return NormalizedBgpPath{Best: best, Valid: valid, NextHop: nextHop, ASPath: asPath, Origin: "igp", LocalPref: localPref, MED: med}
}

func routeByPrefix(routes []NormalizedBgpRoute, prefix string) *NormalizedBgpRoute {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}

func pathByNextHop(paths []NormalizedBgpPath, nextHop string) *NormalizedBgpPath {
	for i := range paths {
		if paths[i].NextHop == nextHop {
			return &paths[i]
		}
	}
	return nil
}
