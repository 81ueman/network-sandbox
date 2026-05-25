package ribcompare

import (
	"path/filepath"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
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
	          "bgpRoutePaths": [{
	            "routeType": {"active": true, "valid": true},
	            "localPreference": 100,
	            "med": 10,
	            "weight": 0,
	            "nextHop": "192.0.2.1",
	            "peerEntry": {"peerAddr": "192.0.2.1", "peerAS": 65001},
	            "asPathEntry": {"asPath": "65001 65002"},
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
	path := routes[0].Paths[0]
	if !path.Best || !path.Valid || path.NextHop != "192.0.2.1" || path.LocalPref != 100 || path.MED != 10 || len(path.ASPath) != 2 || path.PeerAS != 65001 {
		t.Fatalf("path = %#v", path)
	}
}

func TestParseSRLinux(t *testing.T) {
	summary := []byte(`{"routes":[{"prefix":"10.0.0.0/24"},{"prefix":"10.0.1.0/24"}]}`)
	prefixes, err := ParseSRLinuxSummary(summary)
	if err != nil {
		t.Fatalf("ParseSRLinuxSummary() error = %v", err)
	}
	if got := len(prefixes); got != 2 {
		t.Fatalf("prefixes = %#v", prefixes)
	}
	detail := []byte(`{"routes":[{"status":"<Best,Valid,Used,>","next-hop":"192.0.2.1","neighbor":"192.0.2.1","local pref":"100","med":"-","community":"65000:1","as path":"65001 65002","origin":"igp"}],"advertised":[{"ignored":true}]}`)
	routes, err := ParseSRLinuxDetail("core-gz", "10.0.0.0/24", detail)
	if err != nil {
		t.Fatalf("ParseSRLinuxDetail() error = %v", err)
	}
	path := routes[0].Paths[0]
	if !path.Best || !path.Valid || path.NextHop != "192.0.2.1" || path.LocalPref != 100 || path.MED != 0 || len(path.ASPath) != 2 || path.Peer != "192.0.2.1" {
		t.Fatalf("path = %#v", path)
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
