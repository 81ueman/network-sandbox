package fibcompare

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestParseLinuxIPRoute(t *testing.T) {
	data := []byte(`[
	  {"dst":"10.0.0.0/24","gateway":"192.0.2.1","dev":"eth1","protocol":"bgp","metric":20},
	  {"dst":"10.0.0.10","gateway":"192.0.2.9","dev":"eth9","protocol":"bgp"},
	  {"dst":"10.0.1.0/24","protocol":"bgp","metric":30,"nexthops":[{"gateway":"192.0.2.1","dev":"eth1","weight":1},{"gateway":"192.0.2.2","dev":"eth2","weight":1}]},
	  {"dst":"default","gateway":"198.51.100.1","dev":"eth0","protocol":"static","metric":100},
	  {"type":"blackhole","dst":"203.0.113.0/24","protocol":"static","metric":10},
	  {"dst":"2001:db8::/64","dev":"eth3","protocol":"kernel"}
	]`)
	routes, err := ParseLinuxIPRoute("r1", data)
	if err != nil {
		t.Fatalf("ParseLinuxIPRoute() error = %v", err)
	}
	if len(routes) != 5 {
		t.Fatalf("routes = %#v", routes)
	}
	if host := routeByPrefix(routes, "10.0.0.10/32"); host == nil {
		t.Fatalf("routes = %#v, want host route normalized to /32", routes)
	}
	ecmp := routeByPrefix(routes, "10.0.1.0/24")
	if ecmp == nil || len(ecmp.NextHops) != 2 {
		t.Fatalf("ecmp route = %#v", ecmp)
	}
	if got, want := ecmp.NextHops[0], (NormalizedFIBNextHop{Address: "192.0.2.1", Interface: "eth1", Weight: 1}); got != want {
		t.Fatalf("first next-hop = %#v, want %#v", got, want)
	}
	if def := routeByPrefix(routes, "0.0.0.0/0"); def == nil || def.Protocol != "static" || def.Metric != 100 {
		t.Fatalf("default route = %#v", def)
	}
	if blackhole := routeByPrefix(routes, "203.0.113.0/24"); blackhole == nil || blackhole.Protocol != "blackhole" || len(blackhole.NextHops) != 0 {
		t.Fatalf("blackhole route = %#v", blackhole)
	}
}

func TestParseLinuxIPRouteCanonicalizesConnectedProtocol(t *testing.T) {
	routes, err := ParseLinuxIPRoute("r1", []byte(`[{"dst":"192.0.2.0/31","dev":"eth1","protocol":"kernel"}]`))
	if err != nil {
		t.Fatalf("ParseLinuxIPRoute() error = %v", err)
	}
	route := routeByPrefix(routes, "192.0.2.0/31")
	if route == nil || route.Protocol != "connected" {
		t.Fatalf("route = %#v", route)
	}
}

func TestParseCEOSRoutes(t *testing.T) {
	data := []byte(`{
	  "vrfs": {"default": {"routes": {
	    "10.0.0.0/24": {
	      "kernelProgrammed": true,
	      "hardwareProgrammed": true,
	      "routeType": "eBGP",
	      "preference": 200,
	      "metric": 10,
	      "vias": [{"nexthopAddr":"192.0.2.1","interface":"Ethernet1"}]
	    },
	    "198.51.100.0/31": {
	      "kernelProgrammed": true,
	      "routeType": "connected",
	      "vias": [{"interface":"Ethernet2"}]
	    },
	    "203.0.113.0/24": {
	      "kernelProgrammed": true,
	      "routeType": "static",
	      "vias": [{"interface":"Null0"}]
	    }
	  }}}
	}`)
	routes, err := ParseCEOSRoutes("ceos1", data)
	if err != nil {
		t.Fatalf("ParseCEOSRoutes() error = %v", err)
	}
	route := routeByPrefix(routes, "10.0.0.0/24")
	if route == nil {
		t.Fatalf("routes = %#v", routes)
	}
	if route.Protocol != "bgp" || route.Preference != 200 || route.Metric != 10 {
		t.Fatalf("route attrs = %#v", route)
	}
	if got, want := route.NextHops, []NormalizedFIBNextHop{{Address: "192.0.2.1", Interface: "Ethernet1"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("next-hops = %#v, want %#v", got, want)
	}
	connected := routeByPrefix(routes, "198.51.100.0/31")
	if connected == nil || connected.Protocol != "connected" {
		t.Fatalf("connected route = %#v", connected)
	}
	blackhole := routeByPrefix(routes, "203.0.113.0/24")
	if blackhole == nil || blackhole.Protocol != "blackhole" || len(blackhole.NextHops) != 0 {
		t.Fatalf("blackhole route = %#v", blackhole)
	}
}

func TestParseSRLinuxRoutes(t *testing.T) {
	data := []byte("\x00noise\r\n" + `{
	  "instance": [{
	    "Name": "default",
	    "ip route": [
	      {"Prefix":"10.0.0.0/24","Route Type":"bgp","Active":"True","Metric":0,"Pref":170,"Next-hop (Type)":"192.0.2.1/31 (indirect/local)","Next-hop Interface":"ethernet-1/1.0 "},
	      {"Prefix":"198.51.100.0/31","Route Type":"local","Active":"True","Metric":0,"Pref":0,"Next-hop (Type)":"198.51.100.1 (direct)","Next-hop Interface":"ethernet-1/2.0 "},
	      {"Prefix":"198.51.100.0/24","Route Type":"blackhole","Active":"True","Metric":0,"Pref":1,"Next-hop (Type)":"None"},
	      {"Prefix":"203.0.113.0/24","Route Type":"bgp","Active":"False","Next-hop (Type)":"192.0.2.2/31 (indirect/local)","Next-hop Interface":"ethernet-1/3.0 "}
	    ]
	  }]
	}` + "\r\n")
	routes, err := ParseSRLinuxRoutes("srl1", data)
	if err != nil {
		t.Fatalf("ParseSRLinuxRoutes() error = %v", err)
	}
	if routeByPrefix(routes, "203.0.113.0/24") != nil {
		t.Fatalf("inactive route was parsed: %#v", routes)
	}
	route := routeByPrefix(routes, "10.0.0.0/24")
	if route == nil {
		t.Fatalf("routes = %#v", routes)
	}
	if route.Protocol != "bgp" || route.Preference != 170 {
		t.Fatalf("route attrs = %#v", route)
	}
	if got, want := route.NextHops, []NormalizedFIBNextHop{{Address: "192.0.2.1", Interface: "ethernet-1/1.0"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("next-hops = %#v, want %#v", got, want)
	}
	connected := routeByPrefix(routes, "198.51.100.0/31")
	if connected == nil || connected.Protocol != "connected" {
		t.Fatalf("connected route = %#v", connected)
	}
	blackhole := routeByPrefix(routes, "198.51.100.0/24")
	if blackhole == nil || blackhole.Protocol != "blackhole" || len(blackhole.NextHops) != 0 {
		t.Fatalf("blackhole route = %#v", blackhole)
	}
}

func TestParseSRLinuxRouteDetailsNormalizesPeerGateway(t *testing.T) {
	data := []byte(`{
	  "instance": [{
	    "Name": "default",
	    "ip route": [{
	      "Destination": "10.4.0.0/16",
	      "ID": 0,
	      "Route Type": "bgp",
	      "Route Owner": "bgp_mgr",
	      "Origin Network Instance": "default",
	      "Metric": 0,
	      "Preference": 170,
	      "Active": true,
	      "ip route nexthop": {
	        "Next Hop Count": 1,
	        "Next hops": "198.18.20.5 (indirect) resolved by route to 198.18.20.4/31 (local)\n  via 198.18.20.5 (direct) via [ethernet-1/4.0]"
	      },
	      "ip route backup nexthop": {
	        "Backup Next Hop Count": 0,
	        "Backup Next hops": ""
	      }
	    }]
	  }]
	}`)
	routes, err := ParseSRLinuxRouteDetails("core-gz", data)
	if err != nil {
		t.Fatalf("ParseSRLinuxRouteDetails() error = %v", err)
	}
	route := routeByPrefix(routes, "10.4.0.0/16")
	if route == nil {
		t.Fatalf("routes = %#v", routes)
	}
	if route.Protocol != "bgp" || route.Preference != 170 {
		t.Fatalf("route attrs = %#v", route)
	}
	want := []NormalizedFIBNextHop{{Address: "198.18.20.5", Interface: "ethernet-1/4.0"}}
	if !reflect.DeepEqual(route.NextHops, want) {
		t.Fatalf("next-hops = %#v, want %#v", route.NextHops, want)
	}
}

func TestComparableRoutesIncludesConnectedClasses(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "r1", Kind: model.KindFRR, Interfaces: []model.Interface{
				{Name: "lo", Address: "10.255.0.1/32"},
				{Name: "eth1", Address: "192.0.2.1/31"},
			}},
			{Name: "r2", Kind: model.KindFRR, Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.0/31"}}},
		},
		Links: []model.Link{{Name: "r1-r2", A: "r1", B: "r2", AIntf: "eth1", BIntf: "eth1"}},
	}
	routes := []NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "192.0.2.0/31", Protocol: "connected", NextHops: []NormalizedFIBNextHop{{Interface: "eth1"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.255.0.1/32", Protocol: "kernel", NextHops: []NormalizedFIBNextHop{{Interface: "lo"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "203.0.113.1/32", Protocol: "kernel", NextHops: []NormalizedFIBNextHop{{Interface: "dummy0"}}},
	}
	filtered := ComparableRoutes(topo, routes, Options{})
	if len(filtered) != 2 {
		t.Fatalf("filtered routes = %#v", filtered)
	}
	if route := routeByPrefix(filtered, "192.0.2.0/31"); route == nil || route.ConnectedClass != model.ConnectedRouteClassLink {
		t.Fatalf("link route = %#v", route)
	}
	if route := routeByPrefix(filtered, "10.255.0.1/32"); route == nil || route.ConnectedClass != model.ConnectedRouteClassLoopback {
		t.Fatalf("loopback route = %#v", route)
	}
	if route := routeByPrefix(filtered, "192.0.2.0/31"); route == nil || len(route.NextHops) != 1 || route.NextHops[0].Address != "" {
		t.Fatalf("connected route next-hop should compare by interface only: %#v", route)
	}
}

func TestExpectedForNodesNormalizesModeledFIB(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "src", Kind: model.KindFRR, ASN: 65000, Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.1/31"}}, Neighbors: []model.BGPNeighbor{{
				PeerNode:  "dst",
				RemoteAS:  65001,
				Activated: true,
			}}},
			{Name: "dst", Kind: model.KindFRR, ASN: 65001, Prefixes: model.MustPrefixes("10.0.0.0/24"), Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.0/31"}}, Neighbors: []model.BGPNeighbor{{
				PeerNode:  "src",
				RemoteAS:  65000,
				Activated: true,
			}}},
		},
		Links: []model.Link{{Name: "src-dst", A: "src", B: "dst", AIntf: "eth1", BIntf: "eth1", Cost: 7, Subnet: "192.0.2.0/31"}},
	}
	routes := ExpectedForNodes(topo, []model.Node{topo.Nodes[0]})
	route := routeByPrefix(routes, "10.0.0.0/24")
	if route == nil {
		t.Fatalf("routes = %#v, want 10.0.0.0/24", routes)
	}
	wantHop := NormalizedFIBNextHop{Address: "192.0.2.0", Interface: "eth1"}
	if !reflect.DeepEqual(route.NextHops, []NormalizedFIBNextHop{wantHop}) || route.Protocol != "bgp" || route.Metric != 7 {
		t.Fatalf("route = %#v", route)
	}
}

func TestExpectedForNodesKeepsLocalBlackholeAndSuppressesSamePrefixBGPFIB(t *testing.T) {
	prefix := model.MustPrefix("203.0.113.0/24")
	topo := &model.Topology{Nodes: []model.Node{{
		Name:     "r1",
		Kind:     model.KindFRR,
		ASN:      65000,
		Prefixes: []model.Prefix{prefix},
		Routes:   []model.ConfiguredRoute{{Prefix: prefix, Kind: model.RouteSourceBlackhole, Interface: "Null0"}},
	}}}
	routes := ExpectedForNodes(topo, topo.Nodes)
	if route := routeByPrefix(routes, prefix.String()); route == nil || route.Protocol != "blackhole" || len(route.NextHops) != 0 {
		t.Fatalf("blackhole FIB route = %#v in %#v", route, routes)
	}
	for _, route := range routes {
		if route.Prefix == prefix.String() && route.Protocol == "bgp" {
			t.Fatalf("same-prefix BGP route should not be expected in local FIB: %#v", routes)
		}
	}
}

func TestCompareReportsRouteAndNextHopDiffs(t *testing.T) {
	expected := []NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.1", Interface: "eth1"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.1.0/24"},
	}
	actual := []NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.2", Interface: "eth1"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.2.0/24"},
	}
	result := Compare(expected, actual)
	if result.OK {
		t.Fatalf("Compare() OK, want diffs")
	}
	if len(result.MissingRoutes) != 1 || len(result.UnexpectedRoutes) != 1 || len(result.MissingNextHops) != 1 || len(result.UnexpectedNextHops) != 1 {
		t.Fatalf("result = %#v", result)
	}
}

func TestNormalizeRoutesMergesDuplicateNextHops(t *testing.T) {
	routes, conflicts := NormalizeRoutes([]NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, Preference: 20, NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.1", Interface: "eth1"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, Preference: 20, NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.2", Interface: "eth2"}}},
	})
	if len(conflicts) != 0 || len(routes) != 1 {
		t.Fatalf("routes=%#v conflicts=%#v, want one merged route and no conflicts", routes, conflicts)
	}
	want := []NormalizedFIBNextHop{
		{Address: "192.0.2.1", Interface: "eth1"},
		{Address: "192.0.2.2", Interface: "eth2"},
	}
	if !reflect.DeepEqual(routes[0].NextHops, want) {
		t.Fatalf("next-hops = %#v, want %#v", routes[0].NextHops, want)
	}
}

func TestCompareReportsDuplicateRouteConflictForPreference(t *testing.T) {
	result := Compare([]NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, Preference: 20},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, Preference: 30},
	}, nil)
	if result.OK || len(result.DuplicateRouteConflicts) != 1 {
		t.Fatalf("result = %#v, want duplicate route conflict", result)
	}
	conflict := result.DuplicateRouteConflicts[0]
	if conflict.Side != "expected" || conflict.Reason != "preference mismatch" || len(conflict.Routes) != 2 {
		t.Fatalf("conflict = %#v", conflict)
	}
}

func TestCompareReportsDuplicateRouteConflictForConnectedClass(t *testing.T) {
	result := Compare([]NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "192.0.2.0/31", Protocol: "connected", ConnectedClass: model.ConnectedRouteClassLink, Installed: true},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "192.0.2.0/31", Protocol: "connected", ConnectedClass: model.ConnectedRouteClassLoopback, Installed: true},
	}, nil)
	if result.OK || len(result.DuplicateRouteConflicts) != 1 || result.DuplicateRouteConflicts[0].Reason != "connected_class mismatch" {
		t.Fatalf("result = %#v, want connected class duplicate conflict", result)
	}
}

func TestCompareReportsExpectedAndActualDuplicateRouteConflicts(t *testing.T) {
	expected := []NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, Preference: 20},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, Preference: 30},
	}
	actual := []NormalizedFIBRoute{
		{Node: "r2", VRF: "default", AFI: "ipv4", Prefix: "10.0.1.0/24", Protocol: "bgp", Installed: true, Metric: 10},
		{Node: "r2", VRF: "default", AFI: "ipv4", Prefix: "10.0.1.0/24", Protocol: "bgp", Installed: true, Metric: 20},
	}
	result := Compare(expected, actual)
	if result.OK || len(result.DuplicateRouteConflicts) != 2 {
		t.Fatalf("result = %#v, want expected and actual duplicate conflicts", result)
	}
	if result.DuplicateRouteConflicts[0].Side != "expected" || result.DuplicateRouteConflicts[1].Side != "actual" {
		t.Fatalf("conflicts = %#v", result.DuplicateRouteConflicts)
	}
}

func TestCompareDuplicateRoutesDoNotSilentlyOverwrite(t *testing.T) {
	expected := []NormalizedFIBRoute{{
		Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true,
		NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.1", Interface: "eth1"}},
	}}
	actual := []NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.2", Interface: "eth2"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Installed: true, NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.1", Interface: "eth1"}}},
	}
	result := Compare(expected, actual)
	if result.OK || len(result.UnexpectedNextHops) != 1 || result.UnexpectedNextHops[0].NextHopKey != "192.0.2.2|eth2" {
		t.Fatalf("result = %#v, want duplicate next-hop merged into visible diff", result)
	}
}

func TestFormatAndJSONIncludeDuplicateRouteConflict(t *testing.T) {
	result := Result{DuplicateRouteConflicts: []DuplicateRouteConflict{{
		RouteKey: "r1|default|ipv4|10.0.0.0/24",
		Side:     "expected",
		Reason:   "preference mismatch",
		Routes: []NormalizedFIBRoute{
			{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Preference: 20},
			{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", Preference: 30},
		},
	}}}
	lines := FormatDiffs(result)
	if len(lines) != 1 || !strings.Contains(lines[0], "duplicate FIB route conflict") || !strings.Contains(lines[0], "reason=preference mismatch") {
		t.Fatalf("lines = %#v", lines)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(data), "DuplicateRouteConflicts") || !strings.Contains(string(data), "preference mismatch") {
		t.Fatalf("json = %s, want duplicate conflict", data)
	}
}

func TestCollectRejectsUnsupportedNodes(t *testing.T) {
	_, err := Collect(context.Background(), fakeRunner{}, []model.Node{{Name: "unknown1", Kind: model.DeviceKind("unknown")}}, Options{})
	if err == nil || !strings.Contains(err.Error(), "unsupported live FIB collector") {
		t.Fatalf("Collect() error = %v", err)
	}
}

func TestCollectFRRKernelRoutes(t *testing.T) {
	runner := fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		got := name + " " + strings.Join(args, " ")
		switch got {
		case "docker exec -i clab-test-r1 ip -j route show table main":
			return []byte(`[{"dst":"10.0.0.0/24","gateway":"192.0.2.1","dev":"eth1","protocol":"bgp"}]`), nil
		case "docker exec -i clab-test-r1 ip -j route show table local":
			return []byte(`[]`), nil
		default:
			return nil, errors.New("unexpected command: " + got)
		}
	}}
	routes, err := Collect(context.Background(), runner, []model.Node{{Name: "r1", Kind: model.KindFRR, ContainerName: "clab-test-r1"}}, Options{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(routes) != 1 || routes[0].Prefix != "10.0.0.0/24" {
		t.Fatalf("routes = %#v", routes)
	}
}

func TestCollectAllSupportedKinds(t *testing.T) {
	runner := fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch {
		case cmd == "docker exec -i frr1 ip -j route show table main":
			return []byte(`[{"dst":"10.0.0.0/24","gateway":"192.0.2.1","dev":"eth1","protocol":"bgp"}]`), nil
		case cmd == "docker exec -i frr1 ip -j route show table local":
			return []byte(`[]`), nil
		case cmd == "docker exec -i ceos1 Cli -p 15 -c show ip route vrf default | json":
			return []byte(`{"vrfs":{"default":{"routes":{"10.0.1.0/24":{"kernelProgrammed":true,"routeType":"eBGP","vias":[{"nexthopAddr":"192.0.2.2","interface":"Ethernet1"}]}}}}}`), nil
		case cmd == "docker exec -i srl1 sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast summary":
			return []byte(`{"instance":[{"ip route":[{"Prefix":"10.0.2.0/24","Route Type":"bgp","Active":"True","Next-hop (Type)":"192.0.2.3/31 (indirect/local)","Next-hop Interface":"ethernet-1/1.0 "}]}]}`), nil
		case cmd == "docker exec -i srl1 sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast prefix 10.0.2.0/24 detail":
			return []byte(`{"instance":[{"ip route":[{"Destination":"10.0.2.0/24","Route Type":"bgp","Active":true,"ip route nexthop":{"Next hops":"192.0.2.2 (indirect) resolved by route to 192.0.2.3/31 (local)\n  via 192.0.2.2 (direct) via [ethernet-1/1.0]"}}]}]}`), nil
		default:
			return nil, errors.New("unexpected command: " + cmd)
		}
	}}
	routes, err := Collect(context.Background(), runner, []model.Node{
		{Name: "frr", Kind: model.KindFRR, ContainerName: "frr1"},
		{Name: "ceos", Kind: model.KindCEOS, ContainerName: "ceos1"},
		{Name: "srl", Kind: model.KindSRLinux, ContainerName: "srl1"},
	}, Options{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	for _, prefix := range []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"} {
		if routeByPrefix(routes, prefix) == nil {
			t.Fatalf("routes missing %s: %#v", prefix, routes)
		}
	}
}

func TestCollectSRLinuxUsesRouteDetailPeerGateway(t *testing.T) {
	runner := fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch cmd {
		case "docker exec -i srl1 sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast summary":
			return []byte(`{"instance":[{"ip route":[
			  {"Prefix":"10.4.0.0/16","Route Type":"bgp","Active":"True","Metric":0,"Pref":170,"Next-hop (Type)":"198.18.20.4/31 (indirect/local)","Next-hop Interface":"ethernet-1/4.0 "},
			  {"Prefix":"198.18.20.4/31","Route Type":"local","Active":"True","Next-hop (Type)":"198.18.20.4 (direct)","Next-hop Interface":"ethernet-1/4.0 "}
			]}]}`), nil
		case "docker exec -i srl1 sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast prefix 10.4.0.0/16 detail":
			return []byte(`{"instance":[{"ip route":[{"Destination":"10.4.0.0/16","Route Type":"bgp","Active":true,"Preference":170,"ip route nexthop":{"Next Hop Count":1,"Next hops":"198.18.20.5 (indirect) resolved by route to 198.18.20.4/31 (local)\n  via 198.18.20.5 (direct) via [ethernet-1/4.0]"}}]}]}`), nil
		default:
			return nil, errors.New("unexpected command: " + cmd)
		}
	}}
	routes, err := Collect(context.Background(), runner, []model.Node{{Name: "core-gz", Kind: model.KindSRLinux, ContainerName: "srl1"}}, Options{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	route := routeByPrefix(routes, "10.4.0.0/16")
	if route == nil {
		t.Fatalf("routes = %#v", routes)
	}
	want := []NormalizedFIBNextHop{{Address: "198.18.20.5", Interface: "ethernet-1/4.0"}}
	if !reflect.DeepEqual(route.NextHops, want) {
		t.Fatalf("next-hops = %#v, want %#v", route.NextHops, want)
	}
}

func TestCollectSRLinuxFallsBackToTTYWhenJSONIsEmpty(t *testing.T) {
	runner := fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch {
		case cmd == "docker exec -i srl1 sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast summary":
			return []byte{}, nil
		case strings.HasPrefix(cmd, "script -q /dev/null -c docker exec -it 'srl1' sr_cli --output-format json --pagination off -- 'show' 'network-instance' 'default' 'route-table' 'ipv4-unicast' 'summary'"):
			return []byte(`{"instance":[{"ip route":[{"Prefix":"198.18.20.4/31","Route Type":"local","Active":"True","Next-hop (Type)":"198.18.20.4 (direct)","Next-hop Interface":"ethernet-1/4.0 "}]}]}`), nil
		default:
			return nil, errors.New("unexpected command: " + cmd)
		}
	}}
	routes, err := Collect(context.Background(), runner, []model.Node{{Name: "core-gz", Kind: model.KindSRLinux, ContainerName: "srl1"}}, Options{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if routeByPrefix(routes, "198.18.20.4/31") == nil {
		t.Fatalf("routes = %#v", routes)
	}
}

func TestComparableRoutesFiltersNonBGPAndUnsupportedNextHops(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "r1", Kind: model.KindFRR, Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.1/31"}, {Name: "eth2", Address: "198.51.100.1/31"}}},
			{Name: "r2", Kind: model.KindFRR, Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.0/31"}}},
			{Name: "nos1", Kind: model.DeviceKind("unknown"), Interfaces: []model.Interface{{Name: "eth1", Address: "198.51.100.0/31"}}},
		},
		Links: []model.Link{
			{Name: "r1-r2", A: "r1", B: "r2", AIntf: "eth1", BIntf: "eth1"},
			{Name: "r1-nos1", A: "r1", B: "nos1", AIntf: "eth2", BIntf: "eth1"},
		},
	}
	routes := []NormalizedFIBRoute{
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "0.0.0.0/0", Protocol: "", NextHops: []NormalizedFIBNextHop{{Address: "172.16.0.1", Interface: "eth0"}}},
		{Node: "r1", VRF: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Protocol: "bgp", NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.0", Interface: "eth1"}, {Address: "198.51.100.0", Interface: "eth2"}}},
	}
	filtered := ComparableRoutes(topo, routes, Options{AllowUnsupported: true})
	if len(filtered) != 1 {
		t.Fatalf("filtered routes = %#v", filtered)
	}
	if got, want := filtered[0].NextHops, []NormalizedFIBNextHop{{Address: "192.0.2.0", Interface: "eth1"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("next-hops = %#v, want %#v", got, want)
	}
}

func TestAnalyzeComparableRoutesReportsManagementFallback(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "r1", Kind: model.KindFRR, Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.1/31"}}},
			{Name: "r2", Kind: model.KindFRR, Interfaces: []model.Interface{{Name: "eth1", Address: "192.0.2.0/31"}}},
		},
		Links: []model.Link{{Name: "r1-r2", A: "r1", B: "r2", AIntf: "eth1", BIntf: "eth1"}},
	}
	routes := []NormalizedFIBRoute{{
		Node:     "r1",
		VRF:      "default",
		AFI:      "ipv4",
		Prefix:   "10.3.0.0/16",
		Protocol: "bgp",
		NextHops: []NormalizedFIBNextHop{{Address: "172.86.191.1", Interface: "eth0"}},
	}}
	result := AnalyzeComparableRoutes(topo, routes, Options{})
	if len(result.Routes) != 0 {
		t.Fatalf("routes = %#v, want unresolved route excluded", result.Routes)
	}
	if len(result.Unresolved) != 1 {
		t.Fatalf("unresolved = %#v, want one diagnostic", result.Unresolved)
	}
	got := result.Unresolved[0]
	if got.RouteKey != "r1|default|ipv4|10.3.0.0/16" || got.Reason != "unresolved_or_mgmt_fallback" {
		t.Fatalf("diagnostic = %#v", got)
	}
	if len(got.NextHops) != 1 || got.NextHops[0].Reason != "unresolved_or_mgmt_fallback" {
		t.Fatalf("next-hop diagnostic = %#v", got.NextHops)
	}
}

func TestCompareFilterResultsWarnExcludesUnresolvedRoute(t *testing.T) {
	expected := FilterResult{Routes: []NormalizedFIBRoute{{
		Node:     "r1",
		VRF:      "default",
		AFI:      "ipv4",
		Prefix:   "10.3.0.0/16",
		Protocol: "bgp",
		NextHops: []NormalizedFIBNextHop{{Address: "192.0.2.0", Interface: "eth1"}},
	}}}
	actual := FilterResult{Unresolved: []UnresolvedRoute{{
		RouteKey: "r1|default|ipv4|10.3.0.0/16",
		Node:     "r1",
		VRF:      "default",
		AFI:      "ipv4",
		Prefix:   "10.3.0.0/16",
		Protocol: "bgp",
		Reason:   "unresolved_or_mgmt_fallback",
	}}}
	result := CompareFilterResults(expected, actual, Options{})
	if !result.OK {
		t.Fatalf("result = %#v, want warning policy to exclude unresolved route from strict comparison", result)
	}

	result = CompareFilterResults(expected, actual, Options{UnresolvedPolicy: UnresolvedPolicyFail})
	if result.OK || len(result.UnresolvedRoutes) != 1 {
		t.Fatalf("result = %#v, want unresolved route as failing diff", result)
	}
}

func TestComparableRoutesKeepsSRLinuxDetailNextHopAddress(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "core-gz", Kind: model.KindSRLinux, Interfaces: []model.Interface{{Name: "ethernet-1/4.0", Address: "198.18.20.4/31"}}},
			{Name: "core-hz", Kind: model.KindFRR, Interfaces: []model.Interface{{Name: "eth3", Address: "198.18.20.5/31"}}},
		},
		Links: []model.Link{{Name: "gz-hz", A: "core-gz", B: "core-hz", AIntf: "e1-4", BIntf: "eth3"}},
	}
	routes := []NormalizedFIBRoute{{
		Node:     "core-gz",
		VRF:      "default",
		AFI:      "ipv4",
		Prefix:   "10.4.0.0/16",
		Protocol: "bgp",
		NextHops: []NormalizedFIBNextHop{{Address: "198.18.20.5", Interface: "ethernet-1/4.0"}},
	}}
	filtered := ComparableRoutes(topo, routes, Options{})
	if len(filtered) != 1 {
		t.Fatalf("filtered routes = %#v", filtered)
	}
	want := []NormalizedFIBNextHop{{Address: "198.18.20.5", Interface: "ethernet-1/4"}}
	if !reflect.DeepEqual(filtered[0].NextHops, want) {
		t.Fatalf("next-hops = %#v, want %#v", filtered[0].NextHops, want)
	}
}

type fakeRunner struct {
	fn func(name string, args ...string) ([]byte, error)
}

func (f fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if f.fn == nil {
		return nil, errors.New("unexpected command")
	}
	return f.fn(name, args...)
}

func routeByPrefix(routes []NormalizedFIBRoute, prefix string) *NormalizedFIBRoute {
	for i := range routes {
		if routes[i].Prefix == prefix {
			return &routes[i]
		}
	}
	return nil
}
