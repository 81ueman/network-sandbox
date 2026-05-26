package fibcompare

import (
	"context"
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
	  {"dst":"2001:db8::/64","dev":"eth3","protocol":"kernel"}
	]`)
	routes, err := ParseLinuxIPRoute("r1", data)
	if err != nil {
		t.Fatalf("ParseLinuxIPRoute() error = %v", err)
	}
	if len(routes) != 4 {
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
}

func TestParseSRLinuxRoutes(t *testing.T) {
	data := []byte("\x00noise\r\n" + `{
	  "instance": [{
	    "Name": "default",
	    "ip route": [
	      {"Prefix":"10.0.0.0/24","Route Type":"bgp","Active":"True","Metric":0,"Pref":170,"Next-hop (Type)":"192.0.2.1/31 (indirect/local)","Next-hop Interface":"ethernet-1/1.0 "},
	      {"Prefix":"198.51.100.0/31","Route Type":"local","Active":"True","Metric":0,"Pref":0,"Next-hop (Type)":"198.51.100.1 (direct)","Next-hop Interface":"ethernet-1/2.0 "},
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
		case strings.HasPrefix(cmd, "script -q /dev/null -c docker exec -it 'srl1' sr_cli"):
			return []byte(`{"instance":[{"ip route":[{"Prefix":"10.0.2.0/24","Route Type":"bgp","Active":"True","Next-hop (Type)":"192.0.2.3/31 (indirect/local)","Next-hop Interface":"ethernet-1/1.0 "}]}]}`), nil
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
