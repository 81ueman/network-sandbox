package ribcompare

import (
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

func Expected(topo *model.Topology) []NormalizedBgpRoute {
	return ExpectedWithFailureSet(topo, sim.NoFailures())
}

func ExpectedForNodes(topo *model.Topology, nodes []model.Node) []NormalizedBgpRoute {
	return ExpectedForNodesWithFailureSet(topo, nodes, sim.NoFailures())
}

func ExpectedForNodesWithFailureSet(topo *model.Topology, nodes []model.Node, failures sim.FailureSet) []NormalizedBgpRoute {
	allowed := map[string]bool{}
	for _, n := range nodes {
		allowed[n.Name] = true
	}
	return expected(topo, allowed, failures)
}

func ExpectedWithFailureSet(topo *model.Topology, failures sim.FailureSet) []NormalizedBgpRoute {
	return expected(topo, nil, failures)
}

func expected(topo *model.Topology, allowed map[string]bool, failures sim.FailureSet) []NormalizedBgpRoute {
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		panic(err)
	}
	g := sim.NewGraph(topo)
	ctx := g.FailureContext(failures)
	var out []NormalizedBgpRoute
	for _, n := range topo.Nodes {
		if allowed != nil && !allowed[n.Name] {
			continue
		}
		if ctx.NodeFailed(model.NodeID(n.Name)) {
			continue
		}
		for prefix, rib := range g.RIBTable(n.Name) {
			pathsByProtocol := map[string][]NormalizedBgpPath{}
			for _, route := range rib {
				route = route.Normalize()
				if route.Condition == nil || !route.Condition.Eval(ctx) {
					continue
				}
				if !routeComparableInLiveRIB(idx, n.Name, route) {
					continue
				}
				protocol := expectedRouteProtocol(route)
				pathsByProtocol[protocol] = append(pathsByProtocol[protocol], expectedPath(idx, n, route, ctx))
			}
			for _, protocol := range sortedProtocolKeys(pathsByProtocol) {
				paths := pathsByProtocol[protocol]
				if len(paths) == 0 {
					continue
				}
				sortPaths(paths, DefaultBgpRibCompareOptions())
				out = append(out, NormalizedBgpRoute{
					Node:            n.Name,
					NetworkInstance: "default",
					AFI:             "ipv4",
					Prefix:          prefix,
					Protocol:        protocol,
					ConnectedClass:  connectedClassForProtocol(protocol, rib),
					Paths:           paths,
				})
			}
		}
	}
	sortRoutes(out)
	return out
}

func sortedProtocolKeys(m map[string][]NormalizedBgpPath) []string {
	order := []string{"bgp", "connected", "static", "blackhole"}
	var out []string
	seen := map[string]bool{}
	for _, protocol := range order {
		if _, ok := m[protocol]; ok {
			out = append(out, protocol)
			seen[protocol] = true
		}
	}
	for protocol := range m {
		if !seen[protocol] {
			out = append(out, protocol)
		}
	}
	return out
}

func expectedRouteProtocol(route sim.RIBEntry) string {
	route = route.Normalize()
	switch route.SourceKind {
	case model.RouteSourceConnected:
		return "connected"
	case model.RouteSourceStatic:
		return "static"
	case model.RouteSourceBlackhole:
		return "blackhole"
	default:
		return "bgp"
	}
}

func connectedClassForProtocol(protocol string, routes []sim.RIBEntry) model.ConnectedRouteClass {
	if protocol != "connected" {
		return ""
	}
	for _, route := range routes {
		route = route.Normalize()
		if expectedRouteProtocol(route) == "connected" && route.RouteSource.ConnectedClass != "" {
			return route.RouteSource.ConnectedClass
		}
	}
	return ""
}

func routeComparableInLiveRIB(idx *model.TopologyIndex, node string, route sim.RIBEntry) bool {
	route = route.Normalize()
	switch route.SourceKind {
	case model.RouteSourceBGP, model.RouteSourceAggregate:
		return true
	case model.RouteSourceConnected:
		return comparableConnectedClass(route.RouteSource.ConnectedClass)
	case model.RouteSourceStatic:
		return route.RouteSource.NextHop != ""
	case model.RouteSourceBlackhole:
		return true
	default:
		return false
	}
}

func comparableConnectedClass(class model.ConnectedRouteClass) bool {
	switch class {
	case model.ConnectedRouteClassLink, model.ConnectedRouteClassLoopback, model.ConnectedRouteClassService:
		return true
	default:
		return false
	}
}

func expectedPath(idx *model.TopologyIndex, node model.Node, route sim.RIBEntry, ctx sim.FailureContext) NormalizedBgpPath {
	route = route.Normalize()
	if expectedRouteProtocol(route) != "bgp" {
		return NormalizedBgpPath{
			Best:      route.SelectedCond != nil && route.SelectedCond.Eval(ctx),
			Valid:     expectedRouteValid(node, route),
			NextHop:   routeNextHopAddress(idx, node.Name, route),
			Origin:    "igp",
			LocalPref: 100,
		}
	}
	return NormalizedBgpPath{
		Best:      route.SelectedCond != nil && route.SelectedCond.Eval(ctx),
		Valid:     expectedRouteValid(node, route),
		NextHop:   routeNextHopAddress(idx, node.Name, route),
		ASPath:    append([]uint32(nil), route.ASPath...),
		Origin:    expectedRouteOrigin(route),
		LocalPref: defaultLocalPref(route.LocalPref),
		MED:       route.MED,
	}
}

func expectedRouteOrigin(route sim.RIBEntry) string {
	route = route.Normalize()
	if route.Attrs.OriginCode != "" {
		return string(route.Attrs.OriginCode)
	}
	return "igp"
}
