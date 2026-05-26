package fibcompare

import (
	"github.com/81ueman/network-sandbox/hoyan/internal/dataplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

func Expected(topo *model.Topology) []NormalizedFIBRoute {
	return ExpectedForNodes(topo, topo.Nodes)
}

func ExpectedForNodes(topo *model.Topology, nodes []model.Node) []NormalizedFIBRoute {
	allowed := map[string]bool{}
	for _, n := range nodes {
		allowed[n.Name] = true
	}
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		panic(err)
	}
	graph := sim.NewGraph(topo)
	ctx := graph.FailureContext(sim.NoFailures())
	byRoute := map[string]NormalizedFIBRoute{}
	for _, n := range topo.Nodes {
		if !allowed[n.Name] || ctx.NodeFailed(model.NodeID(n.Name)) {
			continue
		}
		suppressedBGP := bgpSuppressedByNonBGPFIB(graph.FIB(n.Name), ctx)
		behavior := sim.BehaviorFor(n.Kind)
		for _, rib := range graph.RIBTable(n.Name) {
			for _, entry := range rib {
				entry = entry.Normalize()
				if entry.SourceKind != model.RouteSourceBGP {
					continue
				}
				if suppressedBGP[entry.Prefix.String()] {
					continue
				}
				if entry.SelectedCond == nil || !entry.SelectedCond.Eval(ctx) || !behavior.RouteValidForRIB(n, entry) {
					continue
				}
				addExpectedRoute(byRoute, idx, n.Name, entry.Prefix.String(), entry.NextHop, entry.RouteSource.Interface, entry.SourceKind, entry.RouteSource.ConnectedClass, idx.PathCost(entry.Links))
			}
		}
		for _, entry := range graph.FIB(n.Name) {
			if entry.SourceKind == model.RouteSourceBGP {
				continue
			}
			if entry.Condition == nil || !entry.Condition.Eval(ctx) {
				continue
			}
			addExpectedRoute(byRoute, idx, n.Name, entry.Prefix.String(), entry.NextHop, entry.Interface, entry.SourceKind, entry.ConnectedClass, entry.Path.Cost)
		}
	}
	out := make([]NormalizedFIBRoute, 0, len(byRoute))
	for _, route := range byRoute {
		route.NextHops = dedupeNextHops(route.NextHops)
		out = append(out, route)
	}
	sortRoutes(out)
	return out
}

func bgpSuppressedByNonBGPFIB(entries []dataplane.FIBEntry, ctx sim.FailureContext) map[string]bool {
	out := map[string]bool{}
	for _, entry := range entries {
		if entry.SourceKind == model.RouteSourceBGP {
			continue
		}
		if entry.Condition == nil || !entry.Condition.Eval(ctx) {
			continue
		}
		out[entry.Prefix.String()] = true
	}
	return out
}

func addExpectedRoute(byRoute map[string]NormalizedFIBRoute, idx *model.TopologyIndex, node, prefix, nextHop, iface string, source model.RouteSourceKind, class model.ConnectedRouteClass, metric int) {
	route := NormalizedFIBRoute{
		Node:           node,
		VRF:            "default",
		AFI:            "ipv4",
		Prefix:         prefix,
		Protocol:       expectedProtocol(source, nextHop),
		ConnectedClass: class,
		Metric:         metric,
		Installed:      true,
	}
	if nextHop != "" {
		route.NextHops = []NormalizedFIBNextHop{expectedNextHop(idx, node, nextHop)}
	} else if iface != "" && source != model.RouteSourceBlackhole {
		route.NextHops = []NormalizedFIBNextHop{{Interface: iface}}
	}
	key := routeKey(route)
	existing := byRoute[key]
	if existing.Node == "" {
		byRoute[key] = route
		return
	}
	existing.NextHops = append(existing.NextHops, route.NextHops...)
	if route.Metric < existing.Metric || existing.Metric == 0 {
		existing.Metric = route.Metric
	}
	byRoute[key] = existing
}

func expectedProtocol(source model.RouteSourceKind, nextHop string) string {
	switch source {
	case model.RouteSourceConnected:
		return "connected"
	case model.RouteSourceStatic, model.RouteSourceBlackhole:
		return "static"
	}
	return "bgp"
}

func expectedNextHop(idx *model.TopologyIndex, node, nextHop string) NormalizedFIBNextHop {
	out := NormalizedFIBNextHop{}
	if ref, ok := idx.InterfaceToPeer(node, nextHop); ok {
		out.Interface = ref.ConfigName
	}
	if addr, ok := idx.PeerAddress(node, nextHop); ok {
		out.Address = addr.String()
		return out
	}
	out.Address = nextHop
	return out
}

func dedupeNextHops(in []NormalizedFIBNextHop) []NormalizedFIBNextHop {
	seen := map[string]bool{}
	var out []NormalizedFIBNextHop
	for _, hop := range in {
		key := nextHopKey(hop)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hop)
	}
	sortNextHops(out)
	return out
}
