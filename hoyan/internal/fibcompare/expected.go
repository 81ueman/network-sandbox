package fibcompare

import (
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
		behavior := sim.BehaviorFor(n.Kind)
		for _, rib := range graph.RIBTable(n.Name) {
			for _, entry := range rib {
				entry = entry.Normalize()
				if entry.SelectedCond == nil || !entry.SelectedCond.Eval(ctx) || !behavior.RouteValidForRIB(n, entry) {
					continue
				}
				addExpectedRoute(byRoute, idx, n.Name, entry.Prefix.String(), entry.NextHop, idx.PathCost(entry.Links))
			}
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

func addExpectedRoute(byRoute map[string]NormalizedFIBRoute, idx *model.TopologyIndex, node, prefix, nextHop string, metric int) {
	route := NormalizedFIBRoute{
		Node:      node,
		VRF:       "default",
		AFI:       "ipv4",
		Prefix:    prefix,
		Protocol:  expectedProtocol(nextHop),
		Metric:    metric,
		Installed: true,
	}
	if nextHop != "" {
		route.NextHops = []NormalizedFIBNextHop{expectedNextHop(idx, node, nextHop)}
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

func expectedProtocol(nextHop string) string {
	if nextHop == "" {
		return "connected"
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
