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
			var paths []NormalizedBgpPath
			for _, route := range rib {
				if route.Condition == nil || !route.Condition.Eval(ctx) {
					continue
				}
				paths = append(paths, expectedPath(idx, n, route, ctx))
			}
			if len(paths) == 0 {
				continue
			}
			sortPaths(paths, DefaultBgpRibCompareOptions())
			out = append(out, NormalizedBgpRoute{
				Node:            n.Name,
				NetworkInstance: "default",
				AFI:             "ipv4",
				Prefix:          prefix,
				Paths:           paths,
			})
		}
	}
	sortRoutes(out)
	return out
}

func expectedPath(idx *model.TopologyIndex, node model.Node, route sim.RIBEntry, ctx sim.FailureContext) NormalizedBgpPath {
	route = route.Normalize()
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
