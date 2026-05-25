package ribcompare

import (
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

func peerAddress(idx *model.TopologyIndex, node, peer string) string {
	if peer == "" {
		return ""
	}
	if addr, ok := idx.PeerAddress(node, peer); ok {
		return addr.String()
	}
	return peer
}

func routeNextHopAddress(idx *model.TopologyIndex, node string, route sim.RIBEntry) string {
	route = route.Normalize()
	if route.ForwardingNextHop.Addr != "" {
		return route.ForwardingNextHop.Addr
	}
	if route.NextHop == "" {
		return ""
	}
	if direct := peerAddress(idx, node, route.NextHop); direct != route.NextHop {
		return direct
	}
	for i := 0; i+1 < len(route.Nodes); i++ {
		if route.Nodes[i] != route.NextHop {
			continue
		}
		if addr := peerAddress(idx, route.Nodes[i+1], route.NextHop); addr != route.NextHop {
			return addr
		}
	}
	return route.NextHop
}

func expectedRouteValid(node model.Node, route sim.RIBEntry) bool {
	return sim.BehaviorFor(node.Kind).RouteValidForRIB(node, route)
}
