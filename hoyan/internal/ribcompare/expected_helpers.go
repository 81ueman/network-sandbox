package ribcompare

import (
	"fmt"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

func peerAddress(idx *model.TopologyIndex, node, peer string) string {
	if peer == "" {
		return ""
	}
	link, ok := idx.LinkBetween(node, peer)
	if !ok {
		return peer
	}
	if addr, ok := idx.PeerAddressOnLink(node, peer); ok {
		return addr.String()
	}
	a, b := linkAddresses(link.Subnet)
	switch {
	case link.A == node && link.B == peer:
		return trimMask(b)
	case link.B == node && link.A == peer:
		return trimMask(a)
	default:
		return peer
	}
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

func linkAddresses(raw string) (string, string) {
	// Legacy fallback for incomplete topology data. Normal next-hop resolution
	// uses parsed interface addresses from TopologyIndex instead of guessing
	// endpoint addresses from a link subnet.
	parts := strings.Split(raw, "/")
	prefixLen := ""
	if len(parts) == 2 {
		prefixLen = "/" + parts[1]
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return raw, raw
	}
	last := 0
	fmt.Sscanf(octets[3], "%d", &last)
	a := parts[0] + prefixLen
	octets[3] = fmt.Sprint(last + 1)
	b := strings.Join(octets, ".") + prefixLen
	return a, b
}

func trimMask(addr string) string {
	return strings.Split(addr, "/")[0]
}
