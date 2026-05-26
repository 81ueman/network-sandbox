package fibcompare

import (
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func ComparableRoutes(topo *model.Topology, routes []NormalizedFIBRoute, opts Options) []NormalizedFIBRoute {
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		panic(err)
	}
	var out []NormalizedFIBRoute
	for _, route := range routes {
		route.Protocol = canonicalProtocol(route.Protocol)
		if route.Protocol == "connected" && route.ConnectedClass == "" {
			route.ConnectedClass = idx.ConnectedClassForRoute(route.Node, route.Prefix, firstNextHopInterface(route.NextHops))
		}
		if !comparableProtocol(route) {
			continue
		}
		if route.Protocol == "connected" && !comparableConnectedClass(route.ConnectedClass) {
			continue
		}
		if route.Protocol == "static" && len(route.NextHops) == 0 {
			continue
		}
		filtered := route
		filtered.NextHops = normalizeRouteNextHops(idx, filtered)
		if route.Protocol == "bgp" {
			filtered.NextHops = comparableNextHops(idx, route.Node, filtered.NextHops, opts)
			filtered.NextHops = normalizeRouteNextHops(idx, filtered)
			if len(route.NextHops) > 0 && len(filtered.NextHops) == 0 {
				continue
			}
		}
		out = append(out, filtered)
	}
	sortRoutes(out)
	return out
}

func comparableProtocol(route NormalizedFIBRoute) bool {
	switch route.Protocol {
	case "bgp", "connected", "static":
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

func firstNextHopInterface(hops []NormalizedFIBNextHop) string {
	for _, hop := range hops {
		if hop.Interface != "" {
			return hop.Interface
		}
	}
	return ""
}

func normalizeRouteNextHops(idx *model.TopologyIndex, route NormalizedFIBRoute) []NormalizedFIBNextHop {
	node, ok := idx.Node(route.Node)
	if !ok {
		return dedupeNextHops(route.NextHops)
	}
	out := make([]NormalizedFIBNextHop, 0, len(route.NextHops))
	for _, hop := range route.NextHops {
		for _, alias := range model.InterfaceAliases(node.Kind, hop.Interface) {
			if strings.HasSuffix(alias, ".0") {
				hop.Interface = strings.TrimSuffix(alias, ".0")
				break
			}
			hop.Interface = alias
			break
		}
		if node.Kind == model.KindSRLinux {
			hop.Address = ""
		}
		out = append(out, hop)
	}
	return dedupeNextHops(out)
}

func comparableNextHops(idx *model.TopologyIndex, node string, hops []NormalizedFIBNextHop, opts Options) []NormalizedFIBNextHop {
	var out []NormalizedFIBNextHop
	for _, hop := range hops {
		peer, ok := peerForNextHopInterface(idx, node, hop.Interface)
		if !ok {
			if hop.Interface == "" && hop.Address != "" && !isNodeName(idx, hop.Address) {
				out = append(out, hop)
			}
			continue
		}
		peerNode, ok := idx.Node(peer)
		if !ok {
			continue
		}
		if opts.AllowUnsupported && !supportsLiveFIB(peerNode.Kind) {
			continue
		}
		out = append(out, hop)
	}
	return dedupeNextHops(out)
}

func peerForNextHopInterface(idx *model.TopologyIndex, node, iface string) (string, bool) {
	if idx == nil || iface == "" {
		return "", false
	}
	n, ok := idx.Node(node)
	if !ok {
		return "", false
	}
	for _, edge := range idx.Adj[model.NodeID(node)] {
		link := edge.Link
		localIface := link.AIntf
		if link.B == node {
			localIface = link.BIntf
		}
		if model.EquivalentInterfaceName(n.Kind, localIface, iface) {
			return string(edge.To), true
		}
	}
	return "", false
}

func isNodeName(idx *model.TopologyIndex, name string) bool {
	_, ok := idx.Node(name)
	return ok
}

func supportsLiveFIB(kind model.DeviceKind) bool {
	switch kind {
	case model.KindFRR, model.KindCEOS, model.KindSRLinux:
		return true
	default:
		return false
	}
}
