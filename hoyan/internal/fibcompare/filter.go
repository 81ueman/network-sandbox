package fibcompare

import (
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func ComparableRoutes(topo *model.Topology, routes []NormalizedFIBRoute, opts Options) []NormalizedFIBRoute {
	return AnalyzeComparableRoutes(topo, routes, opts).Routes
}

func AnalyzeComparableRoutes(topo *model.Topology, routes []NormalizedFIBRoute, opts Options) FilterResult {
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		panic(err)
	}
	var out []NormalizedFIBRoute
	var unresolved []UnresolvedRoute
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
			var routeUnresolved []UnresolvedNextHop
			filtered.NextHops, routeUnresolved = comparableNextHops(idx, route.Node, filtered.NextHops, opts)
			if len(routeUnresolved) > 0 {
				unresolved = append(unresolved, unresolvedRoute(filtered, routeUnresolved))
			}
			filtered.NextHops = normalizeRouteNextHops(idx, filtered)
			if len(route.NextHops) > 0 && len(filtered.NextHops) == 0 {
				continue
			}
		}
		out = append(out, filtered)
	}
	sortRoutes(out)
	sortUnresolvedRoutes(unresolved)
	return FilterResult{Routes: out, Unresolved: unresolved}
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

func comparableNextHops(idx *model.TopologyIndex, node string, hops []NormalizedFIBNextHop, opts Options) ([]NormalizedFIBNextHop, []UnresolvedNextHop) {
	var out []NormalizedFIBNextHop
	var unresolved []UnresolvedNextHop
	for _, hop := range hops {
		peer, ok := peerForNextHopInterface(idx, node, hop.Interface)
		if !ok {
			if hop.Interface == "" && hop.Address != "" && !isNodeName(idx, hop.Address) {
				out = append(out, hop)
			} else {
				unresolved = append(unresolved, unresolvedNextHop(idx, node, hop))
			}
			continue
		}
		peerNode, ok := idx.Node(peer)
		if !ok {
			unresolved = append(unresolved, unresolvedNextHop(idx, node, hop))
			continue
		}
		if opts.AllowUnsupported && !supportsLiveFIB(peerNode.Kind) {
			continue
		}
		out = append(out, hop)
	}
	return dedupeNextHops(out), dedupeUnresolvedNextHops(unresolved)
}

func unresolvedRoute(route NormalizedFIBRoute, hops []UnresolvedNextHop) UnresolvedRoute {
	reason := "unresolved_or_mgmt_fallback"
	if len(hops) == 1 && hops[0].Reason != "" {
		reason = hops[0].Reason
	}
	return UnresolvedRoute{
		RouteKey: routeKey(route),
		Node:     route.Node,
		VRF:      route.VRF,
		AFI:      route.AFI,
		Prefix:   route.Prefix,
		Protocol: route.Protocol,
		NextHops: hops,
		Reason:   reason,
	}
}

func unresolvedNextHop(idx *model.TopologyIndex, node string, hop NormalizedFIBNextHop) UnresolvedNextHop {
	reason := "topology_interface_missing"
	if hop.Interface == "" {
		reason = "unresolved_recursive_next_hop"
	} else if isManagementInterface(idx, node, hop.Interface) {
		reason = "unresolved_or_mgmt_fallback"
	}
	return UnresolvedNextHop{Address: hop.Address, Interface: hop.Interface, Reason: reason}
}

func isManagementInterface(idx *model.TopologyIndex, node, iface string) bool {
	if iface == "" {
		return false
	}
	if strings.EqualFold(iface, "eth0") || strings.EqualFold(iface, "mgmt0") || strings.EqualFold(iface, "Management1") || strings.EqualFold(iface, "mgmt") {
		return true
	}
	if idx == nil {
		return false
	}
	n, ok := idx.Node(node)
	if !ok {
		return false
	}
	for _, local := range n.Interfaces {
		if model.EquivalentInterfaceName(n.Kind, local.Name, iface) {
			return strings.HasPrefix(strings.ToLower(local.Name), "mgmt")
		}
	}
	return false
}

func dedupeUnresolvedNextHops(in []UnresolvedNextHop) []UnresolvedNextHop {
	seen := map[string]bool{}
	var out []UnresolvedNextHop
	for _, hop := range in {
		key := hop.Address + "|" + hop.Interface + "|" + hop.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hop)
	}
	return out
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
