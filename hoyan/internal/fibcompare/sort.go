package fibcompare

import "sort"

func sortRoutes(routes []NormalizedFIBRoute) {
	sort.SliceStable(routes, func(i, j int) bool {
		return routeKey(routes[i]) < routeKey(routes[j])
	})
	for i := range routes {
		sortNextHops(routes[i].NextHops)
	}
}

func sortNextHops(hops []NormalizedFIBNextHop) {
	sort.SliceStable(hops, func(i, j int) bool {
		return nextHopKey(hops[i]) < nextHopKey(hops[j])
	})
}

func routeKey(r NormalizedFIBRoute) string {
	protocol := canonicalProtocol(r.Protocol)
	if protocol != "" && protocol != "bgp" {
		return r.Node + "|" + r.VRF + "|" + r.AFI + "|" + protocol + "|" + r.Prefix
	}
	return r.Node + "|" + r.VRF + "|" + r.AFI + "|" + r.Prefix
}

func nextHopKey(h NormalizedFIBNextHop) string {
	return h.Address + "|" + h.Interface
}

func sortUnresolvedRoutes(routes []UnresolvedRoute) {
	sort.SliceStable(routes, func(i, j int) bool {
		return unresolvedRouteSortKey(routes[i]) < unresolvedRouteSortKey(routes[j])
	})
}

func unresolvedRouteSortKey(route UnresolvedRoute) string {
	return route.RouteKey + "|" + route.Reason
}
