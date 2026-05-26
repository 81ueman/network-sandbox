package fibcompare

func NormalizeRoutes(routes []NormalizedFIBRoute) ([]NormalizedFIBRoute, []DuplicateRouteConflict) {
	return normalizeRoutesForSide("", routes)
}

func normalizeRoutesForSide(side string, routes []NormalizedFIBRoute) ([]NormalizedFIBRoute, []DuplicateRouteConflict) {
	entries := map[string]routeIndexEntry{}
	for _, route := range routes {
		route.Protocol = canonicalProtocol(route.Protocol)
		route.NextHops = dedupeNextHops(route.NextHops)
		key := routeKey(route)
		entry, ok := entries[key]
		if !ok {
			entries[key] = routeIndexEntry{route: route, routes: []NormalizedFIBRoute{route}}
			continue
		}
		merged, reason, ok := mergeDuplicateRoute(entry.route, route)
		entry.routes = append(entry.routes, route)
		if !ok {
			entry.conflicted = true
			if entry.reason == "" {
				entry.reason = reason
			}
		} else {
			entry.route = merged
		}
		entries[key] = entry
	}

	out := make([]NormalizedFIBRoute, 0, len(entries))
	var conflicts []DuplicateRouteConflict
	for key, entry := range entries {
		if entry.conflicted {
			conflicts = append(conflicts, DuplicateRouteConflict{
				RouteKey: key,
				Side:     side,
				Reason:   entry.reason,
				Routes:   entry.routes,
			})
			continue
		}
		out = append(out, entry.route)
	}
	sortRoutes(out)
	sortDuplicateRouteConflicts(conflicts)
	return out, conflicts
}

type routeIndexEntry struct {
	route      NormalizedFIBRoute
	routes     []NormalizedFIBRoute
	conflicted bool
	reason     string
}

func mergeDuplicateRoute(a, b NormalizedFIBRoute) (NormalizedFIBRoute, string, bool) {
	conflict := func(field string) (NormalizedFIBRoute, string, bool) {
		return NormalizedFIBRoute{}, field + " mismatch", false
	}
	if a.Node != b.Node {
		return conflict("node")
	}
	if a.VRF != b.VRF {
		return conflict("vrf")
	}
	if a.AFI != b.AFI {
		return conflict("afi")
	}
	if a.Prefix != b.Prefix {
		return conflict("prefix")
	}
	if canonicalProtocol(a.Protocol) != canonicalProtocol(b.Protocol) {
		return conflict("protocol")
	}
	if a.ConnectedClass != b.ConnectedClass {
		return conflict("connected_class")
	}
	if a.Preference != 0 && b.Preference != 0 && a.Preference != b.Preference {
		return conflict("preference")
	}
	if a.Metric != 0 && b.Metric != 0 && a.Metric != b.Metric {
		return conflict("metric")
	}
	if a.Installed != b.Installed {
		return conflict("installed")
	}

	merged := a
	if merged.Protocol == "" {
		merged.Protocol = canonicalProtocol(b.Protocol)
	}
	if merged.Preference == 0 {
		merged.Preference = b.Preference
	}
	if merged.Metric == 0 {
		merged.Metric = b.Metric
	}
	merged.NextHops = unionNextHops(a.NextHops, b.NextHops)
	return merged, "", true
}

func unionNextHops(a, b []NormalizedFIBNextHop) []NormalizedFIBNextHop {
	out := make([]NormalizedFIBNextHop, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return dedupeNextHops(out)
}
