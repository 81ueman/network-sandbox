package fibcompare

func CompareFilterResults(expected, actual FilterResult, opts Options) Result {
	policy := opts.UnresolvedPolicy.normalized()
	expectedRoutes := expected.Routes
	actualRoutes := actual.Routes
	if policy == UnresolvedPolicyWarn || policy == UnresolvedPolicyIgnore {
		expectedRoutes = removeRoutesByKey(expectedRoutes, unresolvedRouteKeys(actual.Unresolved))
		actualRoutes = removeRoutesByKey(actualRoutes, unresolvedRouteKeys(actual.Unresolved))
	}
	result := Compare(expectedRoutes, actualRoutes)
	if policy == UnresolvedPolicyFail {
		result.UnresolvedRoutes = append(result.UnresolvedRoutes, actual.Unresolved...)
		sortUnresolvedRoutes(result.UnresolvedRoutes)
		result.OK = false
	}
	return result
}

func WarningDiagnostics(result FilterResult, opts Options) []UnresolvedRoute {
	if opts.UnresolvedPolicy.normalized() != UnresolvedPolicyWarn {
		return nil
	}
	return result.Unresolved
}

func removeRoutesByKey(routes []NormalizedFIBRoute, keys map[string]bool) []NormalizedFIBRoute {
	if len(keys) == 0 {
		return routes
	}
	out := make([]NormalizedFIBRoute, 0, len(routes))
	for _, route := range routes {
		if keys[routeKey(route)] {
			continue
		}
		out = append(out, route)
	}
	return out
}

func unresolvedRouteKeys(routes []UnresolvedRoute) map[string]bool {
	out := map[string]bool{}
	for _, route := range routes {
		out[route.RouteKey] = true
	}
	return out
}
