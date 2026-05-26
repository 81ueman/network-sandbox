package fibcompare

import "sort"

func Compare(expected, actual []NormalizedFIBRoute) Result {
	exp := map[string]NormalizedFIBRoute{}
	act := map[string]NormalizedFIBRoute{}
	for _, route := range expected {
		route.NextHops = dedupeNextHops(route.NextHops)
		exp[routeKey(route)] = route
	}
	for _, route := range actual {
		route.NextHops = dedupeNextHops(route.NextHops)
		act[routeKey(route)] = route
	}
	keys := sortedUnion(exp, act)
	var result Result
	for _, key := range keys {
		e, eok := exp[key]
		a, aok := act[key]
		switch {
		case !eok:
			result.UnexpectedRoutes = append(result.UnexpectedRoutes, key)
			continue
		case !aok:
			result.MissingRoutes = append(result.MissingRoutes, key)
			continue
		}
		compareNextHops(key, e.NextHops, a.NextHops, &result)
		if e.Preference != 0 && a.Preference != 0 && e.Preference != a.Preference {
			result.Mismatched = append(result.Mismatched, AttributeMismatch{RouteKey: key, Field: "preference", Expected: e.Preference, Actual: a.Preference})
		}
	}
	sort.Strings(result.MissingRoutes)
	sort.Strings(result.UnexpectedRoutes)
	sortNextHopDiffs(result.MissingNextHops)
	sortNextHopDiffs(result.UnexpectedNextHops)
	sort.Slice(result.Mismatched, func(i, j int) bool {
		return result.Mismatched[i].RouteKey+"|"+result.Mismatched[i].Field < result.Mismatched[j].RouteKey+"|"+result.Mismatched[j].Field
	})
	result.OK = len(result.MissingRoutes) == 0 &&
		len(result.UnexpectedRoutes) == 0 &&
		len(result.MissingNextHops) == 0 &&
		len(result.UnexpectedNextHops) == 0 &&
		len(result.Mismatched) == 0 &&
		len(result.UnresolvedRoutes) == 0 &&
		len(result.UnsupportedNodes) == 0
	return result
}

func compareNextHops(routeKey string, expected, actual []NormalizedFIBNextHop, result *Result) {
	exp := map[string]bool{}
	act := map[string]bool{}
	for _, hop := range expected {
		exp[nextHopKey(hop)] = true
	}
	for _, hop := range actual {
		act[nextHopKey(hop)] = true
	}
	for _, key := range sortedBoolUnion(exp, act) {
		switch {
		case !exp[key]:
			result.UnexpectedNextHops = append(result.UnexpectedNextHops, NextHopDiff{RouteKey: routeKey, NextHopKey: key})
		case !act[key]:
			result.MissingNextHops = append(result.MissingNextHops, NextHopDiff{RouteKey: routeKey, NextHopKey: key})
		}
	}
}

func sortedUnion(a, b map[string]NormalizedFIBRoute) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolUnion(a, b map[string]bool) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortNextHopDiffs(diffs []NextHopDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].RouteKey+"|"+diffs[i].NextHopKey < diffs[j].RouteKey+"|"+diffs[j].NextHopKey
	})
}
