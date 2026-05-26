package fibcompare

import "fmt"

func FormatDiffs(result Result) []string {
	var out []string
	for _, n := range result.UnsupportedNodes {
		out = append(out, fmt.Sprintf("[DIFF] unsupported live FIB collector for %s", n))
	}
	for _, route := range result.UnresolvedRoutes {
		out = append(out, fmt.Sprintf("[DIFF] %s unresolved live BGP route reason=%s next-hops=%s", route.RouteKey, route.Reason, formatUnresolvedNextHops(route.NextHops)))
	}
	for _, conflict := range result.DuplicateRouteConflicts {
		out = append(out, fmt.Sprintf("[DIFF] duplicate FIB route conflict %s side=%s reason=%s records=%d", conflict.RouteKey, conflict.Side, conflict.Reason, len(conflict.Routes)))
	}
	for _, key := range result.MissingRoutes {
		out = append(out, fmt.Sprintf("[DIFF] %s route missing", key))
	}
	for _, key := range result.UnexpectedRoutes {
		out = append(out, fmt.Sprintf("[DIFF] %s route unexpected", key))
	}
	for _, diff := range result.MissingNextHops {
		out = append(out, fmt.Sprintf("[DIFF] %s next-hop %s missing", diff.RouteKey, diff.NextHopKey))
	}
	for _, diff := range result.UnexpectedNextHops {
		out = append(out, fmt.Sprintf("[DIFF] %s next-hop %s unexpected", diff.RouteKey, diff.NextHopKey))
	}
	for _, mismatch := range result.Mismatched {
		out = append(out, fmt.Sprintf("[DIFF] %s field=%s expected=%v actual=%v", mismatch.RouteKey, mismatch.Field, mismatch.Expected, mismatch.Actual))
	}
	return out
}

func FormatWarnings(routes []UnresolvedRoute) []string {
	var out []string
	for _, route := range routes {
		out = append(out, fmt.Sprintf("[WARN] %s unresolved live BGP route reason=%s next-hops=%s; route excluded from strict FIB comparison", route.RouteKey, route.Reason, formatUnresolvedNextHops(route.NextHops)))
	}
	return out
}

func formatUnresolvedNextHops(hops []UnresolvedNextHop) string {
	if len(hops) == 0 {
		return "[]"
	}
	out := "["
	for i, hop := range hops {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("{address=%q interface=%q reason=%s}", hop.Address, hop.Interface, hop.Reason)
	}
	return out + "]"
}
