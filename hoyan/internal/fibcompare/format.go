package fibcompare

import "fmt"

func FormatDiffs(result Result) []string {
	var out []string
	for _, n := range result.UnsupportedNodes {
		out = append(out, fmt.Sprintf("[DIFF] unsupported live FIB collector for %s", n))
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
