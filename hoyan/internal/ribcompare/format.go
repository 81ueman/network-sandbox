package ribcompare

import (
	"fmt"
)

func FormatDiffs(result BgpRibCompareResult) []string {
	var out []string
	for _, k := range result.MissingPrefixes {
		out = append(out, fmt.Sprintf("[DIFF] %s prefix missing", k))
	}
	for _, k := range result.UnexpectedPrefixes {
		out = append(out, fmt.Sprintf("[DIFF] %s prefix unexpected", k))
	}
	for _, d := range result.MissingPaths {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s missing", d.RouteKey, d.PathKey))
	}
	for _, d := range result.UnexpectedPaths {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s unexpected", d.RouteKey, d.PathKey))
	}
	for _, m := range result.Mismatched {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s field=%s expected=%v actual=%v", m.RouteKey, m.PathKey, m.Field, m.Expected, m.Actual))
	}
	for _, c := range result.DuplicatePathConflicts {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s duplicate path conflict side=%s paths=%d", c.RouteKey, c.PathKey, c.Side, len(c.Paths)))
	}
	return out
}
