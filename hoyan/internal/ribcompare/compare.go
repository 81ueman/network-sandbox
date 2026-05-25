package ribcompare

import (
	"sort"
)

func CompareBgpRib(expected []NormalizedBgpRoute, actual []NormalizedBgpRoute, opts BgpRibCompareOptions) BgpRibCompareResult {
	opts = fillCompareDefaults(opts)
	exp := map[string]NormalizedBgpRoute{}
	act := map[string]NormalizedBgpRoute{}
	for _, r := range expected {
		exp[routeKey(r)] = normalizeRoute(r)
	}
	for _, r := range actual {
		act[routeKey(r)] = normalizeRoute(r)
	}
	keys := sortedUnionKeys(exp, act)
	var result BgpRibCompareResult
	for _, key := range keys {
		e, eok := exp[key]
		a, aok := act[key]
		switch {
		case !eok:
			if !opts.AllowExtraPrefixes {
				result.UnexpectedPrefixes = append(result.UnexpectedPrefixes, key)
			}
			continue
		case !aok:
			result.MissingPrefixes = append(result.MissingPrefixes, key)
			continue
		}
		comparePaths(key, e.Paths, a.Paths, opts, &result)
	}
	sortPathDiffs(result.MissingPaths)
	sortPathDiffs(result.UnexpectedPaths)
	sort.Slice(result.Mismatched, func(i, j int) bool {
		return mismatchSortKey(result.Mismatched[i]) < mismatchSortKey(result.Mismatched[j])
	})
	result.OK = len(result.MissingPrefixes) == 0 &&
		len(result.UnexpectedPrefixes) == 0 &&
		len(result.MissingPaths) == 0 &&
		len(result.UnexpectedPaths) == 0 &&
		len(result.Mismatched) == 0
	return result
}

func Compare(expected []NormalizedBgpRoute, actual []NormalizedBgpRoute) BgpRibCompareResult {
	return CompareBgpRib(expected, actual, DefaultBgpRibCompareOptions())
}
