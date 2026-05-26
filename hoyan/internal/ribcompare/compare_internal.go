package ribcompare

import "reflect"

func fillCompareDefaults(opts BgpRibCompareOptions) BgpRibCompareOptions {
	if !opts.CompareBest && !opts.CompareValid && !opts.CompareNextHop && !opts.CompareASPath &&
		!opts.CompareOrigin && !opts.CompareLocalPref && !opts.CompareMED && !opts.CompareWeight &&
		!opts.CompareCommunities && !opts.CompareLargeCommunities && !opts.CompareOriginatorID &&
		!opts.CompareClusterList && !opts.ComparePeer && !opts.ComparePeerAS {
		return DefaultBgpRibCompareOptions()
	}
	return opts
}

func comparePaths(routeKey string, expected, actual []NormalizedBgpPath, opts BgpRibCompareOptions, result *BgpRibCompareResult) {
	exp, expConflicts := buildPathIndex(routeKey, "expected", expected, opts)
	act, actConflicts := buildPathIndex(routeKey, "actual", actual, opts)
	result.DuplicatePathConflicts = append(result.DuplicatePathConflicts, expConflicts...)
	result.DuplicatePathConflicts = append(result.DuplicatePathConflicts, actConflicts...)
	keys := sortedUnionKeys(exp, act)
	for _, key := range keys {
		e, eok := exp[key]
		a, aok := act[key]
		switch {
		case !eok:
			if !opts.AllowExtraPaths {
				result.UnexpectedPaths = append(result.UnexpectedPaths, PathDiff{RouteKey: routeKey, PathKey: key})
			}
		case !aok:
			result.MissingPaths = append(result.MissingPaths, PathDiff{RouteKey: routeKey, PathKey: key})
		default:
			appendMismatches(routeKey, key, e, a, opts, result)
		}
	}
}

type pathIndexEntry struct {
	path       NormalizedBgpPath
	paths      []NormalizedBgpPath
	conflicted bool
}

func buildPathIndex(routeKey, side string, paths []NormalizedBgpPath, opts BgpRibCompareOptions) (map[string]NormalizedBgpPath, []DuplicatePathConflict) {
	entries := map[string]pathIndexEntry{}
	for _, p := range paths {
		p = normalizePath(p)
		key := pathKey(p, opts)
		entry, ok := entries[key]
		if !ok {
			entries[key] = pathIndexEntry{path: p, paths: []NormalizedBgpPath{p}}
			continue
		}
		if !samePathAttributes(entry.path, p) {
			entry.conflicted = true
		}
		// The simulator can produce the same visible BGP path under multiple
		// failure conditions with different selected/valid states. Keep that as
		// a single visible path, but only when all non-state attributes match.
		entry.path.Best = entry.path.Best || p.Best
		entry.path.Valid = entry.path.Valid || p.Valid
		entry.paths = append(entry.paths, p)
		entries[key] = entry
	}

	index := map[string]NormalizedBgpPath{}
	var conflicts []DuplicatePathConflict
	for key, entry := range entries {
		if entry.conflicted {
			conflicts = append(conflicts, DuplicatePathConflict{
				RouteKey: routeKey,
				PathKey:  key,
				Side:     side,
				Paths:    entry.paths,
			})
			continue
		}
		index[key] = entry.path
	}
	return index, conflicts
}

func samePathAttributes(a, b NormalizedBgpPath) bool {
	a.Best = false
	a.Valid = false
	b.Best = false
	b.Valid = false
	return reflect.DeepEqual(a, b)
}

func appendMismatches(routeKey, pathKey string, e, a NormalizedBgpPath, opts BgpRibCompareOptions, result *BgpRibCompareResult) {
	check := func(enabled bool, field string, expected, actual any) {
		if enabled && !reflect.DeepEqual(expected, actual) {
			result.Mismatched = append(result.Mismatched, AttributeMismatch{RouteKey: routeKey, PathKey: pathKey, Field: field, Expected: expected, Actual: actual})
		}
	}
	check(opts.CompareBest, "best", e.Best, a.Best)
	check(opts.CompareValid, "valid", e.Valid, a.Valid)
	check(opts.CompareNextHop, "next_hop", e.NextHop, a.NextHop)
	check(opts.CompareASPath, "as_path", e.ASPath, a.ASPath)
	check(opts.CompareOrigin, "origin", e.Origin, a.Origin)
	check(opts.CompareLocalPref, "local_pref", e.LocalPref, a.LocalPref)
	check(opts.CompareMED, "med", e.MED, a.MED)
	check(opts.CompareWeight, "weight", e.Weight, a.Weight)
	check(opts.CompareCommunities, "communities", e.Communities, a.Communities)
	check(opts.CompareLargeCommunities, "large_communities", e.LargeCommunities, a.LargeCommunities)
	check(opts.CompareOriginatorID, "originator_id", e.OriginatorID, a.OriginatorID)
	check(opts.CompareClusterList, "cluster_list", e.ClusterList, a.ClusterList)
	check(opts.ComparePeer, "peer", e.Peer, a.Peer)
	check(opts.ComparePeerAS, "peer_as", e.PeerAS, a.PeerAS)
}
