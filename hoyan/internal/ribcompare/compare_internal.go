package ribcompare

import (
	"reflect"
)

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
	exp := map[string]NormalizedBgpPath{}
	act := map[string]NormalizedBgpPath{}
	for _, p := range expected {
		key := pathKey(p, opts)
		exp[key] = mergeDuplicatePath(exp[key], normalizePath(p))
	}
	for _, p := range actual {
		key := pathKey(p, opts)
		act[key] = mergeDuplicatePath(act[key], normalizePath(p))
	}
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

func mergeDuplicatePath(existing, next NormalizedBgpPath) NormalizedBgpPath {
	if reflect.DeepEqual(existing, NormalizedBgpPath{}) {
		return next
	}
	existing.Best = existing.Best || next.Best
	existing.Valid = existing.Valid || next.Valid
	return existing
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
