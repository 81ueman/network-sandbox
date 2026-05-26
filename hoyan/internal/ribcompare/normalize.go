package ribcompare

import (
	"fmt"
	"strconv"
	"strings"
)

func normalizeRoute(r NormalizedBgpRoute) NormalizedBgpRoute {
	if r.NetworkInstance == "" {
		r.NetworkInstance = "default"
	}
	if r.AFI == "" {
		r.AFI = "ipv4"
	}
	for i := range r.Paths {
		r.Paths[i] = normalizePath(r.Paths[i])
	}
	return r
}

func normalizePath(p NormalizedBgpPath) NormalizedBgpPath {
	p.Origin = normalizeOrigin(p.Origin)
	p.Communities = sortedStrings(p.Communities)
	p.LargeCommunities = sortedStrings(p.LargeCommunities)
	p.ClusterList = sortedStrings(p.ClusterList)
	return p
}

func routeKey(r NormalizedBgpRoute) string {
	r = normalizeRoute(r)
	return r.Node + "|" + r.NetworkInstance + "|" + r.AFI + "|" + r.Prefix
}

func pathKey(p NormalizedBgpPath, opts BgpRibCompareOptions) string {
	// Path identity is deliberately narrower than full path equality. The
	// default identity is next-hop plus AS path; attributes such as best, valid,
	// origin, local-pref, MED, weight, communities, originator ID, and cluster
	// list are compared after identity matching so attribute mismatches stay
	// distinct from missing/unexpected paths. ComparePeer and ComparePeerAS are
	// the only options that extend identity, letting callers distinguish
	// otherwise identical multipath entries learned from different peers.
	parts := []string{"nh=" + p.NextHop, "as=" + formatASPath(p.ASPath)}
	if opts.ComparePeer && p.Peer != "" {
		parts = append(parts, "peer="+p.Peer)
	}
	if opts.ComparePeerAS && p.PeerAS != 0 {
		parts = append(parts, fmt.Sprintf("peer_as=%d", p.PeerAS))
	}
	return strings.Join(parts, "|")
}

func parseASPath(raw string) []uint32 {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, ",", " "))
	if raw == "" || raw == "-" {
		return nil
	}
	var out []uint32
	for _, f := range strings.Fields(raw) {
		f = strings.Trim(f, "{}[]()")
		asn, err := strconv.ParseUint(f, 10, 32)
		if err == nil {
			out = append(out, uint32(asn))
		}
	}
	return out
}

func formatASPath(path []uint32) string {
	parts := make([]string, 0, len(path))
	for _, asn := range path {
		parts = append(parts, fmt.Sprint(asn))
	}
	return strings.Join(parts, " ")
}

func normalizeOrigin(origin string) string {
	switch strings.ToLower(strings.TrimSpace(origin)) {
	case "", "i", "igp":
		return "igp"
	case "e", "egp":
		return "egp"
	case "?", "incomplete":
		return "incomplete"
	default:
		return strings.ToLower(strings.TrimSpace(origin))
	}
}

func defaultLocalPref(v int) int {
	if v == 0 {
		return 100
	}
	return v
}
