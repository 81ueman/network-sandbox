package ribcompare

import (
	"encoding/json"
	"sort"
	"strings"
)

func ParseSRLinuxSummary(data []byte) ([]string, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	found := map[string]bool{}
	walkJSON(root, func(key string, value any) {
		if strings.EqualFold(key, "prefix") || strings.EqualFold(key, "route") || strings.EqualFold(key, "network") {
			if s := stringValue(value); isPrefix(s) {
				found[s] = true
			}
		}
		if isPrefix(key) {
			found[key] = true
		}
	})
	var out []string
	for prefix := range found {
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out, nil
}

func ParseSRLinuxDetail(node, prefix string, data []byte) ([]NormalizedBgpRoute, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var routeMaps []map[string]any
	walkSRLinuxRouteSections(root, false, &routeMaps)
	if len(routeMaps) == 0 {
		if m := asMap(root); len(m) > 0 {
			routeMaps = append(routeMaps, m)
		}
	}
	route := NormalizedBgpRoute{Node: node, NetworkInstance: "default", AFI: "ipv4", Prefix: prefix}
	for _, m := range routeMaps {
		status := firstString(m, "status", "route status", "route-status")
		asPath := parseASPath(firstString(m, "as path", "as-path", "asPath"))
		nextHop := normalizeLocalNextHop(firstString(m, "next-hop", "nextHop", "next hop"))
		peer := firstString(m, "neighbor", "peer")
		if nextHop == "" && peer == "0.0.0.0" && len(asPath) == 0 {
			continue
		}
		route.Paths = append(route.Paths, NormalizedBgpPath{
			Best:        strings.Contains(strings.ToLower(status), "best"),
			Valid:       strings.Contains(strings.ToLower(status), "valid"),
			NextHop:     nextHop,
			ASPath:      asPath,
			Origin:      normalizeOrigin(firstString(m, "origin")),
			LocalPref:   defaultLocalPref(intValue(firstPresent(m, "local pref", "local-pref", "localPreference"))),
			MED:         intValue(firstPresent(m, "med")),
			Communities: appendCommunities(nil, firstPresent(m, "community", "communities")),
			Peer:        peer,
			PeerAS:      uint32(intValue(firstPresent(m, "peer-as", "peer as", "peerAS"))),
		})
	}
	if len(route.Paths) == 0 {
		return nil, nil
	}
	sortPaths(route.Paths, DefaultBgpRibCompareOptions())
	return []NormalizedBgpRoute{route}, nil
}
