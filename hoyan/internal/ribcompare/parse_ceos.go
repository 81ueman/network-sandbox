package ribcompare

import (
	"encoding/json"
)

func ParseCEOS(node string, data []byte) ([]NormalizedBgpRoute, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	vrfs := asMap(root["vrfs"])
	if len(vrfs) == 0 {
		vrfs = map[string]any{"default": root}
	}
	var out []NormalizedBgpRoute
	for ni, rawVRF := range vrfs {
		vrf := asMap(rawVRF)
		entries := asMap(vrf["bgpRouteEntries"])
		for prefix, rawEntry := range entries {
			entry := asMap(rawEntry)
			route := NormalizedBgpRoute{Node: node, NetworkInstance: ni, AFI: "ipv4", Prefix: prefix}
			for _, rawPath := range asSlice(entry["bgpRoutePaths"]) {
				p := asMap(rawPath)
				routeType := asMap(p["routeType"])
				peer := asMap(p["peerEntry"])
				asPathEntry := asMap(p["asPathEntry"])
				route.Paths = append(route.Paths, NormalizedBgpPath{
					Best:      boolValue(routeType["active"]),
					Valid:     boolValue(routeType["valid"]),
					NextHop:   normalizeLocalNextHop(stringValue(p["nextHop"])),
					ASPath:    parseASPath(stringValue(asPathEntry["asPath"])),
					Origin:    normalizeOrigin(firstString(p, "routeOrigin", "origin")),
					LocalPref: defaultLocalPref(intValue(p["localPreference"])),
					MED:       intValue(p["med"]),
					Weight:    intValue(p["weight"]),
					Communities: sortedStrings(appendCommunities(nil,
						firstPresent(p, "community", "communities", "communityList"),
						firstPresent(asPathEntry, "community", "communities", "communityList"),
					)),
					LargeCommunities: sortedStrings(appendCommunities(nil,
						firstPresent(p, "largeCommunity", "largeCommunities", "largeCommunityList"),
						firstPresent(asPathEntry, "largeCommunity", "largeCommunities", "largeCommunityList"),
					)),
					Peer:   stringValue(peer["peerAddr"]),
					PeerAS: uint32(intValue(peer["peerAS"])),
				})
			}
			if len(route.Paths) > 0 {
				sortPaths(route.Paths, DefaultBgpRibCompareOptions())
				out = append(out, route)
			}
		}
	}
	sortRoutes(out)
	return out, nil
}
