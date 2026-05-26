package fibcompare

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var srlinuxDetailNextHopRE = regexp.MustCompile(`(?m)(?:^|\s)(?:via\s+)?([0-9A-Fa-f:.]+)\s+\([^)]*\)\s+via\s+\[([^\]]+)\]`)

func ParseSRLinuxRoutes(node string, data []byte) ([]NormalizedFIBRoute, error) {
	cleaned, err := jsonPayload(data)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(cleaned, &raw); err != nil {
		return nil, err
	}
	var out []NormalizedFIBRoute
	for _, inst := range sliceValue(raw["instance"]) {
		m := mapValue(inst)
		for _, item := range sliceValue(m["ip route"]) {
			route, ok := srlinuxRoute(node, mapValue(item))
			if ok {
				out = append(out, route)
			}
		}
	}
	sortRoutes(out)
	return out, nil
}

func ParseSRLinuxRouteDetails(node string, data []byte) ([]NormalizedFIBRoute, error) {
	cleaned, err := jsonPayload(data)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(cleaned, &raw); err != nil {
		return nil, err
	}
	var out []NormalizedFIBRoute
	for _, inst := range sliceValue(raw["instance"]) {
		m := mapValue(inst)
		for _, item := range sliceValue(m["ip route"]) {
			route, ok := srlinuxDetailRoute(node, mapValue(item))
			if ok {
				out = append(out, route)
			}
		}
	}
	sortRoutes(out)
	return out, nil
}

func jsonPayload(data []byte) ([]byte, error) {
	s := string(data)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end < start {
		return nil, fmt.Errorf("no JSON object found")
	}
	return []byte(s[start : end+1]), nil
}

func srlinuxRoute(node string, m map[string]any) (NormalizedFIBRoute, bool) {
	if !boolString(m["Active"]) {
		return NormalizedFIBRoute{}, false
	}
	prefix := stringValue(m["Prefix"])
	if prefix == "" {
		return NormalizedFIBRoute{}, false
	}
	protocol := canonicalProtocol(stringValue(m["Route Type"]))
	route := NormalizedFIBRoute{
		Node:       node,
		VRF:        "default",
		AFI:        "ipv4",
		Prefix:     prefix,
		Protocol:   protocol,
		Preference: intValue(m["Pref"]),
		Metric:     intValue(m["Metric"]),
		Installed:  true,
	}
	hop := NormalizedFIBNextHop{
		Address:   srlinuxNextHopAddress(stringValue(m["Next-hop (Type)"])),
		Interface: strings.TrimSpace(stringValue(m["Next-hop Interface"])),
	}
	if hop.Address != "" || hop.Interface != "" {
		route.NextHops = append(route.NextHops, hop)
	}
	backupHop := NormalizedFIBNextHop{
		Address:   srlinuxNextHopAddress(stringValue(m["Backup Next-hop (Type)"])),
		Interface: strings.TrimSpace(stringValue(m["Backup Next-hop Interface"])),
	}
	if backupHop.Address != "" || backupHop.Interface != "" {
		route.NextHops = append(route.NextHops, backupHop)
	}
	if discardNextHops(route.NextHops) {
		route.Protocol = "blackhole"
		route.NextHops = nil
	}
	route.NextHops = dedupeNextHops(route.NextHops)
	return route, true
}

func srlinuxDetailRoute(node string, m map[string]any) (NormalizedFIBRoute, bool) {
	if !boolValue(m["Active"]) {
		return NormalizedFIBRoute{}, false
	}
	prefix := stringValue(m["Destination"])
	if prefix == "" {
		prefix = stringValue(m["Prefix"])
	}
	if prefix == "" {
		return NormalizedFIBRoute{}, false
	}
	route := NormalizedFIBRoute{
		Node:       node,
		VRF:        "default",
		AFI:        "ipv4",
		Prefix:     prefix,
		Protocol:   canonicalProtocol(stringValue(m["Route Type"])),
		Preference: firstIntValue(m["Preference"], m["Pref"]),
		Metric:     intValue(m["Metric"]),
		Installed:  true,
	}
	route.NextHops = append(route.NextHops, srlinuxDetailNextHops(mapValue(m["ip route nexthop"]), "Next hops")...)
	route.NextHops = append(route.NextHops, srlinuxDetailNextHops(mapValue(m["ip route backup nexthop"]), "Backup Next hops")...)
	route.NextHops = dedupeNextHops(route.NextHops)
	return route, true
}

func srlinuxDetailNextHops(m map[string]any, key string) []NormalizedFIBNextHop {
	raw := stringValue(m[key])
	if raw == "" {
		return nil
	}
	matches := srlinuxDetailNextHopRE.FindAllStringSubmatch(raw, -1)
	out := make([]NormalizedFIBNextHop, 0, len(matches))
	for _, match := range matches {
		addr := srlinuxNextHopAddress(match[1])
		iface := strings.TrimSpace(match[2])
		if addr == "" && iface == "" {
			continue
		}
		out = append(out, NormalizedFIBNextHop{Address: addr, Interface: iface})
	}
	return out
}

func srlinuxNextHopAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "None" {
		return ""
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	addr := fields[0]
	if pfx, err := netip.ParsePrefix(addr); err == nil {
		return pfx.Addr().String()
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.String()
	}
	return addr
}

func firstIntValue(values ...any) int {
	for _, v := range values {
		if got := intValue(v); got != 0 {
			return got
		}
	}
	return 0
}
