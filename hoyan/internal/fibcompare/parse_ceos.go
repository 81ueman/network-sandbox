package fibcompare

import "encoding/json"

func ParseCEOSRoutes(node string, data []byte) ([]NormalizedFIBRoute, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	vrfs := mapValue(raw["vrfs"])
	defaultVRF := mapValue(vrfs["default"])
	routes := mapValue(defaultVRF["routes"])
	out := make([]NormalizedFIBRoute, 0, len(routes))
	for prefix, value := range routes {
		m := mapValue(value)
		if !boolValue(m["kernelProgrammed"]) && !boolValue(m["hardwareProgrammed"]) {
			continue
		}
		route := NormalizedFIBRoute{
			Node:       node,
			VRF:        "default",
			AFI:        "ipv4",
			Prefix:     prefix,
			NextHops:   ceosNextHops(m["vias"]),
			Protocol:   ceosProtocol(stringValue(m["routeType"])),
			Preference: intValue(m["preference"]),
			Metric:     intValue(m["metric"]),
			Installed:  true,
		}
		route.NextHops = dedupeNextHops(route.NextHops)
		out = append(out, route)
	}
	sortRoutes(out)
	return out, nil
}

func ceosProtocol(routeType string) string {
	return canonicalProtocol(routeType)
}

func ceosNextHops(raw any) []NormalizedFIBNextHop {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]NormalizedFIBNextHop, 0, len(items))
	for _, item := range items {
		m := mapValue(item)
		out = append(out, NormalizedFIBNextHop{
			Address:   stringValue(m["nexthopAddr"]),
			Interface: stringValue(m["interface"]),
			Weight:    intValue(m["weight"]),
		})
	}
	return out
}
