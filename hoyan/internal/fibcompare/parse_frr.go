package fibcompare

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
)

func ParseLinuxIPRoute(node string, data []byte) ([]NormalizedFIBRoute, error) {
	var raw []map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []NormalizedFIBRoute
	for i, item := range raw {
		prefix, ok, err := routePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("route[%d]: %w", i, err)
		}
		if !ok {
			continue
		}
		route := NormalizedFIBRoute{
			Node:       node,
			VRF:        "default",
			AFI:        "ipv4",
			Prefix:     prefix,
			NextHops:   routeNextHops(item),
			Protocol:   linuxRouteProtocol(item),
			Preference: intValue(item["pref"]),
			Metric:     intValue(item["metric"]),
			Installed:  true,
		}
		route.NextHops = dedupeNextHops(route.NextHops)
		out = append(out, route)
	}
	sortRoutes(out)
	return out, nil
}

func linuxRouteProtocol(item map[string]any) string {
	if protocol := canonicalProtocol(stringValue(item["protocol"])); protocol != "" {
		return protocol
	}
	return canonicalProtocol(stringValue(item["type"]))
}

func routePrefix(item map[string]any) (string, bool, error) {
	dst := stringValue(item["dst"])
	if dst == "" {
		return "", false, nil
	}
	if dst == "default" {
		return "0.0.0.0/0", true, nil
	}
	if addr, err := netip.ParseAddr(dst); err == nil {
		if !addr.Is4() {
			return "", false, nil
		}
		return netip.PrefixFrom(addr, 32).String(), true, nil
	}
	pfx, err := netip.ParsePrefix(dst)
	if err != nil {
		return "", false, err
	}
	if !pfx.Addr().Is4() {
		return "", false, nil
	}
	return pfx.Masked().String(), true, nil
}

func routeNextHops(item map[string]any) []NormalizedFIBNextHop {
	if raw, ok := item["nexthops"].([]any); ok {
		out := make([]NormalizedFIBNextHop, 0, len(raw))
		for _, elem := range raw {
			m, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, NormalizedFIBNextHop{
				Address:   stringValue(m["gateway"]),
				Interface: stringValue(m["dev"]),
				Weight:    intValue(m["weight"]),
			})
		}
		return out
	}
	if gateway := stringValue(item["gateway"]); gateway != "" || stringValue(item["dev"]) != "" {
		return []NormalizedFIBNextHop{{
			Address:   gateway,
			Interface: stringValue(item["dev"]),
			Weight:    intValue(item["weight"]),
		}}
	}
	return nil
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatInt(int64(x), 10)
	default:
		return ""
	}
}

func intValue(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case json.Number:
		i, _ := strconv.Atoi(x.String())
		return i
	case string:
		i, _ := strconv.Atoi(x)
		return i
	default:
		return 0
	}
}
