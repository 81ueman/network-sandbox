package fibcompare

import "strings"

func canonicalProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ebgp", "ibgp", "bgp":
		return "bgp"
	case "kernel", "connected", "direct", "local", "host":
		return "connected"
	case "static", "blackhole":
		return "static"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}
