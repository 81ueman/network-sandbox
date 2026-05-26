package fibcompare

import "strings"

func canonicalProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ebgp", "ibgp", "bgp":
		return "bgp"
	case "kernel", "connected", "direct", "local", "host":
		return "connected"
	case "static":
		return "static"
	case "blackhole", "discard", "drop", "null0", "null":
		return "blackhole"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}
