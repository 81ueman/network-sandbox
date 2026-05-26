package ribcompare

import (
	"fmt"
	"strings"
)

func BGPOnly(routes []NormalizedBgpRoute) []NormalizedBgpRoute {
	return RoutesWithSources(routes, RouteSourcesBGP)
}

func RoutesWithSources(routes []NormalizedBgpRoute, sources RouteSources) []NormalizedBgpRoute {
	if sources == "" {
		sources = RouteSourcesAll
	}
	out := make([]NormalizedBgpRoute, 0, len(routes))
	for _, route := range routes {
		protocol := strings.ToLower(strings.TrimSpace(normalizeRoute(route).Protocol))
		if sources == RouteSourcesBGP && protocol != "bgp" {
			continue
		}
		out = append(out, route)
	}
	sortRoutes(out)
	return out
}

func SourceSummary(routes []NormalizedBgpRoute) map[string]int {
	out := map[string]int{}
	for _, route := range routes {
		protocol := strings.ToLower(strings.TrimSpace(normalizeRoute(route).Protocol))
		if protocol == "" {
			protocol = "bgp"
		}
		out[protocol]++
	}
	return out
}

func FormatSourceSummary(summary map[string]int) string {
	order := []string{"bgp", "connected", "static", "blackhole"}
	var parts []string
	seen := map[string]bool{}
	for _, source := range order {
		if count, ok := summary[source]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", source, count))
			seen[source] = true
		}
	}
	for source, count := range summary {
		if !seen[source] {
			parts = append(parts, fmt.Sprintf("%s=%d", source, count))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
