package ribcompare

import (
	"net/netip"
	"strings"
)

func walkJSON(v any, visit func(key string, value any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			visit(k, v)
			walkJSON(v, visit)
		}
	case []any:
		for _, v := range x {
			walkJSON(v, visit)
		}
	}
}

func walkSRLinuxRouteSections(v any, ignored bool, out *[]map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			nextIgnored := ignored || isIgnoredSRLinuxRouteSection(k)
			if !nextIgnored && strings.EqualFold(k, "routes") {
				for _, item := range asSlice(v) {
					if m := asMap(item); len(m) > 0 {
						*out = append(*out, m)
					}
				}
			}
			walkSRLinuxRouteSections(v, nextIgnored, out)
		}
	case []any:
		for _, v := range x {
			walkSRLinuxRouteSections(v, ignored, out)
		}
	}
}

func isIgnoredSRLinuxRouteSection(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "advertised") || strings.Contains(key, "non-route")
}

func isPrefix(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}
