package ribcompare

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func asSlice(v any) []any {
	if xs, ok := v.([]any); ok {
		return xs
	}
	return nil
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case fmt.Stringer:
		return strings.TrimSpace(x.String())
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%.0f", x)
		}
		return fmt.Sprint(x)
	default:
		return ""
	}
}

func intValue(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	case string:
		if x == "" || x == "-" {
			return 0
		}
		i, _ := strconv.Atoi(strings.TrimSpace(x))
		return i
	default:
		return 0
	}
}

func boolValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || strings.EqualFold(x, "yes") || strings.EqualFold(x, "active") || strings.EqualFold(x, "valid")
	default:
		return false
	}
}

func firstPresent(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return nil
}

func firstString(m map[string]any, keys ...string) string {
	return stringValue(firstPresent(m, keys...))
}

func sortedStrings(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func splitCommunities(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", " ")
	if raw == "" || raw == "-" {
		return nil
	}
	return sortedStrings(strings.Fields(raw))
}

func appendCommunities(out []string, values ...any) []string {
	for _, value := range values {
		switch x := value.(type) {
		case nil:
			continue
		case []any:
			for _, item := range x {
				out = appendCommunities(out, item)
			}
		case []string:
			for _, item := range x {
				out = appendCommunities(out, item)
			}
		default:
			out = append(out, splitCommunities(stringValue(x))...)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return sortedStrings(out)
}

func normalizeLocalNextHop(nextHop string) string {
	if nextHop == "0.0.0.0" {
		return ""
	}
	return nextHop
}
