package fibcompare

import "strings"

func mapValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func sliceValue(v any) []any {
	if xs, ok := v.([]any); ok {
		return xs
	}
	return nil
}

func boolValue(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return boolString(v)
}

func boolString(v any) bool {
	s := strings.ToLower(strings.TrimSpace(stringValue(v)))
	return s == "true" || s == "yes" || s == "up"
}
