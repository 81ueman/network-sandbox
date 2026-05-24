//go:build z3

package solver

import "testing"

func TestZ3Backend(t *testing.T) {
	ans, err := (Z3Backend{}).Solve(FailureProblem{
		Links:       []string{"a", "b", "c"},
		MaxFailures: 2,
		Forbidden:   [][]string{{"a", "c"}},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if !ans.Sat || ans.Backend != "z3" {
		t.Fatalf("answer = %#v", ans)
	}
}
