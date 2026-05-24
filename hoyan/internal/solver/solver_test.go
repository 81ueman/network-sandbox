package solver

import "testing"

func TestEnumeratingBackend(t *testing.T) {
	ans, err := DefaultBackend().Solve(FailureProblem{
		Links:       []string{"a", "b", "c"},
		MaxFailures: 2,
		Forbidden:   [][]string{{"a", "c"}},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if !ans.Sat || len(ans.Failures) != 2 {
		t.Fatalf("answer = %#v", ans)
	}
}

func TestEnumeratingBackendUnsat(t *testing.T) {
	ans, err := DefaultBackend().Solve(FailureProblem{
		Links:       []string{"a", "b", "c"},
		MaxFailures: 1,
		Forbidden:   [][]string{{"a", "c"}},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if ans.Sat {
		t.Fatalf("answer = %#v, want unsat", ans)
	}
}
