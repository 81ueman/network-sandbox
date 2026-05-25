//go:build z3

package solver

import (
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/symbolic"
)

func TestZ3Backend(t *testing.T) {
	ans, err := (Z3Backend{}).Solve(FailureProblem{
		Elements:    linkElements("a", "b", "c"),
		MaxFailures: 2,
		Forbidden:   [][]FailureElement{linkElements("a", "c")},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if !ans.Sat || ans.Backend != "z3" {
		t.Fatalf("answer = %#v", ans)
	}
}

func TestZ3BackendSymbolicGoal(t *testing.T) {
	reachable := symbolic.Or(
		symbolic.And(symbolic.LinkVar("a"), symbolic.LinkVar("b")),
		symbolic.And(symbolic.LinkVar("c"), symbolic.LinkVar("d")),
	)
	ans, err := (Z3Backend{}).SolveSymbolic(SymbolicFailureProblem{
		Elements:    linkElements("a", "b", "c", "d"),
		MaxFailures: 1,
		Goal:        symbolic.Not(reachable),
	})
	if err != nil {
		t.Fatalf("SolveSymbolic() error = %v", err)
	}
	if ans.Sat {
		t.Fatalf("answer = %#v, want unsat with one failure against redundant paths", ans)
	}
	ans, err = (Z3Backend{}).SolveSymbolic(SymbolicFailureProblem{
		Elements:    linkElements("a", "b", "c", "d"),
		MaxFailures: 2,
		Goal:        symbolic.Not(reachable),
	})
	if err != nil {
		t.Fatalf("SolveSymbolic() error = %v", err)
	}
	if !ans.Sat || ans.Backend != "z3-symbolic" || len(ans.Failures) != 2 {
		t.Fatalf("answer = %#v, want two-failure symbolic cut", ans)
	}
}

func TestZ3BackendSymbolicMatchesEnumeratedProblem(t *testing.T) {
	elements := linkElements("a", "b", "c", "d")
	enumerated, err := (Z3Backend{}).Solve(FailureProblem{
		Elements:    elements,
		MaxFailures: 2,
		Forbidden: [][]FailureElement{
			linkElements("a", "c"),
			linkElements("a", "d"),
			linkElements("b", "c"),
			linkElements("b", "d"),
		},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	reachable := symbolic.Or(
		symbolic.And(symbolic.LinkVar("a"), symbolic.LinkVar("b")),
		symbolic.And(symbolic.LinkVar("c"), symbolic.LinkVar("d")),
	)
	symbolicAns, err := (Z3Backend{}).SolveSymbolic(SymbolicFailureProblem{
		Elements:    elements,
		MaxFailures: 2,
		Goal:        symbolic.Not(reachable),
	})
	if err != nil {
		t.Fatalf("SolveSymbolic() error = %v", err)
	}
	if !enumerated.Sat || !symbolicAns.Sat || len(enumerated.Failures) != len(symbolicAns.Failures) {
		t.Fatalf("enumerated=%#v symbolic=%#v, want matching SAT answers", enumerated, symbolicAns)
	}
}
