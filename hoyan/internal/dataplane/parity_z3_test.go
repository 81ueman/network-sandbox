//go:build z3

package dataplane

import (
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

func TestPacketReachabilityFailureEnumerationMatchesZ3SymbolicBackend(t *testing.T) {
	engine := redundantPathEngine()
	from, to, protocol := "src", "10.0.0.10", "icmp"
	maxFailures := 2
	elements := []solver.FailureElement{
		{Kind: solver.FailureLink, Name: "src-primary"},
		{Kind: solver.FailureLink, Name: "primary-dst"},
		{Kind: solver.FailureLink, Name: "src-backup"},
		{Kind: solver.FailureLink, Name: "backup-dst"},
		{Kind: solver.FailureNode, Name: "primary"},
		{Kind: solver.FailureNode, Name: "backup"},
	}

	forbidden := concreteBreakingFailureCombos(engine, from, to, protocol, elements, maxFailures)
	enumerated, err := (solver.Z3Backend{}).Solve(solver.FailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Forbidden:   forbidden,
	})
	if err != nil {
		t.Fatalf("Z3 concrete Solve() error = %v", err)
	}
	symbolicResult := engine.SymbolicPacketReachability(from, to, protocol)
	z3Symbolic, err := (solver.Z3Backend{}).SolveSymbolic(solver.SymbolicFailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Goal:        failure.BoolExpr(symbolicResult.Unreachable),
	})
	if err != nil {
		t.Fatalf("Z3 symbolic SolveSymbolic() error = %v", err)
	}
	assertSolverParityAnswer(t, engine, from, to, protocol, maxFailures, enumerated, z3Symbolic)
}

func TestRouteReachabilityFailureEnumerationMatchesZ3SymbolicBackend(t *testing.T) {
	engine := routeRedundantPathEngine()
	from, prefix := "src", "10.0.0.0/24"
	maxFailures := 2
	elements := []solver.FailureElement{
		{Kind: solver.FailureLink, Name: "src-primary"},
		{Kind: solver.FailureLink, Name: "primary-dst"},
		{Kind: solver.FailureLink, Name: "src-backup"},
		{Kind: solver.FailureLink, Name: "backup-dst"},
		{Kind: solver.FailureNode, Name: "primary"},
		{Kind: solver.FailureNode, Name: "backup"},
	}

	forbidden := concreteBreakingRouteFailureCombos(engine, from, prefix, elements, maxFailures)
	enumerated, err := (solver.Z3Backend{}).Solve(solver.FailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Forbidden:   forbidden,
	})
	if err != nil {
		t.Fatalf("Z3 route Solve() error = %v", err)
	}
	symbolicResult := engine.SymbolicRouteReachability(from, prefix)
	z3Symbolic, err := (solver.Z3Backend{}).SolveSymbolic(solver.SymbolicFailureProblem{
		Elements:    elements,
		MaxFailures: maxFailures,
		Goal:        failure.BoolExpr(symbolicResult.Unreachable),
	})
	if err != nil {
		t.Fatalf("Z3 route SolveSymbolic() error = %v", err)
	}
	assertRouteSolverParityAnswer(t, engine, from, prefix, maxFailures, enumerated, z3Symbolic)
}
