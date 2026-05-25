package solver

import "github.com/81ueman/network-sandbox/hoyan/internal/symbolic"

type FailureElementKind string

const (
	FailureLink FailureElementKind = "link"
	FailureNode FailureElementKind = "node"
)

type FailureElement struct {
	Kind FailureElementKind
	Name string
}

func (e FailureElement) String() string {
	return string(e.Kind) + ":" + e.Name
}

type FailureProblem struct {
	// Forbidden is an enumerated list of already-known bad failure combos.
	// A combo satisfies this problem when it contains every element in at least
	// one forbidden clause. This legacy problem shape does not encode packet or
	// route reachability itself.
	Elements    []FailureElement
	MaxFailures int
	Forbidden   [][]FailureElement
}

type SymbolicFailureProblem struct {
	Elements    []FailureElement
	MaxFailures int
	Goal        symbolic.Expr
}

type Answer struct {
	Sat      bool
	Failures []FailureElement
	Backend  string
}

func (a Answer) FailureStrings() []string {
	out := make([]string, 0, len(a.Failures))
	for _, f := range a.Failures {
		out = append(out, f.String())
	}
	return out
}

type Backend interface {
	Solve(problem FailureProblem) (Answer, error)
}

type SymbolicBackend interface {
	SolveSymbolic(problem SymbolicFailureProblem) (Answer, error)
}

type EnumeratingBackend struct{}

func (EnumeratingBackend) Solve(problem FailureProblem) (Answer, error) {
	for k := 0; k <= problem.MaxFailures; k++ {
		var out []FailureElement
		if findCombo(problem.Elements, k, 0, nil, func(combo []FailureElement) bool {
			if satisfiesForbidden(combo, problem.Forbidden) {
				out = append([]FailureElement(nil), combo...)
				return true
			}
			return false
		}) {
			return Answer{Sat: true, Failures: out, Backend: "enumerating"}, nil
		}
	}
	return Answer{Sat: false, Backend: "enumerating"}, nil
}

func (EnumeratingBackend) SolveSymbolic(problem SymbolicFailureProblem) (Answer, error) {
	for k := 0; k <= problem.MaxFailures; k++ {
		var out []FailureElement
		if findCombo(problem.Elements, k, 0, nil, func(combo []FailureElement) bool {
			if evalSymbolicGoal(problem.Goal, combo) {
				out = append([]FailureElement(nil), combo...)
				return true
			}
			return false
		}) {
			return Answer{Sat: true, Failures: out, Backend: "enumerating-symbolic"}, nil
		}
	}
	return Answer{Sat: false, Backend: "enumerating-symbolic"}, nil
}

func satisfiesForbidden(combo []FailureElement, forbidden [][]FailureElement) bool {
	set := map[string]bool{}
	for _, element := range combo {
		set[element.String()] = true
	}
	for _, clause := range forbidden {
		ok := true
		for _, element := range clause {
			if !set[element.String()] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func findCombo(elements []FailureElement, want, start int, cur []FailureElement, fn func([]FailureElement) bool) bool {
	if len(cur) == want {
		return fn(cur)
	}
	for i := start; i < len(elements); i++ {
		cur = append(cur, elements[i])
		if findCombo(elements, want, i+1, cur, fn) {
			return true
		}
		cur = cur[:len(cur)-1]
	}
	return false
}

func evalSymbolicGoal(expr symbolic.Expr, failures []FailureElement) bool {
	failed := map[string]bool{}
	for _, element := range failures {
		failed[element.String()] = true
	}
	var eval func(symbolic.Expr) bool
	eval = func(e symbolic.Expr) bool {
		switch e.Kind {
		case symbolic.KindTrue:
			return true
		case symbolic.KindFalse:
			return false
		case symbolic.KindVar:
			return !failed[string(e.VarKind)+":"+e.Name]
		case symbolic.KindAnd:
			for _, child := range e.Children {
				if !eval(child) {
					return false
				}
			}
			return true
		case symbolic.KindOr:
			for _, child := range e.Children {
				if eval(child) {
					return true
				}
			}
			return false
		case symbolic.KindNot:
			if len(e.Children) == 0 {
				return false
			}
			return !eval(e.Children[0])
		default:
			return true
		}
	}
	return eval(expr)
}
