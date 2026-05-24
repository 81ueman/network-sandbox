package solver

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
	Elements    []FailureElement
	MaxFailures int
	Forbidden   [][]FailureElement
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
