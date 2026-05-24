package solver

type FailureProblem struct {
	Links       []string
	MaxFailures int
	Forbidden   [][]string
}

type Answer struct {
	Sat      bool
	Failures []string
	Backend  string
}

type Backend interface {
	Solve(problem FailureProblem) (Answer, error)
}

type EnumeratingBackend struct{}

func (EnumeratingBackend) Solve(problem FailureProblem) (Answer, error) {
	for k := 0; k <= problem.MaxFailures; k++ {
		var out []string
		if findCombo(problem.Links, k, 0, nil, func(combo []string) bool {
			if satisfiesForbidden(combo, problem.Forbidden) {
				out = append([]string(nil), combo...)
				return true
			}
			return false
		}) {
			return Answer{Sat: true, Failures: out, Backend: "enumerating"}, nil
		}
	}
	return Answer{Sat: false, Backend: "enumerating"}, nil
}

func satisfiesForbidden(combo []string, forbidden [][]string) bool {
	set := map[string]bool{}
	for _, name := range combo {
		set[name] = true
	}
	for _, clause := range forbidden {
		ok := true
		for _, name := range clause {
			if !set[name] {
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

func findCombo(links []string, want, start int, cur []string, fn func([]string) bool) bool {
	if len(cur) == want {
		return fn(cur)
	}
	for i := start; i < len(links); i++ {
		cur = append(cur, links[i])
		if findCombo(links, want, i+1, cur, fn) {
			return true
		}
		cur = cur[:len(cur)-1]
	}
	return false
}
