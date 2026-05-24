package solver

import "testing"

func TestEnumeratingBackend(t *testing.T) {
	ans, err := DefaultBackend().Solve(FailureProblem{
		Elements:    linkElements("a", "b", "c"),
		MaxFailures: 2,
		Forbidden:   [][]FailureElement{linkElements("a", "c")},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if !ans.Sat || len(ans.Failures) != 2 {
		t.Fatalf("answer = %#v", ans)
	}
	if ans.Failures[0].Kind != FailureLink || ans.Failures[0].Name == "" {
		t.Fatalf("typed failure not preserved: %#v", ans.Failures)
	}
}

func TestEnumeratingBackendUnsat(t *testing.T) {
	ans, err := DefaultBackend().Solve(FailureProblem{
		Elements:    linkElements("a", "b", "c"),
		MaxFailures: 1,
		Forbidden:   [][]FailureElement{linkElements("a", "c")},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if ans.Sat {
		t.Fatalf("answer = %#v, want unsat", ans)
	}
}

func TestEnumeratingBackendNodeOnly(t *testing.T) {
	ans, err := DefaultBackend().Solve(FailureProblem{
		Elements:    []FailureElement{{Kind: FailureNode, Name: "n1"}},
		MaxFailures: 1,
		Forbidden:   [][]FailureElement{{{Kind: FailureNode, Name: "n1"}}},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if !ans.Sat || len(ans.Failures) != 1 || ans.Failures[0] != (FailureElement{Kind: FailureNode, Name: "n1"}) {
		t.Fatalf("answer = %#v, want node n1", ans)
	}
}

func TestEnumeratingBackendMixedElements(t *testing.T) {
	ans, err := DefaultBackend().Solve(FailureProblem{
		Elements: []FailureElement{
			{Kind: FailureLink, Name: "l1"},
			{Kind: FailureNode, Name: "n1"},
		},
		MaxFailures: 1,
		Forbidden: [][]FailureElement{
			{{Kind: FailureNode, Name: "n1"}},
		},
	})
	if err != nil {
		t.Fatalf("Solve() error = %v", err)
	}
	if !ans.Sat || len(ans.Failures) != 1 || ans.Failures[0].Kind != FailureNode || ans.Failures[0].Name != "n1" {
		t.Fatalf("answer = %#v, want node n1", ans)
	}
}

func TestAnswerFailureStrings(t *testing.T) {
	got := (Answer{Failures: []FailureElement{{Kind: FailureLink, Name: "l1"}, {Kind: FailureNode, Name: "n1"}}}).FailureStrings()
	want := []string{"link:l1", "node:n1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("FailureStrings() = %v, want %v", got, want)
	}
}

func linkElements(names ...string) []FailureElement {
	out := make([]FailureElement, 0, len(names))
	for _, name := range names {
		out = append(out, FailureElement{Kind: FailureLink, Name: name})
	}
	return out
}
