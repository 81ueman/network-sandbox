package verify

import (
	"path/filepath"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestRunBundledQueries(t *testing.T) {
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	queries, err := model.LoadQueries(filepath.Join("..", "..", "intent", "queries.yml"))
	if err != nil {
		t.Fatalf("LoadQueries() error = %v", err)
	}
	report := Run(topo, queries)
	if len(report.Results) != 13 {
		t.Fatalf("results = %d, want 13", len(report.Results))
	}
	for _, result := range report.Results {
		switch result.Name {
		case "bj-client-to-hz-http-denied", "bj-client-to-hz-http-denied-live-linux-acl", "sh-client-to-hz-http-denied-live-ceos", "gz-client-to-hz-http-denied-live-srlinux":
			if result.Reachable {
				t.Fatalf("%s should be denied", result.Name)
			}
		case "bj-client-to-hz-https-allowed-linux-acl", "sh-client-to-hz-https-allowed-ceos", "gz-client-to-hz-https-allowed-srlinux":
			if !result.Reachable {
				t.Fatalf("%s should be allowed: %s", result.Name, result.Reason)
			}
		}
	}
}

func TestRunWithOptionsExpandsPrefixClasses(t *testing.T) {
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	queries, err := model.LoadQueries(filepath.Join("..", "..", "intent", "queries.yml"))
	if err != nil {
		t.Fatalf("LoadQueries() error = %v", err)
	}
	report := RunWithOptions(topo, queries, VerifyOptions{UsePrefixUniverse: true})
	if len(report.Results) <= 13 {
		t.Fatalf("prefix-class results = %d, want more than legacy query count", len(report.Results))
	}
	var foundRouteClass, foundPacketClass, foundFailureClass bool
	for _, result := range report.Results {
		if len(result.PrefixClassIDs) == 0 || len(result.PrefixSpaces) == 0 || len(result.MatchedPredicates) == 0 {
			t.Fatalf("result missing prefix-class metadata: %#v", result)
		}
		if result.ReachableCondition == "" || result.UnreachableCondition == "" {
			t.Fatalf("result missing symbolic conditions: %#v", result)
		}
		switch result.QueryType {
		case "route":
			foundRouteClass = true
		case "packet":
			foundPacketClass = true
		case "failure":
			foundFailureClass = true
		}
	}
	if !foundRouteClass || !foundPacketClass || !foundFailureClass {
		t.Fatalf("missing class-expanded query types: route=%v packet=%v failure=%v", foundRouteClass, foundPacketClass, foundFailureClass)
	}
}

func TestRunWithOptionsCollapsesEquivalentPrefixClassResults(t *testing.T) {
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	queries, err := model.LoadQueries(filepath.Join("..", "..", "intent", "queries.yml"))
	if err != nil {
		t.Fatalf("LoadQueries() error = %v", err)
	}
	raw := RunWithOptions(topo, queries, VerifyOptions{UsePrefixUniverse: true})
	collapsed := RunWithOptions(topo, queries, VerifyOptions{UsePrefixUniverse: true, CollapseEquivalentResults: true})
	if len(collapsed.Results) >= len(raw.Results) {
		t.Fatalf("collapsed results = %d, raw results = %d; want fewer collapsed results", len(collapsed.Results), len(raw.Results))
	}
	for _, result := range collapsed.Results {
		if len(result.PrefixClassIDs) == 0 {
			t.Fatalf("collapsed result missing class list: %#v", result)
		}
	}
}
