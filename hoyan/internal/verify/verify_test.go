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
	if len(report.Results) != 10 {
		t.Fatalf("results = %d, want 10", len(report.Results))
	}
	for _, result := range report.Results {
		switch result.Name {
		case "bj-client-to-hz-http-denied", "bj-client-to-hz-http-denied-live-linux-acl", "sh-client-to-hz-http-denied-live-ceos", "gz-client-to-hz-http-denied-live-srlinux":
			if result.Reachable {
				t.Fatalf("%s should be denied", result.Name)
			}
		}
	}
}
