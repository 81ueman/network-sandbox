package verify

import (
	"path/filepath"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestRunBundledQueries(t *testing.T) {
	topo, err := model.LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	queries, err := model.LoadQueries(filepath.Join("..", "..", "intent", "queries.yml"))
	if err != nil {
		t.Fatalf("LoadQueries() error = %v", err)
	}
	report := Run(topo, queries)
	if len(report.Results) != 6 {
		t.Fatalf("results = %d, want 6", len(report.Results))
	}
	for _, result := range report.Results {
		if result.Name == "bj-client-to-hz-http-denied" && result.Reachable {
			t.Fatalf("http query should be denied")
		}
	}
}
