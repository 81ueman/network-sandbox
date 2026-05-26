package verify

import (
	"path/filepath"
	"strings"
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
			if result.Metadata.Reachable {
				t.Fatalf("%s should be denied", result.Name)
			}
		case "bj-client-to-hz-https-allowed-linux-acl", "sh-client-to-hz-https-allowed-ceos", "gz-client-to-hz-https-allowed-srlinux":
			if !result.Metadata.Reachable {
				t.Fatalf("%s should be allowed: %s", result.Name, result.Metadata.Reason)
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
		if result.PrefixClass == nil || len(result.PrefixClass.ClassIDs) == 0 || len(result.PrefixClass.Spaces) == 0 || len(result.PrefixClass.MatchedPredicates) == 0 {
			t.Fatalf("result missing prefix-class metadata: %#v", result)
		}
		if result.ReachableCondition() == "" || result.UnreachableCondition() == "" {
			t.Fatalf("result missing symbolic conditions: %#v", result)
		}
		switch result.Type {
		case QueryTypeRoute:
			foundRouteClass = true
		case QueryTypePacket:
			foundPacketClass = true
		case QueryTypeFailure:
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
		if result.PrefixClass == nil || len(result.PrefixClass.ClassIDs) == 0 {
			t.Fatalf("collapsed result missing class list: %#v", result)
		}
	}
}

func TestRouteCheckPrefixClassesEvaluateClassSpace(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{
				Name: "src",
				Kind: model.KindFRR,
				ASN:  65001,
				Neighbors: []model.BGPNeighbor{{
					PeerNode:  "dst",
					RemoteAS:  65002,
					Activated: true,
				}},
			},
			{
				Name:     "dst",
				Kind:     model.KindFRR,
				ASN:      65002,
				Prefixes: model.MustPrefixes("10.0.1.0/24"),
				Neighbors: []model.BGPNeighbor{{
					PeerNode:  "src",
					RemoteAS:  65001,
					Activated: true,
				}},
			},
		},
		Links: []model.Link{{
			Name: "src-dst",
			A:    "src",
			B:    "dst",
			Cost: 10,
		}},
	}
	queries := &model.Queries{RouteChecks: []model.RouteCheck{{
		Name:        "src-to-wide-prefix",
		From:        "src",
		Prefix:      model.MustPrefix("10.0.0.0/16"),
		MaxFailures: 1,
	}}}

	report := RunWithOptions(topo, queries, VerifyOptions{UsePrefixUniverse: true})
	if len(report.Results) < 2 {
		t.Fatalf("prefix-class route results = %d, want split classes: %#v", len(report.Results), report.Results)
	}
	var routedClass, unroutedClass *model.PrefixClassID
	for i := range report.Results {
		result := report.Results[i]
		if result.Type != QueryTypeRoute {
			continue
		}
		if result.ReachableCondition() == "" || result.UnreachableCondition() == "" {
			t.Fatalf("route class result missing symbolic conditions: %#v", result)
		}
		if result.PrefixClass != nil && strings.Contains(result.PrefixClass.Space, "10.0.1.0/24") {
			if !result.Metadata.Reachable {
				t.Fatalf("route class for advertised /24 should be reachable: %#v", result)
			}
			if counterexample := result.Counterexample(); len(counterexample) == 0 || counterexample[0] != "src-dst" {
				t.Fatalf("reachable class counterexample = %v, want src-dst", counterexample)
			}
			routedClass = result.PrefixClass.ClassID
			continue
		}
		if result.Metadata.Reachable {
			t.Fatalf("non-advertised class should be unreachable: %#v", result)
		}
		if len(result.Counterexample()) != 0 {
			t.Fatalf("unreachable class should not get a resilience counterexample: %#v", result)
		}
		if result.PrefixClass != nil {
			unroutedClass = result.PrefixClass.ClassID
		}
	}
	if routedClass == nil || unroutedClass == nil || *routedClass == *unroutedClass {
		t.Fatalf("did not find distinct reachable/unreachable route classes: %#v", report.Results)
	}
}
