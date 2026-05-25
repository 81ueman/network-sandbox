package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
	"github.com/81ueman/network-sandbox/hoyan/internal/verify"
)

func main() {
	topologyPath := flag.String("topology", "hoyan.clab.yml", "containerlab topology YAML")
	policiesPath := flag.String("policies", "intent/policies.yml", "verifier-only policy YAML")
	queriesPath := flag.String("queries", "intent/queries.yml", "query YAML")
	flag.Parse()

	topo, warnings, err := model.LoadLabTopologyWithWarnings(*topologyPath, *policiesPath)
	if err != nil {
		die(err)
	}
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
	queries, err := model.LoadQueries(*queriesPath)
	if err != nil {
		die(err)
	}
	report := verify.Run(topo, queries)
	for _, result := range report.Results {
		status := "PASS"
		if result.Reachable != result.Expected {
			status = "FAIL"
		}
		fmt.Printf("[%s] %s reachable=%v expected=%v\n", status, result.Name, result.Reachable, result.Expected)
		if len(result.Path.Nodes) > 0 {
			fmt.Printf("  path: %s\n", sim.FormatPath(result.Path))
		}
		if len(result.Counterexample) > 0 {
			fmt.Printf("  counterexample: %s\n", strings.Join(result.Counterexample, ", "))
		}
		if result.Reason != "" {
			fmt.Printf("  reason: %s\n", result.Reason)
		}
	}
	if !report.OK() {
		os.Exit(1)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
