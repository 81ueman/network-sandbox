package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

func main() {
	topologyPath := flag.String("topology", "hoyan.clab.yml", "containerlab topology YAML")
	policiesPath := flag.String("policies", "intent/policies.yml", "verifier-only policy YAML")
	flag.Parse()
	topo, err := model.LoadLabTopology(*topologyPath, *policiesPath)
	if err != nil {
		die(err)
	}
	nodes := ribcompare.SupportedNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, nodes)
	actual, err := ribcompare.Collect(context.Background(), ribcompare.ExecRunner{}, nodes)
	if err != nil {
		die(err)
	}
	result := ribcompare.CompareBgpRib(expected, actual, ribcompare.LiveBgpRibCompareOptions())
	for _, line := range ribcompare.FormatDiffs(result) {
		fmt.Println(line)
	}
	if !result.OK {
		os.Exit(1)
	}
	fmt.Println("BGP RIBs match expected modeled paths")
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
