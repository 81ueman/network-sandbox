package main

import (
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
	frrNodes := ribcompare.FRRNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, frrNodes)
	actual, err := ribcompare.CollectFRR(frrNodes)
	if err != nil {
		die(err)
	}
	diffs := ribcompare.Compare(expected, actual)
	for _, d := range diffs {
		fmt.Printf("[DIFF] %s %s expected=%s actual=%s\n", d.Node, d.Prefix, d.Expected, d.Actual)
	}
	if len(diffs) > 0 {
		os.Exit(1)
	}
	fmt.Println("RIBs match expected FRR best paths")
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
