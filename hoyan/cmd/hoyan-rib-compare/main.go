package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

type options struct {
	topologyPath string
	policiesPath string
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		die(err)
	}
	topo, err := model.LoadLabTopology(opts.topologyPath, opts.policiesPath)
	if err != nil {
		die(err)
	}
	nodes := ribcompare.SupportedNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, nodes)
	actual, err := ribcompare.Collect(context.Background(), ribcompare.ExecRunner{}, nodes)
	if err != nil {
		die(err)
	}
	result := ribcompare.CompareBgpRib(expected, actual, ribcompare.DefaultBgpRibCompareOptions())
	for _, line := range ribcompare.FormatDiffs(result) {
		fmt.Println(line)
	}
	if !result.OK {
		os.Exit(1)
	}
	fmt.Println("BGP RIBs match expected modeled paths")
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("hoyan-rib-compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	topologyPath := fs.String("topology", "hoyan.clab.yml", "containerlab topology YAML")
	policiesPath := fs.String("policies", "", "optional deprecated verifier-only policy YAML")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	return options{topologyPath: *topologyPath, policiesPath: *policiesPath}, nil
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
