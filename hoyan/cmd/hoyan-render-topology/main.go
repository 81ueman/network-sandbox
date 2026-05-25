package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type options struct {
	topologyPath string
	outputPath   string
	suffix       string
	labName      string
	mgmtNetwork  string
	mgmtSubnet   string
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		die(err)
	}
	data, err := os.ReadFile(opts.topologyPath)
	if err != nil {
		die(err)
	}
	sourceDir, err := filepath.Abs(filepath.Dir(opts.topologyPath))
	if err != nil {
		die(err)
	}
	renderOpts := model.TopologyRenderOptions{
		Suffix:      opts.suffix,
		LabName:     opts.labName,
		MgmtNetwork: opts.mgmtNetwork,
		MgmtSubnet:  opts.mgmtSubnet,
	}
	if shouldRewriteConfigPaths(sourceDir, opts.outputPath) {
		renderOpts.SourceDir = sourceDir
	}
	out, err := model.RenderIsolatedTopology(data, renderOpts)
	if err != nil {
		die(err)
	}
	if opts.outputPath == "" || opts.outputPath == "-" {
		if _, err := os.Stdout.Write(out); err != nil {
			die(err)
		}
		return
	}
	if err := os.WriteFile(opts.outputPath, out, 0o644); err != nil {
		die(err)
	}
}

func shouldRewriteConfigPaths(sourceDir, outputPath string) bool {
	if outputPath == "" || outputPath == "-" {
		return false
	}
	outputDir, err := filepath.Abs(filepath.Dir(outputPath))
	if err != nil {
		return true
	}
	return outputDir != sourceDir
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("hoyan-render-topology", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	topologyPath := fs.String("topology", "hoyan.clab.yml", "source containerlab topology YAML")
	outputPath := fs.String("output", "-", "generated topology path, or - for stdout")
	suffix := fs.String("suffix", "", "isolation suffix appended to the lab name")
	labName := fs.String("lab-name", "", "generated lab name")
	mgmtNetwork := fs.String("mgmt-network", "", "generated Docker management network name")
	mgmtSubnet := fs.String("mgmt-subnet", "", "generated Docker management IPv4 /24 subnet")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	return options{
		topologyPath: *topologyPath,
		outputPath:   *outputPath,
		suffix:       *suffix,
		labName:      *labName,
		mgmtNetwork:  *mgmtNetwork,
		mgmtSubnet:   *mgmtSubnet,
	}, nil
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
