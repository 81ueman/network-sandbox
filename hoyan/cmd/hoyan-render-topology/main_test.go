package main

import "testing"

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "hoyan.clab.yml" || opts.outputPath != "-" {
		t.Fatalf("opts = %#v", opts)
	}
}

func TestParseOptionsAcceptsIsolationFlags(t *testing.T) {
	opts, err := parseOptions([]string{
		"-topology", "source.clab.yml",
		"-output", "generated.clab.yml",
		"-suffix", "issue-21",
		"-lab-name", "hoyan-custom",
		"-mgmt-network", "hoyan-custom",
		"-mgmt-subnet", "172.86.21.0/24",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "source.clab.yml" || opts.outputPath != "generated.clab.yml" || opts.suffix != "issue-21" || opts.labName != "hoyan-custom" || opts.mgmtNetwork != "hoyan-custom" || opts.mgmtSubnet != "172.86.21.0/24" {
		t.Fatalf("opts = %#v", opts)
	}
}
