package main

import "testing"

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "hoyan.clab.yml" {
		t.Fatalf("opts = %#v", opts)
	}
}

func TestParseOptionsAcceptsPaths(t *testing.T) {
	opts, err := parseOptions([]string{"-topology", "custom.clab.yml"})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "custom.clab.yml" {
		t.Fatalf("opts = %#v", opts)
	}
}
