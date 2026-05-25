package main

import "testing"

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "hoyan.clab.yml" || opts.policiesPath != "" {
		t.Fatalf("opts = %#v", opts)
	}
}

func TestParseOptionsAcceptsPaths(t *testing.T) {
	opts, err := parseOptions([]string{"-topology", "custom.clab.yml", "-policies", "custom-policies.yml"})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "custom.clab.yml" || opts.policiesPath != "custom-policies.yml" {
		t.Fatalf("opts = %#v", opts)
	}
}
