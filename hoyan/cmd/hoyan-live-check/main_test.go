package main

import "testing"

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "hoyan.clab.yml" || opts.policiesPath != "" || opts.queriesPath != "intent/queries.yml" || opts.maxPolls != 3 {
		t.Fatalf("opts = %#v", opts)
	}
}

func TestParseOptionsAcceptsLiveCheckFlags(t *testing.T) {
	opts, err := parseOptions([]string{
		"-topology", "custom.clab.yml",
		"-policies", "custom-policies.yml",
		"-queries", "custom-queries.yml",
		"-max-polls", "7",
		"-keep-on-failure",
		"-skip-destroy",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.topologyPath != "custom.clab.yml" || opts.policiesPath != "custom-policies.yml" || opts.queriesPath != "custom-queries.yml" || opts.maxPolls != 7 || !opts.keepOnFailure || !opts.skipDestroy {
		t.Fatalf("opts = %#v", opts)
	}
}
