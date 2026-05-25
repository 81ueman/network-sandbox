package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/livecheck"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

type options struct {
	topologyPath  string
	policiesPath  string
	queriesPath   string
	timeout       time.Duration
	pollInterval  time.Duration
	maxPolls      int
	keepOnFailure bool
	skipDestroy   bool
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	err = livecheck.Run(context.Background(), livecheck.Options{
		Topology:      opts.topologyPath,
		Policies:      opts.policiesPath,
		Queries:       opts.queriesPath,
		Timeout:       opts.timeout,
		PollInterval:  opts.pollInterval,
		MaxPolls:      opts.maxPolls,
		KeepOnFailure: opts.keepOnFailure,
		SkipDestroy:   opts.skipDestroy,
		Out:           os.Stdout,
	}, ribcompare.ExecRunner{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("hoyan-live-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	topologyPath := fs.String("topology", "hoyan.clab.yml", "containerlab topology YAML")
	policiesPath := fs.String("policies", "", "optional deprecated verifier-only policy YAML")
	queriesPath := fs.String("queries", "intent/queries.yml", "query YAML for live dataplane checks")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall wait timeout")
	pollInterval := fs.Duration("poll-interval", 25*time.Second, "poll interval")
	maxPolls := fs.Int("max-polls", 3, "maximum BGP collection polls before reporting diffs")
	keepOnFailure := fs.Bool("keep-on-failure", false, "leave lab running when the check fails")
	skipDestroy := fs.Bool("skip-destroy", false, "leave lab running after the check")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	return options{
		topologyPath:  *topologyPath,
		policiesPath:  *policiesPath,
		queriesPath:   *queriesPath,
		timeout:       *timeout,
		pollInterval:  *pollInterval,
		maxPolls:      *maxPolls,
		keepOnFailure: *keepOnFailure,
		skipDestroy:   *skipDestroy,
	}, nil
}
