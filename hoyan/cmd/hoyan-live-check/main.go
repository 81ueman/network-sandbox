package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/livecheck"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

func main() {
	topologyPath := flag.String("topology", "hoyan.clab.yml", "containerlab topology YAML")
	policiesPath := flag.String("policies", "intent/policies.yml", "verifier-only policy YAML")
	timeout := flag.Duration("timeout", 5*time.Minute, "overall wait timeout")
	pollInterval := flag.Duration("poll-interval", 25*time.Second, "poll interval")
	maxPolls := flag.Int("max-polls", 3, "maximum FRR BGP collection polls before reporting diffs")
	keepOnFailure := flag.Bool("keep-on-failure", false, "leave lab running when the check fails")
	skipDestroy := flag.Bool("skip-destroy", false, "leave lab running after the check")
	flag.Parse()

	err := livecheck.Run(context.Background(), livecheck.Options{
		Topology:      *topologyPath,
		Policies:      *policiesPath,
		Timeout:       *timeout,
		PollInterval:  *pollInterval,
		MaxPolls:      *maxPolls,
		KeepOnFailure: *keepOnFailure,
		SkipDestroy:   *skipDestroy,
		Out:           os.Stdout,
	}, ribcompare.ExecRunner{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
