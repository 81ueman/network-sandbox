package livecheck

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

type Options struct {
	Topology      string
	Policies      string
	Timeout       time.Duration
	PollInterval  time.Duration
	MaxPolls      int
	KeepOnFailure bool
	SkipDestroy   bool
	Out           io.Writer
}

func Run(ctx context.Context, opts Options, runner ribcompare.Runner) (err error) {
	if opts.Topology == "" {
		opts.Topology = "hoyan.clab.yml"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 25 * time.Second
	}
	if opts.MaxPolls == 0 {
		opts.MaxPolls = 3
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	topo, err := model.LoadLabTopology(opts.Topology, opts.Policies)
	if err != nil {
		return err
	}
	frrNodes := ribcompare.FRRNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, frrNodes)

	fmt.Fprintf(opts.Out, "deploying %s\n", opts.Topology)
	if _, err := runner.Run(ctx, "containerlab", "deploy", "--reconfigure", "-t", opts.Topology); err != nil {
		return fmt.Errorf("containerlab deploy: %w", err)
	}
	defer func() {
		if opts.SkipDestroy || (err != nil && opts.KeepOnFailure) {
			return
		}
		fmt.Fprintf(opts.Out, "destroying %s\n", opts.Topology)
		if _, destroyErr := runner.Run(context.Background(), "containerlab", "destroy", "--cleanup", "-t", opts.Topology); err == nil && destroyErr != nil {
			err = fmt.Errorf("containerlab destroy: %w", destroyErr)
		}
	}()

	deadlineCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if err := WaitForFRRContainers(deadlineCtx, runner, frrNodes, opts.PollInterval); err != nil {
		return err
	}
	fmt.Fprintln(opts.Out, "waiting for FRR BGP routes")
	actual, err := WaitForExpectedRoutes(deadlineCtx, runner, frrNodes, expected, opts.PollInterval, opts.MaxPolls)
	if err != nil {
		if len(actual) > 0 {
			for _, d := range ribcompare.Compare(expected, actual) {
				fmt.Fprintf(opts.Out, "[DIFF] %s %s expected=%s actual=%s\n", d.Node, d.Prefix, d.Expected, d.Actual)
			}
		}
		return err
	}
	diffs := ribcompare.Compare(expected, actual)
	for _, d := range diffs {
		fmt.Fprintf(opts.Out, "[DIFF] %s %s expected=%s actual=%s\n", d.Node, d.Prefix, d.Expected, d.Actual)
	}
	if len(diffs) > 0 {
		return fmt.Errorf("live RIB comparison found %d diff(s)", len(diffs))
	}
	fmt.Fprintln(opts.Out, "live FRR RIBs match modeled best paths")
	return nil
}

func WaitForFRRContainers(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, interval time.Duration) error {
	var lastErr error
	return poll(ctx, interval, func() (bool, error) {
		for _, n := range nodes {
			out, err := runner.Run(ctx, "docker", "inspect", "-f", "{{.State.Running}}", n.Name)
			if err != nil {
				lastErr = fmt.Errorf("docker inspect -f {{.State.Running}} %s: %w", n.Name, err)
				return false, nil
			}
			if strings.TrimSpace(string(out)) != "true" {
				lastErr = fmt.Errorf("container %s is not running", n.Name)
				return false, nil
			}
		}
		return true, nil
	}, func() error {
		if lastErr != nil {
			return fmt.Errorf("FRR containers did not become ready: %w", lastErr)
		}
		return fmt.Errorf("FRR containers did not become ready")
	})
}

func WaitForExpectedRoutes(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, expected []ribcompare.ExpectedRoute, interval time.Duration, maxPolls int) ([]ribcompare.ActualRoute, error) {
	var last []ribcompare.ActualRoute
	var lastErr error
	bestSeen := 0
	polls := 0
	err := poll(ctx, interval, func() (bool, error) {
		polls++
		actual, err := ribcompare.CollectFRRWithRunner(ctx, runner, nodes)
		if err != nil {
			lastErr = err
			if maxPolls > 0 && polls >= maxPolls {
				return false, convergenceError(lastErr, bestSeen, len(expected))
			}
			return false, nil
		}
		last = actual
		if seen := CountExpectedRoutes(expected, actual); seen > bestSeen {
			bestSeen = seen
		}
		if HasExpectedRoutes(expected, actual) {
			return true, nil
		}
		if maxPolls > 0 && polls >= maxPolls {
			return false, convergenceError(lastErr, bestSeen, len(expected))
		}
		return false, nil
	}, func() error {
		return convergenceError(lastErr, bestSeen, len(expected))
	})
	if err != nil {
		return last, err
	}
	return last, nil
}

func convergenceError(lastErr error, seen, total int) error {
	if lastErr != nil {
		return fmt.Errorf("expected BGP routes did not converge; last collection error: %w", lastErr)
	}
	return fmt.Errorf("expected BGP routes did not converge: saw %d/%d expected routes", seen, total)
}

func HasExpectedRoutes(expected []ribcompare.ExpectedRoute, actual []ribcompare.ActualRoute) bool {
	return CountExpectedRoutes(expected, actual) == len(expected)
}

func CountExpectedRoutes(expected []ribcompare.ExpectedRoute, actual []ribcompare.ActualRoute) int {
	seen := map[string]bool{}
	for _, route := range actual {
		seen[route.Node+"|"+route.Prefix] = true
	}
	count := 0
	for _, route := range expected {
		if seen[route.Node+"|"+route.Prefix] {
			count++
		}
	}
	return count
}

func poll(ctx context.Context, interval time.Duration, fn func() (bool, error), onTimeout func() error) error {
	if interval <= 0 {
		interval = time.Second
	}
	for {
		ok, err := fn()
		if err != nil || ok {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if onTimeout != nil {
				return onTimeout()
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
