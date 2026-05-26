package livecheck

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/fibcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

type Options struct {
	Topology       string
	Queries        string
	Timeout        time.Duration
	PollInterval   time.Duration
	MaxPolls       int
	StrictConfig   bool
	CompareOptions ribcompare.BgpRibCompareOptions
	CheckFIB       bool
	FIBOptions     fibcompare.Options
	KeepOnFailure  bool
	SkipDestroy    bool
	Out            io.Writer
}

const DefaultMaxPolls = 5

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
		opts.MaxPolls = DefaultMaxPolls
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	compareOptions := opts.CompareOptions
	if isZeroCompareOptions(compareOptions) {
		compareOptions = ribcompare.DefaultBgpRibCompareOptions()
	}
	topo, _, err := model.LoadLabTopologyWithOptions(opts.Topology, model.LoadLabTopologyOptions{StrictConfig: opts.StrictConfig})
	if err != nil {
		return err
	}
	queriesPath := opts.Queries
	if queriesPath == "" {
		queriesPath = "intent/queries.yml"
	}
	queries, err := model.LoadQueries(queriesPath)
	if err != nil {
		return err
	}
	nodes := ribcompare.SupportedNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, nodes)

	if err := BuildLocalImages(ctx, runner, opts.Topology, opts.Out); err != nil {
		return err
	}
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
	if err := WaitForContainers(deadlineCtx, runner, nodes, opts.PollInterval); err != nil {
		return err
	}
	if err := ApplyNftablesPolicies(deadlineCtx, runner, topo, opts.Out); err != nil {
		return err
	}
	fmt.Fprintln(opts.Out, "waiting for BGP RIB routes")
	actual, result, err := WaitForMatchingRIBs(deadlineCtx, runner, nodes, expected, opts.PollInterval, opts.MaxPolls, compareOptions)
	if err != nil {
		if len(actual) > 0 {
			for _, line := range ribcompare.FormatDiffs(result) {
				fmt.Fprintln(opts.Out, line)
			}
		}
		return err
	}
	for _, line := range ribcompare.FormatDiffs(result) {
		fmt.Fprintln(opts.Out, line)
	}
	if !result.OK {
		return fmt.Errorf("live BGP RIB comparison found diff(s)")
	}
	fmt.Fprintln(opts.Out, "live BGP RIBs match modeled paths")
	if opts.CheckFIB {
		fibNodes := topo.Nodes
		if opts.FIBOptions.AllowUnsupported {
			fibNodes = fibcompare.SupportedNodes(fibNodes)
		}
		expectedFIB := fibcompare.ComparableRoutes(topo, fibcompare.ExpectedForNodes(topo, fibNodes), opts.FIBOptions)
		actualFIB, err := fibcompare.Collect(deadlineCtx, runner, fibNodes, opts.FIBOptions)
		if err != nil {
			return err
		}
		actualFIB = fibcompare.ComparableRoutes(topo, actualFIB, opts.FIBOptions)
		fibResult := fibcompare.Compare(expectedFIB, actualFIB)
		for _, line := range fibcompare.FormatDiffs(fibResult) {
			fmt.Fprintln(opts.Out, line)
		}
		if !fibResult.OK {
			return fmt.Errorf("live FIB comparison found diff(s)")
		}
		fmt.Fprintln(opts.Out, "live FIBs match modeled forwarding entries")
	}
	if err := RunDataplaneChecks(deadlineCtx, runner, topo, queries, opts.Out); err != nil {
		return err
	}
	return nil
}

func BuildLocalImages(ctx context.Context, runner ribcompare.Runner, topologyPath string, out io.Writer) error {
	root := filepath.Dir(topologyPath)
	dockerfile := filepath.Join(root, "images", "frr-nftables", "Dockerfile")
	if _, err := os.Stat(dockerfile); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	contextDir := filepath.Dir(dockerfile)
	if _, err := runner.Run(ctx, "docker", "image", "inspect", "hoyan-frr-nftables:10.6.1"); err == nil {
		if out != nil {
			fmt.Fprintln(out, "using existing hoyan-frr-nftables:10.6.1")
		}
		return nil
	}
	if out != nil {
		fmt.Fprintln(out, "building hoyan-frr-nftables:10.6.1")
	}
	if _, err := runner.Run(ctx, "docker", "build", "-t", "hoyan-frr-nftables:10.6.1", contextDir); err != nil {
		return fmt.Errorf("docker build hoyan-frr-nftables:10.6.1: %w", err)
	}
	return nil
}

func isZeroCompareOptions(opts ribcompare.BgpRibCompareOptions) bool {
	return reflect.DeepEqual(opts, ribcompare.BgpRibCompareOptions{})
}

func WaitForFRRContainers(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, interval time.Duration) error {
	return WaitForContainers(ctx, runner, nodes, interval)
}

func WaitForContainers(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, interval time.Duration) error {
	var lastErr error
	return poll(ctx, interval, func() (bool, error) {
		for _, n := range nodes {
			containerName := n.RuntimeName()
			out, err := runner.Run(ctx, "docker", "inspect", "-f", "{{.State.Running}}", containerName)
			if err != nil {
				lastErr = fmt.Errorf("docker inspect -f {{.State.Running}} %s: %w", containerName, err)
				return false, nil
			}
			if strings.TrimSpace(string(out)) != "true" {
				lastErr = fmt.Errorf("container %s is not running", containerName)
				return false, nil
			}
		}
		return true, nil
	}, func() error {
		if lastErr != nil {
			return fmt.Errorf("containers did not become ready: %w", lastErr)
		}
		return fmt.Errorf("containers did not become ready")
	})
}

func WaitForExpectedRoutes(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, expected []ribcompare.NormalizedBgpRoute, interval time.Duration, maxPolls int) ([]ribcompare.NormalizedBgpRoute, error) {
	var last []ribcompare.NormalizedBgpRoute
	var lastErr error
	bestSeen := 0
	polls := 0
	err := poll(ctx, interval, func() (bool, error) {
		polls++
		actual, err := ribcompare.CollectWithRunner(ctx, runner, nodes)
		if err != nil {
			lastErr = err
			if maxPolls > 0 && polls >= maxPolls {
				return false, convergenceError(lastErr, bestSeen, len(expected))
			}
			return false, nil
		}
		lastErr = nil
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

func WaitForMatchingRIBs(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, expected []ribcompare.NormalizedBgpRoute, interval time.Duration, maxPolls int, compareOptions ribcompare.BgpRibCompareOptions) ([]ribcompare.NormalizedBgpRoute, ribcompare.BgpRibCompareResult, error) {
	if isZeroCompareOptions(compareOptions) {
		compareOptions = ribcompare.DefaultBgpRibCompareOptions()
	}
	var last []ribcompare.NormalizedBgpRoute
	var lastResult ribcompare.BgpRibCompareResult
	var lastErr error
	bestSeen := 0
	bestDiffCount := -1
	polls := 0
	err := poll(ctx, interval, func() (bool, error) {
		polls++
		actual, err := ribcompare.CollectWithRunner(ctx, runner, nodes)
		if err != nil {
			lastErr = err
			if maxPolls > 0 && polls >= maxPolls {
				return false, ribMatchConvergenceError(lastErr, bestSeen, len(expected), bestDiffCount)
			}
			return false, nil
		}
		lastErr = nil
		last = actual
		if seen := CountExpectedRoutes(expected, actual); seen > bestSeen {
			bestSeen = seen
		}
		lastResult = ribcompare.CompareBgpRib(expected, actual, compareOptions)
		diffCount := countDiffs(lastResult)
		if bestDiffCount == -1 || diffCount < bestDiffCount {
			bestDiffCount = diffCount
		}
		if lastResult.OK {
			return true, nil
		}
		if maxPolls > 0 && polls >= maxPolls {
			return false, ribMatchConvergenceError(lastErr, bestSeen, len(expected), bestDiffCount)
		}
		return false, nil
	}, func() error {
		return ribMatchConvergenceError(lastErr, bestSeen, len(expected), bestDiffCount)
	})
	if err != nil {
		return last, lastResult, err
	}
	return last, lastResult, nil
}

func convergenceError(lastErr error, seen, total int) error {
	if lastErr != nil {
		return fmt.Errorf("expected BGP routes did not converge; last collection error: %w", lastErr)
	}
	return fmt.Errorf("expected BGP routes did not converge: saw %d/%d expected routes", seen, total)
}

func ribMatchConvergenceError(lastErr error, seen, total, bestDiffCount int) error {
	if lastErr != nil {
		return fmt.Errorf("BGP RIBs did not converge to modeled paths; last collection error: %w", lastErr)
	}
	if bestDiffCount < 0 {
		return fmt.Errorf("BGP RIBs did not converge to modeled paths: saw %d/%d expected routes", seen, total)
	}
	return fmt.Errorf("BGP RIBs did not converge to modeled paths: saw %d/%d expected routes, best diff count %d", seen, total, bestDiffCount)
}

func HasExpectedRoutes(expected []ribcompare.NormalizedBgpRoute, actual []ribcompare.NormalizedBgpRoute) bool {
	return CountExpectedRoutes(expected, actual) == len(expected)
}

func CountExpectedRoutes(expected []ribcompare.NormalizedBgpRoute, actual []ribcompare.NormalizedBgpRoute) int {
	seen := map[string]bool{}
	for _, route := range actual {
		seen[route.Node+"|"+route.NetworkInstance+"|"+route.AFI+"|"+route.Prefix] = true
	}
	count := 0
	for _, route := range expected {
		ni := route.NetworkInstance
		if ni == "" {
			ni = "default"
		}
		afi := route.AFI
		if afi == "" {
			afi = "ipv4"
		}
		if seen[route.Node+"|"+ni+"|"+afi+"|"+route.Prefix] {
			count++
		}
	}
	return count
}

func countDiffs(result ribcompare.BgpRibCompareResult) int {
	return len(result.MissingPrefixes) + len(result.UnexpectedPrefixes) + len(result.MissingPaths) + len(result.UnexpectedPaths) + len(result.Mismatched) + len(result.DuplicatePathConflicts)
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
