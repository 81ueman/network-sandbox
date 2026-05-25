package livecheck

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

type RIBFailureScenario struct {
	Name        string
	Failures    sim.FailureSet
	ActiveNodes []model.Node
	Inject      func(context.Context, ribcompare.Runner) error
	Cleanup     func(context.Context, ribcompare.Runner) error
}

type RIBFailureCheckOptions struct {
	Interval       time.Duration
	MaxPolls       int
	CompareOptions ribcompare.BgpRibCompareOptions
	Out            io.Writer
}

func CompareRIBsWithFailures(ctx context.Context, runner ribcompare.Runner, topo *model.Topology, scenario RIBFailureScenario, opts RIBFailureCheckOptions) error {
	if opts.Interval == 0 {
		opts.Interval = 25 * time.Second
	}
	if opts.MaxPolls == 0 {
		opts.MaxPolls = 3
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	compareOptions := opts.CompareOptions
	if isZeroCompareOptions(compareOptions) {
		compareOptions = ribcompare.DefaultBgpRibCompareOptions()
	}
	activeNodes := scenario.ActiveNodes
	if activeNodes == nil {
		activeNodes = ribcompare.SupportedNodes(topo.Nodes)
	}
	expected := ribcompare.ExpectedForNodesWithFailureSet(topo, activeNodes, scenario.Failures)
	if scenario.Inject != nil {
		fmt.Fprintf(opts.Out, "injecting failure scenario %s\n", scenario.Name)
		if err := scenario.Inject(ctx, runner); err != nil {
			return err
		}
	}
	if scenario.Cleanup != nil {
		defer func() {
			_ = scenario.Cleanup(context.Background(), runner)
		}()
	}
	actual, diffs, err := WaitForMatchingRIBs(ctx, runner, activeNodes, expected, opts.Interval, opts.MaxPolls, compareOptions)
	if err != nil {
		printRIBDiffs(opts.Out, expected, actual, compareOptions)
		return err
	}
	printDiffs(opts.Out, diffs)
	if !diffs.OK {
		return fmt.Errorf("failure scenario %s found live BGP RIB diff(s)", scenario.Name)
	}
	fmt.Fprintf(opts.Out, "failure scenario %s live BGP RIBs match modeled paths\n", scenario.Name)
	return nil
}

func LinkFailureScenario(topo *model.Topology, linkName string) (RIBFailureScenario, error) {
	link, ok := findLink(topo, linkName)
	if !ok {
		return RIBFailureScenario{}, fmt.Errorf("link %s not found", linkName)
	}
	if link.AIntf == "" || link.BIntf == "" {
		return RIBFailureScenario{}, fmt.Errorf("link %s is missing endpoint interface names", linkName)
	}
	return RIBFailureScenario{
		Name:     "link-" + link.Name,
		Failures: sim.LinkFailures(model.LinkID(link.Name)),
		Inject: func(ctx context.Context, runner ribcompare.Runner) error {
			if _, err := runner.Run(ctx, "containerlab", "tools", "netem", "set", "--name", topo.Name, "-n", link.A, "-i", link.AIntf, "--loss", "100"); err != nil {
				return fmt.Errorf("netem set %s:%s: %w", link.A, link.AIntf, err)
			}
			if _, err := runner.Run(ctx, "containerlab", "tools", "netem", "set", "--name", topo.Name, "-n", link.B, "-i", link.BIntf, "--loss", "100"); err != nil {
				return fmt.Errorf("netem set %s:%s: %w", link.B, link.BIntf, err)
			}
			return nil
		},
		Cleanup: func(ctx context.Context, runner ribcompare.Runner) error {
			var firstErr error
			if _, err := runner.Run(ctx, "containerlab", "tools", "netem", "reset", "--name", topo.Name, "-n", link.A, "-i", link.AIntf); err != nil {
				firstErr = fmt.Errorf("netem reset %s:%s: %w", link.A, link.AIntf, err)
			}
			if _, err := runner.Run(ctx, "containerlab", "tools", "netem", "reset", "--name", topo.Name, "-n", link.B, "-i", link.BIntf); firstErr == nil && err != nil {
				firstErr = fmt.Errorf("netem reset %s:%s: %w", link.B, link.BIntf, err)
			}
			return firstErr
		},
	}, nil
}

func NodeFailureScenario(topo *model.Topology, nodeName string) (RIBFailureScenario, error) {
	node, ok := topo.Node(nodeName)
	if !ok {
		return RIBFailureScenario{}, fmt.Errorf("node %s not found", nodeName)
	}
	return RIBFailureScenario{
		Name:        "node-" + nodeName,
		Failures:    sim.NodeFailures(model.NodeID(nodeName)),
		ActiveNodes: activeSupportedNodes(topo.Nodes, map[string]bool{nodeName: true}),
		Inject: func(ctx context.Context, runner ribcompare.Runner) error {
			containerName := node.RuntimeName()
			if _, err := runner.Run(ctx, "docker", "stop", containerName); err != nil {
				return fmt.Errorf("docker stop %s: %w", containerName, err)
			}
			return nil
		},
	}, nil
}

func activeSupportedNodes(nodes []model.Node, failed map[string]bool) []model.Node {
	var out []model.Node
	for _, node := range nodes {
		if !failed[node.Name] {
			out = append(out, node)
		}
	}
	return ribcompare.SupportedNodes(out)
}

func findLink(topo *model.Topology, name string) (model.Link, bool) {
	for _, link := range topo.Links {
		if link.Name == name {
			return link, true
		}
	}
	return model.Link{}, false
}

func printRIBDiffs(out io.Writer, expected []ribcompare.NormalizedBgpRoute, actual []ribcompare.NormalizedBgpRoute, compareOptions ribcompare.BgpRibCompareOptions) {
	if out == nil {
		return
	}
	printDiffs(out, ribcompare.CompareBgpRib(expected, actual, compareOptions))
}

func printDiffs(out io.Writer, diffs ribcompare.BgpRibCompareResult) {
	if out == nil {
		return
	}
	for _, line := range ribcompare.FormatDiffs(diffs) {
		fmt.Fprintln(out, line)
	}
}
