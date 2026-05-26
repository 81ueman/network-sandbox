package fibcompare

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func Collect(ctx context.Context, runner Runner, nodes []model.Node, opts Options) ([]NormalizedFIBRoute, error) {
	var out []NormalizedFIBRoute
	unsupported := unsupportedNodes(nodes)
	if len(unsupported) > 0 && !opts.AllowUnsupported {
		return nil, UnsupportedNodesError{Nodes: unsupported}
	}
	frrNodes := nodesByKind(nodes, model.KindFRR)
	if len(frrNodes) > 0 {
		routes, err := frrCollector{}.Collect(ctx, runner, frrNodes)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	ceosNodes := nodesByKind(nodes, model.KindCEOS)
	if len(ceosNodes) > 0 {
		routes, err := ceosCollector{}.Collect(ctx, runner, ceosNodes)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	srlinuxNodes := nodesByKind(nodes, model.KindSRLinux)
	if len(srlinuxNodes) > 0 {
		routes, err := srlinuxCollector{}.Collect(ctx, runner, srlinuxNodes)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func SupportedNodes(nodes []model.Node) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if supportsLiveFIB(n.Kind) {
			out = append(out, n)
		}
	}
	return out
}

func unsupportedNodes(nodes []model.Node) []string {
	var out []string
	for _, n := range nodes {
		if !supportsLiveFIB(n.Kind) {
			out = append(out, n.Name+"("+string(n.Kind)+")")
		}
	}
	sort.Strings(out)
	return out
}

func nodesByKind(nodes []model.Node, kind model.DeviceKind) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

type frrCollector struct{}
type ceosCollector struct{}
type srlinuxCollector struct{}

func (frrCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedFIBRoute, error) {
	var out []NormalizedFIBRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "ip", "-j", "route", "show", "table", "main")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s ip -j route show table main: %w", containerName, err)
		}
		routes, err := ParseLinuxIPRoute(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s Linux kernel FIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (ceosCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedFIBRoute, error) {
	var out []NormalizedFIBRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "Cli", "-p", "15", "-c", "show ip route vrf default bgp | json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s Cli -p 15 -c %q: %w", containerName, "show ip route vrf default bgp | json", err)
		}
		routes, err := ParseCEOSRoutes(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s cEOS installed FIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (srlinuxCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedFIBRoute, error) {
	var out []NormalizedFIBRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		command := fmt.Sprintf("docker exec -it %s sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast summary", shellQuote(containerName))
		data, err := runner.Run(ctx, "script", "-q", "/dev/null", "-c", command)
		if err != nil {
			return nil, fmt.Errorf("docker exec -it %s sr_cli route-table ipv4-unicast summary: %w", containerName, err)
		}
		routes, err := ParseSRLinuxRoutes(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux installed FIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
