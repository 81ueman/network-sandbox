package ribcompare

import (
	"context"
	"fmt"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	collectors := collectorsByKind()
	for _, kind := range []model.DeviceKind{model.KindFRR, model.KindCEOS, model.KindSRLinux} {
		collector := collectors[kind]
		selected := NodesByKind(nodes, kind)
		if len(selected) == 0 {
			continue
		}
		routes, err := collector.Collect(ctx, runner, selected)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func CollectWithRunner(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return Collect(ctx, runner, nodes)
}

func CollectFRR(nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return CollectFRRWithRunner(context.Background(), ExecRunner{}, nodes)
}

func CollectFRRWithRunner(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return frrCollector{}.Collect(ctx, runner, nodes)
}

func SupportedNodes(nodes []model.Node) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if _, ok := collectorsByKind()[n.Kind]; ok {
			out = append(out, n)
		}
	}
	return out
}

func FRRNodes(nodes []model.Node) []model.Node {
	return NodesByKind(nodes, model.KindFRR)
}

func NodesByKind(nodes []model.Node, kind model.DeviceKind) []model.Node {
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

func collectorsByKind() map[model.DeviceKind]BgpRibCollector {
	return map[model.DeviceKind]BgpRibCollector{
		model.KindFRR:     frrCollector{},
		model.KindCEOS:    ceosCollector{},
		model.KindSRLinux: srlinuxCollector{},
	}
}

func (frrCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "vtysh", "-c", "show ip bgp json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s vtysh -c %q: %w", containerName, "show ip bgp json", err)
		}
		routes, err := ParseFRR(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s FRR BGP RIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (ceosCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "Cli", "-p", "15", "-c", "show ip bgp | json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s Cli -p 15 -c %q: %w", containerName, "show ip bgp | json", err)
		}
		routes, err := ParseCEOS(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s cEOS BGP RIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (srlinuxCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		summary, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "sr_cli", "--output-format", "json", "--pagination", "off", "--", "show", "network-instance", "default", "protocols", "bgp", "routes", "ipv4", "summary")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s sr_cli BGP ipv4 summary: %w", containerName, err)
		}
		prefixes, err := ParseSRLinuxSummary(summary)
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux BGP RIB summary: %w", n.Name, err)
		}
		for _, prefix := range prefixes {
			detail, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "sr_cli", "--output-format", "json", "--pagination", "off", "--", "show", "network-instance", "default", "protocols", "bgp", "routes", "ipv4", "prefix", prefix, "detail")
			if err != nil {
				return nil, fmt.Errorf("docker exec -i %s sr_cli BGP ipv4 prefix %s detail: %w", containerName, prefix, err)
			}
			routes, err := ParseSRLinuxDetail(n.Name, prefix, detail)
			if err != nil {
				return nil, fmt.Errorf("%s SR Linux BGP RIB prefix %s detail: %w", n.Name, prefix, err)
			}
			out = append(out, routes...)
		}
	}
	sortRoutes(out)
	return out, nil
}
