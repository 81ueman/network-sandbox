package ribcompare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

const srlinuxJSONMaxAttempts = 3

var srlinuxJSONRetryDelay = 250 * time.Millisecond

func Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	out, err := collectBGP(ctx, runner, nodes)
	if err != nil {
		return nil, err
	}
	nonBGP, err := collectNonBGPRoutes(ctx, runner, nodes)
	if err != nil {
		return nil, err
	}
	out = append(out, nonBGP...)
	sortRoutes(out)
	return out, nil
}

func CollectBGPOnlyWithRunner(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return collectBGP(ctx, runner, nodes)
}

func collectBGP(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
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

func collectorsByKind() map[model.DeviceKind]Collector {
	return map[model.DeviceKind]Collector{
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

func collectNonBGPRoutes(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	collectors := collectorsByKind()
	for _, kind := range []model.DeviceKind{model.KindFRR, model.KindCEOS, model.KindSRLinux} {
		collector := collectors[kind]
		selected := NodesByKind(nodes, kind)
		if len(selected) == 0 {
			continue
		}
		routes, err := collector.CollectRouteTables(ctx, runner, selected)
		if err != nil {
			return nil, err
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
		summary, err := RunSRLinuxJSON(ctx, runner, containerName, "show", "network-instance", "default", "protocols", "bgp", "routes", "ipv4", "summary")
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux BGP RIB summary collection: %w", n.Name, err)
		}
		prefixes, err := ParseSRLinuxSummary(summary)
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux BGP RIB summary: %w", n.Name, err)
		}
		for _, prefix := range prefixes {
			detail, err := RunSRLinuxJSON(ctx, runner, containerName, "show", "network-instance", "default", "protocols", "bgp", "routes", "ipv4", "prefix", prefix, "detail")
			if err != nil {
				return nil, fmt.Errorf("%s SR Linux BGP RIB prefix %s detail collection: %w", n.Name, prefix, err)
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

func RunSRLinuxJSON(ctx context.Context, runner Runner, containerName string, showArgs ...string) ([]byte, error) {
	args := append([]string{"exec", "-i", containerName, "sr_cli", "--output-format", "json", "--pagination", "off", "--"}, showArgs...)
	var last []byte
	for attempt := 1; attempt <= srlinuxJSONMaxAttempts; attempt++ {
		data, err := runner.Run(ctx, "docker", args...)
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s sr_cli %s: %w", containerName, strings.Join(showArgs, " "), err)
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) > 0 && json.Valid(trimmed) {
			return data, nil
		}
		last = data
		if attempt < srlinuxJSONMaxAttempts {
			if err := sleepContext(ctx, srlinuxJSONRetryDelay); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("docker exec -i %s sr_cli %s returned malformed JSON after %d attempts: bytes=%d preview=%q", containerName, strings.Join(showArgs, " "), srlinuxJSONMaxAttempts, len(last), previewBytes(last, 160))
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func previewBytes(data []byte, limit int) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) <= limit {
		return string(trimmed)
	}
	return string(trimmed[:limit]) + "..."
}
