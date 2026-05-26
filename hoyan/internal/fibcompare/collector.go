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
		for _, table := range []string{"main", "local"} {
			data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "ip", "-j", "route", "show", "table", table)
			if err != nil {
				return nil, fmt.Errorf("docker exec -i %s ip -j route show table %s: %w", containerName, table, err)
			}
			routes, err := ParseLinuxIPRoute(n.Name, data)
			if err != nil {
				return nil, fmt.Errorf("%s Linux kernel FIB table %s: %w", n.Name, table, err)
			}
			out = append(out, routes...)
		}
	}
	sortRoutes(out)
	return out, nil
}

func (ceosCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedFIBRoute, error) {
	var out []NormalizedFIBRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "Cli", "-p", "15", "-c", "show ip route vrf default | json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s Cli -p 15 -c %q: %w", containerName, "show ip route vrf default | json", err)
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
		data, err := runSRLinuxFIBJSON(ctx, runner, containerName, "show", "network-instance", "default", "route-table", "ipv4-unicast", "summary")
		if err != nil {
			return nil, fmt.Errorf("%s sr_cli route-table ipv4-unicast summary: %w", containerName, err)
		}
		routes, err := ParseSRLinuxRoutes(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux installed FIB: %w", n.Name, err)
		}
		for i := range routes {
			if !srlinuxNeedsRouteDetail(routes[i]) {
				continue
			}
			detail, err := runSRLinuxFIBJSON(ctx, runner, containerName, "show", "network-instance", "default", "route-table", "ipv4-unicast", "prefix", routes[i].Prefix, "detail")
			if err != nil {
				return nil, fmt.Errorf("%s sr_cli route-table ipv4-unicast prefix %s detail: %w", containerName, routes[i].Prefix, err)
			}
			detailRoutes, err := ParseSRLinuxRouteDetails(n.Name, detail)
			if err != nil {
				return nil, fmt.Errorf("%s SR Linux installed FIB prefix %s detail: %w", n.Name, routes[i].Prefix, err)
			}
			if detailRoute, ok := srlinuxRouteDetailFor(routes[i], detailRoutes); ok && len(detailRoute.NextHops) > 0 {
				routes[i].NextHops = detailRoute.NextHops
			}
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func runSRLinuxFIBJSON(ctx context.Context, runner Runner, containerName string, showArgs ...string) ([]byte, error) {
	args := append([]string{"exec", "-i", containerName, "sr_cli", "--output-format", "json", "--pagination", "off", "--"}, showArgs...)
	data, err := runner.Run(ctx, "docker", args...)
	if err == nil {
		if _, payloadErr := jsonPayload(data); payloadErr == nil {
			return data, nil
		}
	}
	command := "docker exec -it " + shellQuote(containerName) + " sr_cli --output-format json --pagination off -- " + shellJoin(showArgs)
	data, ttyErr := runner.Run(ctx, "script", "-q", "/dev/null", "-c", command)
	if ttyErr != nil {
		if err != nil {
			return nil, fmt.Errorf("docker exec -i/it %s sr_cli %s: %w", containerName, strings.Join(showArgs, " "), ttyErr)
		}
		return nil, fmt.Errorf("docker exec -it %s sr_cli %s: %w", containerName, strings.Join(showArgs, " "), ttyErr)
	}
	return data, nil
}

func srlinuxNeedsRouteDetail(route NormalizedFIBRoute) bool {
	switch canonicalProtocol(route.Protocol) {
	case "bgp", "static":
		return true
	default:
		return false
	}
}

func srlinuxRouteDetailFor(summary NormalizedFIBRoute, details []NormalizedFIBRoute) (NormalizedFIBRoute, bool) {
	for _, detail := range details {
		if detail.Node == summary.Node && detail.VRF == summary.VRF && detail.AFI == summary.AFI && detail.Prefix == summary.Prefix && canonicalProtocol(detail.Protocol) == canonicalProtocol(summary.Protocol) {
			return detail, true
		}
	}
	return NormalizedFIBRoute{}, false
}

func shellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
