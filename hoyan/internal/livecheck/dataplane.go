package livecheck

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

func RunDataplaneChecks(ctx context.Context, runner ribcompare.Runner, topo *model.Topology, queries *model.Queries, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	if queries == nil || len(queries.PacketChecks) == 0 {
		return nil
	}
	graph := sim.NewGraph(topo)
	for _, check := range queries.PacketChecks {
		if check.MaxFailures != 0 {
			continue
		}
		if check.LiveProbe != nil && !*check.LiveProbe {
			fmt.Fprintf(out, "[dataplane] %s skipped live probe\n", check.Name)
			continue
		}
		expected := true
		if check.ExpectReachable != nil {
			expected = *check.ExpectReachable
		}
		spec := model.PacketSpec{Protocol: check.Protocol, DstPort: model.ExactPort(check.DstPort)}
		_, modeled, reason := graph.PacketReachableSpec(check.From, check.To, spec, failure.None())
		live, err := runPacketProbe(ctx, runner, topo, check)
		if err != nil {
			return fmt.Errorf("%s live dataplane probe: %w", check.Name, err)
		}
		fmt.Fprintf(out, "[dataplane] %s live=%v modeled=%v expected=%v\n", check.Name, live, modeled, expected)
		if reason != "" {
			fmt.Fprintf(out, "  modeled reason: %s\n", reason)
		}
		if live != expected {
			return fmt.Errorf("%s live dataplane reachable=%v expected=%v", check.Name, live, expected)
		}
		if live != modeled {
			return fmt.Errorf("%s live dataplane reachable=%v modeled=%v", check.Name, live, modeled)
		}
	}
	return nil
}

func runPacketProbe(ctx context.Context, runner ribcompare.Runner, topo *model.Topology, check model.PacketCheck) (bool, error) {
	src, ok := topo.Node(check.From)
	if !ok {
		return false, fmt.Errorf("source node %s not found", check.From)
	}
	switch strings.ToLower(check.Protocol) {
	case "icmp":
		out, err := runDockerExecTTY(ctx, runner, src.RuntimeName(), "ping", "-c", "3", "-W", "1", check.To)
		if err != nil {
			return false, err
		}
		return pingSucceeded(string(out)), nil
	case "tcp":
		if check.DstPort <= 0 {
			return false, fmt.Errorf("tcp packet check requires dst_port")
		}
		if err := ensureTCPListener(ctx, runner, topo, check.To, check.DstPort); err != nil {
			return false, err
		}
		out, err := runDockerExecTTY(ctx, runner, src.RuntimeName(), "nc", "-z", "-v", "-w", "2", check.To, strconv.Itoa(check.DstPort))
		if err != nil {
			return false, err
		}
		return tcpConnectSucceeded(string(out)), nil
	default:
		return false, fmt.Errorf("unsupported live packet protocol %q", check.Protocol)
	}
}

func runDockerExecTTY(ctx context.Context, runner ribcompare.Runner, container string, args ...string) ([]byte, error) {
	cmd := "docker exec -it " + shellQuote(container)
	for _, arg := range args {
		cmd += " " + shellQuote(arg)
	}
	return runner.Run(ctx, "script", "-q", "/dev/null", "-c", cmd)
}

func pingSucceeded(out string) bool {
	out = strings.ReplaceAll(out, "\x00", "")
	return strings.Contains(out, " 0% packet loss") || strings.Contains(out, "0% packet loss") || strings.Contains(out, " 3 packets received")
}

func tcpConnectSucceeded(out string) bool {
	out = strings.ReplaceAll(out, "\x00", "")
	return strings.Contains(out, " open") || strings.Contains(out, "succeeded") || strings.Contains(out, "Connected")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func ensureTCPListener(ctx context.Context, runner ribcompare.Runner, topo *model.Topology, dst string, port int) error {
	dstNode, _, ok := topo.OriginForIP(dst)
	if !ok {
		return fmt.Errorf("destination %s is not originated by any node", dst)
	}
	node, ok := topo.Node(dstNode)
	if !ok {
		return fmt.Errorf("destination node %s not found", dstNode)
	}
	portText := strconv.Itoa(port)
	script := "command -v nc >/dev/null || exit 127; " +
		"pkill -f 'nc -l -p " + portText + "' >/dev/null 2>&1 || true; " +
		"while true; do nc -l -p " + portText + " >/dev/null 2>&1; done"
	if _, err := runner.Run(ctx, "docker", "exec", "-d", node.RuntimeName(), "sh", "-lc", script); err != nil {
		return fmt.Errorf("start tcp listener on %s port %s: %w", node.Name, portText, err)
	}
	return nil
}
