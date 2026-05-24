package ribcompare

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

type ExpectedRoute struct {
	Node     string
	Prefix   string
	NextHop  string
	NextHops []string
	ASPath   []uint32
}

type ActualRoute struct {
	Node    string
	Prefix  string
	NextHop string
	ASPath  []uint32
}

type Diff struct {
	Node     string
	Prefix   string
	Expected string
	Actual   string
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

func Expected(topo *model.Topology) []ExpectedRoute {
	return ExpectedWithFailureSet(topo, sim.NoFailures())
}

func ExpectedForNodes(topo *model.Topology, nodes []model.Node) []ExpectedRoute {
	return ExpectedForNodesWithFailureSet(topo, nodes, sim.NoFailures())
}

func ExpectedForNodesWithFailureSet(topo *model.Topology, nodes []model.Node, failures sim.FailureSet) []ExpectedRoute {
	allowed := map[string]bool{}
	for _, n := range nodes {
		allowed[n.Name] = true
	}
	return expected(topo, allowed, failures)
}

func ExpectedWithFailureSet(topo *model.Topology, failures sim.FailureSet) []ExpectedRoute {
	return expected(topo, nil, failures)
}

func expected(topo *model.Topology, allowed map[string]bool, failures sim.FailureSet) []ExpectedRoute {
	g := sim.NewGraph(topo)
	ctx := g.FailureContext(failures)
	var out []ExpectedRoute
	for _, n := range topo.Nodes {
		if allowed != nil && !allowed[n.Name] {
			continue
		}
		if ctx.NodeFailed(n.Name) {
			continue
		}
		decision := sim.BehaviorFor(n.Kind).DecisionProcess()
		for prefix, rib := range g.RIBTable(n.Name) {
			for i, route := range rib {
				if route.SelectedCond == nil || !route.SelectedCond.Eval(ctx) {
					continue
				}
				nextHops := []string{routeNextHopAddress(topo, n.Name, route)}
				for _, alt := range rib[i+1:] {
					if alt.Condition == nil || !alt.Condition.Eval(ctx) {
						continue
					}
					if decision.Equivalent(n, route, alt) {
						nextHops = appendUnique(nextHops, routeNextHopAddress(topo, n.Name, alt))
					}
				}
				out = append(out, ExpectedRoute{
					Node:     n.Name,
					Prefix:   prefix,
					NextHop:  nextHops[0],
					NextHops: nextHops,
					ASPath:   route.ASPath,
				})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node == out[j].Node {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].Node < out[j].Node
	})
	return out
}

func Compare(expected []ExpectedRoute, actual []ActualRoute) []Diff {
	exp := map[string]ExpectedRoute{}
	act := map[string]ActualRoute{}
	keys := map[string]bool{}
	for _, r := range expected {
		key := r.Node + "|" + r.Prefix
		exp[key] = r
		keys[key] = true
	}
	for _, r := range actual {
		key := r.Node + "|" + r.Prefix
		act[key] = r
	}
	var diffs []Diff
	for key := range keys {
		e, eok := exp[key]
		a, aok := act[key]
		parts := strings.Split(key, "|")
		switch {
		case !eok:
			continue
		case !aok:
			diffs = append(diffs, Diff{Node: parts[0], Prefix: parts[1], Expected: formatExpected(e), Actual: "missing"})
		case e.NextHop != "" && a.NextHop != "" && !containsString(expectedNextHops(e), a.NextHop):
			diffs = append(diffs, Diff{Node: parts[0], Prefix: parts[1], Expected: formatExpected(e), Actual: formatActual(a)})
		}
	}
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Node == diffs[j].Node {
			return diffs[i].Prefix < diffs[j].Prefix
		}
		return diffs[i].Node < diffs[j].Node
	})
	return diffs
}

func CollectFRR(nodes []model.Node) ([]ActualRoute, error) {
	return CollectFRRWithRunner(context.Background(), ExecRunner{}, nodes)
}

func CollectFRRWithRunner(ctx context.Context, runner Runner, nodes []model.Node) ([]ActualRoute, error) {
	var out []ActualRoute
	for _, n := range nodes {
		if n.Kind != "frr" {
			continue
		}
		data, err := runner.Run(ctx, "docker", "exec", n.Name, "vtysh", "-c", "show ip bgp json")
		if err != nil {
			return nil, fmt.Errorf("docker exec %s vtysh -c %q: %w", n.Name, "show ip bgp json", err)
		}
		routes, err := ParseFRR(n.Name, data)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

func FRRNodes(nodes []model.Node) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if n.Kind == "frr" {
			out = append(out, n)
		}
	}
	return out
}

func ParseFRR(node string, data []byte) ([]ActualRoute, error) {
	type routeEntry struct {
		Prefix   string `json:"prefix"`
		Valid    bool   `json:"valid"`
		Best     bool   `json:"bestpath"`
		Nexthops []struct {
			IP string `json:"ip"`
		} `json:"nexthops"`
		Path string `json:"path"`
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if payload, ok := raw["routes"]; ok {
		if err := json.Unmarshal(payload, &raw); err != nil {
			return nil, err
		}
	}
	var out []ActualRoute
	for prefix, payload := range raw {
		if !strings.Contains(prefix, "/") {
			continue
		}
		var routes []routeEntry
		if err := json.Unmarshal(payload, &routes); err != nil {
			continue
		}
		for _, r := range routes {
			if !r.Valid || !r.Best {
				continue
			}
			nextHop := ""
			if len(r.Nexthops) > 0 {
				nextHop = r.Nexthops[0].IP
				if nextHop == "0.0.0.0" {
					nextHop = ""
				}
			}
			out = append(out, ActualRoute{Node: node, Prefix: prefix, NextHop: nextHop})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node == out[j].Node {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].Node < out[j].Node
	})
	return out, nil
}

func formatExpected(r ExpectedRoute) string {
	if len(r.NextHops) > 1 {
		return "next-hop in [" + strings.Join(r.NextHops, ",") + "]"
	}
	return "next-hop=" + r.NextHop
}

func formatActual(r ActualRoute) string {
	return "next-hop=" + r.NextHop
}

func peerAddress(topo *model.Topology, node, peer string) string {
	if peer == "" {
		return ""
	}
	for _, l := range topo.Links {
		a, b := linkAddresses(l.Subnet)
		switch {
		case l.A == node && l.B == peer:
			return trimMask(b)
		case l.B == node && l.A == peer:
			return trimMask(a)
		}
	}
	return peer
}

func routeNextHopAddress(topo *model.Topology, node string, route sim.RIBEntry) string {
	if route.NextHop == "" {
		return ""
	}
	if direct := peerAddress(topo, node, route.NextHop); direct != route.NextHop {
		return direct
	}
	for i := 0; i+1 < len(route.Nodes); i++ {
		if route.Nodes[i] != route.NextHop {
			continue
		}
		if addr := peerAddress(topo, route.Nodes[i+1], route.NextHop); addr != route.NextHop {
			return addr
		}
	}
	return route.NextHop
}

func linkAddresses(raw string) (string, string) {
	parts := strings.Split(raw, "/")
	prefixLen := ""
	if len(parts) == 2 {
		prefixLen = "/" + parts[1]
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return raw, raw
	}
	last := 0
	fmt.Sscanf(octets[3], "%d", &last)
	a := parts[0] + prefixLen
	octets[3] = fmt.Sprint(last + 1)
	b := strings.Join(octets, ".") + prefixLen
	return a, b
}

func trimMask(addr string) string {
	return strings.Split(addr, "/")[0]
}

func expectedNextHops(r ExpectedRoute) []string {
	if len(r.NextHops) > 0 {
		return r.NextHops
	}
	return []string{r.NextHop}
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func appendUnique(xs []string, x string) []string {
	for _, existing := range xs {
		if existing == x {
			return xs
		}
	}
	return append(xs, x)
}
