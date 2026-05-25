package dataplane

import (
	"net/netip"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func (e *Engine) RouteReachable(from, prefix string, failures failure.Set) (Path, bool) {
	pfx, err := model.ParsePrefix(prefix)
	if err != nil {
		return Path{}, false
	}
	ctx := e.FailureContext(failures)
	if ctx.NodeFailed(model.NodeID(from)) {
		return Path{}, false
	}
	var best *controlplane.RIBEntry
	for _, r := range e.rib[from][pfx.String()] {
		if r.SelectedCond != nil && r.SelectedCond.Eval(ctx) {
			cp := r
			best = &cp
			break
		}
	}
	if best == nil {
		return Path{}, false
	}
	nodes := append([]string(nil), best.Nodes...)
	links := append([]string(nil), best.Links...)
	reverse(nodes)
	reverse(links)
	return Path{Nodes: nodes, Links: links, Cost: e.idx.PathCost(best.Links)}, true
}

func (e *Engine) PacketReachable(from, to, protocol string, failures failure.Set) (Path, bool, string) {
	ctx := e.FailureContext(failures)
	dstNode, dstPrefix, ok := e.idx.OriginForIP(to)
	if !ok {
		return Path{}, false, "destination prefix not advertised"
	}
	if ctx.NodeFailed(model.NodeID(from)) {
		return Path{}, false, "source node is down"
	}
	if ctx.NodeFailed(model.NodeID(dstNode)) {
		return Path{}, false, "destination node is down"
	}
	current := from
	visited := map[string]bool{}
	full := Path{Nodes: []string{from}}
	for {
		if ctx.NodeFailed(model.NodeID(current)) {
			return full, false, "current node is down"
		}
		if visited[current] {
			return full, false, "forwarding loop"
		}
		visited[current] = true
		if e.originates(current, dstPrefix.NetIP()) {
			return full, true, ""
		}
		currentNode, _ := e.idx.Node(current)
		if pol, ok := controlplane.BehaviorFor(currentNode.Kind).CheckDataIngress(currentNode, controlplane.PacketMessage{Node: current, Prefix: dstPrefix.NetIP(), Protocol: protocol}, e.idx.Topology.Policies); ok {
			return full, false, "denied by policy " + pol
		}
		rule, ok := e.LookupFIB(current, to, ctx)
		if !ok {
			return full, false, "no forwarding route"
		}
		if pol, ok := controlplane.BehaviorFor(currentNode.Kind).CheckDataEgress(currentNode, controlplane.PacketMessage{Node: current, Prefix: dstPrefix.NetIP(), Protocol: protocol}, e.idx.Topology.Policies); ok {
			return full, false, "denied by policy " + pol
		}
		if rule.NextHop == "" {
			return full, false, "selected route has no next-hop"
		}
		if ctx.NodeFailed(model.NodeID(rule.NextHop)) {
			return full, false, "next-hop node is down"
		}
		link, ok := e.idx.LinkBetween(current, rule.NextHop)
		if !ok || ctx.LinkFailed(model.LinkID(link.Name)) {
			return full, false, "next-hop link is down"
		}
		full.Links = append(full.Links, link.Name)
		full.Nodes = append(full.Nodes, rule.NextHop)
		full.Cost += link.Cost
		current = rule.NextHop
	}
}

func (e *Engine) FailureContext(failures failure.Set) failure.Context {
	if failures.Links == nil {
		failures.Links = map[model.LinkID]bool{}
	}
	if failures.Nodes == nil {
		failures.Nodes = map[model.NodeID]bool{}
	}
	return failure.Context{Failures: failures, LinksByName: e.idx.LinksByName}
}

func (e *Engine) originates(node string, prefix netip.Prefix) bool {
	n, ok := e.idx.Node(node)
	if !ok {
		return false
	}
	for _, raw := range n.Prefixes {
		if raw.NetIP() == prefix {
			return true
		}
	}
	return false
}

func reverse[T any](xs []T) {
	for i, j := 0, len(xs)-1; i < j; i, j = i+1, j-1 {
		xs[i], xs[j] = xs[j], xs[i]
	}
}
