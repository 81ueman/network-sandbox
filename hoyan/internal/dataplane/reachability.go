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
		r = r.Normalize()
		if r.SelectedCond != nil && r.SelectedCond.Eval(ctx) {
			cp := r
			best = &cp
			break
		}
	}
	if best == nil {
		return Path{}, false
	}
	return routePath(e.idx, *best), true
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
	return e.packetReachableFrom(packetReachableState{
		current:   from,
		to:        to,
		protocol:  protocol,
		dstPrefix: dstPrefix.NetIP(),
		ctx:       ctx,
		visited:   map[string]bool{},
		full:      Path{Nodes: []string{from}},
	})
}

type packetReachableState struct {
	current          string
	to               string
	protocol         string
	dstPrefix        netip.Prefix
	ingressInterface string
	ctx              failure.Context
	visited          map[string]bool
	full             Path
}

func (e *Engine) packetReachableFrom(state packetReachableState) (Path, bool, string) {
	if state.ctx.NodeFailed(model.NodeID(state.current)) {
		return state.full, false, "current node is down"
	}
	if state.visited[state.current] {
		return state.full, false, "forwarding loop"
	}
	if e.originates(state.current, state.dstPrefix) {
		return state.full, true, ""
	}
	currentNode, _ := e.idx.Node(state.current)
	packet := controlplane.PacketMessage{Node: state.current, Prefix: state.dstPrefix, Protocol: state.protocol, IngressInterface: state.ingressInterface}
	if pol, ok := controlplane.BehaviorFor(currentNode.Kind).CheckDataIngress(currentNode, packet, e.idx.Topology.Policies); ok {
		return state.full, false, "denied by policy " + pol
	}
	candidates := e.SymbolicLookupFIB(state.current, state.to)
	if len(candidates) == 0 {
		return state.full, false, "no forwarding route"
	}
	nextVisited := copyVisited(state.visited)
	nextVisited[state.current] = true
	var firstReason string
	for _, candidate := range candidates {
		if !candidate.Cond.Eval(state.ctx) {
			continue
		}
		rule := candidate.Entry
		nextFull, ok, reason := e.tryPacketCandidate(state, nextVisited, packet, currentNode, rule)
		if ok {
			return nextFull, true, ""
		}
		if firstReason == "" {
			firstReason = reason
		}
	}
	if firstReason == "" {
		return state.full, false, "no forwarding route"
	}
	return state.full, false, firstReason
}

func (e *Engine) tryPacketCandidate(state packetReachableState, nextVisited map[string]bool, packet controlplane.PacketMessage, currentNode model.Node, rule FIBEntry) (Path, bool, string) {
	if rule.NextHop == "" {
		return state.full, false, "selected route has no next-hop"
	}
	if state.ctx.NodeFailed(model.NodeID(rule.NextHop)) {
		return state.full, false, "next-hop node is down"
	}
	link, ok := e.idx.LinkBetween(state.current, rule.NextHop)
	if !ok || state.ctx.LinkFailed(model.LinkID(link.Name)) {
		return state.full, false, "next-hop link is down"
	}
	packet.EgressInterface = interfaceOnLink(link, state.current)
	if pol, ok := controlplane.BehaviorFor(currentNode.Kind).CheckDataEgress(currentNode, packet, e.idx.Topology.Policies); ok {
		return state.full, false, "denied by policy " + pol
	}
	nextFull := Path{
		Nodes: append(append([]string(nil), state.full.Nodes...), rule.NextHop),
		Links: append(append([]string(nil), state.full.Links...), link.Name),
		Cost:  state.full.Cost + link.Cost,
	}
	return e.packetReachableFrom(packetReachableState{
		current:          rule.NextHop,
		to:               state.to,
		protocol:         state.protocol,
		dstPrefix:        state.dstPrefix,
		ingressInterface: interfaceOnLink(link, rule.NextHop),
		ctx:              state.ctx,
		visited:          nextVisited,
		full:             nextFull,
	})
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

func (e *Engine) originatesPrefixSet(node string, dst model.PrefixSet) bool {
	n, ok := e.idx.Node(node)
	if !ok || dst == nil {
		return false
	}
	for _, raw := range n.Prefixes {
		if !raw.IsZero() && (model.ExactPrefixSet{Prefix: raw}).Overlaps(dst) {
			return true
		}
	}
	return false
}

func (e *Engine) hasOriginForPrefixSet(dst model.PrefixSet) bool {
	if e == nil || e.idx == nil || dst == nil {
		return false
	}
	for _, node := range e.idx.NodesByName {
		for _, raw := range node.Prefixes {
			if !raw.IsZero() && (model.ExactPrefixSet{Prefix: raw}).Overlaps(dst) {
				return true
			}
		}
	}
	return false
}

func reverse[T any](xs []T) {
	for i, j := 0, len(xs)-1; i < j; i, j = i+1, j-1 {
		xs[i], xs[j] = xs[j], xs[i]
	}
}

func interfaceOnLink(link model.Link, node string) string {
	switch node {
	case link.A:
		return link.AIntf
	case link.B:
		return link.BIntf
	default:
		return ""
	}
}
