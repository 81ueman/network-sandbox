package dataplane

import (
	"net/netip"
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type SymbolicPacketState struct {
	Node             string
	IngressInterface string
	Packet           controlplane.PacketMessage
	Cond             failure.Cond
	Path             Path
}

type SymbolicFIBCandidate struct {
	Entry FIBEntry
	Cond  failure.Cond
}

type SymbolicPacketPath struct {
	Path   Path
	Cond   failure.Cond
	States []SymbolicPacketState
}

type SymbolicReachabilityResult struct {
	Reachable   failure.Cond
	Unreachable failure.Cond
	Paths       []SymbolicPacketPath
	Reason      string
}

type SymbolicRoutePath struct {
	Path Path
	Cond failure.Cond
}

type SymbolicRouteReachabilityResult struct {
	Reachable   failure.Cond
	Unreachable failure.Cond
	Paths       []SymbolicRoutePath
	Reason      string
}

func (e *Engine) SymbolicLookupFIB(node, dst string) []SymbolicFIBCandidate {
	ip, err := netip.ParseAddr(dst)
	if err != nil {
		return nil
	}
	entries := matchingFIBEntries(e.fib[node], ip)
	var out []SymbolicFIBCandidate
	var higher []failure.Cond
	for _, entry := range entries {
		entryCond := e.expandLinkVars(condOrTrue(entry.Condition))
		cond := entryCond
		if len(higher) > 0 {
			cond = failure.And(cond, failure.Not(failure.Or(higher...)))
		}
		out = append(out, SymbolicFIBCandidate{Entry: entry, Cond: cond})
		higher = append(higher, entryCond)
	}
	return out
}

func (e *Engine) SymbolicRouteReachability(from, prefix string) SymbolicRouteReachabilityResult {
	reachable := failure.False()
	result := SymbolicRouteReachabilityResult{Reachable: reachable, Unreachable: failure.True()}
	if e == nil || e.idx == nil {
		result.Reason = "topology index is unavailable"
		return result
	}
	pfx, err := model.ParsePrefix(prefix)
	if err != nil {
		result.Reason = "invalid prefix"
		return result
	}
	if _, ok := e.idx.Node(from); !ok {
		result.Reason = "source node not found"
		return result
	}
	routes := e.rib[from][pfx.String()]
	paths := make([]SymbolicRoutePath, 0, len(routes))
	conds := make([]failure.Cond, 0, len(routes))
	for _, route := range routes {
		route = route.Normalize()
		if route.SelectedCond == nil {
			continue
		}
		cond := failure.And(failure.NodeVar(from), e.expandLinkVars(route.SelectedCond))
		path := routePath(e.idx, route)
		paths = append(paths, SymbolicRoutePath{Path: path, Cond: cond})
		conds = append(conds, cond)
	}
	reachable = failure.Or(conds...)
	return SymbolicRouteReachabilityResult{
		Reachable:   reachable,
		Unreachable: failure.Not(reachable),
		Paths:       paths,
	}
}

func (e *Engine) SymbolicPacketReachability(from, to, protocol string) SymbolicReachabilityResult {
	reachable := failure.False()
	result := SymbolicReachabilityResult{Reachable: reachable, Unreachable: failure.True()}
	if e == nil || e.idx == nil {
		result.Reason = "topology index is unavailable"
		return result
	}
	dstNode, dstPrefix, ok := e.idx.OriginForIP(to)
	if !ok {
		result.Reason = "destination prefix not advertised"
		return result
	}
	if _, ok := e.idx.Node(from); !ok {
		result.Reason = "source node not found"
		return result
	}
	maxHops := len(e.idx.NodesByName)
	if maxHops == 0 {
		maxHops = len(e.fib) + 1
	}
	packet := controlplane.PacketMessage{Node: from, Prefix: dstPrefix.NetIP(), Protocol: protocol}
	initial := SymbolicPacketState{
		Node:   from,
		Packet: packet,
		Cond:   failure.And(failure.NodeVar(from), failure.NodeVar(dstNode)),
		Path:   Path{Nodes: []string{from}},
	}
	var paths []SymbolicPacketPath
	e.symbolicForward(initial, to, dstPrefix.NetIP(), maxHops, map[string]bool{}, nil, &paths)
	conds := make([]failure.Cond, 0, len(paths))
	for _, path := range paths {
		conds = append(conds, path.Cond)
	}
	reachable = failure.Or(conds...)
	return SymbolicReachabilityResult{
		Reachable:   reachable,
		Unreachable: failure.Not(reachable),
		Paths:       paths,
	}
}

func routePath(idx *model.TopologyIndex, route controlplane.RIBEntry) Path {
	route = route.Normalize()
	nodes := append([]string(nil), route.Nodes...)
	links := append([]string(nil), route.Links...)
	reverse(nodes)
	reverse(links)
	return Path{Nodes: nodes, Links: links, Cost: idx.PathCost(route.Links)}
}

func (e *Engine) symbolicForward(state SymbolicPacketState, dst string, dstPrefix netip.Prefix, maxHops int, visited map[string]bool, states []SymbolicPacketState, paths *[]SymbolicPacketPath) {
	if isFalseCond(state.Cond) {
		return
	}
	if visited[state.Node] {
		return
	}
	states = append(states, state)
	if e.originates(state.Node, dstPrefix) {
		*paths = append(*paths, SymbolicPacketPath{Path: state.Path, Cond: condOrTrue(state.Cond), States: append([]SymbolicPacketState(nil), states...)})
		return
	}
	if len(state.Path.Nodes) > maxHops {
		return
	}
	currentNode, ok := e.idx.Node(state.Node)
	if !ok {
		return
	}
	packet := state.Packet
	packet.Node = state.Node
	packet.IngressInterface = state.IngressInterface
	if _, denied := controlplane.BehaviorFor(currentNode.Kind).CheckDataIngress(currentNode, packet, e.idx.Topology.Policies); denied {
		return
	}
	nextVisited := copyVisited(visited)
	nextVisited[state.Node] = true
	candidates := e.SymbolicLookupFIB(state.Node, dst)
	for _, candidate := range candidates {
		entry := candidate.Entry
		if entry.NextHop == "" {
			continue
		}
		link, ok := e.idx.LinkBetween(state.Node, entry.NextHop)
		if !ok {
			continue
		}
		packet.EgressInterface = ingressInterface(link, state.Node)
		if _, ok := controlplane.BehaviorFor(currentNode.Kind).CheckDataEgress(currentNode, packet, e.idx.Topology.Policies); ok {
			continue
		}
		nextCond := failure.And(
			state.Cond,
			candidate.Cond,
			e.linkUpCond(link),
		)
		nextPath := Path{
			Nodes: append(append([]string(nil), state.Path.Nodes...), entry.NextHop),
			Links: append(append([]string(nil), state.Path.Links...), link.Name),
			Cost:  state.Path.Cost + link.Cost,
		}
		nextState := SymbolicPacketState{
			Node:             entry.NextHop,
			IngressInterface: ingressInterface(link, entry.NextHop),
			Packet:           packet,
			Cond:             nextCond,
			Path:             nextPath,
		}
		e.symbolicForward(nextState, dst, dstPrefix, maxHops, nextVisited, states, paths)
	}
}

func matchingFIBEntries(entries []FIBEntry, ip netip.Addr) []FIBEntry {
	var out []FIBEntry
	for _, entry := range entries {
		if entry.Prefix.Contains(ip) {
			out = append(out, entry)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Prefix.Bits() == out[j].Prefix.Bits() {
			return false
		}
		return out[i].Prefix.Bits() > out[j].Prefix.Bits()
	})
	return out
}

func condOrTrue(cond failure.Cond) failure.Cond {
	if cond == nil {
		return failure.True()
	}
	return cond
}

func (e *Engine) expandLinkVars(cond failure.Cond) failure.Cond {
	if e == nil || e.idx == nil {
		return cond
	}
	return failure.ExpandLinkVars(cond, e.idx.LinksByName)
}

func (e *Engine) linkUpCond(link model.Link) failure.Cond {
	return e.expandLinkVars(failure.LinkVar(link.Name))
}

func isFalseCond(cond failure.Cond) bool {
	return cond != nil && cond.Key() == failure.False().Key()
}

func copyVisited(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func ingressInterface(link model.Link, node string) string {
	switch node {
	case link.A:
		return link.AIntf
	case link.B:
		return link.BIntf
	default:
		return ""
	}
}
