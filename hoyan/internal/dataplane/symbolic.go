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

type SymbolicPacketBlockedPath struct {
	Path      Path
	Cond      failure.Cond
	Reason    string
	Policy    string
	Node      string
	Interface string
	Stage     string
	Source    model.PolicySource
}

type SymbolicUnreachableReasonKind string

const (
	UnreachableNoRoute                  SymbolicUnreachableReasonKind = "no_route"
	UnreachableNoNextHop                SymbolicUnreachableReasonKind = "no_next_hop"
	UnreachableNodeFailed               SymbolicUnreachableReasonKind = "node_failed"
	UnreachableLinkFailed               SymbolicUnreachableReasonKind = "link_failed"
	UnreachableIngressPolicy            SymbolicUnreachableReasonKind = "ingress_policy"
	UnreachableEgressPolicy             SymbolicUnreachableReasonKind = "egress_policy"
	UnreachableLoop                     SymbolicUnreachableReasonKind = "loop"
	UnreachableDestinationNotAdvertised SymbolicUnreachableReasonKind = "destination_not_advertised"
)

type SymbolicUnreachableReason struct {
	Kind       SymbolicUnreachableReasonKind
	Node       string
	Link       string
	Interface  string
	PolicyName string
	PolicyRaw  string
	Path       Path
	Cond       failure.Cond
	Message    string
}

type SymbolicReachabilityResult struct {
	Reachable          failure.Cond
	Unreachable        failure.Cond
	Paths              []SymbolicPacketPath
	Blocked            []SymbolicPacketBlockedPath
	UnreachableReasons []SymbolicUnreachableReason
	Reason             string
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
	return e.symbolicLookupFIBEntries(entries)
}

func (e *Engine) SymbolicLookupFIBForPrefixSet(node string, dst model.PrefixSet) []SymbolicFIBCandidate {
	entries := matchingFIBEntriesForPrefixSet(e.fib[node], dst)
	return e.symbolicLookupFIBEntries(entries)
}

func (e *Engine) symbolicLookupFIBEntries(entries []FIBEntry) []SymbolicFIBCandidate {
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
		result.UnreachableReasons = []SymbolicUnreachableReason{{
			Kind:    UnreachableDestinationNotAdvertised,
			Cond:    failure.True(),
			Message: result.Reason,
		}}
		return result
	}
	if _, ok := e.idx.Node(from); !ok {
		result.Reason = "source node not found"
		return result
	}
	dstSet := model.ExactPrefixSet{Prefix: dstPrefix}
	return e.symbolicPacketReachabilityForPrefixSet(from, dstSet, dstPrefix.NetIP(), protocol, failure.And(failure.NodeVar(from), failure.NodeVar(dstNode)))
}

func (e *Engine) SymbolicPacketReachabilityForPrefixSet(from string, dst model.PrefixSet, protocol string) SymbolicReachabilityResult {
	result := SymbolicReachabilityResult{Reachable: failure.False(), Unreachable: failure.True()}
	if e == nil || e.idx == nil {
		result.Reason = "topology index is unavailable"
		return result
	}
	if dst == nil {
		result.Reason = "destination prefix set is empty"
		return result
	}
	if _, ok := e.idx.Node(from); !ok {
		result.Reason = "source node not found"
		return result
	}
	rep, ok := representativePrefixForSet(dst)
	if !ok {
		result.Reason = "destination prefix set is unsupported"
		return result
	}
	if !e.hasOriginForPrefixSet(dst) {
		result.Reason = "destination prefix not advertised"
		return result
	}
	return e.symbolicPacketReachabilityForPrefixSet(from, dst, rep.NetIP(), protocol, failure.NodeVar(from))
}

func (e *Engine) SymbolicPacketReachabilityForClass(from string, universe model.PrefixUniverse, classID model.PrefixClassID, protocol string) SymbolicReachabilityResult {
	for _, class := range universe.Classes {
		if class.ID == classID {
			return e.SymbolicPacketReachabilityForPrefixSet(from, class.Space, protocol)
		}
	}
	return SymbolicReachabilityResult{
		Reachable:   failure.False(),
		Unreachable: failure.True(),
		Reason:      "prefix class not found",
	}
}

func (e *Engine) symbolicPacketReachabilityForPrefixSet(from string, dst model.PrefixSet, packetPrefix netip.Prefix, protocol string, initialCond failure.Cond) SymbolicReachabilityResult {
	maxHops := len(e.idx.NodesByName)
	if maxHops == 0 {
		maxHops = len(e.fib) + 1
	}
	packet := controlplane.PacketMessage{Node: from, Prefix: packetPrefix, DstSet: dst, Protocol: protocol}
	var reasons []SymbolicUnreachableReason
	addUnreachableReason(&reasons, SymbolicUnreachableReason{
		Kind:    UnreachableNodeFailed,
		Node:    from,
		Cond:    failure.Not(failure.NodeVar(from)),
		Path:    Path{Nodes: []string{from}},
		Message: "source node is down",
	})
	for _, dstNode := range e.originNodesForPrefixSet(dst) {
		if dstNode == from {
			continue
		}
		addUnreachableReason(&reasons, SymbolicUnreachableReason{
			Kind:    UnreachableNodeFailed,
			Node:    dstNode,
			Cond:    failure.Not(failure.NodeVar(dstNode)),
			Path:    Path{Nodes: []string{from}},
			Message: "destination node is down",
		})
	}
	initial := SymbolicPacketState{
		Node:   from,
		Packet: packet,
		Cond:   initialCond,
		Path:   Path{Nodes: []string{from}},
	}
	var paths []SymbolicPacketPath
	var blocked []SymbolicPacketBlockedPath
	e.symbolicForward(initial, dst, packetPrefix, maxHops, map[string]bool{}, nil, &paths, &blocked, &reasons)
	conds := make([]failure.Cond, 0, len(paths))
	for _, path := range paths {
		conds = append(conds, path.Cond)
	}
	reachable := failure.Or(conds...)
	return SymbolicReachabilityResult{
		Reachable:          reachable,
		Unreachable:        failure.Not(reachable),
		Paths:              paths,
		Blocked:            blocked,
		UnreachableReasons: reasons,
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

func (e *Engine) symbolicForward(state SymbolicPacketState, dst model.PrefixSet, packetPrefix netip.Prefix, maxHops int, visited map[string]bool, states []SymbolicPacketState, paths *[]SymbolicPacketPath, blocked *[]SymbolicPacketBlockedPath, reasons *[]SymbolicUnreachableReason) {
	if isFalseCond(state.Cond) {
		return
	}
	if visited[state.Node] {
		addUnreachableReason(reasons, SymbolicUnreachableReason{
			Kind:    UnreachableLoop,
			Node:    state.Node,
			Cond:    condOrTrue(state.Cond),
			Path:    state.Path,
			Message: "forwarding loop",
		})
		return
	}
	states = append(states, state)
	if e.originatesPrefixSet(state.Node, dst) {
		cond := failure.And(condOrTrue(state.Cond), failure.NodeVar(state.Node))
		*paths = append(*paths, SymbolicPacketPath{Path: state.Path, Cond: cond, States: append([]SymbolicPacketState(nil), states...)})
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
	ingressDecision := controlplane.BehaviorFor(currentNode.Kind).CheckDataIngressSymbolic(currentNode, packet, e.idx.Topology.Policies)
	if ingressDecision.Denied {
		denyCond := failure.And(state.Cond, ingressDecision.Cond)
		e.appendBlockedPolicyPath(blocked, state.Path, denyCond, ingressDecision, state.Node, packet.IngressInterface, "ingress")
		addUnreachableReason(reasons, SymbolicUnreachableReason{
			Kind:       UnreachableIngressPolicy,
			Node:       state.Node,
			Interface:  packet.IngressInterface,
			PolicyName: ingressDecision.PolicyName,
			PolicyRaw:  ingressDecision.Source.Raw,
			Cond:       denyCond,
			Path:       state.Path,
			Message:    ingressDecision.Reason,
		})
		return
	}
	nextVisited := copyVisited(visited)
	nextVisited[state.Node] = true
	candidates := e.SymbolicLookupFIBForPrefixSet(state.Node, dst)
	candidateConds := make([]failure.Cond, 0, len(candidates))
	for _, candidate := range candidates {
		candidateConds = append(candidateConds, candidate.Cond)
	}
	addUnreachableReason(reasons, SymbolicUnreachableReason{
		Kind:    UnreachableNoRoute,
		Node:    state.Node,
		Cond:    failure.And(state.Cond, failure.Not(failure.Or(candidateConds...))),
		Path:    state.Path,
		Message: "no forwarding route",
	})
	for _, candidate := range candidates {
		entry := candidate.Entry
		if entry.NextHop == "" {
			addUnreachableReason(reasons, SymbolicUnreachableReason{
				Kind:    UnreachableNoNextHop,
				Node:    state.Node,
				Cond:    failure.And(state.Cond, candidate.Cond),
				Path:    state.Path,
				Message: "selected route has no next-hop",
			})
			continue
		}
		addUnreachableReason(reasons, SymbolicUnreachableReason{
			Kind:    UnreachableNodeFailed,
			Node:    entry.NextHop,
			Cond:    failure.And(state.Cond, failure.Not(failure.NodeVar(entry.NextHop))),
			Path:    state.Path,
			Message: "next-hop node is down",
		})
		link, ok := e.idx.LinkBetween(state.Node, entry.NextHop)
		if !ok {
			addUnreachableReason(reasons, SymbolicUnreachableReason{
				Kind:    UnreachableLinkFailed,
				Node:    state.Node,
				Link:    state.Node + "-" + entry.NextHop,
				Cond:    failure.And(state.Cond, candidate.Cond, failure.NodeVar(entry.NextHop)),
				Path:    state.Path,
				Message: "next-hop link is down",
			})
			continue
		}
		packet.EgressInterface = ingressInterface(link, state.Node)
		addUnreachableReason(reasons, SymbolicUnreachableReason{
			Kind:    UnreachableLinkFailed,
			Node:    state.Node,
			Link:    link.Name,
			Cond:    failure.And(state.Cond, failure.NodeVar(entry.NextHop), failure.Not(failure.LinkVar(link.Name))),
			Path:    state.Path,
			Message: "next-hop link is down",
		})
		nextPath := Path{
			Nodes: append(append([]string(nil), state.Path.Nodes...), entry.NextHop),
			Links: append(append([]string(nil), state.Path.Links...), link.Name),
			Cost:  state.Path.Cost + link.Cost,
		}
		egressDecision := controlplane.BehaviorFor(currentNode.Kind).CheckDataEgressSymbolic(currentNode, packet, e.idx.Topology.Policies)
		if egressDecision.Denied {
			denyCond := failure.And(state.Cond, candidate.Cond, egressDecision.Cond)
			e.appendBlockedPolicyPath(blocked, nextPath, denyCond, egressDecision, state.Node, packet.EgressInterface, "egress")
			addUnreachableReason(reasons, SymbolicUnreachableReason{
				Kind:       UnreachableEgressPolicy,
				Node:       state.Node,
				Interface:  packet.EgressInterface,
				PolicyName: egressDecision.PolicyName,
				PolicyRaw:  egressDecision.Source.Raw,
				Cond:       denyCond,
				Path:       nextPath,
				Message:    egressDecision.Reason,
			})
			continue
		}
		nextCond := failure.And(
			state.Cond,
			candidate.Cond,
			failure.Not(egressDecision.Cond),
			e.linkUpCond(link),
		)
		nextState := SymbolicPacketState{
			Node:             entry.NextHop,
			IngressInterface: ingressInterface(link, entry.NextHop),
			Packet:           packet,
			Cond:             nextCond,
			Path:             nextPath,
		}
		e.symbolicForward(nextState, dst, packetPrefix, maxHops, nextVisited, states, paths, blocked, reasons)
	}
}

func (e *Engine) appendBlockedPolicyPath(blocked *[]SymbolicPacketBlockedPath, path Path, cond failure.Cond, decision controlplane.PolicyDecision, node, iface, stage string) {
	if blocked == nil {
		return
	}
	*blocked = append(*blocked, SymbolicPacketBlockedPath{
		Path:      clonePath(path),
		Cond:      condOrTrue(cond),
		Reason:    decision.Reason,
		Policy:    decision.PolicyName,
		Node:      node,
		Interface: iface,
		Stage:     stage,
		Source:    decision.Source,
	})
}

func clonePath(path Path) Path {
	return Path{
		Nodes: append([]string(nil), path.Nodes...),
		Links: append([]string(nil), path.Links...),
		Cost:  path.Cost,
	}
}

func addUnreachableReason(reasons *[]SymbolicUnreachableReason, reason SymbolicUnreachableReason) {
	if reasons == nil || isFalseCond(reason.Cond) {
		return
	}
	reason.Cond = condOrTrue(reason.Cond)
	reason.Path.Nodes = append([]string(nil), reason.Path.Nodes...)
	reason.Path.Links = append([]string(nil), reason.Path.Links...)
	*reasons = append(*reasons, reason)
}

func (e *Engine) policyByName(name string) model.Policy {
	if e == nil || e.idx == nil || e.idx.Topology == nil {
		return model.Policy{}
	}
	for _, pol := range e.idx.Topology.Policies {
		if pol.Name == name {
			return pol
		}
	}
	return model.Policy{}
}

func policyMessage(name, raw string) string {
	msg := "denied by policy " + name
	if raw != "" {
		msg += ": " + raw
	}
	return msg
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

func matchingFIBEntriesForPrefixSet(entries []FIBEntry, dst model.PrefixSet) []FIBEntry {
	if dst == nil {
		return nil
	}
	var out []FIBEntry
	for _, entry := range entries {
		entrySet := model.ExactPrefixSet{Prefix: model.PrefixFromNetIP(entry.Prefix)}
		if entrySet.Overlaps(dst) {
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

func representativePrefixForSet(set model.PrefixSet) (model.Prefix, bool) {
	switch s := set.(type) {
	case model.ExactPrefixSet:
		return s.Prefix, !s.Prefix.IsZero()
	case model.PrefixRangeSet:
		return s.Base, !s.Base.IsZero()
	default:
		return model.Prefix{}, false
	}
}

func (e *Engine) originNodesForPrefixSet(dst model.PrefixSet) []string {
	if e == nil || e.idx == nil || dst == nil {
		return nil
	}
	var out []string
	for _, node := range e.idx.NodesByName {
		for _, raw := range node.Prefixes {
			if !raw.IsZero() && (model.ExactPrefixSet{Prefix: raw}).Overlaps(dst) {
				out = append(out, node.Name)
				break
			}
		}
	}
	sort.Strings(out)
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
