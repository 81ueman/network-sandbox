package model

import (
	"fmt"
	"net/netip"
	"sort"
)

type TopologyIndex struct {
	Topology         *Topology
	NodesByName      map[NodeID]Node
	LinksByName      map[LinkID]Link
	Adj              map[NodeID][]AdjEdge
	LinksByEndpoints map[EndpointPair]Link
	OriginsByPrefix  map[string]NodeID
}

type AdjEdge struct {
	To   NodeID
	Link Link
}

type EndpointPair struct {
	A NodeID
	B NodeID
}

func NewEndpointPair(a, b string) EndpointPair {
	if b < a {
		a, b = b, a
	}
	return EndpointPair{A: NodeID(a), B: NodeID(b)}
}

func BuildTopologyIndex(topo *Topology) (*TopologyIndex, error) {
	idx := &TopologyIndex{
		Topology:         topo,
		NodesByName:      map[NodeID]Node{},
		LinksByName:      map[LinkID]Link{},
		Adj:              map[NodeID][]AdjEdge{},
		LinksByEndpoints: map[EndpointPair]Link{},
		OriginsByPrefix:  map[string]NodeID{},
	}
	if topo == nil {
		return idx, nil
	}
	for _, node := range topo.Nodes {
		nodeID := NodeID(node.Name)
		if _, exists := idx.NodesByName[nodeID]; exists {
			return nil, fmt.Errorf("duplicate node %q", node.Name)
		}
		idx.NodesByName[nodeID] = node
		for _, prefix := range node.Prefixes {
			idx.OriginsByPrefix[prefix.String()] = nodeID
		}
	}
	for _, link := range topo.Links {
		linkID := LinkID(link.Name)
		if _, exists := idx.LinksByName[linkID]; exists {
			return nil, fmt.Errorf("duplicate link %q", link.Name)
		}
		if _, ok := idx.NodesByName[NodeID(link.A)]; !ok {
			return nil, fmt.Errorf("link %s references unknown node %s", link.Name, link.A)
		}
		if _, ok := idx.NodesByName[NodeID(link.B)]; !ok {
			return nil, fmt.Errorf("link %s references unknown node %s", link.Name, link.B)
		}
		pair := NewEndpointPair(link.A, link.B)
		if existing, exists := idx.LinksByEndpoints[pair]; exists {
			return nil, fmt.Errorf("duplicate link endpoints %s-%s: %s and %s", pair.A, pair.B, existing.Name, link.Name)
		}
		idx.LinksByName[linkID] = link
		idx.LinksByEndpoints[pair] = link
		idx.Adj[NodeID(link.A)] = append(idx.Adj[NodeID(link.A)], AdjEdge{To: NodeID(link.B), Link: link})
		idx.Adj[NodeID(link.B)] = append(idx.Adj[NodeID(link.B)], AdjEdge{To: NodeID(link.A), Link: link})
	}
	for node := range idx.Adj {
		sort.Slice(idx.Adj[node], func(i, j int) bool {
			if idx.Adj[node][i].Link.Cost == idx.Adj[node][j].Link.Cost {
				return idx.Adj[node][i].To < idx.Adj[node][j].To
			}
			return idx.Adj[node][i].Link.Cost < idx.Adj[node][j].Link.Cost
		})
	}
	return idx, nil
}

func (idx *TopologyIndex) Node(name string) (Node, bool) {
	if idx == nil {
		return Node{}, false
	}
	node, ok := idx.NodesByName[NodeID(name)]
	return node, ok
}

func (idx *TopologyIndex) Link(name string) (Link, bool) {
	if idx == nil {
		return Link{}, false
	}
	link, ok := idx.LinksByName[LinkID(name)]
	return link, ok
}

func (idx *TopologyIndex) LinkBetween(a, b string) (Link, bool) {
	if idx == nil {
		return Link{}, false
	}
	link, ok := idx.LinksByEndpoints[NewEndpointPair(a, b)]
	return link, ok
}

func (idx *TopologyIndex) AddressOnLink(node, peer string) (netip.Addr, bool) {
	link, ok := idx.LinkBetween(node, peer)
	if !ok {
		return netip.Addr{}, false
	}
	switch {
	case link.A == node && link.B == peer:
		return idx.interfaceAddress(node, link.AIntf)
	case link.B == node && link.A == peer:
		return idx.interfaceAddress(node, link.BIntf)
	default:
		return netip.Addr{}, false
	}
}

func (idx *TopologyIndex) PeerAddressOnLink(node, peer string) (netip.Addr, bool) {
	return idx.AddressOnLink(peer, node)
}

func (idx *TopologyIndex) interfaceAddress(node, name string) (netip.Addr, bool) {
	n, ok := idx.Node(node)
	if !ok {
		return netip.Addr{}, false
	}
	pfx, ok := interfaceAddr(n.Interfaces, name)
	if !ok {
		return netip.Addr{}, false
	}
	return pfx.Addr(), true
}

func (idx *TopologyIndex) PathCost(links []string) int {
	cost := 0
	for _, name := range links {
		if link, ok := idx.Link(name); ok {
			cost += link.Cost
		}
	}
	return cost
}

func (idx *TopologyIndex) OriginForPrefix(prefix string) (string, bool) {
	if idx == nil {
		return "", false
	}
	want, err := ParsePrefix(prefix)
	if err != nil {
		return "", false
	}
	node, ok := idx.OriginsByPrefix[want.String()]
	return string(node), ok
}

func (idx *TopologyIndex) OriginForIP(addr string) (string, Prefix, bool) {
	if idx == nil {
		return "", Prefix{}, false
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", Prefix{}, false
	}
	var bestNode NodeID
	var bestPrefix Prefix
	for prefix, node := range idx.OriginsByPrefix {
		pfx, err := ParsePrefix(prefix)
		if err != nil || !pfx.Contains(ip) {
			continue
		}
		if bestNode == "" || pfx.Bits() > bestPrefix.Bits() {
			bestNode = node
			bestPrefix = pfx
		}
	}
	return string(bestNode), bestPrefix, bestNode != ""
}
