package model

import (
	"fmt"
	"net/netip"
	"sort"
)

type TopologyIndex struct {
	Topology         *Topology
	NodesByName      map[string]Node
	LinksByName      map[string]Link
	Adj              map[string][]AdjEdge
	LinksByEndpoints map[EndpointPair]Link
	OriginsByPrefix  map[string]string
}

type AdjEdge struct {
	To   string
	Link Link
}

type EndpointPair struct {
	A string
	B string
}

func NewEndpointPair(a, b string) EndpointPair {
	if b < a {
		a, b = b, a
	}
	return EndpointPair{A: a, B: b}
}

func BuildTopologyIndex(topo *Topology) (*TopologyIndex, error) {
	idx := &TopologyIndex{
		Topology:         topo,
		NodesByName:      map[string]Node{},
		LinksByName:      map[string]Link{},
		Adj:              map[string][]AdjEdge{},
		LinksByEndpoints: map[EndpointPair]Link{},
		OriginsByPrefix:  map[string]string{},
	}
	if topo == nil {
		return idx, nil
	}
	for _, node := range topo.Nodes {
		if _, exists := idx.NodesByName[node.Name]; exists {
			return nil, fmt.Errorf("duplicate node %q", node.Name)
		}
		idx.NodesByName[node.Name] = node
		for _, prefix := range node.Prefixes {
			idx.OriginsByPrefix[prefix.String()] = node.Name
		}
	}
	for _, link := range topo.Links {
		if _, exists := idx.LinksByName[link.Name]; exists {
			return nil, fmt.Errorf("duplicate link %q", link.Name)
		}
		if _, ok := idx.NodesByName[link.A]; !ok {
			return nil, fmt.Errorf("link %s references unknown node %s", link.Name, link.A)
		}
		if _, ok := idx.NodesByName[link.B]; !ok {
			return nil, fmt.Errorf("link %s references unknown node %s", link.Name, link.B)
		}
		pair := NewEndpointPair(link.A, link.B)
		if existing, exists := idx.LinksByEndpoints[pair]; exists {
			return nil, fmt.Errorf("duplicate link endpoints %s-%s: %s and %s", pair.A, pair.B, existing.Name, link.Name)
		}
		idx.LinksByName[link.Name] = link
		idx.LinksByEndpoints[pair] = link
		idx.Adj[link.A] = append(idx.Adj[link.A], AdjEdge{To: link.B, Link: link})
		idx.Adj[link.B] = append(idx.Adj[link.B], AdjEdge{To: link.A, Link: link})
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
	node, ok := idx.NodesByName[name]
	return node, ok
}

func (idx *TopologyIndex) Link(name string) (Link, bool) {
	if idx == nil {
		return Link{}, false
	}
	link, ok := idx.LinksByName[name]
	return link, ok
}

func (idx *TopologyIndex) LinkBetween(a, b string) (Link, bool) {
	if idx == nil {
		return Link{}, false
	}
	link, ok := idx.LinksByEndpoints[NewEndpointPair(a, b)]
	return link, ok
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
	return node, ok
}

func (idx *TopologyIndex) OriginForIP(addr string) (string, Prefix, bool) {
	if idx == nil {
		return "", Prefix{}, false
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", Prefix{}, false
	}
	var bestNode string
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
	return bestNode, bestPrefix, bestNode != ""
}
