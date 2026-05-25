package failure

import (
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

type Set struct {
	Links map[model.LinkID]bool
	Nodes map[model.NodeID]bool
}

type Context struct {
	Failures    Set
	LinksByName map[model.LinkID]model.Link
}

type SearchOptions struct {
	IncludeLinks bool
	IncludeNodes bool
	MaxFailures  int
}

func None() Set {
	return Set{Links: map[model.LinkID]bool{}, Nodes: map[model.NodeID]bool{}}
}

func Links(names ...model.LinkID) Set {
	return NewSet(names, nil)
}

func Nodes(names ...model.NodeID) Set {
	return NewSet(nil, names)
}

func NewSet(links []model.LinkID, nodes []model.NodeID) Set {
	out := None()
	for _, name := range links {
		out.Links[name] = true
	}
	for _, name := range nodes {
		out.Nodes[name] = true
	}
	return out
}

func SetFromMap(raw map[string]bool) Set {
	out := None()
	for key, failed := range raw {
		if !failed {
			continue
		}
		switch {
		case strings.HasPrefix(key, "link:"):
			out.Links[model.LinkID(strings.TrimPrefix(key, "link:"))] = true
		case strings.HasPrefix(key, "node:"):
			out.Nodes[model.NodeID(strings.TrimPrefix(key, "node:"))] = true
		default:
			out.Links[model.LinkID(key)] = true
		}
	}
	return out
}

func SetFromElements(elements []solver.FailureElement) Set {
	out := None()
	for _, element := range elements {
		switch element.Kind {
		case solver.FailureLink:
			out.Links[model.LinkID(element.Name)] = true
		case solver.FailureNode:
			out.Nodes[model.NodeID(element.Name)] = true
		}
	}
	return out
}

func (ctx Context) NodeFailed(node model.NodeID) bool {
	return ctx.Failures.Nodes[node]
}

func (ctx Context) LinkFailed(linkName model.LinkID) bool {
	if ctx.Failures.Links[linkName] {
		return true
	}
	link, ok := ctx.LinksByName[linkName]
	if !ok {
		return false
	}
	return ctx.Failures.Nodes[model.NodeID(link.A)] || ctx.Failures.Nodes[model.NodeID(link.B)]
}

func SearchElements(topo *model.Topology, opts SearchOptions) []solver.FailureElement {
	var elements []solver.FailureElement
	if opts.IncludeLinks {
		links := append([]model.Link(nil), topo.Links...)
		sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
		for _, link := range eligibleLinks(links) {
			elements = append(elements, solver.FailureElement{Kind: solver.FailureLink, Name: link.Name})
		}
	}
	if opts.IncludeNodes {
		nodes := append([]model.Node(nil), topo.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
		for _, node := range eligibleNodes(nodes) {
			elements = append(elements, solver.FailureElement{Kind: solver.FailureNode, Name: node.Name})
		}
	}
	return elements
}

func FindElementCombo(elements []solver.FailureElement, want, start int, cur []solver.FailureElement, fn func([]solver.FailureElement) bool) bool {
	if len(cur) == want {
		return fn(cur)
	}
	for i := start; i < len(elements); i++ {
		cur = append(cur, elements[i])
		if FindElementCombo(elements, want, i+1, cur, fn) {
			return true
		}
		cur = cur[:len(cur)-1]
	}
	return false
}

func eligibleLinks(links []model.Link) []model.Link {
	var out []model.Link
	for _, l := range links {
		if strings.Contains(l.Name, "cust") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func eligibleNodes(nodes []model.Node) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if strings.Contains(n.Name, "cust") {
			continue
		}
		out = append(out, n)
	}
	return out
}
