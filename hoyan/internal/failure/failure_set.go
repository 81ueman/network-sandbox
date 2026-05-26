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
	Domain       model.FailureDomain
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
	domain := opts.Domain
	if domain.IsZero() {
		domain = DefaultWANFailureDomain()
	}
	rolesByNode := nodeRoles(topo.Nodes)
	if opts.IncludeLinks {
		links := append([]model.Link(nil), topo.Links...)
		sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
		for _, link := range links {
			if !linkEligible(link, rolesByNode, domain) {
				continue
			}
			elements = append(elements, solver.FailureElement{Kind: solver.FailureLink, Name: link.Name})
		}
	}
	if opts.IncludeNodes {
		nodes := append([]model.Node(nil), topo.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
		for _, node := range nodes {
			if !nodeEligible(node, domain) {
				continue
			}
			elements = append(elements, solver.FailureElement{Kind: solver.FailureNode, Name: node.Name})
		}
	}
	return elements
}

func DefaultWANFailureDomain() model.FailureDomain {
	return model.FailureDomain{
		ExcludeNodeRoles: []string{"customer"},
		ExcludeLinkRoles: []string{"customer"},
	}
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

func nodeEligible(node model.Node, domain model.FailureDomain) bool {
	if stringSet(domain.ExcludeNodes)[node.Name] {
		return false
	}
	if node.Role != "" && stringSet(domain.ExcludeNodeRoles)[node.Role] {
		return false
	}
	hasInclude := len(domain.IncludeNodes) > 0 || len(domain.IncludeNodeRoles) > 0
	if !hasInclude {
		return true
	}
	if stringSet(domain.IncludeNodes)[node.Name] {
		return true
	}
	return node.Role != "" && stringSet(domain.IncludeNodeRoles)[node.Role]
}

func linkEligible(link model.Link, rolesByNode map[string]string, domain model.FailureDomain) bool {
	if stringSet(domain.ExcludeLinks)[link.Name] {
		return false
	}
	linkRoles := effectiveLinkRoles(link, rolesByNode)
	if intersects(linkRoles, stringSet(domain.ExcludeLinkRoles)) {
		return false
	}
	hasInclude := len(domain.IncludeLinks) > 0 || len(domain.IncludeLinkRoles) > 0
	if !hasInclude {
		return true
	}
	if stringSet(domain.IncludeLinks)[link.Name] {
		return true
	}
	return intersects(linkRoles, stringSet(domain.IncludeLinkRoles))
}

func nodeRoles(nodes []model.Node) map[string]string {
	out := map[string]string{}
	for _, node := range nodes {
		if node.Role != "" {
			out[node.Name] = node.Role
		}
	}
	return out
}

func effectiveLinkRoles(link model.Link, rolesByNode map[string]string) []string {
	seen := map[string]bool{}
	var roles []string
	for _, role := range []string{link.Role, rolesByNode[link.A], rolesByNode[link.B]} {
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		roles = append(roles, role)
	}
	return roles
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func intersects(values []string, set map[string]bool) bool {
	for _, value := range values {
		if set[value] {
			return true
		}
	}
	return false
}
