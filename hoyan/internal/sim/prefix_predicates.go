package sim

import (
	"fmt"
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func CollectRIBPrefixPredicates(g *Graph) []model.PrefixPredicate {
	if g == nil {
		return nil
	}
	var nodes []string
	for node := range g.rib {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	var out []model.PrefixPredicate
	seen := map[string]bool{}
	for _, node := range nodes {
		var prefixes []string
		for prefix := range g.rib[node] {
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		for _, rawPrefix := range prefixes {
			routes := append([]RIBEntry(nil), g.rib[node][rawPrefix]...)
			sort.SliceStable(routes, func(i, j int) bool {
				left := routes[i].Normalize()
				right := routes[j].Normalize()
				if left.Provenance.OriginNode == right.Provenance.OriginNode {
					return left.Provenance.FromNode < right.Provenance.FromNode
				}
				return left.Provenance.OriginNode < right.Provenance.OriginNode
			})
			for _, route := range routes {
				route = route.Normalize()
				if route.NLRI.Prefix.IsZero() {
					continue
				}
				source := fmt.Sprintf("rib:%s:%s", node, route.NLRI.Prefix.String())
				if route.Provenance.OriginNode != "" {
					source += ":origin=" + route.Provenance.OriginNode
				}
				key := source + "\x00" + route.NLRI.Prefix.String()
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, model.PrefixPredicate{
					Source: source,
					Set:    model.ExactPrefixSet{Prefix: route.NLRI.Prefix},
				})
			}
		}
	}
	return out
}

func CollectFIBPrefixPredicates(g *Graph) []model.PrefixPredicate {
	if g == nil {
		return nil
	}
	var nodes []string
	for node := range g.fib {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	var out []model.PrefixPredicate
	seen := map[string]bool{}
	for _, node := range nodes {
		entries := append([]FIBEntry(nil), g.fib[node]...)
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].Prefix.String() == entries[j].Prefix.String() {
				return entries[i].GroupID < entries[j].GroupID
			}
			return entries[i].Prefix.String() < entries[j].Prefix.String()
		})
		for _, entry := range entries {
			if !entry.Prefix.IsValid() {
				continue
			}
			prefix := model.PrefixFromNetIP(entry.Prefix)
			if prefix.IsZero() {
				continue
			}
			source := fmt.Sprintf("fib:%s:%s", node, prefix.String())
			if entry.GroupID != "" {
				source += ":group=" + entry.GroupID
			}
			key := source + "\x00" + prefix.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, model.PrefixPredicate{
				Source: source,
				Set:    model.ExactPrefixSet{Prefix: prefix},
			})
		}
	}
	return out
}
