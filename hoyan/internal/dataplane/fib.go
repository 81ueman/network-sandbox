package dataplane

import (
	"net/netip"
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type Path struct {
	Nodes []string
	Links []string
	Cost  int
}

type FIBEntry struct {
	Prefix    netip.Prefix
	NextHop   string
	Path      Path
	Condition failure.Cond
}

type Engine struct {
	idx *model.TopologyIndex
	rib map[string]map[string][]controlplane.RIBEntry
	fib map[string][]FIBEntry
}

func NewEngine(idx *model.TopologyIndex, rib map[string]map[string][]controlplane.RIBEntry, fib map[string][]FIBEntry) *Engine {
	return &Engine{idx: idx, rib: rib, fib: fib}
}

func (e *Engine) DeriveFIB() {
	for node, byPrefix := range e.rib {
		var entries []FIBEntry
		n, _ := e.idx.Node(node)
		behavior := controlplane.BehaviorFor(n.Kind)
		for _, routes := range byPrefix {
			seenSelected := map[string]bool{}
			var installed []controlplane.RIBEntry
			for _, route := range routes {
				selectedKey := ""
				if route.SelectedCond != nil {
					selectedKey = route.SelectedCond.Key()
				}
				if seenSelected[selectedKey] {
					continue
				}
				if !behavior.RouteInstallableInFIB(n, installed, route) {
					continue
				}
				seenSelected[selectedKey] = true
				installed = append(installed, route)
				entries = append(entries, FIBEntry{
					Prefix:    route.Prefix.NetIP(),
					NextHop:   route.NextHop,
					Path:      Path{Nodes: route.Nodes, Links: route.Links, Cost: e.idx.PathCost(route.Links)},
					Condition: route.SelectedCond,
				})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Prefix.Bits() == entries[j].Prefix.Bits() {
				return entries[i].Prefix.String() < entries[j].Prefix.String()
			}
			return entries[i].Prefix.Bits() > entries[j].Prefix.Bits()
		})
		e.fib[node] = entries
	}
}

func (e *Engine) LookupFIB(node, dst string, ctx failure.Context) (FIBEntry, bool) {
	ip, err := netip.ParseAddr(dst)
	if err != nil {
		return FIBEntry{}, false
	}
	for _, rule := range e.fib[node] {
		if rule.Prefix.Contains(ip) && rule.Condition.Eval(ctx) {
			return rule, true
		}
	}
	return FIBEntry{}, false
}
