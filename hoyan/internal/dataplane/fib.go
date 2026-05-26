package dataplane

import (
	"net/netip"
	"sort"
	"strconv"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type Path struct {
	Nodes []string
	Links []string
	Cost  int
}

type NextHopResolutionStatus string

const (
	NextHopResolutionResolvedAdjacent    NextHopResolutionStatus = "resolved_adjacent"
	NextHopResolutionUnresolvedRecursive NextHopResolutionStatus = "unresolved_recursive_next_hop"
	NextHopResolutionManagementFallback  NextHopResolutionStatus = "next_hop_management_fallback"
)

type FIBEntry struct {
	Prefix netip.Prefix
	// NextHop is the resolved adjacent topology node used by modeled packet
	// forwarding. It is not a raw BGP next-hop address.
	NextHop          string
	RawNextHop       string
	NextHopAddress   string
	Interface        string
	ResolutionStatus NextHopResolutionStatus
	ResolutionReason string
	SourceKind       model.RouteSourceKind
	Discard          bool
	ConnectedClass   model.ConnectedRouteClass
	Path             Path
	Condition        failure.Cond
	Rank             int
	GroupID          string
	Equivalent       bool
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
			routes = append([]controlplane.RIBEntry(nil), routes...)
			sort.SliceStable(routes, func(i, j int) bool {
				ai, aj := fibAdminDistance(routes[i]), fibAdminDistance(routes[j])
				if ai == aj {
					return routes[i].SourceKind < routes[j].SourceKind
				}
				return ai < aj
			})
			seenSelected := map[string]bool{}
			var installed []controlplane.RIBEntry
			var groups []fibRouteGroup
			for _, route := range routes {
				route = route.Normalize()
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
				group, newGroup := routeGroupFor(behavior.DecisionProcess(), n, groups, route)
				installed = append(installed, route)
				if newGroup {
					groups = append(groups, group)
				} else {
					for i := range entries {
						if entries[i].GroupID == group.id {
							entries[i].Equivalent = true
						}
					}
				}
				resolvedNextHop := route.ForwardingNextHop.Node
				if resolvedNextHop == "" && route.ForwardingNextHop.Addr == "" {
					resolvedNextHop = route.NextHop
				}
				nextHopAddress := route.ForwardingNextHop.Addr
				rawNextHop := route.NextHop
				if rawNextHop == "" {
					rawNextHop = nextHopAddress
				}
				resolutionStatus, resolutionReason := nextHopResolution(resolvedNextHop, nextHopAddress)
				entries = append(entries, FIBEntry{
					Prefix:           route.Prefix.NetIP(),
					NextHop:          resolvedNextHop,
					RawNextHop:       rawNextHop,
					NextHopAddress:   nextHopAddress,
					Interface:        route.RouteSource.Interface,
					ResolutionStatus: resolutionStatus,
					ResolutionReason: resolutionReason,
					SourceKind:       route.SourceKind,
					Discard:          route.SourceKind == model.RouteSourceBlackhole,
					ConnectedClass:   route.RouteSource.ConnectedClass,
					Path:             Path{Nodes: route.Nodes, Links: route.Links, Cost: e.idx.PathCost(route.Links)},
					Condition:        route.SelectedCond,
					Rank:             group.rank,
					GroupID:          group.id,
					Equivalent:       group.equivalent,
				})
			}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].Prefix.Bits() == entries[j].Prefix.Bits() {
				if entries[i].Rank == entries[j].Rank {
					return entries[i].Prefix.String() < entries[j].Prefix.String()
				}
				return entries[i].Rank < entries[j].Rank
			}
			return entries[i].Prefix.Bits() > entries[j].Prefix.Bits()
		})
		e.fib[node] = entries
	}
}

func fibAdminDistance(route controlplane.RIBEntry) int {
	route = route.Normalize()
	if route.RouteSource.AdminDistance != 0 || route.SourceKind == model.RouteSourceConnected {
		return route.RouteSource.AdminDistance
	}
	switch route.SourceKind {
	case model.RouteSourceConnected:
		return 0
	case model.RouteSourceStatic, model.RouteSourceBlackhole:
		return 1
	default:
		return 200
	}
}

type fibRouteGroup struct {
	route      controlplane.RIBEntry
	rank       int
	id         string
	equivalent bool
}

func routeGroupFor(decision controlplane.BGPDecisionProcess, node model.Node, groups []fibRouteGroup, route controlplane.RIBEntry) (fibRouteGroup, bool) {
	prefix := route.Prefix.String()
	for _, group := range groups {
		if decision.Equivalent(node, group.route, route) {
			return fibRouteGroup{
				route:      route,
				rank:       group.rank,
				id:         group.id,
				equivalent: true,
			}, false
		}
	}
	rank := len(groups)
	return fibRouteGroup{
		route: route,
		rank:  rank,
		id:    prefix + "#rank-" + strconv.Itoa(rank),
	}, true
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

func nextHopResolution(node, addr string) (NextHopResolutionStatus, string) {
	if node != "" {
		return NextHopResolutionResolvedAdjacent, ""
	}
	if addr != "" {
		return NextHopResolutionUnresolvedRecursive, "recursive next-hop unresolved"
	}
	return "", ""
}

func (entry FIBEntry) effectiveResolutionStatus() NextHopResolutionStatus {
	if entry.ResolutionStatus != "" {
		return entry.ResolutionStatus
	}
	if entry.NextHop == "" && (entry.RawNextHop != "" || entry.NextHopAddress != "") {
		return NextHopResolutionUnresolvedRecursive
	}
	if _, err := netip.ParseAddr(entry.NextHop); err == nil {
		return NextHopResolutionUnresolvedRecursive
	}
	return ""
}
