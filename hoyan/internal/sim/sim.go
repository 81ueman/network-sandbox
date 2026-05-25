package sim

import (
	"fmt"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/controlplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/dataplane"
	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

type RIBEntry = controlplane.RIBEntry
type FIBEntry = dataplane.FIBEntry
type Path = dataplane.Path
type FailureSet = failure.Set
type FailureContext = failure.Context
type FailureSearchOptions = failure.SearchOptions
type Cond = failure.Cond
type ControlMessage = controlplane.ControlMessage
type PacketMessage = controlplane.PacketMessage
type BGPRouteDecision = controlplane.BGPRouteDecision
type BGPBehavior = controlplane.BGPBehavior
type BGPDecisionProcess = controlplane.BGPDecisionProcess
type DeviceBehavior = controlplane.DeviceBehavior

type Graph struct {
	topo      *model.Topology
	topoIndex *model.TopologyIndex
	rib       map[string]map[string][]RIBEntry
	fib       map[string][]FIBEntry
}

type Result struct {
	Name           string
	Reachable      bool
	Expected       bool
	Path           Path
	Counterexample []string
	Reason         string
}

func NoFailures() FailureSet { return failure.None() }
func LinkFailures(names ...model.LinkID) FailureSet {
	return failure.Links(names...)
}
func NodeFailures(names ...model.NodeID) FailureSet {
	return failure.Nodes(names...)
}
func NewFailureSet(links []model.LinkID, nodes []model.NodeID) FailureSet {
	return failure.NewSet(links, nodes)
}
func FailureSetFromMap(raw map[string]bool) FailureSet {
	return failure.SetFromMap(raw)
}
func FailureSetFromElements(elements []solver.FailureElement) FailureSet {
	return failure.SetFromElements(elements)
}

func True() Cond           { return failure.True() }
func False() Cond          { return failure.False() }
func Var(name string) Cond { return failure.Var(name) }
func LinkVar(name string) Cond {
	return failure.LinkVar(name)
}
func NodeVar(name string) Cond {
	return failure.NodeVar(name)
}
func And(cs ...Cond) Cond { return failure.And(cs...) }
func Or(cs ...Cond) Cond  { return failure.Or(cs...) }
func Not(c Cond) Cond     { return failure.Not(c) }

func RegisterBehavior(kind model.DeviceKind, behavior DeviceBehavior) func() {
	return controlplane.RegisterBehavior(kind, behavior)
}
func BehaviorFor(kind model.DeviceKind) DeviceBehavior {
	return controlplane.BehaviorFor(kind)
}
func NewGenericBehavior(kind model.DeviceKind) DeviceBehavior {
	return controlplane.NewGenericBehavior(kind)
}
func NewFRRBehavior() DeviceBehavior {
	return controlplane.NewFRRBehavior()
}
func NewCEOSBehavior() DeviceBehavior {
	return controlplane.NewCEOSBehavior()
}
func NewSRLinuxBehavior() DeviceBehavior {
	return controlplane.NewSRLinuxBehavior()
}
func DefaultBGPDecisionProcess() BGPDecisionProcess {
	return controlplane.DefaultBGPDecisionProcess()
}

func NewGraph(topo *model.Topology) *Graph {
	idx, err := model.BuildTopologyIndex(topo)
	if err != nil {
		panic(err)
	}
	g := &Graph{
		topo:      topo,
		topoIndex: idx,
		rib:       map[string]map[string][]RIBEntry{},
		fib:       map[string][]FIBEntry{},
	}
	controlplane.NewEngine(idx, g.rib).Simulate()
	dataplane.NewEngine(idx, g.rib, g.fib).DeriveFIB()
	return g
}

func (g *Graph) RIB(node, prefix string) []RIBEntry {
	return append([]RIBEntry(nil), g.rib[node][prefix]...)
}

func (g *Graph) RIBTable(node string) map[string][]RIBEntry {
	out := map[string][]RIBEntry{}
	for prefix, routes := range g.rib[node] {
		out[prefix] = append([]RIBEntry(nil), routes...)
	}
	return out
}

func (g *Graph) FIB(node string) []FIBEntry {
	return append([]FIBEntry(nil), g.fib[node]...)
}

func (g *Graph) FailureContext(failures FailureSet) FailureContext {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).FailureContext(failures)
}

func (g *Graph) RouteReachable(from, prefix string, failures FailureSet) (Path, bool) {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).RouteReachable(from, prefix, failures)
}

func (g *Graph) PacketReachable(from, to, protocol string, failures FailureSet) (Path, bool, string) {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).PacketReachable(from, to, protocol, failures)
}

func (g *Graph) FindBreakingFailures(from string, target Target, maxFailures int) ([]string, bool) {
	ans, ok := g.FindBreakingFailuresWithOptions(from, target, FailureSearchOptions{
		IncludeLinks: true,
		MaxFailures:  maxFailures,
	})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(ans))
	for _, element := range ans {
		if element.Kind == solver.FailureLink {
			out = append(out, element.Name)
			continue
		}
		out = append(out, element.String())
	}
	return out, true
}

func (g *Graph) FindBreakingFailuresWithOptions(from string, target Target, opts FailureSearchOptions) ([]solver.FailureElement, bool) {
	if opts.MaxFailures < 0 {
		return nil, false
	}
	if !opts.IncludeLinks && !opts.IncludeNodes {
		return nil, false
	}
	elements := failure.SearchElements(g.topo, opts)
	if len(elements) == 0 {
		return nil, false
	}
	var forbidden [][]solver.FailureElement
	for k := 0; k <= opts.MaxFailures; k++ {
		failure.FindElementCombo(elements, k, 0, nil, func(combo []solver.FailureElement) bool {
			if !target.Reachable(g, from, FailureSetFromElements(combo)) {
				forbidden = append(forbidden, append([]solver.FailureElement(nil), combo...))
			}
			return false
		})
	}
	ans, err := solver.DefaultBackend().Solve(solver.FailureProblem{
		Elements:    elements,
		MaxFailures: opts.MaxFailures,
		Forbidden:   forbidden,
	})
	if err != nil || !ans.Sat {
		return nil, false
	}
	return ans.Failures, true
}

type Target interface {
	Reachable(g *Graph, from string, failures FailureSet) bool
}

type PrefixTarget string

func (t PrefixTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	_, ok := g.RouteReachable(from, string(t), failures)
	return ok
}

type PacketTarget struct {
	To       string
	Protocol string
}

func (t PacketTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	_, ok, _ := g.PacketReachable(from, t.To, t.Protocol, failures)
	return ok
}

func FormatPath(p Path) string {
	if len(p.Nodes) == 0 {
		return ""
	}
	return fmt.Sprintf("%s cost=%d", strings.Join(p.Nodes, " -> "), p.Cost)
}
