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
type SymbolicFIBCandidate = dataplane.SymbolicFIBCandidate
type SymbolicPacketBlockedPath = dataplane.SymbolicPacketBlockedPath
type SymbolicPacketPath = dataplane.SymbolicPacketPath
type SymbolicPacketState = dataplane.SymbolicPacketState
type SymbolicReachabilityResult = dataplane.SymbolicReachabilityResult
type SymbolicUnreachableReason = dataplane.SymbolicUnreachableReason
type SymbolicUnreachableReasonKind = dataplane.SymbolicUnreachableReasonKind
type SymbolicRoutePath = dataplane.SymbolicRoutePath
type SymbolicRouteReachabilityResult = dataplane.SymbolicRouteReachabilityResult
type FailureSet = failure.Set
type FailureContext = failure.Context
type FailureSearchOptions = failure.SearchOptions
type Cond = failure.Cond
type ControlMessage = controlplane.ControlMessage
type PacketMessage = controlplane.PacketMessage
type BGPRouteDecision = controlplane.BGPRouteDecision
type BGPBehavior = controlplane.BGPBehavior
type BGPDecisionProcess = controlplane.BGPDecisionProcess
type BGPDecisionOptions = controlplane.BGPDecisionOptions
type DeviceBehavior = controlplane.DeviceBehavior

type Graph struct {
	topo      *model.Topology
	topoIndex *model.TopologyIndex
	rib       map[string]map[string][]RIBEntry
	fib       map[string][]FIBEntry
}

type Result struct {
	Name                 string                `json:"name"`
	QueryType            string                `json:"query_type,omitempty"`
	Reachable            bool                  `json:"reachable"`
	Expected             bool                  `json:"expected"`
	Path                 Path                  `json:"path,omitempty"`
	Counterexample       []string              `json:"counterexample,omitempty"`
	Reason               string                `json:"reason,omitempty"`
	PrefixClassID        *model.PrefixClassID  `json:"class_id,omitempty"`
	PrefixClassIDs       []model.PrefixClassID `json:"class_ids,omitempty"`
	PrefixSpace          string                `json:"space,omitempty"`
	PrefixSpaces         []string              `json:"spaces,omitempty"`
	MatchedPredicates    []string              `json:"matched_predicates,omitempty"`
	ReachableCondition   string                `json:"reachable_condition,omitempty"`
	UnreachableCondition string                `json:"unreachable_condition,omitempty"`
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
func DefaultWANFailureDomain() model.FailureDomain {
	return failure.DefaultWANFailureDomain()
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
func DefaultBGPDecisionOptions() BGPDecisionOptions {
	return controlplane.DefaultBGPDecisionOptions()
}
func NewBGPDecisionProcess(options BGPDecisionOptions) BGPDecisionProcess {
	return controlplane.NewBGPDecisionProcess(options)
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

func (g *Graph) RouteReachableForPrefixSet(from string, dst model.PrefixSet, failures FailureSet) (Path, bool) {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).RouteReachableForPrefixSet(from, dst, failures)
}

func (g *Graph) PacketReachable(from, to, protocol string, failures FailureSet) (Path, bool, string) {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).PacketReachable(from, to, protocol, failures)
}

func (g *Graph) PacketReachableSpec(from, to string, spec model.PacketSpec, failures FailureSet) (Path, bool, string) {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).PacketReachableSpec(from, to, spec, failures)
}

func (g *Graph) SymbolicPacketReachability(from, to, protocol string) SymbolicReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicPacketReachability(from, to, protocol)
}

func (g *Graph) SymbolicPacketReachabilitySpec(from, to string, spec model.PacketSpec) SymbolicReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicPacketReachabilitySpec(from, to, spec)
}

func (g *Graph) SymbolicPacketReachabilityForPrefixSet(from string, dst model.PrefixSet, protocol string) SymbolicReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicPacketReachabilityForPrefixSet(from, dst, protocol)
}

func (g *Graph) SymbolicPacketReachabilityForPrefixSetSpec(from string, dst model.PrefixSet, spec model.PacketSpec) SymbolicReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicPacketReachabilityForPrefixSetSpec(from, dst, spec)
}

func (g *Graph) SymbolicPacketReachabilityForClass(from string, universe model.PrefixUniverse, classID model.PrefixClassID, protocol string) SymbolicReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicPacketReachabilityForClass(from, universe, classID, protocol)
}

func (g *Graph) SymbolicRouteReachability(from, prefix string) SymbolicRouteReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicRouteReachability(from, prefix)
}

func (g *Graph) SymbolicRouteReachabilityForPrefixSet(from string, dst model.PrefixSet) SymbolicRouteReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicRouteReachabilityForPrefixSet(from, dst)
}

func (g *Graph) SymbolicRouteReachabilityForClass(from string, universe model.PrefixUniverse, classID model.PrefixClassID) SymbolicRouteReachabilityResult {
	return dataplane.NewEngine(g.topoIndex, g.rib, g.fib).SymbolicRouteReachabilityForClass(from, universe, classID)
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
	elements := g.failureElements(opts)
	if len(elements) == 0 {
		return nil, false
	}
	if problem, ok := g.symbolicFailureProblem(from, target, opts, elements); ok {
		if ans, ok := solveSymbolicFailureProblem(problem); ok {
			return ans, true
		}
		return nil, false
	}
	forbidden := g.enumerateForbiddenFailures(from, target, opts, elements)
	ans, ok := solveEnumeratedFailureProblem(solver.FailureProblem{
		Elements:    elements,
		MaxFailures: opts.MaxFailures,
		Forbidden:   forbidden,
	})
	if !ok {
		return nil, false
	}
	return ans, true
}

func (g *Graph) failureElements(opts FailureSearchOptions) []solver.FailureElement {
	if !opts.IncludeLinks && !opts.IncludeNodes {
		return nil
	}
	return failure.SearchElements(g.topo, opts)
}

func (g *Graph) enumerateForbiddenFailures(from string, target Target, opts FailureSearchOptions, elements []solver.FailureElement) [][]solver.FailureElement {
	var forbidden [][]solver.FailureElement
	for k := 0; k <= opts.MaxFailures; k++ {
		failure.FindElementCombo(elements, k, 0, nil, func(combo []solver.FailureElement) bool {
			if !target.Reachable(g, from, FailureSetFromElements(combo)) {
				forbidden = append(forbidden, append([]solver.FailureElement(nil), combo...))
			}
			return false
		})
	}
	return forbidden
}

func solveEnumeratedFailureProblem(problem solver.FailureProblem) ([]solver.FailureElement, bool) {
	ans, err := solver.DefaultBackend().Solve(problem)
	if err != nil || !ans.Sat {
		return nil, false
	}
	return ans.Failures, true
}

func (g *Graph) symbolicFailureProblem(from string, target Target, opts FailureSearchOptions, elements []solver.FailureElement) (solver.SymbolicFailureProblem, bool) {
	var goal failure.Cond
	switch t := target.(type) {
	case PacketTarget:
		result := g.SymbolicPacketReachabilitySpec(from, t.To, t.Spec())
		goal = result.Unreachable
	case PacketPrefixTarget:
		result := g.SymbolicPacketReachabilityForPrefixSetSpec(from, model.ExactPrefixSet{Prefix: t.Prefix}, t.Spec())
		goal = result.Unreachable
	case PacketClassTarget:
		result := t.symbolicReachability(g, from)
		goal = result.Unreachable
	case PrefixTarget:
		result := g.SymbolicRouteReachability(from, string(t))
		goal = result.Unreachable
	case RoutePrefixSetTarget:
		result := g.SymbolicRouteReachabilityForPrefixSet(from, t.Space)
		goal = result.Unreachable
	case RouteClassTarget:
		result := t.symbolicReachability(g, from)
		goal = result.Unreachable
	default:
		return solver.SymbolicFailureProblem{}, false
	}
	return solver.SymbolicFailureProblem{
		Elements:    elements,
		MaxFailures: opts.MaxFailures,
		Goal:        failure.BoolExpr(goal),
	}, true
}

func solveSymbolicFailureProblem(problem solver.SymbolicFailureProblem) ([]solver.FailureElement, bool) {
	backend, ok := solver.DefaultBackend().(solver.SymbolicBackend)
	if !ok {
		return nil, false
	}
	ans, err := backend.SolveSymbolic(problem)
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

type RoutePrefixSetTarget struct {
	Space model.PrefixSet
}

func (t RoutePrefixSetTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	_, ok := g.RouteReachableForPrefixSet(from, t.Space, failures)
	return ok
}

type RouteClassTarget struct {
	Universe model.PrefixUniverse
	ClassID  model.PrefixClassID
}

func (t RouteClassTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	result := t.symbolicReachability(g, from)
	return result.Reachable.Eval(g.FailureContext(failures))
}

func (t RouteClassTarget) symbolicReachability(g *Graph, from string) SymbolicRouteReachabilityResult {
	return g.SymbolicRouteReachabilityForClass(from, t.Universe, t.ClassID)
}

type PacketTarget struct {
	To       string
	Protocol string
	DstPort  int
}

func (t PacketTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	_, ok, _ := g.PacketReachableSpec(from, t.To, t.Spec(), failures)
	return ok
}

func (t PacketTarget) Spec() model.PacketSpec {
	return model.PacketSpec{Protocol: t.Protocol, DstPort: model.ExactPort(t.DstPort)}
}

type PacketPrefixTarget struct {
	Prefix   model.Prefix
	Protocol string
	DstPort  int
}

func (t PacketPrefixTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	if t.Prefix.IsZero() {
		return false
	}
	_, ok, _ := g.PacketReachableSpec(from, t.Prefix.Addr().String(), t.Spec(), failures)
	return ok
}

func (t PacketPrefixTarget) Spec() model.PacketSpec {
	return model.PacketSpec{Protocol: t.Protocol, DstPort: model.ExactPort(t.DstPort)}
}

type PacketClassTarget struct {
	Universe model.PrefixUniverse
	ClassID  model.PrefixClassID
	Protocol string
	DstPort  int
}

func (t PacketClassTarget) Reachable(g *Graph, from string, failures FailureSet) bool {
	result := t.symbolicReachability(g, from)
	return result.Reachable.Eval(g.FailureContext(failures))
}

func (t PacketClassTarget) Spec() model.PacketSpec {
	return model.PacketSpec{Protocol: t.Protocol, DstPort: model.ExactPort(t.DstPort)}
}

func (t PacketClassTarget) symbolicReachability(g *Graph, from string) SymbolicReachabilityResult {
	for _, class := range t.Universe.Classes {
		if class.ID == t.ClassID {
			return g.SymbolicPacketReachabilityForPrefixSetSpec(from, class.Space, t.Spec())
		}
	}
	return SymbolicReachabilityResult{
		Reachable:   False(),
		Unreachable: True(),
		Reason:      "prefix class not found",
	}
}

func FormatPath(p Path) string {
	if len(p.Nodes) == 0 {
		return ""
	}
	return fmt.Sprintf("%s cost=%d", strings.Join(p.Nodes, " -> "), p.Cost)
}
