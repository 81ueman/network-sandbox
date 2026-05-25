package controlplane

import (
	"fmt"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type RIBEntry struct {
	NLRI              RouteNLRI
	Attrs             BGPAttributes
	Provenance        RouteProvenance
	ForwardingNextHop RouteNextHop

	// Deprecated: use NLRI.Prefix. This compatibility field will be removed after callers migrate.
	Prefix model.Prefix
	// Deprecated: use Provenance.OriginNode. This is an origin node, not a BGP origin-code.
	Origin string
	// Deprecated: use Provenance.FromNode.
	From string
	// Deprecated: use ForwardingNextHop.Node for simulated routes. Live comparison resolves ForwardingNextHop.Addr separately.
	NextHop string
	// Deprecated: use Provenance.PathNodes.
	Nodes []string
	// Deprecated: use Provenance.PathLinks.
	Links []string
	// Deprecated: use Attrs.ASPath.
	ASPath []uint32
	// Deprecated: use Attrs.Communities.
	Communities []string
	// Deprecated: use Attrs.OriginCode.
	OriginCode string
	// Deprecated: use Attrs.LocalPref.
	LocalPref int
	// Deprecated: use Attrs.MED.
	MED int
	// Deprecated: use Attrs.LearnedIBGP.
	LearnedIBGP bool
	// Deprecated: use Attrs.Invalid.
	Invalid      bool
	BaseCond     failure.Cond
	Condition    failure.Cond
	SelectedCond failure.Cond
}

type RouteNLRI struct {
	Prefix model.Prefix
}

type BGPOriginCode string

const (
	BGPOriginIGP        BGPOriginCode = "igp"
	BGPOriginEGP        BGPOriginCode = "egp"
	BGPOriginIncomplete BGPOriginCode = "incomplete"
)

type BGPAttributes struct {
	ASPath      []uint32
	Communities []string
	OriginCode  BGPOriginCode
	LocalPref   int
	MED         int
	LearnedIBGP bool
	Invalid     bool
}

type RouteProvenance struct {
	OriginNode string
	FromNode   string
	PathNodes  []string
	PathLinks  []string
}

// RouteNextHop keeps simulated forwarding next-hop node identity separate from
// the resolved address used when comparing against live device RIB output.
type RouteNextHop struct {
	Node string
	Addr string
}

func (h RouteNextHop) Valid() bool {
	return h.Node != "" || h.Addr != ""
}

func (r RIBEntry) Normalize() RIBEntry {
	if r.NLRI.Prefix.IsZero() {
		r.NLRI.Prefix = r.Prefix
	}
	if r.Prefix.IsZero() {
		r.Prefix = r.NLRI.Prefix
	}
	if r.Provenance.OriginNode == "" {
		r.Provenance.OriginNode = r.Origin
	}
	if r.Origin == "" {
		r.Origin = r.Provenance.OriginNode
	}
	if r.Provenance.FromNode == "" {
		r.Provenance.FromNode = r.From
	}
	if r.From == "" {
		r.From = r.Provenance.FromNode
	}
	if len(r.Provenance.PathNodes) == 0 {
		r.Provenance.PathNodes = append([]string(nil), r.Nodes...)
	}
	if len(r.Nodes) == 0 {
		r.Nodes = append([]string(nil), r.Provenance.PathNodes...)
	}
	if len(r.Provenance.PathLinks) == 0 {
		r.Provenance.PathLinks = append([]string(nil), r.Links...)
	}
	if len(r.Links) == 0 {
		r.Links = append([]string(nil), r.Provenance.PathLinks...)
	}
	if r.ForwardingNextHop.Node == "" {
		r.ForwardingNextHop.Node = r.NextHop
	}
	if r.NextHop == "" {
		r.NextHop = r.ForwardingNextHop.Node
	}
	if r.Attrs.ASPath == nil {
		r.Attrs.ASPath = append([]uint32(nil), r.ASPath...)
	}
	if r.ASPath == nil {
		r.ASPath = append([]uint32(nil), r.Attrs.ASPath...)
	}
	if r.Attrs.Communities == nil {
		r.Attrs.Communities = append([]string(nil), r.Communities...)
	}
	if r.Communities == nil {
		r.Communities = append([]string(nil), r.Attrs.Communities...)
	}
	if r.Attrs.OriginCode == "" {
		r.Attrs.OriginCode = BGPOriginCode(r.OriginCode)
	}
	if r.Attrs.OriginCode == "" {
		r.Attrs.OriginCode = BGPOriginIGP
	}
	if r.OriginCode == "" {
		r.OriginCode = string(r.Attrs.OriginCode)
	}
	if r.Attrs.LocalPref == 0 {
		r.Attrs.LocalPref = r.LocalPref
	}
	if r.LocalPref == 0 {
		r.LocalPref = r.Attrs.LocalPref
	}
	if r.Attrs.MED == 0 {
		r.Attrs.MED = r.MED
	}
	if r.MED == 0 {
		r.MED = r.Attrs.MED
	}
	r.Attrs.LearnedIBGP = r.Attrs.LearnedIBGP || r.LearnedIBGP
	r.LearnedIBGP = r.Attrs.LearnedIBGP
	r.Attrs.Invalid = r.Attrs.Invalid || r.Invalid
	r.Invalid = r.Attrs.Invalid
	return r
}

type Engine struct {
	idx *model.TopologyIndex
	rib map[string]map[string][]RIBEntry
}

func NewEngine(idx *model.TopologyIndex, rib map[string]map[string][]RIBEntry) *Engine {
	return &Engine{idx: idx, rib: rib}
}

func (e *Engine) Simulate() {
	for _, origin := range e.idx.Topology.Nodes {
		for _, prefix := range origin.Prefixes {
			originCond := failure.NodeVar(origin.Name)
			e.addRIB(origin.Name, prefix, RIBEntry{
				NLRI:       RouteNLRI{Prefix: prefix},
				Attrs:      BGPAttributes{OriginCode: BGPOriginIGP, LocalPref: 100},
				Provenance: RouteProvenance{OriginNode: origin.Name, PathNodes: []string{origin.Name}},
				BaseCond:   originCond,
				Condition:  originCond,
			})
			e.walkBGP(RIBEntry{
				NLRI:       RouteNLRI{Prefix: prefix},
				Attrs:      BGPAttributes{OriginCode: BGPOriginIGP},
				Provenance: RouteProvenance{OriginNode: origin.Name, PathNodes: []string{origin.Name}},
				BaseCond:   originCond,
				Condition:  originCond,
			})
		}
	}
	e.SelectRoutes()
	e.ConvergeAdvertisementConditions()
}

func (e *Engine) SelectRoutes() {
	for node, byPrefix := range e.rib {
		for prefix, routes := range byPrefix {
			n, _ := e.idx.Node(node)
			behavior := BehaviorFor(n.Kind)
			routes = behavior.SelectRoutes(n, routes)
			for i := range routes {
				if !behavior.RouteValidForRIB(n, routes[i]) {
					routes[i].SelectedCond = failure.False()
					continue
				}
				selected := routes[i].Condition
				var higherDistinct []failure.Cond
				for j := 0; j < i; j++ {
					if !behavior.RouteValidForRIB(n, routes[j]) {
						continue
					}
					if behavior.DecisionProcess().Equivalent(n, routes[j], routes[i]) {
						continue
					}
					higherDistinct = append(higherDistinct, routes[j].Condition)
				}
				if len(higherDistinct) > 0 {
					selected = failure.And(selected, failure.Not(failure.Or(higherDistinct...)))
				}
				routes[i].SelectedCond = selected
			}
			e.rib[node][prefix] = routes
		}
	}
}

func (e *Engine) ApplyAdvertisementConditions() bool {
	changed := false
	for node, byPrefix := range e.rib {
		for prefix, routes := range byPrefix {
			for i := range routes {
				base := routes[i].BaseCond
				if base == nil {
					base = routes[i].Condition
				}
				nextCond := base
				if len(routes[i].Nodes) > 1 {
					if parent, ok := e.ParentRoute(routes[i]); ok {
						parentSelected := parent.SelectedCond
						if parentSelected == nil {
							parentSelected = parent.Condition
						}
						nextCond = failure.And(base, parentSelected)
					} else {
						nextCond = failure.False()
					}
				}
				if routes[i].Condition == nil || routes[i].Condition.Key() != nextCond.Key() {
					routes[i].Condition = nextCond
					changed = true
				}
			}
			e.rib[node][prefix] = routes
		}
	}
	return changed
}

func (e *Engine) ConvergeAdvertisementConditions() {
	maxIterations := e.MaxRouteDepth() + 1
	if maxIterations < 1 {
		maxIterations = 1
	}
	for i := 0; i < maxIterations; i++ {
		if !e.ApplyAdvertisementConditions() {
			return
		}
		e.SelectRoutes()
	}
	panic(fmt.Sprintf("advertisement conditions did not converge within %d iterations", maxIterations))
}

func (e *Engine) MaxRouteDepth() int {
	maxDepth := 0
	for _, byPrefix := range e.rib {
		for _, routes := range byPrefix {
			for _, route := range routes {
				if len(route.Nodes) > maxDepth {
					maxDepth = len(route.Nodes)
				}
			}
		}
	}
	return maxDepth
}

func (e *Engine) ParentRoute(route RIBEntry) (RIBEntry, bool) {
	route = route.Normalize()
	if route.From == "" || len(route.Nodes) < 2 {
		return RIBEntry{}, false
	}
	parentNodes := strings.Join(route.Nodes[:len(route.Nodes)-1], ">")
	for _, candidate := range e.rib[route.From][route.Prefix.String()] {
		if strings.Join(candidate.Nodes, ">") == parentNodes {
			return candidate, true
		}
	}
	return RIBEntry{}, false
}

func (e *Engine) walkBGP(route RIBEntry) {
	route = route.Normalize()
	current := route.Nodes[len(route.Nodes)-1]
	curNode, _ := e.idx.Node(current)
	curBehavior := BehaviorFor(curNode.Kind)
	for _, adj := range e.idx.Adj[model.NodeID(current)] {
		next := string(adj.To)
		session, ok := e.bgpSession(current, next)
		if !ok {
			continue
		}
		nextNode, _ := e.idx.Node(next)
		nextBehavior := BehaviorFor(nextNode.Kind)
		exportMsg := ControlMessage{From: current, To: next, Prefix: route.Prefix.String(), Route: route}
		if !curBehavior.CheckControlEgress(curNode, exportMsg, e.idx.Topology.Policies) {
			continue
		}
		exported := curBehavior.ExportRoute(curNode, nextNode, session, route)
		if !exported.Accept {
			continue
		}
		exportPolicy := applyRoutePolicy(e.idx, curNode, next, session.ExportPolicy, exported.Route)
		if !exportPolicy.Accept {
			continue
		}
		exported.Route = exportPolicy.Route
		importMsg := ControlMessage{From: current, To: next, Prefix: exported.Route.Prefix.String(), Route: exported.Route}
		if !nextBehavior.CheckControlIngress(nextNode, importMsg, e.idx.Topology.Policies) {
			continue
		}
		receiverSession, _ := e.bgpSession(next, current)
		imported := nextBehavior.ImportRoute(nextNode, curNode, receiverSession, exported.Route)
		if !imported.Accept {
			continue
		}
		importPolicy := applyRoutePolicy(e.idx, nextNode, current, receiverSession.ImportPolicy, imported.Route)
		if !importPolicy.Accept {
			continue
		}
		imported.Route = importPolicy.Route
		revisitsNode := containsString(route.Nodes, next)
		if revisitsNode && !imported.Route.Invalid {
			continue
		}
		nextLinks := append(append([]string(nil), imported.Route.Links...), adj.Link.Name)
		nextNodes := append(append([]string(nil), imported.Route.Nodes...), next)
		nextCond := failure.And(imported.Route.Condition, failure.LinkVar(adj.Link.Name), failure.NodeVar(next))

		entry := imported.Route
		entry.From = current
		entry.Nodes = nextNodes
		entry.Links = nextLinks
		entry.Provenance.FromNode = current
		entry.Provenance.PathNodes = append([]string(nil), nextNodes...)
		entry.Provenance.PathLinks = append([]string(nil), nextLinks...)
		entry.BaseCond = nextCond
		entry.Condition = nextCond
		entry.LocalPref = defaultLocalPref(entry.LocalPref)
		entry.Attrs.LocalPref = entry.LocalPref
		entry = entry.Normalize()

		e.addRIB(next, entry.Prefix, entry)
		if !nextBehavior.RouteEligibleForAdvertisement(nextNode, entry) {
			continue
		}
		e.walkBGP(entry)
	}
}

func (e *Engine) bgpSession(a, b string) (model.BGPNeighbor, bool) {
	an, ok := e.idx.Node(a)
	if !ok {
		return model.BGPNeighbor{}, false
	}
	for _, peer := range an.Neighbors {
		if peer.PeerNode == b && (peer.Activated || peer.RemoteAS != 0) {
			return peer, true
		}
	}
	return model.BGPNeighbor{}, false
}

func (e *Engine) addRIB(node string, prefix model.Prefix, entry RIBEntry) {
	entry = entry.Normalize()
	if prefix.IsZero() {
		prefix = entry.Prefix
	}
	if e.rib[node] == nil {
		e.rib[node] = map[string][]RIBEntry{}
	}
	key := prefix.String()
	for _, existing := range e.rib[node][key] {
		if routeKey(existing) == routeKey(entry) {
			return
		}
	}
	e.rib[node][key] = append(e.rib[node][key], entry)
}

func EquivalentInstalledRoute(decision BGPDecisionProcess, node model.Node, installed []RIBEntry, route RIBEntry) bool {
	for _, existing := range installed {
		if decision.Equivalent(node, existing, route) {
			return true
		}
	}
	return false
}

func routeKey(r RIBEntry) string {
	r = r.Normalize()
	valid := "valid"
	if r.Invalid {
		valid = "invalid"
	}
	return r.Prefix.String() + "|" + r.Origin + "|" + strings.Join(r.Nodes, ">") + "|" + valid
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsASN(xs []uint32, x uint32) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func prependASN(asn uint32, path []uint32) []uint32 {
	out := make([]uint32, 0, len(path)+1)
	out = append(out, asn)
	out = append(out, path...)
	return out
}
