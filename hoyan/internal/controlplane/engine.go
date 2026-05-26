package controlplane

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type RIBEntry struct {
	NLRI                  RouteNLRI
	Attrs                 BGPAttributes
	Provenance            RouteProvenance
	ForwardingNextHop     RouteNextHop
	SourceKind            model.RouteSourceKind
	RouteSource           model.ConfiguredRoute
	AggregateContributors []string

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
	if r.SourceKind == "" {
		r.SourceKind = model.RouteSourceBGP
	}
	if r.RouteSource.Kind == "" {
		r.RouteSource.Kind = r.SourceKind
	}
	if r.RouteSource.Prefix.IsZero() {
		r.RouteSource.Prefix = r.Prefix
	}
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
		for _, route := range e.connectedRoutes(origin) {
			e.installConfiguredRoute(origin, route)
		}
		for _, route := range origin.Routes {
			if route.Kind == model.RouteSourceAggregate {
				continue
			}
			e.installConfiguredRoute(origin, route)
		}
		for _, prefix := range origin.Prefixes {
			originCond := failure.NodeVar(origin.Name)
			route := RIBEntry{
				NLRI:        RouteNLRI{Prefix: prefix},
				Attrs:       BGPAttributes{OriginCode: BGPOriginIGP, LocalPref: 100},
				Provenance:  RouteProvenance{OriginNode: origin.Name, PathNodes: []string{origin.Name}},
				SourceKind:  model.RouteSourceBGP,
				RouteSource: model.ConfiguredRoute{Node: origin.Name, NetworkInstance: model.NetworkInstanceDefault, AFI: model.AFIIPv4, Prefix: prefix, Kind: model.RouteSourceBGP, AdminDistance: 200},
				BaseCond:    originCond,
				Condition:   originCond,
			}
			e.addRIB(origin.Name, prefix, route)
			e.walkBGP(route)
		}
		for _, route := range e.redistributedRoutes(origin) {
			e.walkBGP(route)
		}
	}
	e.SelectRoutes()
	e.ConvergeAdvertisementConditions()
	for _, origin := range e.idx.Topology.Nodes {
		for _, route := range e.aggregateRoutes(origin) {
			e.addRIB(origin.Name, route.Prefix, route)
			e.walkBGP(route)
		}
	}
	e.SelectRoutes()
	e.ConvergeAdvertisementConditions()
}

func (e *Engine) connectedRoutes(node model.Node) []model.ConfiguredRoute {
	var out []model.ConfiguredRoute
	for _, iface := range node.Interfaces {
		pfx, err := netip.ParsePrefix(iface.Address)
		if err != nil {
			continue
		}
		prefix := model.PrefixFromNetIP(pfx.Masked())
		out = append(out, model.ConfiguredRoute{
			Node:            node.Name,
			NetworkInstance: model.NetworkInstanceDefault,
			AFI:             model.AFIIPv4,
			Prefix:          prefix,
			Interface:       iface.Name,
			Kind:            model.RouteSourceConnected,
			ConnectedClass:  e.idx.ConnectedClass(node.Name, iface, prefix),
			AdminDistance:   0,
		})
	}
	return out
}

func (e *Engine) installConfiguredRoute(node model.Node, route model.ConfiguredRoute) {
	if route.Prefix.IsZero() {
		return
	}
	route.Node = node.Name
	if route.NetworkInstance == "" {
		route.NetworkInstance = model.NetworkInstanceDefault
	}
	if route.AFI == "" {
		route.AFI = model.AFIIPv4
	}
	if route.AdminDistance == 0 && route.Kind != model.RouteSourceConnected {
		route.AdminDistance = 1
	}
	cond := failure.NodeVar(node.Name)
	entry := RIBEntry{
		NLRI:              RouteNLRI{Prefix: route.Prefix},
		Attrs:             BGPAttributes{OriginCode: BGPOriginIncomplete},
		Provenance:        RouteProvenance{OriginNode: node.Name, PathNodes: []string{node.Name}},
		ForwardingNextHop: e.configuredRouteNextHop(node.Name, route),
		SourceKind:        route.Kind,
		RouteSource:       route,
		BaseCond:          cond,
		Condition:         cond,
	}
	e.addRIB(node.Name, route.Prefix, entry)
}

func (e *Engine) redistributedRoutes(node model.Node) []RIBEntry {
	var out []RIBEntry
	for _, redist := range node.Redistribute {
		for _, route := range e.redistributionCandidates(node, redist.Kind) {
			entry := e.bgpRouteFromConfiguredRoute(node, route)
			if redist.RouteMap != "" {
				decision := applyRoutePolicy(e.idx, node, "", redist.RouteMap, entry)
				if !decision.Accept {
					continue
				}
				entry = decision.Route
			}
			e.addRIB(node.Name, entry.Prefix, entry)
			out = append(out, entry)
		}
	}
	return out
}

func (e *Engine) redistributionCandidates(node model.Node, kind model.RouteSourceKind) []model.ConfiguredRoute {
	var out []model.ConfiguredRoute
	if kind == model.RouteSourceConnected {
		out = append(out, e.connectedRoutes(node)...)
	}
	if kind == model.RouteSourceStatic {
		for _, route := range node.Routes {
			if route.Kind == model.RouteSourceStatic || route.Kind == model.RouteSourceBlackhole {
				out = append(out, route)
			}
		}
	}
	return out
}

func (e *Engine) bgpRouteFromConfiguredRoute(node model.Node, route model.ConfiguredRoute) RIBEntry {
	cond := failure.NodeVar(node.Name)
	entry := RIBEntry{
		NLRI:       RouteNLRI{Prefix: route.Prefix},
		Attrs:      BGPAttributes{OriginCode: BGPOriginIncomplete, LocalPref: 100},
		Provenance: RouteProvenance{OriginNode: node.Name, PathNodes: []string{node.Name}},
		SourceKind: model.RouteSourceBGP,
		RouteSource: model.ConfiguredRoute{
			Node:            node.Name,
			NetworkInstance: model.NetworkInstanceDefault,
			AFI:             model.AFIIPv4,
			Prefix:          route.Prefix,
			Kind:            model.RouteSourceBGP,
			Source:          route.Source,
			AdminDistance:   200,
		},
		BaseCond:  cond,
		Condition: cond,
	}
	return entry.Normalize()
}

func (e *Engine) aggregateRoutes(node model.Node) []RIBEntry {
	var out []RIBEntry
	for _, route := range node.Routes {
		if route.Kind != model.RouteSourceAggregate || route.Prefix.IsZero() {
			continue
		}
		route.Node = node.Name
		if route.NetworkInstance == "" {
			route.NetworkInstance = model.NetworkInstanceDefault
		}
		if route.AFI == "" {
			route.AFI = model.AFIIPv4
		}
		if route.AdminDistance == 0 {
			route.AdminDistance = 200
		}
		cond, contributors, ok := e.aggregateContributorCond(node.Name, route.Prefix)
		if !ok {
			continue
		}
		entry := RIBEntry{
			NLRI:                  RouteNLRI{Prefix: route.Prefix},
			Attrs:                 BGPAttributes{OriginCode: BGPOriginIGP, LocalPref: 100},
			Provenance:            RouteProvenance{OriginNode: node.Name, PathNodes: []string{node.Name}},
			SourceKind:            model.RouteSourceAggregate,
			RouteSource:           route,
			AggregateContributors: contributors,
			BaseCond:              cond,
			Condition:             cond,
		}
		out = append(out, entry.Normalize())
	}
	return out
}

func (e *Engine) aggregateContributorCond(node string, aggregate model.Prefix) (failure.Cond, []string, bool) {
	var contributors []failure.Cond
	contributorPrefixes := map[string]bool{}
	for prefix, routes := range e.rib[node] {
		candidate, err := model.ParsePrefix(prefix)
		if err != nil || !isMoreSpecificWithin(candidate, aggregate) {
			continue
		}
		for _, route := range routes {
			route = route.Normalize()
			if route.SourceKind == model.RouteSourceAggregate {
				continue
			}
			cond := route.SelectedCond
			if cond == nil {
				cond = route.Condition
			}
			if cond != nil {
				contributors = append(contributors, cond)
				contributorPrefixes[candidate.String()] = true
			}
		}
	}
	if len(contributors) == 0 {
		return failure.False(), nil, false
	}
	prefixes := make([]string, 0, len(contributorPrefixes))
	for prefix := range contributorPrefixes {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	return failure.Or(contributors...), prefixes, true
}

func isMoreSpecificWithin(candidate, aggregate model.Prefix) bool {
	if candidate.IsZero() || aggregate.IsZero() {
		return false
	}
	return candidate.Bits() > aggregate.Bits() && aggregate.Contains(candidate.Addr())
}

func (e *Engine) configuredRouteNextHop(node string, route model.ConfiguredRoute) RouteNextHop {
	if route.NextHop == "" {
		return RouteNextHop{}
	}
	for _, adj := range e.idx.Adj[model.NodeID(node)] {
		if addr, ok := e.idx.PeerAddress(node, string(adj.To)); ok && addr.String() == route.NextHop {
			return RouteNextHop{Node: string(adj.To), Addr: route.NextHop}
		}
	}
	return RouteNextHop{Addr: route.NextHop}
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
					if routeSelectionFamily(routes[j]) != routeSelectionFamily(routes[i]) {
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

func routeSelectionFamily(route RIBEntry) model.RouteSourceKind {
	route = route.Normalize()
	if route.SourceKind == model.RouteSourceBGP || route.SourceKind == model.RouteSourceAggregate {
		return model.RouteSourceBGP
	}
	return ""
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
						if len(parent.Normalize().Nodes) == 1 && (parent.SourceKind == model.RouteSourceBGP || parent.SourceKind == model.RouteSourceAggregate) {
							parentSelected = parent.Condition
						}
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
		candidate = candidate.Normalize()
		if candidate.SourceKind != route.SourceKind {
			continue
		}
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
		routeForExport := e.applyAggregateSuppression(curNode, route)
		exported := curBehavior.ExportRoute(curNode, nextNode, session, routeForExport)
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

func (e *Engine) applyAggregateSuppression(node model.Node, route RIBEntry) RIBEntry {
	route = route.Normalize()
	for _, aggregate := range node.Routes {
		if aggregate.Kind != model.RouteSourceAggregate || !aggregate.SummaryOnly {
			continue
		}
		if !isMoreSpecificWithin(route.Prefix, aggregate.Prefix) {
			continue
		}
		cond, _, ok := e.aggregateContributorCond(node.Name, aggregate.Prefix)
		if !ok {
			continue
		}
		route.BaseCond = failure.And(route.BaseCond, failure.Not(cond))
		route.Condition = failure.And(route.Condition, failure.Not(cond))
	}
	return route.Normalize()
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
	return r.Prefix.String() + "|" + string(r.SourceKind) + "|" + r.Origin + "|" + r.NextHop + "|" + r.RouteSource.Interface + "|" + strings.Join(r.Nodes, ">") + "|" + valid
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
