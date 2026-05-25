package sim

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

type Graph struct {
	topo        *model.Topology
	adj         map[string][]edge
	rib         map[string]map[string][]RIBEntry
	fib         map[string][]FIBEntry
	linksByName map[model.LinkID]model.Link
}

type edge struct {
	to   string
	link model.Link
}

type Path struct {
	Nodes []string
	Links []string
	Cost  int
}

type Result struct {
	Name           string
	Reachable      bool
	Expected       bool
	Path           Path
	Counterexample []string
	Reason         string
}

type RIBEntry struct {
	Prefix       model.Prefix
	Origin       string
	From         string
	NextHop      string
	Nodes        []string
	Links        []string
	ASPath       []uint32
	Communities  []string
	OriginCode   string
	LocalPref    int
	MED          int
	LearnedIBGP  bool
	Invalid      bool
	BaseCond     Cond
	Condition    Cond
	SelectedCond Cond
}

type FIBEntry struct {
	Prefix    netip.Prefix
	NextHop   string
	Path      Path
	Condition Cond
}

type FailureSet struct {
	Links map[model.LinkID]bool
	Nodes map[model.NodeID]bool
}

type FailureContext struct {
	Failures    FailureSet
	LinksByName map[model.LinkID]model.Link
}

type FailureSearchOptions struct {
	IncludeLinks bool
	IncludeNodes bool
	MaxFailures  int
}

type Cond interface {
	Eval(ctx FailureContext) bool
	String() string
}

type condVarKind string

const (
	condVarLink condVarKind = "link"
	condVarNode condVarKind = "node"
)

type trueCond struct{}
type varCond struct {
	kind condVarKind
	name string
}
type andCond []Cond
type orCond []Cond
type notCond struct{ c Cond }

func NoFailures() FailureSet {
	return FailureSet{Links: map[model.LinkID]bool{}, Nodes: map[model.NodeID]bool{}}
}

func LinkFailures(names ...model.LinkID) FailureSet {
	return NewFailureSet(names, nil)
}

func NodeFailures(names ...model.NodeID) FailureSet {
	return NewFailureSet(nil, names)
}

func NewFailureSet(links []model.LinkID, nodes []model.NodeID) FailureSet {
	out := NoFailures()
	for _, name := range links {
		out.Links[name] = true
	}
	for _, name := range nodes {
		out.Nodes[name] = true
	}
	return out
}

func FailureSetFromMap(raw map[string]bool) FailureSet {
	out := NoFailures()
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

func FailureSetFromElements(elements []solver.FailureElement) FailureSet {
	out := NoFailures()
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

func (ctx FailureContext) NodeFailed(node model.NodeID) bool {
	return ctx.Failures.Nodes[node]
}

func (ctx FailureContext) LinkFailed(linkName model.LinkID) bool {
	if ctx.Failures.Links[linkName] {
		return true
	}
	link, ok := ctx.LinksByName[linkName]
	if !ok {
		return false
	}
	return ctx.Failures.Nodes[model.NodeID(link.A)] || ctx.Failures.Nodes[model.NodeID(link.B)]
}

func True() Cond           { return trueCond{} }
func False() Cond          { return notCond{c: trueCond{}} }
func Var(name string) Cond { return LinkVar(name) }
func LinkVar(name string) Cond {
	return varCond{kind: condVarLink, name: name}
}
func NodeVar(name string) Cond {
	return varCond{kind: condVarNode, name: name}
}
func And(cs ...Cond) Cond                 { return flattenAnd(cs) }
func Or(cs ...Cond) Cond                  { return flattenOr(cs) }
func Not(c Cond) Cond                     { return notCond{c: c} }
func (trueCond) Eval(FailureContext) bool { return true }
func (trueCond) String() string           { return "true" }
func (c varCond) Eval(ctx FailureContext) bool {
	switch c.kind {
	case condVarNode:
		return !ctx.NodeFailed(model.NodeID(c.name))
	case condVarLink:
		return !ctx.LinkFailed(model.LinkID(c.name))
	default:
		return true
	}
}
func (c varCond) String() string { return string(c.kind) + ":" + c.name }
func (c andCond) Eval(ctx FailureContext) bool {
	for _, x := range c {
		if !x.Eval(ctx) {
			return false
		}
	}
	return true
}
func (c andCond) String() string { return joinCond(" && ", c) }
func (c orCond) Eval(ctx FailureContext) bool {
	for _, x := range c {
		if x.Eval(ctx) {
			return true
		}
	}
	return false
}
func (c orCond) String() string { return joinCond(" || ", c) }
func (c notCond) Eval(ctx FailureContext) bool {
	return !c.c.Eval(ctx)
}
func (c notCond) String() string { return "!(" + c.c.String() + ")" }

func NewGraph(topo *model.Topology) *Graph {
	g := &Graph{topo: topo, adj: map[string][]edge{}, rib: map[string]map[string][]RIBEntry{}, fib: map[string][]FIBEntry{}, linksByName: map[model.LinkID]model.Link{}}
	for _, l := range topo.Links {
		g.adj[l.A] = append(g.adj[l.A], edge{to: l.B, link: l})
		g.adj[l.B] = append(g.adj[l.B], edge{to: l.A, link: l})
		g.linksByName[model.LinkID(l.Name)] = l
	}
	for node := range g.adj {
		sort.Slice(g.adj[node], func(i, j int) bool {
			if g.adj[node][i].link.Cost == g.adj[node][j].link.Cost {
				return g.adj[node][i].to < g.adj[node][j].to
			}
			return g.adj[node][i].link.Cost < g.adj[node][j].link.Cost
		})
	}
	g.simulateControlPlane()
	g.deriveFIB()
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
	if failures.Links == nil {
		failures.Links = map[model.LinkID]bool{}
	}
	if failures.Nodes == nil {
		failures.Nodes = map[model.NodeID]bool{}
	}
	linksByName := g.linksByName
	if linksByName == nil {
		linksByName = map[model.LinkID]model.Link{}
		for _, link := range g.topo.Links {
			linksByName[model.LinkID(link.Name)] = link
		}
	}
	return FailureContext{Failures: failures, LinksByName: linksByName}
}

func (g *Graph) RouteReachable(from, prefix string, failures FailureSet) (Path, bool) {
	pfx, err := model.ParsePrefix(prefix)
	if err != nil {
		return Path{}, false
	}
	ctx := g.FailureContext(failures)
	if ctx.NodeFailed(model.NodeID(from)) {
		return Path{}, false
	}
	var best *RIBEntry
	for _, r := range g.rib[from][pfx.String()] {
		if r.SelectedCond != nil && r.SelectedCond.Eval(ctx) {
			cp := r
			best = &cp
			break
		}
	}
	if best == nil {
		return Path{}, false
	}
	nodes := append([]string(nil), best.Nodes...)
	links := append([]string(nil), best.Links...)
	reverse(nodes)
	reverse(links)
	return Path{Nodes: nodes, Links: links, Cost: g.pathCost(best.Links)}, true
}

func (g *Graph) PacketReachable(from, to, protocol string, failures FailureSet) (Path, bool, string) {
	ctx := g.FailureContext(failures)
	dstNode, dstPrefix, ok := g.topo.OriginForIP(to)
	if !ok {
		return Path{}, false, "destination prefix not advertised"
	}
	if ctx.NodeFailed(model.NodeID(from)) {
		return Path{}, false, "source node is down"
	}
	if ctx.NodeFailed(model.NodeID(dstNode)) {
		return Path{}, false, "destination node is down"
	}
	current := from
	visited := map[string]bool{}
	full := Path{Nodes: []string{from}}
	for {
		if ctx.NodeFailed(model.NodeID(current)) {
			return full, false, "current node is down"
		}
		if visited[current] {
			return full, false, "forwarding loop"
		}
		visited[current] = true
		if g.originates(current, dstPrefix.NetIP()) {
			return full, true, ""
		}
		currentNode, _ := g.topo.Node(current)
		if pol, ok := behaviorFor(currentNode.Kind).CheckDataIngress(currentNode, PacketMessage{Node: current, Prefix: dstPrefix.NetIP(), Protocol: protocol}, g.topo.Policies); ok {
			return full, false, "denied by policy " + pol
		}
		rule, ok := g.lookupFIB(current, to, ctx)
		if !ok {
			return full, false, "no forwarding route"
		}
		if pol, ok := behaviorFor(currentNode.Kind).CheckDataEgress(currentNode, PacketMessage{Node: current, Prefix: dstPrefix.NetIP(), Protocol: protocol}, g.topo.Policies); ok {
			return full, false, "denied by policy " + pol
		}
		if rule.NextHop == "" {
			return full, false, "selected route has no next-hop"
		}
		if ctx.NodeFailed(model.NodeID(rule.NextHop)) {
			return full, false, "next-hop node is down"
		}
		link, ok := g.linkBetween(current, rule.NextHop)
		if !ok || ctx.LinkFailed(model.LinkID(link.Name)) {
			return full, false, "next-hop link is down"
		}
		full.Links = append(full.Links, link.Name)
		full.Nodes = append(full.Nodes, rule.NextHop)
		full.Cost += link.Cost
		current = rule.NextHop
	}
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
	elements := g.failureSearchElements(opts)
	if len(elements) == 0 {
		return nil, false
	}
	var forbidden [][]solver.FailureElement
	for k := 0; k <= opts.MaxFailures; k++ {
		findElementCombo(elements, k, 0, nil, func(combo []solver.FailureElement) bool {
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

func (g *Graph) failureSearchElements(opts FailureSearchOptions) []solver.FailureElement {
	var elements []solver.FailureElement
	if opts.IncludeLinks {
		links := append([]model.Link(nil), g.topo.Links...)
		sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
		for _, link := range failureEligibleLinks(links) {
			elements = append(elements, solver.FailureElement{Kind: solver.FailureLink, Name: link.Name})
		}
	}
	if opts.IncludeNodes {
		nodes := append([]model.Node(nil), g.topo.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
		for _, node := range failureEligibleNodes(nodes) {
			elements = append(elements, solver.FailureElement{Kind: solver.FailureNode, Name: node.Name})
		}
	}
	return elements
}

func findElementCombo(elements []solver.FailureElement, want, start int, cur []solver.FailureElement, fn func([]solver.FailureElement) bool) bool {
	if len(cur) == want {
		return fn(cur)
	}
	for i := start; i < len(elements); i++ {
		cur = append(cur, elements[i])
		if findElementCombo(elements, want, i+1, cur, fn) {
			return true
		}
		cur = cur[:len(cur)-1]
	}
	return false
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

func (g *Graph) simulateControlPlane() {
	for _, origin := range g.topo.Nodes {
		for _, prefix := range origin.Prefixes {
			originCond := NodeVar(origin.Name)
			g.addRIB(origin.Name, prefix, RIBEntry{
				Prefix:     prefix,
				Origin:     origin.Name,
				Nodes:      []string{origin.Name},
				ASPath:     nil,
				OriginCode: "igp",
				LocalPref:  100,
				BaseCond:   originCond,
				Condition:  originCond,
			})
			g.walkBGP(RIBEntry{
				Prefix:     prefix,
				Origin:     origin.Name,
				NextHop:    "",
				Nodes:      []string{origin.Name},
				ASPath:     nil,
				OriginCode: "igp",
				BaseCond:   originCond,
				Condition:  originCond,
			})
		}
	}
	g.selectRoutes()
	g.convergeAdvertisementConditions()
}

func (g *Graph) selectRoutes() {
	for node, byPrefix := range g.rib {
		for prefix, routes := range byPrefix {
			n, _ := g.topo.Node(node)
			behavior := behaviorFor(n.Kind)
			routes = behavior.SelectRoutes(n, routes)
			for i := range routes {
				if routeInvalidForDevice(n, routes[i]) {
					routes[i].SelectedCond = False()
					continue
				}
				selected := routes[i].Condition
				var higherDistinct []Cond
				for j := 0; j < i; j++ {
					if routeInvalidForDevice(n, routes[j]) {
						continue
					}
					if behavior.DecisionProcess().Equivalent(n, routes[j], routes[i]) {
						continue
					}
					higherDistinct = append(higherDistinct, routes[j].Condition)
				}
				if len(higherDistinct) > 0 {
					selected = And(selected, Not(Or(higherDistinct...)))
				}
				routes[i].SelectedCond = selected
			}
			g.rib[node][prefix] = routes
		}
	}
}

func (g *Graph) applyAdvertisementConditions() bool {
	changed := false
	for node, byPrefix := range g.rib {
		for prefix, routes := range byPrefix {
			for i := range routes {
				base := routes[i].BaseCond
				if base == nil {
					base = routes[i].Condition
				}
				nextCond := base
				if len(routes[i].Nodes) > 1 {
					if parent, ok := g.parentRoute(routes[i]); ok {
						parentSelected := parent.SelectedCond
						if parentSelected == nil {
							parentSelected = parent.Condition
						}
						nextCond = And(base, parentSelected)
					} else {
						nextCond = False()
					}
				}
				if routes[i].Condition == nil || routes[i].Condition.String() != nextCond.String() {
					routes[i].Condition = nextCond
					changed = true
				}
			}
			g.rib[node][prefix] = routes
		}
	}
	return changed
}

func (g *Graph) convergeAdvertisementConditions() {
	maxIterations := g.maxRouteDepth() + 1
	if maxIterations < 1 {
		maxIterations = 1
	}
	for i := 0; i < maxIterations; i++ {
		if !g.applyAdvertisementConditions() {
			return
		}
		g.selectRoutes()
	}
	panic(fmt.Sprintf("advertisement conditions did not converge within %d iterations", maxIterations))
}

func (g *Graph) maxRouteDepth() int {
	maxDepth := 0
	for _, byPrefix := range g.rib {
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

func (g *Graph) parentRoute(route RIBEntry) (RIBEntry, bool) {
	if route.From == "" || len(route.Nodes) < 2 {
		return RIBEntry{}, false
	}
	parentNodes := strings.Join(route.Nodes[:len(route.Nodes)-1], ">")
	for _, candidate := range g.rib[route.From][route.Prefix.String()] {
		if strings.Join(candidate.Nodes, ">") == parentNodes {
			return candidate, true
		}
	}
	return RIBEntry{}, false
}

func (g *Graph) walkBGP(route RIBEntry) {
	current := route.Nodes[len(route.Nodes)-1]
	curNode, _ := g.topo.Node(current)
	curBehavior := behaviorFor(curNode.Kind)
	for _, e := range g.adj[current] {
		next := e.to
		session, ok := g.bgpSession(current, next)
		if !ok {
			continue
		}
		nextNode, _ := g.topo.Node(next)
		nextBehavior := behaviorFor(nextNode.Kind)
		exportMsg := ControlMessage{From: current, To: next, Prefix: route.Prefix.String(), Route: route}
		if !curBehavior.CheckControlEgress(curNode, exportMsg, g.topo.Policies) {
			continue
		}
		exported := curBehavior.ExportRoute(curNode, nextNode, session, route)
		if !exported.Accept {
			continue
		}
		exportPolicy := applyRoutePolicy(g.topo, curNode, next, session.ExportPolicy, exported.Route)
		if !exportPolicy.Accept {
			continue
		}
		exported.Route = exportPolicy.Route
		importMsg := ControlMessage{From: current, To: next, Prefix: exported.Route.Prefix.String(), Route: exported.Route}
		if !nextBehavior.CheckControlIngress(nextNode, importMsg, g.topo.Policies) {
			continue
		}
		receiverSession, _ := g.bgpSession(next, current)
		imported := nextBehavior.ImportRoute(nextNode, curNode, receiverSession, exported.Route)
		if !imported.Accept {
			continue
		}
		importPolicy := applyRoutePolicy(g.topo, nextNode, current, receiverSession.ImportPolicy, imported.Route)
		if !importPolicy.Accept {
			continue
		}
		imported.Route = importPolicy.Route
		revisitsNode := containsString(route.Nodes, next)
		if revisitsNode && !imported.Route.Invalid {
			continue
		}
		nextLinks := append(append([]string(nil), imported.Route.Links...), e.link.Name)
		nextNodes := append(append([]string(nil), imported.Route.Nodes...), next)
		nextCond := And(imported.Route.Condition, LinkVar(e.link.Name), NodeVar(next))

		entry := imported.Route
		entry.From = current
		entry.Nodes = nextNodes
		entry.Links = nextLinks
		entry.BaseCond = nextCond
		entry.Condition = nextCond
		entry.LocalPref = defaultLocalPref(entry.LocalPref)

		g.addRIB(next, entry.Prefix, entry)
		if routeInvalidForDevice(nextNode, entry) {
			continue
		}
		g.walkBGP(entry)
	}
}

func (g *Graph) bgpSession(a, b string) (model.BGPNeighbor, bool) {
	an, ok := g.topo.Node(a)
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

func (g *Graph) deriveFIB() {
	for node, byPrefix := range g.rib {
		var entries []FIBEntry
		n, _ := g.topo.Node(node)
		behavior := behaviorFor(n.Kind)
		for _, routes := range byPrefix {
			seenSelected := map[string]bool{}
			var installed []RIBEntry
			for _, route := range routes {
				selectedKey := ""
				if route.SelectedCond != nil {
					selectedKey = route.SelectedCond.String()
				}
				if seenSelected[selectedKey] {
					continue
				}
				if n.Kind == model.KindFRR && equivalentInstalledRoute(behavior.DecisionProcess(), n, installed, route) {
					continue
				}
				seenSelected[selectedKey] = true
				installed = append(installed, route)
				entries = append(entries, FIBEntry{
					Prefix:    route.Prefix.NetIP(),
					NextHop:   route.NextHop,
					Path:      Path{Nodes: route.Nodes, Links: route.Links, Cost: g.pathCost(route.Links)},
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
		g.fib[node] = entries
	}
}

func equivalentInstalledRoute(decision BGPDecisionProcess, node model.Node, installed []RIBEntry, route RIBEntry) bool {
	for _, existing := range installed {
		if decision.Equivalent(node, existing, route) {
			return true
		}
	}
	return false
}

func (g *Graph) addRIB(node string, prefix model.Prefix, entry RIBEntry) {
	if g.rib[node] == nil {
		g.rib[node] = map[string][]RIBEntry{}
	}
	key := prefix.String()
	for _, existing := range g.rib[node][key] {
		if routeKey(existing) == routeKey(entry) {
			return
		}
	}
	g.rib[node][key] = append(g.rib[node][key], entry)
}

func (g *Graph) lookupFIB(node, dst string, ctx FailureContext) (FIBEntry, bool) {
	ip, err := netip.ParseAddr(dst)
	if err != nil {
		return FIBEntry{}, false
	}
	for _, rule := range g.fib[node] {
		if rule.Prefix.Contains(ip) && rule.Condition.Eval(ctx) {
			return rule, true
		}
	}
	return FIBEntry{}, false
}

func (g *Graph) originates(node string, prefix netip.Prefix) bool {
	n, ok := g.topo.Node(node)
	if !ok {
		return false
	}
	for _, raw := range n.Prefixes {
		if raw.NetIP() == prefix {
			return true
		}
	}
	return false
}

func (g *Graph) linkBetween(a, b string) (model.Link, bool) {
	for _, l := range g.topo.Links {
		if (l.A == a && l.B == b) || (l.A == b && l.B == a) {
			return l, true
		}
	}
	return model.Link{}, false
}

func (g *Graph) pathCost(links []string) int {
	cost := 0
	for _, name := range links {
		for _, l := range g.topo.Links {
			if l.Name == name {
				cost += l.Cost
				break
			}
		}
	}
	return cost
}

func routeKey(r RIBEntry) string {
	valid := "valid"
	if r.Invalid {
		valid = "invalid"
	}
	return r.Prefix.String() + "|" + r.Origin + "|" + strings.Join(r.Nodes, ">") + "|" + valid
}

func routeInvalidForDevice(device model.Node, route RIBEntry) bool {
	if route.Invalid {
		return true
	}
	if device.Kind == model.KindCEOS && route.NextHop != "" && route.NextHop != route.From {
		return true
	}
	return false
}

func failureEligibleLinks(links []model.Link) []model.Link {
	var out []model.Link
	for _, l := range links {
		if strings.Contains(l.Name, "cust") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func failureEligibleNodes(nodes []model.Node) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if strings.Contains(n.Name, "cust") {
			continue
		}
		out = append(out, n)
	}
	return out
}

func FormatPath(p Path) string {
	if len(p.Nodes) == 0 {
		return ""
	}
	return fmt.Sprintf("%s cost=%d", strings.Join(p.Nodes, " -> "), p.Cost)
}

func flattenAnd(cs []Cond) Cond {
	var out []Cond
	for _, c := range cs {
		if _, ok := c.(trueCond); ok {
			continue
		}
		if xs, ok := c.(andCond); ok {
			out = append(out, xs...)
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return trueCond{}
	}
	if len(out) == 1 {
		return out[0]
	}
	return andCond(out)
}

func flattenOr(cs []Cond) Cond {
	var out []Cond
	for _, c := range cs {
		if xs, ok := c.(orCond); ok {
			out = append(out, xs...)
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return notCond{c: trueCond{}}
	}
	if len(out) == 1 {
		return out[0]
	}
	return orCond(out)
}

func joinCond(sep string, cs []Cond) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.String())
	}
	return "(" + strings.Join(parts, sep) + ")"
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

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

func reverse[T any](xs []T) {
	for i, j := 0, len(xs)-1; i < j; i, j = i+1, j-1 {
		xs[i], xs[j] = xs[j], xs[i]
	}
}
