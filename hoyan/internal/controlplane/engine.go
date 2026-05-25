package controlplane

import (
	"fmt"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

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
	BaseCond     failure.Cond
	Condition    failure.Cond
	SelectedCond failure.Cond
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
				Prefix:     prefix,
				Origin:     origin.Name,
				Nodes:      []string{origin.Name},
				ASPath:     nil,
				OriginCode: "igp",
				LocalPref:  100,
				BaseCond:   originCond,
				Condition:  originCond,
			})
			e.walkBGP(RIBEntry{
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
				if RouteInvalidForDevice(n, routes[i]) {
					routes[i].SelectedCond = failure.False()
					continue
				}
				selected := routes[i].Condition
				var higherDistinct []failure.Cond
				for j := 0; j < i; j++ {
					if RouteInvalidForDevice(n, routes[j]) {
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
		entry.BaseCond = nextCond
		entry.Condition = nextCond
		entry.LocalPref = defaultLocalPref(entry.LocalPref)

		e.addRIB(next, entry.Prefix, entry)
		if RouteInvalidForDevice(nextNode, entry) {
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

func RouteInvalidForDevice(device model.Node, route RIBEntry) bool {
	if route.Invalid {
		return true
	}
	if device.Kind == model.KindCEOS && route.NextHop != "" && route.NextHop != route.From {
		return true
	}
	return false
}

func routeKey(r RIBEntry) string {
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
