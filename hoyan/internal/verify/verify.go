package verify

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

type Report struct {
	Results []sim.Result
}

type VerifyOptions struct {
	UsePrefixUniverse         bool
	CollapseEquivalentResults bool
}

func Run(topo *model.Topology, queries *model.Queries) Report {
	return RunWithOptions(topo, queries, VerifyOptions{})
}

func RunWithOptions(topo *model.Topology, queries *model.Queries, opts VerifyOptions) Report {
	if !opts.UsePrefixUniverse {
		return runLegacy(topo, queries)
	}
	return runPrefixClasses(topo, queries, opts)
}

func runLegacy(topo *model.Topology, queries *model.Queries) Report {
	g := sim.NewGraph(topo)
	report := Report{}
	for _, q := range queries.RouteChecks {
		path, reachable := g.RouteReachable(q.From, q.Prefix.String(), sim.NoFailures())
		result := sim.Result{Name: q.Name, QueryType: "route", Reachable: reachable, Expected: true, Path: path}
		if cut, ok := g.FindBreakingFailuresWithOptions(q.From, sim.PrefixTarget(q.Prefix.String()), failureSearchOptions(q.MaxFailures, q.FailureDomain)); ok {
			result.Counterexample = formatFailureElements(cut)
			result.Reason = "reachable now but not resilient to requested failure budget"
		}
		report.Results = append(report.Results, result)
	}
	for _, q := range queries.PacketChecks {
		spec := model.PacketSpec{Protocol: q.Protocol, DstPort: model.ExactPort(q.DstPort)}
		path, reachable, reason := g.PacketReachableSpec(q.From, q.To, spec, sim.NoFailures())
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		result := sim.Result{Name: q.Name, QueryType: "packet", Reachable: reachable, Expected: expected, Path: path, Reason: reason}
		if expected && reachable {
			if cut, ok := g.FindBreakingFailuresWithOptions(q.From, sim.PacketTarget{To: q.To, Protocol: q.Protocol, DstPort: q.DstPort}, failureSearchOptions(q.MaxFailures, q.FailureDomain)); ok {
				result.Counterexample = formatFailureElements(cut)
				result.Reason = "reachable now but not resilient to requested failure budget"
			}
		}
		report.Results = append(report.Results, result)
	}
	for _, q := range queries.FailureChecks {
		var target sim.Target
		if !q.Prefix.IsZero() {
			target = sim.PacketPrefixTarget{Prefix: q.Prefix, Protocol: q.Protocol, DstPort: q.DstPort}
		} else {
			target = sim.PacketTarget{To: q.To, Protocol: q.Protocol, DstPort: q.DstPort}
		}
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		result := sim.Result{Name: q.Name, QueryType: "failure", Expected: expected}
		if cut, ok := g.FindBreakingFailuresWithOptions(q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain)); ok {
			result.Reachable = false
			result.Counterexample = formatFailureElements(cut)
			result.Reason = "counterexample within failure budget"
		} else {
			result.Reachable = true
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func runPrefixClasses(topo *model.Topology, queries *model.Queries, opts VerifyOptions) Report {
	g := sim.NewGraph(topo)
	universe, err := model.NewPrefixUniverse(topo, queries)
	if err != nil {
		return Report{Results: []sim.Result{{
			Name:      "prefix-universe",
			QueryType: "setup",
			Expected:  true,
			Reason:    err.Error(),
		}}}
	}
	report := Report{}
	for _, q := range queries.RouteChecks {
		classes := universe.ClassesMatching(model.ExactPrefixSet{Prefix: q.Prefix})
		for _, classID := range classes {
			class, ok := prefixClass(universe, classID)
			if !ok {
				continue
			}
			symbolic := g.SymbolicRouteReachabilityForPrefixSet(q.From, class.Space)
			path, reachable := g.RouteReachableForPrefixSet(q.From, class.Space, sim.NoFailures())
			result := classResult(universe, class, sim.Result{
				Name:                 q.Name,
				QueryType:            "route",
				Reachable:            reachable,
				Expected:             true,
				Path:                 path,
				ReachableCondition:   symbolic.Reachable.String(),
				UnreachableCondition: symbolic.Unreachable.String(),
				Reason:               symbolic.Reason,
			})
			if reachable {
				target := sim.RouteClassTarget{Universe: universe, ClassID: classID}
				if cut, ok := g.FindBreakingFailuresWithOptions(q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain)); ok {
					result.Counterexample = formatFailureElements(cut)
					result.Reason = "reachable now but not resilient to requested failure budget"
				}
			}
			report.Results = append(report.Results, result)
		}
	}
	for _, q := range queries.PacketChecks {
		spec := model.PacketSpec{Protocol: q.Protocol, DstPort: model.ExactPort(q.DstPort)}
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		for _, classID := range packetClasses(topo, universe, q.To) {
			class, ok := prefixClass(universe, classID)
			if !ok {
				continue
			}
			symbolic := g.SymbolicPacketReachabilityForPrefixSetSpec(q.From, class.Space, spec)
			reachable := symbolic.Reachable.Eval(g.FailureContext(sim.NoFailures()))
			result := classResult(universe, class, sim.Result{
				Name:                 q.Name,
				QueryType:            "packet",
				Reachable:            reachable,
				Expected:             expected,
				ReachableCondition:   symbolic.Reachable.String(),
				UnreachableCondition: symbolic.Unreachable.String(),
				Reason:               symbolic.Reason,
			})
			if expected && reachable {
				target := sim.PacketClassTarget{Universe: universe, ClassID: classID, Protocol: q.Protocol, DstPort: q.DstPort}
				if cut, ok := g.FindBreakingFailuresWithOptions(q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain)); ok {
					result.Counterexample = formatFailureElements(cut)
					result.Reason = "reachable now but not resilient to requested failure budget"
				}
			}
			report.Results = append(report.Results, result)
		}
	}
	for _, q := range queries.FailureChecks {
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		for _, classID := range failureClasses(topo, universe, q) {
			class, ok := prefixClass(universe, classID)
			if !ok {
				continue
			}
			target := sim.PacketClassTarget{Universe: universe, ClassID: classID, Protocol: q.Protocol, DstPort: q.DstPort}
			symbolic := g.SymbolicPacketReachabilityForPrefixSetSpec(q.From, class.Space, target.Spec())
			result := classResult(universe, class, sim.Result{
				Name:                 q.Name,
				QueryType:            "failure",
				Expected:             expected,
				ReachableCondition:   symbolic.Reachable.String(),
				UnreachableCondition: symbolic.Unreachable.String(),
				Reason:               symbolic.Reason,
			})
			if cut, ok := g.FindBreakingFailuresWithOptions(q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain)); ok {
				result.Reachable = false
				result.Counterexample = formatFailureElements(cut)
				result.Reason = "counterexample within failure budget"
			} else {
				result.Reachable = true
			}
			report.Results = append(report.Results, result)
		}
	}
	if opts.CollapseEquivalentResults {
		report.Results = collapseResults(report.Results)
	}
	return report
}

func packetClasses(topo *model.Topology, universe model.PrefixUniverse, to string) []model.PrefixClassID {
	if addr, err := netip.ParseAddr(to); err == nil {
		return classesForAddr(universe, addr)
	}
	return classesForDestinationNode(topo, universe, to)
}

func failureClasses(topo *model.Topology, universe model.PrefixUniverse, q model.FailureCheck) []model.PrefixClassID {
	if !q.Prefix.IsZero() {
		return universe.ClassesMatching(model.ExactPrefixSet{Prefix: q.Prefix})
	}
	return packetClasses(topo, universe, q.To)
}

func classesForDestinationNode(topo *model.Topology, universe model.PrefixUniverse, to string) []model.PrefixClassID {
	if topo == nil {
		return nil
	}
	node, ok := topo.Node(to)
	if !ok {
		return nil
	}
	seen := map[model.PrefixClassID]bool{}
	var out []model.PrefixClassID
	for _, prefix := range node.Prefixes {
		for _, id := range universe.ClassesMatching(model.ExactPrefixSet{Prefix: prefix}) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func classesForAddr(universe model.PrefixUniverse, addr netip.Addr) []model.PrefixClassID {
	for _, class := range universe.Classes {
		if model.AddressSpaceContains(class.Space, addr) {
			return []model.PrefixClassID{class.ID}
		}
	}
	return nil
}

func prefixClass(universe model.PrefixUniverse, id model.PrefixClassID) (model.PrefixClass, bool) {
	for _, class := range universe.Classes {
		if class.ID == id {
			return class, true
		}
	}
	return model.PrefixClass{}, false
}

func classResult(universe model.PrefixUniverse, class model.PrefixClass, result sim.Result) sim.Result {
	id := class.ID
	result.PrefixClassID = &id
	result.PrefixClassIDs = []model.PrefixClassID{id}
	result.PrefixSpace = class.Space.String()
	result.PrefixSpaces = []string{class.Space.String()}
	result.MatchedPredicates = matchedPredicates(universe, class)
	return result
}

func matchedPredicates(universe model.PrefixUniverse, class model.PrefixClass) []string {
	byID := map[model.PrefixPredicateID]string{}
	for _, predicate := range universe.Predicates {
		byID[predicate.ID] = predicate.Source
	}
	out := make([]string, 0, len(class.MatchingPredicates))
	seen := map[string]bool{}
	for _, id := range class.MatchingPredicates {
		if source := byID[id]; source != "" {
			if seen[source] {
				continue
			}
			seen[source] = true
			out = append(out, source)
		}
	}
	sort.Strings(out)
	return out
}

func collapseResults(results []sim.Result) []sim.Result {
	type aggregate struct {
		result sim.Result
		seen   map[string]bool
	}
	groups := map[string]*aggregate{}
	var order []string
	for _, result := range results {
		key := collapseKey(result)
		group, ok := groups[key]
		if !ok {
			cp := result
			cp.PrefixClassID = nil
			cp.PrefixClassIDs = nil
			cp.PrefixSpace = ""
			cp.PrefixSpaces = nil
			cp.MatchedPredicates = nil
			group = &aggregate{result: cp, seen: map[string]bool{}}
			groups[key] = group
			order = append(order, key)
		}
		if result.PrefixClassID != nil {
			classKey := fmt.Sprintf("%d", *result.PrefixClassID)
			if !group.seen[classKey] {
				group.seen[classKey] = true
				group.result.PrefixClassIDs = append(group.result.PrefixClassIDs, *result.PrefixClassID)
			}
		}
		if result.PrefixSpace != "" && !containsString(group.result.PrefixSpaces, result.PrefixSpace) {
			group.result.PrefixSpaces = append(group.result.PrefixSpaces, result.PrefixSpace)
		}
		for _, predicate := range result.MatchedPredicates {
			if !containsString(group.result.MatchedPredicates, predicate) {
				group.result.MatchedPredicates = append(group.result.MatchedPredicates, predicate)
			}
		}
	}
	out := make([]sim.Result, 0, len(order))
	for _, key := range order {
		result := groups[key].result
		sort.Slice(result.PrefixClassIDs, func(i, j int) bool { return result.PrefixClassIDs[i] < result.PrefixClassIDs[j] })
		sort.Strings(result.PrefixSpaces)
		sort.Strings(result.MatchedPredicates)
		out = append(out, result)
	}
	return out
}

func collapseKey(result sim.Result) string {
	return strings.Join([]string{
		result.Name,
		result.QueryType,
		fmt.Sprint(result.Reachable),
		fmt.Sprint(result.Expected),
		strings.Join(result.Counterexample, ","),
		result.Reason,
		result.ReachableCondition,
		result.UnreachableCondition,
	}, "\x00")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func failureSearchOptions(maxFailures int, domain model.FailureDomain) sim.FailureSearchOptions {
	return sim.FailureSearchOptions{
		IncludeLinks: true,
		MaxFailures:  maxFailures,
		Domain:       domain,
	}
}

func formatFailureElements(elements []solver.FailureElement) []string {
	out := make([]string, 0, len(elements))
	for _, element := range elements {
		if element.Kind == solver.FailureLink {
			out = append(out, element.Name)
			continue
		}
		out = append(out, element.String())
	}
	return out
}

func (r Report) OK() bool {
	for _, result := range r.Results {
		if result.Reachable != result.Expected {
			return false
		}
	}
	return true
}
