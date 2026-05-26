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

type VerifyOptions struct {
	UsePrefixUniverse         bool
	CollapseEquivalentResults bool
	MaxPrefixClasses          int
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
		result := NewRouteResult(q.Name, reachable, true, path, "")
		if cut, ok := findBreakingFailures(g, q.From, sim.PrefixTarget(q.Prefix.String()), failureSearchOptions(q.MaxFailures, q.FailureDomain), &result); ok {
			result.SetCounterexample(formatFailureElements(cut))
			result.Metadata.Reason = "reachable now but not resilient to requested failure budget"
		}
		report.Results = append(report.Results, result)
	}
	for _, q := range queries.PacketChecks {
		ports := q.DstPortValues()
		for _, port := range ports {
			spec := model.PacketSpec{Protocol: q.Protocol, DstPort: model.ExactPort(port)}
			path, reachable, reason := g.PacketReachableSpec(q.From, q.To, spec, sim.NoFailures())
			expected := true
			if q.ExpectReachable != nil {
				expected = *q.ExpectReachable
			}
			result := NewPacketResult(queryResultName(q.Name, port, len(ports)), reachable, expected, path, reason)
			if expected && reachable {
				target := sim.PacketTarget{To: q.To, Protocol: q.Protocol, DstPort: port}
				if cut, ok := findBreakingFailures(g, q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain), &result); ok {
					result.SetCounterexample(formatFailureElements(cut))
					result.Metadata.Reason = "reachable now but not resilient to requested failure budget"
				}
			}
			report.Results = append(report.Results, result)
		}
	}
	for _, q := range queries.FailureChecks {
		ports := q.DstPortValues()
		for _, port := range ports {
			var target sim.SymbolicTarget
			if !q.Prefix.IsZero() {
				target = sim.PacketPrefixTarget{Prefix: q.Prefix, Protocol: q.Protocol, DstPort: port}
			} else {
				target = sim.PacketTarget{To: q.To, Protocol: q.Protocol, DstPort: port}
			}
			expected := true
			if q.ExpectReachable != nil {
				expected = *q.ExpectReachable
			}
			result := NewFailureResult(queryResultName(q.Name, port, len(ports)), true, expected, "")
			if cut, ok := findBreakingFailures(g, q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain), &result); ok {
				result.Metadata.Reachable = false
				result.SetCounterexample(formatFailureElements(cut))
				result.Metadata.Reason = "counterexample within failure budget"
			}
			report.Results = append(report.Results, result)
		}
	}
	return report
}

func runPrefixClasses(topo *model.Topology, queries *model.Queries, opts VerifyOptions) Report {
	g := sim.NewGraph(topo)
	universe, err := prefixUniverseForGraph(topo, queries, g, nil)
	if err != nil {
		return Report{Results: []Result{NewSetupResult("prefix-universe", true, err.Error())}}
	}
	if err := checkPrefixClassLimit(universe, opts.MaxPrefixClasses); err != nil {
		stats := universe.Stats
		return Report{Stats: &stats, Results: []Result{NewSetupResult("prefix-universe", true, err.Error())}}
	}
	stats := universe.Stats
	report := Report{Stats: &stats}
	for _, q := range queries.RouteChecks {
		classes := universe.ClassesMatching(model.ExactPrefixSet{Prefix: q.Prefix})
		for _, classID := range classes {
			class, ok := prefixClass(universe, classID)
			if !ok {
				continue
			}
			symbolic := g.SymbolicRouteReachabilityForPrefixSet(q.From, class.Space)
			path, reachable := g.RouteReachableForPrefixSet(q.From, class.Space, sim.NoFailures())
			result := classResult(universe, class, NewRouteResult(q.Name, reachable, true, path, symbolic.Reason))
			result.SetConditions(symbolic.Reachable.String(), symbolic.Unreachable.String())
			if reachable {
				target := sim.RouteClassTarget{Universe: universe, ClassID: classID}
				if cut, ok := findBreakingFailures(g, q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain), &result); ok {
					result.SetCounterexample(formatFailureElements(cut))
					result.Metadata.Reason = "reachable now but not resilient to requested failure budget"
				}
			}
			report.Results = append(report.Results, result)
		}
	}
	for _, q := range queries.PacketChecks {
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		ports := q.DstPortValues()
		for _, port := range ports {
			spec := model.PacketSpec{Protocol: q.Protocol, DstPort: model.ExactPort(port)}
			for _, classID := range packetClasses(topo, universe, q.To) {
				class, ok := prefixClass(universe, classID)
				if !ok {
					continue
				}
				symbolic := g.SymbolicPacketReachabilityForPrefixSetSpec(q.From, class.Space, spec)
				reachable := symbolic.Reachable.Eval(g.FailureContext(sim.NoFailures()))
				result := classResult(universe, class, NewPacketResult(queryResultName(q.Name, port, len(ports)), reachable, expected, sim.Path{}, symbolic.Reason))
				result.SetConditions(symbolic.Reachable.String(), symbolic.Unreachable.String())
				if expected && reachable {
					target := sim.PacketClassTarget{Universe: universe, ClassID: classID, Protocol: q.Protocol, DstPort: port}
					if cut, ok := findBreakingFailures(g, q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain), &result); ok {
						result.SetCounterexample(formatFailureElements(cut))
						result.Metadata.Reason = "reachable now but not resilient to requested failure budget"
					}
				}
				report.Results = append(report.Results, result)
			}
		}
	}
	for _, q := range queries.FailureChecks {
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		ports := q.DstPortValues()
		for _, port := range ports {
			for _, classID := range failureClasses(topo, universe, q) {
				class, ok := prefixClass(universe, classID)
				if !ok {
					continue
				}
				target := sim.PacketClassTarget{Universe: universe, ClassID: classID, Protocol: q.Protocol, DstPort: port}
				symbolic := g.SymbolicPacketReachabilityForPrefixSetSpec(q.From, class.Space, target.Spec())
				result := classResult(universe, class, NewFailureResult(queryResultName(q.Name, port, len(ports)), true, expected, symbolic.Reason))
				result.SetConditions(symbolic.Reachable.String(), symbolic.Unreachable.String())
				if cut, ok := findBreakingFailures(g, q.From, target, failureSearchOptions(q.MaxFailures, q.FailureDomain), &result); ok {
					result.Metadata.Reachable = false
					result.SetCounterexample(formatFailureElements(cut))
					result.Metadata.Reason = "counterexample within failure budget"
				}
				report.Results = append(report.Results, result)
			}
		}
	}
	if opts.CollapseEquivalentResults {
		report.Results = collapseResults(report.Results)
	}
	return report
}

func queryResultName(name string, port int, portCount int) string {
	if portCount <= 1 || port <= 0 {
		return name
	}
	return fmt.Sprintf("%s:dst-port-%d", name, port)
}

func prefixUniverseForGraph(topo *model.Topology, queries *model.Queries, g *sim.Graph, extra []model.PrefixPredicate) (model.PrefixUniverse, error) {
	predicates := model.CollectPrefixPredicateMetadata(topo, queries)
	predicates = append(predicates, sim.CollectRIBPrefixPredicates(g)...)
	predicates = append(predicates, sim.CollectFIBPrefixPredicates(g)...)
	predicates = append(predicates, extra...)
	return model.BuildPrefixUniverseFromPredicates(predicates)
}

func checkPrefixClassLimit(universe model.PrefixUniverse, maxClasses int) error {
	if maxClasses <= 0 || universe.Stats.ClassCount <= maxClasses {
		return nil
	}
	return fmt.Errorf("prefix universe class count %d exceeds --max-prefix-classes %d", universe.Stats.ClassCount, maxClasses)
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

func classResult(universe model.PrefixUniverse, class model.PrefixClass, result Result) Result {
	id := class.ID
	result.PrefixClass = &PrefixClassMetadata{
		ClassID:           &id,
		ClassIDs:          []model.PrefixClassID{id},
		Space:             class.Space.String(),
		Spaces:            []string{class.Space.String()},
		MatchedPredicates: matchedPredicates(universe, class),
	}
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

func collapseResults(results []Result) []Result {
	type aggregate struct {
		result Result
		seen   map[string]bool
	}
	groups := map[string]*aggregate{}
	var order []string
	for _, result := range results {
		key := collapseKey(result)
		group, ok := groups[key]
		if !ok {
			cp := result
			cp.PrefixClass = &PrefixClassMetadata{}
			group = &aggregate{result: cp, seen: map[string]bool{}}
			groups[key] = group
			order = append(order, key)
		}
		if result.PrefixClass != nil && result.PrefixClass.ClassID != nil {
			classKey := fmt.Sprintf("%d", *result.PrefixClass.ClassID)
			if !group.seen[classKey] {
				group.seen[classKey] = true
				group.result.PrefixClass.ClassIDs = append(group.result.PrefixClass.ClassIDs, *result.PrefixClass.ClassID)
			}
		}
		if result.PrefixClass != nil {
			if result.PrefixClass.Space != "" && !containsString(group.result.PrefixClass.Spaces, result.PrefixClass.Space) {
				group.result.PrefixClass.Spaces = append(group.result.PrefixClass.Spaces, result.PrefixClass.Space)
			}
			for _, predicate := range result.PrefixClass.MatchedPredicates {
				if !containsString(group.result.PrefixClass.MatchedPredicates, predicate) {
					group.result.PrefixClass.MatchedPredicates = append(group.result.PrefixClass.MatchedPredicates, predicate)
				}
			}
		}
	}
	out := make([]Result, 0, len(order))
	for _, key := range order {
		result := groups[key].result
		if result.PrefixClass != nil {
			sort.Slice(result.PrefixClass.ClassIDs, func(i, j int) bool {
				return result.PrefixClass.ClassIDs[i] < result.PrefixClass.ClassIDs[j]
			})
			sort.Strings(result.PrefixClass.Spaces)
			sort.Strings(result.PrefixClass.MatchedPredicates)
		}
		out = append(out, result)
	}
	return out
}

func collapseKey(result Result) string {
	return strings.Join([]string{
		result.Name,
		string(result.Type),
		fmt.Sprint(result.Metadata.Reachable),
		fmt.Sprint(result.Metadata.Expected),
		strings.Join(result.Counterexample(), ","),
		result.Metadata.Reason,
		result.ReachableCondition(),
		result.UnreachableCondition(),
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

func findBreakingFailures(g *sim.Graph, from string, target sim.SymbolicTarget, opts sim.FailureSearchOptions, result *Result) ([]solver.FailureElement, bool) {
	search, err := g.FindBreakingFailuresSymbolic(from, target, opts)
	result.Solver = &search.Solver
	if err != nil {
		result.Metadata.Reason = appendReason(result.Metadata.Reason, "failure search error: "+err.Error())
		return nil, false
	}
	if !search.Sat {
		return nil, false
	}
	return search.Failures, true
}

func appendReason(existing, extra string) string {
	if existing == "" {
		return extra
	}
	return existing + "; " + extra
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
		if result.Metadata.Reachable != result.Metadata.Expected {
			return false
		}
	}
	return true
}
