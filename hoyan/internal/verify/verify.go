package verify

import (
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
	"github.com/81ueman/network-sandbox/hoyan/internal/solver"
)

type Report struct {
	Results []sim.Result
}

func Run(topo *model.Topology, queries *model.Queries) Report {
	g := sim.NewGraph(topo)
	report := Report{}
	for _, q := range queries.RouteChecks {
		path, reachable := g.RouteReachable(q.From, q.Prefix.String(), sim.NoFailures())
		result := sim.Result{Name: q.Name, Reachable: reachable, Expected: true, Path: path}
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
		result := sim.Result{Name: q.Name, Reachable: reachable, Expected: expected, Path: path, Reason: reason}
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
		result := sim.Result{Name: q.Name, Expected: expected}
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
