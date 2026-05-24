package verify

import (
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

type Report struct {
	Results []sim.Result
}

func Run(topo *model.Topology, queries *model.Queries) Report {
	g := sim.NewGraph(topo)
	report := Report{}
	for _, q := range queries.RouteChecks {
		path, reachable := g.RouteReachable(q.From, q.Prefix, sim.NoFailures())
		result := sim.Result{Name: q.Name, Reachable: reachable, Expected: true, Path: path}
		if cut, ok := g.FindBreakingFailures(q.From, sim.PrefixTarget(q.Prefix), q.MaxFailures); ok {
			result.Counterexample = cut
			result.Reason = "reachable now but not resilient to requested failure budget"
		}
		report.Results = append(report.Results, result)
	}
	for _, q := range queries.PacketChecks {
		path, reachable, reason := g.PacketReachable(q.From, q.To, q.Protocol, sim.NoFailures())
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		result := sim.Result{Name: q.Name, Reachable: reachable, Expected: expected, Path: path, Reason: reason}
		if expected && reachable {
			if cut, ok := g.FindBreakingFailures(q.From, sim.PacketTarget{To: q.To, Protocol: q.Protocol}, q.MaxFailures); ok {
				result.Counterexample = cut
				result.Reason = "reachable now but not resilient to requested failure budget"
			}
		}
		report.Results = append(report.Results, result)
	}
	for _, q := range queries.FailureChecks {
		var target sim.Target
		if q.Prefix != "" {
			target = sim.PrefixTarget(q.Prefix)
		} else {
			target = sim.PacketTarget{To: q.To, Protocol: q.Protocol}
		}
		expected := true
		if q.ExpectReachable != nil {
			expected = *q.ExpectReachable
		}
		result := sim.Result{Name: q.Name, Expected: expected}
		if cut, ok := g.FindBreakingFailures(q.From, target, q.MaxFailures); ok {
			result.Reachable = false
			result.Counterexample = cut
			result.Reason = "counterexample within failure budget"
		} else {
			result.Reachable = true
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func (r Report) OK() bool {
	for _, result := range r.Results {
		if result.Reachable != result.Expected {
			return false
		}
	}
	return true
}
