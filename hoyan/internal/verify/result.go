package verify

import (
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

type QueryType string

const (
	QueryTypeRoute       QueryType = "route"
	QueryTypePacket      QueryType = "packet"
	QueryTypeFailure     QueryType = "failure"
	QueryTypePrefixClass QueryType = "prefix_class"
	QueryTypeSetup       QueryType = "setup"
)

type Report struct {
	Stats   *model.PrefixUniverseStats `json:"prefix_universe_stats,omitempty"`
	Results []Result                   `json:"results"`
}

type Result struct {
	Name        string               `json:"name"`
	Type        QueryType            `json:"type"`
	Metadata    ResultMetadata       `json:"metadata"`
	Route       *RouteResult         `json:"route,omitempty"`
	Packet      *PacketResult        `json:"packet,omitempty"`
	Failure     *FailureResult       `json:"failure,omitempty"`
	PrefixClass *PrefixClassMetadata `json:"prefix_class,omitempty"`
	Solver      *sim.SolverTrace     `json:"solver,omitempty"`
}

type ResultMetadata struct {
	Expected  bool   `json:"expected"`
	Reachable bool   `json:"reachable"`
	Reason    string `json:"reason,omitempty"`
}

type RouteResult struct {
	Path                 sim.Path `json:"path,omitempty"`
	Counterexample       []string `json:"counterexample,omitempty"`
	ReachableCondition   string   `json:"reachable_condition,omitempty"`
	UnreachableCondition string   `json:"unreachable_condition,omitempty"`
}

type PacketResult struct {
	Path                 sim.Path `json:"path,omitempty"`
	Counterexample       []string `json:"counterexample,omitempty"`
	ReachableCondition   string   `json:"reachable_condition,omitempty"`
	UnreachableCondition string   `json:"unreachable_condition,omitempty"`
}

type FailureResult struct {
	Counterexample       []string `json:"counterexample,omitempty"`
	ReachableCondition   string   `json:"reachable_condition,omitempty"`
	UnreachableCondition string   `json:"unreachable_condition,omitempty"`
}

type PrefixClassMetadata struct {
	ClassID           *model.PrefixClassID  `json:"class_id,omitempty"`
	ClassIDs          []model.PrefixClassID `json:"class_ids,omitempty"`
	Space             string                `json:"space,omitempty"`
	Spaces            []string              `json:"spaces,omitempty"`
	MatchedPredicates []string              `json:"matched_predicates,omitempty"`
}

func NewRouteResult(name string, reachable bool, expected bool, path sim.Path, reason string) Result {
	return Result{
		Name: name,
		Type: QueryTypeRoute,
		Metadata: ResultMetadata{
			Expected:  expected,
			Reachable: reachable,
			Reason:    reason,
		},
		Route: &RouteResult{Path: path},
	}
}

func NewPacketResult(name string, reachable bool, expected bool, path sim.Path, reason string) Result {
	return Result{
		Name: name,
		Type: QueryTypePacket,
		Metadata: ResultMetadata{
			Expected:  expected,
			Reachable: reachable,
			Reason:    reason,
		},
		Packet: &PacketResult{Path: path},
	}
}

func NewFailureResult(name string, reachable bool, expected bool, reason string) Result {
	return Result{
		Name: name,
		Type: QueryTypeFailure,
		Metadata: ResultMetadata{
			Expected:  expected,
			Reachable: reachable,
			Reason:    reason,
		},
		Failure: &FailureResult{},
	}
}

func NewSetupResult(name string, expected bool, reason string) Result {
	return Result{
		Name: name,
		Type: QueryTypeSetup,
		Metadata: ResultMetadata{
			Expected: expected,
			Reason:   reason,
		},
	}
}

func (r Result) Path() sim.Path {
	if r.Route != nil {
		return r.Route.Path
	}
	if r.Packet != nil {
		return r.Packet.Path
	}
	return sim.Path{}
}

func (r Result) Counterexample() []string {
	if r.Route != nil {
		return r.Route.Counterexample
	}
	if r.Packet != nil {
		return r.Packet.Counterexample
	}
	if r.Failure != nil {
		return r.Failure.Counterexample
	}
	return nil
}

func (r Result) ReachableCondition() string {
	if r.Route != nil {
		return r.Route.ReachableCondition
	}
	if r.Packet != nil {
		return r.Packet.ReachableCondition
	}
	if r.Failure != nil {
		return r.Failure.ReachableCondition
	}
	return ""
}

func (r Result) UnreachableCondition() string {
	if r.Route != nil {
		return r.Route.UnreachableCondition
	}
	if r.Packet != nil {
		return r.Packet.UnreachableCondition
	}
	if r.Failure != nil {
		return r.Failure.UnreachableCondition
	}
	return ""
}

func (r *Result) SetCounterexample(counterexample []string) {
	if r.Route != nil {
		r.Route.Counterexample = counterexample
		return
	}
	if r.Packet != nil {
		r.Packet.Counterexample = counterexample
		return
	}
	if r.Failure != nil {
		r.Failure.Counterexample = counterexample
	}
}

func (r *Result) SetConditions(reachable, unreachable string) {
	if r.Route != nil {
		r.Route.ReachableCondition = reachable
		r.Route.UnreachableCondition = unreachable
		return
	}
	if r.Packet != nil {
		r.Packet.ReachableCondition = reachable
		r.Packet.UnreachableCondition = unreachable
		return
	}
	if r.Failure != nil {
		r.Failure.ReachableCondition = reachable
		r.Failure.UnreachableCondition = unreachable
	}
}
