package controlplane

import (
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type BGPDecisionProcess interface {
	Less(receiver model.Node, a, b RIBEntry) bool
	Equivalent(receiver model.Node, a, b RIBEntry) bool
}

// BGPDecisionOptions documents vendor bestpath knobs that the model can expose
// explicitly. Not every option is implemented by every decision process yet;
// unsupported knobs are intentionally visible so modeled/live RIB differences
// can point at a known approximation instead of an implicit gap.
type BGPDecisionOptions struct {
	// AlwaysCompareMED preserves the current Hoyan approximation: MED is
	// compared even when candidate paths were learned from different neighbor
	// ASNs. Set false to compare MED only within the same neighboring AS.
	AlwaysCompareMED bool
	// DeterministicMED is documented but not implemented. The model currently
	// sorts all candidate routes in one pass instead of grouping by neighbor AS.
	DeterministicMED bool
	// CompareRouterID is documented but not implemented because modeled routes
	// do not carry router-id or originator-id attributes yet.
	CompareRouterID bool
	// PreferLowerRouterID documents the common router-id tie-break direction
	// for vendors that enable CompareRouterID. It is unused until router-id
	// comparison is implemented.
	PreferLowerRouterID bool
	// Multipath is documented but not implemented here. ECMP/FIB equivalence is
	// tracked separately from single-best BGP route ordering.
	Multipath bool
}

func DefaultBGPDecisionOptions() BGPDecisionOptions {
	return BGPDecisionOptions{
		AlwaysCompareMED:    true,
		PreferLowerRouterID: true,
	}
}

type defaultBGPDecisionProcess struct {
	options BGPDecisionOptions
}

func DefaultBGPDecisionProcess() BGPDecisionProcess {
	return NewBGPDecisionProcess(DefaultBGPDecisionOptions())
}

func NewBGPDecisionProcess(options BGPDecisionOptions) BGPDecisionProcess {
	return defaultBGPDecisionProcess{options: options}
}

func (d defaultBGPDecisionProcess) Options() BGPDecisionOptions {
	return d.options
}

func (d defaultBGPDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
	a = a.Normalize()
	b = b.Normalize()
	if a.LocalPref != b.LocalPref {
		return a.LocalPref > b.LocalPref
	}
	if a.Origin == receiver.Name || b.Origin == receiver.Name {
		return a.Origin == receiver.Name
	}
	if len(a.ASPath) != len(b.ASPath) {
		return len(a.ASPath) < len(b.ASPath)
	}
	if originCodeRank(a.Attrs.OriginCode) != originCodeRank(b.Attrs.OriginCode) {
		return originCodeRank(a.Attrs.OriginCode) < originCodeRank(b.Attrs.OriginCode)
	}
	if d.shouldCompareMED(a, b) && a.MED != b.MED {
		return a.MED < b.MED
	}
	aExternal := !a.LearnedIBGP
	bExternal := !b.LearnedIBGP
	if aExternal != bExternal {
		return aExternal
	}
	if len(a.Links) != len(b.Links) {
		return len(a.Links) < len(b.Links)
	}
	return strings.Join(a.Nodes, ",") < strings.Join(b.Nodes, ",")
}

func (d defaultBGPDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	a = a.Normalize()
	b = b.Normalize()
	if a.LocalPref != b.LocalPref {
		return false
	}
	if (a.Origin == receiver.Name) != (b.Origin == receiver.Name) {
		return false
	}
	if len(a.ASPath) != len(b.ASPath) {
		return false
	}
	if originCodeRank(a.Attrs.OriginCode) != originCodeRank(b.Attrs.OriginCode) {
		return false
	}
	if d.shouldCompareMED(a, b) && a.MED != b.MED {
		return false
	}
	return a.LearnedIBGP == b.LearnedIBGP
}

func (d defaultBGPDecisionProcess) shouldCompareMED(a, b RIBEntry) bool {
	if d.options.AlwaysCompareMED {
		return true
	}
	return neighboringAS(a) == neighboringAS(b)
}

func neighboringAS(route RIBEntry) uint32 {
	if len(route.ASPath) == 0 {
		return 0
	}
	return route.ASPath[0]
}

func originCodeRank(origin BGPOriginCode) int {
	switch origin {
	case BGPOriginIGP:
		return 0
	case BGPOriginEGP:
		return 1
	case BGPOriginIncomplete:
		return 2
	default:
		return 3
	}
}

func firstHopExternal(localASN uint32, path []uint32) bool {
	if len(path) == 0 {
		return false
	}
	return path[0] != localASN
}
