package sim

import (
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type frrBehavior struct{ baseDeviceBehavior }

func NewFRRBehavior() DeviceBehavior {
	return frrBehavior{baseDeviceBehavior{kind: model.KindFRR, decision: frrDecisionProcess{}}}
}

type frrDecisionProcess struct{}

func (frrDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
	if a.LocalPref != b.LocalPref {
		return a.LocalPref > b.LocalPref
	}
	if a.Origin == receiver.Name || b.Origin == receiver.Name {
		return a.Origin == receiver.Name
	}
	if len(a.ASPath) != len(b.ASPath) {
		return len(a.ASPath) < len(b.ASPath)
	}
	if a.MED != b.MED {
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
	return strings.Join(a.Nodes, ",") > strings.Join(b.Nodes, ",")
}

func (frrDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	return defaultBGPDecisionProcess{}.Equivalent(receiver, a, b)
}
