package controlplane

import (
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type frrBehavior struct{ baseDeviceBehavior }

func NewFRRBehavior() DeviceBehavior {
	return frrBehavior{baseDeviceBehavior{kind: model.KindFRR, decision: frrDecisionProcess{defaultBGPDecisionProcess{options: DefaultBGPDecisionOptions()}}}}
}

type frrDecisionProcess struct{ defaultBGPDecisionProcess }

func (d frrDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
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
	return strings.Join(a.Nodes, ",") > strings.Join(b.Nodes, ",")
}

func (d frrDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	return d.defaultBGPDecisionProcess.Equivalent(receiver, a, b)
}

func (b frrBehavior) RouteInstallableInFIB(device model.Node, installed []RIBEntry, route RIBEntry) bool {
	if !b.baseDeviceBehavior.RouteInstallableInFIB(device, installed, route) {
		return false
	}
	return !EquivalentInstalledRoute(b.DecisionProcess(), device, installed, route)
}
