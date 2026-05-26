package controlplane

import "github.com/81ueman/network-sandbox/hoyan/internal/model"

type srlinuxBehavior struct{ baseDeviceBehavior }

func NewSRLinuxBehavior() DeviceBehavior {
	return srlinuxBehavior{baseDeviceBehavior{kind: model.KindSRLinux, decision: srlinuxDecisionProcess{defaultBGPDecisionProcess{options: DefaultBGPDecisionOptions()}}}}
}

type srlinuxDecisionProcess struct{ defaultBGPDecisionProcess }

func (d srlinuxDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
	return d.defaultBGPDecisionProcess.Less(receiver, a, b)
}

func (srlinuxDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	return false
}

func (b srlinuxBehavior) ImportRoute(to model.Node, from model.Node, session model.BGPNeighbor, route RIBEntry) BGPRouteDecision {
	route = route.Normalize()
	if containsASN(route.ASPath, to.ASN) {
		route.Invalid = true
		route.Attrs.Invalid = true
		return BGPRouteDecision{Route: route, Accept: true, Reason: "as loop"}
	}
	return b.baseDeviceBehavior.ImportRoute(to, from, session, route)
}
