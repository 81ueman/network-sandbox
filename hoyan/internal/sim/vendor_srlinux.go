package sim

import "github.com/81ueman/network-sandbox/hoyan/internal/model"

type srlinuxBehavior struct{ baseDeviceBehavior }

func NewSRLinuxBehavior() DeviceBehavior {
	return srlinuxBehavior{baseDeviceBehavior{kind: model.KindSRLinux, decision: srlinuxDecisionProcess{}}}
}

type srlinuxDecisionProcess struct{}

func (srlinuxDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
	return defaultBGPDecisionProcess{}.Less(receiver, a, b)
}

func (srlinuxDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	return false
}

func (b srlinuxBehavior) ImportRoute(to model.Node, from model.Node, session model.BGPNeighbor, route RIBEntry) BGPRouteDecision {
	if containsASN(route.ASPath, to.ASN) {
		route.Invalid = true
		return BGPRouteDecision{Route: route, Accept: true, Reason: "as loop"}
	}
	return b.baseDeviceBehavior.ImportRoute(to, from, session, route)
}
