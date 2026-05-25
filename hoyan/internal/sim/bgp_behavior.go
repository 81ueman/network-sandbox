package sim

import (
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type BGPRouteDecision struct {
	Route  RIBEntry
	Accept bool
	Reason string
}

type BGPBehavior interface {
	SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry
	ExportRoute(from model.Node, to model.Node, session model.BGPNeighbor, route RIBEntry) BGPRouteDecision
	ImportRoute(to model.Node, from model.Node, session model.BGPNeighbor, route RIBEntry) BGPRouteDecision
	DecisionProcess() BGPDecisionProcess
}

type baseDeviceBehavior struct {
	kind     string
	decision BGPDecisionProcess
}

func NewGenericBehavior(kind string) DeviceBehavior {
	return baseDeviceBehavior{kind: kind, decision: DefaultBGPDecisionProcess()}
}

func (b baseDeviceBehavior) SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry {
	out := append([]RIBEntry(nil), routes...)
	sort.Slice(out, func(i, j int) bool {
		return b.DecisionProcess().Less(device, out[i], out[j])
	})
	return out
}

func (b baseDeviceBehavior) ExportRoute(from model.Node, to model.Node, session model.BGPNeighbor, route RIBEntry) BGPRouteDecision {
	isIBGP := from.ASN == to.ASN
	if isIBGP && route.LearnedIBGP {
		return BGPRouteDecision{Route: route, Accept: false, Reason: "ibgp readvertisement"}
	}

	out := route
	out.ASPath = append([]uint32(nil), route.ASPath...)
	if !isIBGP {
		out.ASPath = prependASN(from.ASN, out.ASPath)
	}
	if !isIBGP || session.NextHopSelf || out.NextHop == "" {
		out.NextHop = from.Name
	}
	out.LearnedIBGP = isIBGP

	return BGPRouteDecision{Route: out, Accept: true}
}

func (b baseDeviceBehavior) ImportRoute(to model.Node, from model.Node, session model.BGPNeighbor, route RIBEntry) BGPRouteDecision {
	if containsASN(route.ASPath, to.ASN) {
		return BGPRouteDecision{Route: route, Accept: false, Reason: "as loop"}
	}
	out := route
	if from.ASN != to.ASN {
		out.LocalPref = 0
	}
	return BGPRouteDecision{Route: out, Accept: true}
}

func (b baseDeviceBehavior) DecisionProcess() BGPDecisionProcess {
	if b.decision == nil {
		return DefaultBGPDecisionProcess()
	}
	return b.decision
}
