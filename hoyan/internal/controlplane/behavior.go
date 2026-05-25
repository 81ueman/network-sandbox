package controlplane

import (
	"net/netip"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type ControlMessage struct {
	From   string
	To     string
	Prefix string
	Route  RIBEntry
}

type PacketMessage struct {
	Node             string
	Prefix           netip.Prefix
	DstSet           model.PrefixSet
	Protocol         string
	IngressInterface string
	EgressInterface  string
}

type PolicyDecision struct {
	PolicyName string
	Denied     bool
	Cond       failure.Cond
	Reason     string
	Source     model.PolicySource
}

type DeviceBehavior interface {
	Kind() model.DeviceKind
	BGPBehavior
	CheckControlEgress(device model.Node, msg ControlMessage, policies []model.Policy) bool
	CheckControlIngress(device model.Node, msg ControlMessage, policies []model.Policy) bool
	CheckDataIngress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool)
	CheckDataEgress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool)
	CheckDataIngressSymbolic(device model.Node, pkt PacketMessage, policies []model.Policy) PolicyDecision
	CheckDataEgressSymbolic(device model.Node, pkt PacketMessage, policies []model.Policy) PolicyDecision
	RouteValidForRIB(device model.Node, route RIBEntry) bool
	RouteEligibleForAdvertisement(device model.Node, route RIBEntry) bool
	RouteInstallableInFIB(device model.Node, installed []RIBEntry, route RIBEntry) bool
}

func (b baseDeviceBehavior) Kind() model.DeviceKind {
	return b.kind
}

func (b baseDeviceBehavior) CheckControlIngress(device model.Node, msg ControlMessage, policies []model.Policy) bool {
	return !matchesDenyPolicy(device.Name, msg.From, msg.Prefix, "", "control", "ingress", policies)
}

func (b baseDeviceBehavior) CheckControlEgress(device model.Node, msg ControlMessage, policies []model.Policy) bool {
	return !matchesDenyPolicy(device.Name, msg.To, msg.Prefix, "", "control", "egress", policies)
}

func (b baseDeviceBehavior) CheckDataIngress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool) {
	decision := b.CheckDataIngressSymbolic(device, pkt, policies)
	return decision.PolicyName, decision.Denied
}

func (b baseDeviceBehavior) CheckDataEgress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool) {
	decision := b.CheckDataEgressSymbolic(device, pkt, policies)
	return decision.PolicyName, decision.Denied
}

func (b baseDeviceBehavior) CheckDataIngressSymbolic(device model.Node, pkt PacketMessage, policies []model.Policy) PolicyDecision {
	return policyDecision(device.Name, "", pkt.IngressInterface, pkt.Prefix, pkt.DstSet, pkt.Protocol, "data", "ingress", policies)
}

func (b baseDeviceBehavior) CheckDataEgressSymbolic(device model.Node, pkt PacketMessage, policies []model.Policy) PolicyDecision {
	return policyDecision(device.Name, "", pkt.EgressInterface, pkt.Prefix, pkt.DstSet, pkt.Protocol, "data", "egress", policies)
}

func (b baseDeviceBehavior) RouteValidForRIB(device model.Node, route RIBEntry) bool {
	route = route.Normalize()
	return !route.Invalid
}

func (b baseDeviceBehavior) RouteEligibleForAdvertisement(device model.Node, route RIBEntry) bool {
	return b.RouteValidForRIB(device, route)
}

func (b baseDeviceBehavior) RouteInstallableInFIB(device model.Node, installed []RIBEntry, route RIBEntry) bool {
	return b.RouteValidForRIB(device, route)
}

func matchesDenyPolicy(node, peer, prefix, protocol, plane, stage string, policies []model.Policy) bool {
	decision := policyDecision(node, peer, "", mustPrefix(prefix), nil, protocol, plane, stage, policies)
	return decision.PolicyName != "" && decision.Denied
}

func deniedPolicyName(node, peer, iface string, dst netip.Prefix, dstSet model.PrefixSet, protocol, plane, stage string, policies []model.Policy) (string, bool) {
	decision := policyDecision(node, peer, iface, dst, dstSet, protocol, plane, stage, policies)
	return decision.PolicyName, decision.Denied
}

func policyDecision(node, peer, iface string, dst netip.Prefix, dstSet model.PrefixSet, protocol, plane, stage string, policies []model.Policy) PolicyDecision {
	for _, pol := range policies {
		if pol.Node != node || pol.Action != "deny" {
			continue
		}
		if pol.Plane != "" && pol.Plane != plane {
			continue
		}
		if pol.Plane == "" && plane == "control" {
			continue
		}
		if pol.Stage != "" && pol.Stage != stage {
			continue
		}
		if pol.Peer != "" && pol.Peer != peer {
			continue
		}
		if pol.Interface != "" && !interfaceMatches(pol.Interface, iface) {
			continue
		}
		if pol.Protocol != "" && !strings.EqualFold(pol.Protocol, protocol) {
			continue
		}
		if !pol.DstPrefix.IsZero() {
			if dstSet != nil {
				if !(model.ExactPrefixSet{Prefix: pol.DstPrefix}).Overlaps(dstSet) {
					continue
				}
			} else if !pol.DstPrefix.Overlaps(model.PrefixFromNetIP(dst)) {
				continue
			}
		}
		return PolicyDecision{
			PolicyName: pol.Name,
			Denied:     true,
			Cond:       failure.True(),
			Reason:     "denied by policy " + pol.Name,
			Source:     pol.Source,
		}
	}
	return PolicyDecision{Cond: failure.False()}
}

func interfaceMatches(policyInterface, packetInterface string) bool {
	return model.EquivalentInterfaceName(model.KindFRR, policyInterface, packetInterface) ||
		model.EquivalentInterfaceName(model.KindCEOS, policyInterface, packetInterface) ||
		model.EquivalentInterfaceName(model.KindSRLinux, policyInterface, packetInterface)
}

func mustPrefix(prefix string) netip.Prefix {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Prefix{}
	}
	return pfx
}
