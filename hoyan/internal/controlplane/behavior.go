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
	Node string
	Spec model.PacketSpec

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
	spec := pkt.NormalizedSpec()
	return policyDecision(device.Name, "", spec.IngressInterface, spec, "data", "ingress", policies)
}

func (b baseDeviceBehavior) CheckDataEgressSymbolic(device model.Node, pkt PacketMessage, policies []model.Policy) PolicyDecision {
	spec := pkt.NormalizedSpec()
	return policyDecision(device.Name, "", spec.EgressInterface, spec, "data", "egress", policies)
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
	decision := policyDecision(node, peer, "", model.PacketSpec{DstSet: model.ExactPrefixSet{Prefix: model.PrefixFromNetIP(mustPrefix(prefix))}, Protocol: protocol}, plane, stage, policies)
	return decision.PolicyName != "" && decision.Denied
}

func deniedPolicyName(node, peer, iface string, dst netip.Prefix, dstSet model.PrefixSet, protocol, plane, stage string, policies []model.Policy) (string, bool) {
	decision := policyDecision(node, peer, iface, model.PacketSpec{DstSet: dstSet, Protocol: protocol}, plane, stage, policies)
	if dstSet == nil {
		decision = policyDecision(node, peer, iface, model.PacketSpec{DstSet: model.ExactPrefixSet{Prefix: model.PrefixFromNetIP(dst)}, Protocol: protocol}, plane, stage, policies)
	}
	return decision.PolicyName, decision.Denied
}

func policyDecision(node, peer, iface string, spec model.PacketSpec, plane, stage string, policies []model.Policy) PolicyDecision {
	spec = spec.WithNormalizedPorts()
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
		if pol.Protocol != "" && !strings.EqualFold(pol.Protocol, spec.Protocol) {
			continue
		}
		if !pol.SrcPrefix.IsZero() {
			if spec.SrcSet == nil || !model.AddressSpaceOverlaps(model.ExactPrefixSet{Prefix: pol.SrcPrefix}, spec.SrcSet) {
				continue
			}
		}
		if pol.SrcPort != nil && !pol.SrcPort.Overlaps(spec.SrcPort) {
			continue
		}
		if pol.DstPort != nil && !pol.DstPort.Overlaps(spec.DstPort) {
			continue
		}
		if !pol.DstPrefix.IsZero() {
			if spec.DstSet != nil {
				if !model.AddressSpaceOverlaps(model.ExactPrefixSet{Prefix: pol.DstPrefix}, spec.DstSet) {
					continue
				}
			} else {
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

func (p PacketMessage) NormalizedSpec() model.PacketSpec {
	spec := p.Spec
	if spec.DstSet == nil && p.DstSet != nil {
		spec.DstSet = p.DstSet
	}
	if spec.DstSet == nil && p.Prefix.IsValid() {
		spec.DstSet = model.ExactPrefixSet{Prefix: model.PrefixFromNetIP(p.Prefix)}
	}
	if spec.Protocol == "" {
		spec.Protocol = p.Protocol
	}
	if spec.IngressInterface == "" {
		spec.IngressInterface = p.IngressInterface
	}
	if spec.EgressInterface == "" {
		spec.EgressInterface = p.EgressInterface
	}
	return spec.WithNormalizedPorts()
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
