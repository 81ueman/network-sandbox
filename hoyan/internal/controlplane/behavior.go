package controlplane

import (
	"net/netip"
	"sort"
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
	PolicyName    string
	ACLName       string
	RuleSeq       int
	Action        model.ACLAction
	Denied        bool
	Cond          failure.Cond
	Reason        string
	DefaultAction model.ACLDefaultAction
	Source        model.ConfigSource
}

type DeviceBehavior interface {
	Kind() model.DeviceKind
	BGPBehavior
	CheckControlEgress(device model.Node, msg ControlMessage) bool
	CheckControlIngress(device model.Node, msg ControlMessage) bool
	EvaluateDataACL(device model.Node, pkt PacketMessage, stage string, acls []model.ACL, bindings []model.ACLBinding) PolicyDecision
	RouteValidForRIB(device model.Node, route RIBEntry) bool
	RouteEligibleForAdvertisement(device model.Node, route RIBEntry) bool
	RouteInstallableInFIB(device model.Node, installed []RIBEntry, route RIBEntry) bool
}

func (b baseDeviceBehavior) Kind() model.DeviceKind {
	return b.kind
}

func (b baseDeviceBehavior) CheckControlIngress(device model.Node, msg ControlMessage) bool {
	return true
}

func (b baseDeviceBehavior) CheckControlEgress(device model.Node, msg ControlMessage) bool {
	return true
}

func (b baseDeviceBehavior) EvaluateDataACL(device model.Node, pkt PacketMessage, stage string, acls []model.ACL, bindings []model.ACLBinding) PolicyDecision {
	spec := pkt.NormalizedSpec()
	iface := spec.IngressInterface
	if stage == "egress" {
		iface = spec.EgressInterface
	}
	for _, binding := range bindings {
		if binding.Node != device.Name || binding.Direction != stage {
			continue
		}
		if binding.Interface != "" && !interfaceMatches(binding.Interface, iface) {
			continue
		}
		acl, ok := aclByName(acls, device.Name, binding.ACLName)
		if !ok {
			continue
		}
		return evaluateACL(device, acl, binding, spec)
	}
	return PolicyDecision{Cond: failure.False()}
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

func evaluateACL(device model.Node, acl model.ACL, binding model.ACLBinding, spec model.PacketSpec) PolicyDecision {
	rules := append([]model.ACLRule(nil), acl.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Seq == rules[j].Seq {
			return i < j
		}
		if rules[i].Seq == 0 {
			return false
		}
		if rules[j].Seq == 0 {
			return true
		}
		return rules[i].Seq < rules[j].Seq
	})
	for _, rule := range rules {
		if !aclRuleMatches(rule, spec) {
			continue
		}
		denied := rule.Action == model.ACLDeny
		reason := "permitted by acl " + acl.Name
		if denied {
			reason = "denied by acl " + acl.Name
		}
		return PolicyDecision{
			PolicyName: acl.Name,
			ACLName:    acl.Name,
			RuleSeq:    rule.Seq,
			Action:     rule.Action,
			Denied:     denied,
			Cond:       decisionCond(denied),
			Reason:     reason,
			Source:     rule.Source,
		}
	}
	defaultAction := acl.DefaultAction
	if defaultAction == "" {
		defaultAction = defaultACLActionForDevice(device.Kind)
	}
	denied := defaultAction == model.ACLDefaultDeny
	reason := "default permit by acl " + acl.Name
	if denied {
		reason = "default deny by acl " + acl.Name
	}
	return PolicyDecision{
		PolicyName:    acl.Name,
		ACLName:       acl.Name,
		Action:        model.ACLAction(defaultAction),
		Denied:        denied,
		Cond:          decisionCond(denied),
		Reason:        reason,
		DefaultAction: defaultAction,
		Source:        binding.Source,
	}
}

func decisionCond(denied bool) failure.Cond {
	if denied {
		return failure.True()
	}
	return failure.False()
}

func aclByName(acls []model.ACL, node, name string) (model.ACL, bool) {
	for _, acl := range acls {
		if acl.Node == node && acl.Name == name {
			return acl, true
		}
	}
	return model.ACL{}, false
}

func aclRuleMatches(rule model.ACLRule, spec model.PacketSpec) bool {
	match := rule.Match.WithNormalizedPorts()
	spec = spec.WithNormalizedPorts()
	if match.Protocol != "" && !strings.EqualFold(match.Protocol, spec.Protocol) {
		return false
	}
	if match.SrcSet != nil {
		if !prefixSetMatches(match.SrcSet, spec.SrcSet) {
			return false
		}
	}
	if match.DstSet != nil {
		if !prefixSetMatches(match.DstSet, spec.DstSet) {
			return false
		}
	}
	if match.SrcPort != nil && !match.SrcPort.Overlaps(spec.SrcPort) {
		return false
	}
	if match.DstPort != nil && !match.DstPort.Overlaps(spec.DstPort) {
		return false
	}
	return true
}

func prefixSetMatches(match, packet model.PrefixSet) bool {
	if packet == nil {
		return prefixSetIsAny(match)
	}
	return model.AddressSpaceOverlaps(match, packet)
}

func prefixSetIsAny(set model.PrefixSet) bool {
	exact, ok := set.(model.ExactPrefixSet)
	return ok && exact.Prefix.String() == "0.0.0.0/0"
}

func defaultACLActionForDevice(kind model.DeviceKind) model.ACLDefaultAction {
	switch kind {
	case model.KindCEOS, model.KindSRLinux:
		return model.ACLDefaultDeny
	default:
		return model.ACLDefaultPermit
	}
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
