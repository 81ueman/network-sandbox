package sim

import (
	"net/netip"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type ControlMessage struct {
	From   string
	To     string
	Prefix string
	Route  RIBEntry
}

type PacketMessage struct {
	Node     string
	Prefix   netip.Prefix
	Protocol string
}

type DeviceBehavior interface {
	Kind() string
	BGPBehavior
	CheckControlEgress(device model.Node, msg ControlMessage, policies []model.Policy) bool
	CheckControlIngress(device model.Node, msg ControlMessage, policies []model.Policy) bool
	CheckDataIngress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool)
	CheckDataEgress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool)
}

func (b baseDeviceBehavior) Kind() string {
	return b.kind
}

func (b baseDeviceBehavior) CheckControlIngress(device model.Node, msg ControlMessage, policies []model.Policy) bool {
	return !matchesDenyPolicy(device.Name, msg.From, msg.Prefix, "", "control", "ingress", policies)
}

func (b baseDeviceBehavior) CheckControlEgress(device model.Node, msg ControlMessage, policies []model.Policy) bool {
	return !matchesDenyPolicy(device.Name, msg.To, msg.Prefix, "", "control", "egress", policies)
}

func (b baseDeviceBehavior) CheckDataIngress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool) {
	return deniedPolicyName(device.Name, "", pkt.Prefix, pkt.Protocol, "data", "ingress", policies)
}

func (b baseDeviceBehavior) CheckDataEgress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool) {
	return deniedPolicyName(device.Name, "", pkt.Prefix, pkt.Protocol, "data", "egress", policies)
}

func matchesDenyPolicy(node, peer, prefix, protocol, plane, stage string, policies []model.Policy) bool {
	name, denied := deniedPolicyName(node, peer, mustPrefix(prefix), protocol, plane, stage, policies)
	return name != "" && denied
}

func deniedPolicyName(node, peer string, dst netip.Prefix, protocol, plane, stage string, policies []model.Policy) (string, bool) {
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
		if pol.Protocol != "" && !strings.EqualFold(pol.Protocol, protocol) {
			continue
		}
		if !pol.DstPrefix.IsZero() {
			if !pol.DstPrefix.Overlaps(model.PrefixFromNetIP(dst)) {
				continue
			}
		}
		return pol.Name, true
	}
	return "", false
}

func mustPrefix(prefix string) netip.Prefix {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Prefix{}
	}
	return pfx
}
