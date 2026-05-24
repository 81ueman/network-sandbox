package sim

import (
	"net/netip"
	"sort"
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
	CheckControlIngress(device model.Node, msg ControlMessage, policies []model.Policy) bool
	SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry
	CheckControlEgress(device model.Node, msg ControlMessage, policies []model.Policy) bool
	CheckDataIngress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool)
	CheckDataEgress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool)
}

type baseBGPBehavior struct {
	kind string
}

type frrBehavior struct{ baseBGPBehavior }
type ceosBehavior struct{ baseBGPBehavior }
type srlinuxBehavior struct{ baseBGPBehavior }

func behaviorFor(kind string) DeviceBehavior {
	switch kind {
	case "frr":
		return frrBehavior{baseBGPBehavior{kind: "frr"}}
	case "ceos":
		return ceosBehavior{baseBGPBehavior{kind: "ceos"}}
	case "srlinux":
		return srlinuxBehavior{baseBGPBehavior{kind: "srlinux"}}
	default:
		return baseBGPBehavior{kind: kind}
	}
}

func (b baseBGPBehavior) Kind() string {
	return b.kind
}

func (b baseBGPBehavior) CheckControlIngress(device model.Node, msg ControlMessage, policies []model.Policy) bool {
	return !matchesDenyPolicy(device.Name, msg.From, msg.Prefix, "", "control", "ingress", policies)
}

func (b baseBGPBehavior) SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry {
	out := append([]RIBEntry(nil), routes...)
	sort.Slice(out, func(i, j int) bool {
		return b.lessRIB(device, out[i], out[j])
	})
	return out
}

func (b baseBGPBehavior) CheckControlEgress(device model.Node, msg ControlMessage, policies []model.Policy) bool {
	return !matchesDenyPolicy(device.Name, msg.To, msg.Prefix, "", "control", "egress", policies)
}

func (b baseBGPBehavior) CheckDataIngress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool) {
	return deniedPolicyName(device.Name, "", pkt.Prefix, pkt.Protocol, "data", "ingress", policies)
}

func (b baseBGPBehavior) CheckDataEgress(device model.Node, pkt PacketMessage, policies []model.Policy) (string, bool) {
	return deniedPolicyName(device.Name, "", pkt.Prefix, pkt.Protocol, "data", "egress", policies)
}

func (b baseBGPBehavior) lessRIB(receiver model.Node, a, c RIBEntry) bool {
	if a.LocalPref != c.LocalPref {
		return a.LocalPref > c.LocalPref
	}
	if a.Origin == receiver.Name || c.Origin == receiver.Name {
		return a.Origin == receiver.Name
	}
	if len(a.ASPath) != len(c.ASPath) {
		return len(a.ASPath) < len(c.ASPath)
	}
	if a.MED != c.MED {
		return a.MED < c.MED
	}
	aExternal := firstHopExternal(receiver.ASN, a.ASPath)
	cExternal := firstHopExternal(receiver.ASN, c.ASPath)
	if aExternal != cExternal {
		return aExternal
	}
	if len(a.Links) != len(c.Links) {
		return len(a.Links) < len(c.Links)
	}
	return b.vendorTieBreak(a, c)
}

func (b baseBGPBehavior) vendorTieBreak(a, c RIBEntry) bool {
	aKey := strings.Join(a.Nodes, ",")
	cKey := strings.Join(c.Nodes, ",")
	return aKey < cKey
}

func (b frrBehavior) SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry {
	out := append([]RIBEntry(nil), routes...)
	sort.Slice(out, func(i, j int) bool {
		return b.lessRIB(device, out[i], out[j])
	})
	return out
}

func (b ceosBehavior) SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry {
	out := make([]RIBEntry, 0, len(routes))
	for _, route := range routes {
		if route.NextHop != "" && route.NextHop != route.From {
			continue
		}
		out = append(out, route)
	}
	sort.Slice(out, func(i, j int) bool {
		return b.lessRIB(device, out[i], out[j])
	})
	return out
}

func firstHopExternal(localASN uint32, path []uint32) bool {
	if len(path) == 0 {
		return false
	}
	return path[0] != localASN
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
		if pol.DstPrefix != "" {
			pfx, err := netip.ParsePrefix(pol.DstPrefix)
			if err != nil || !prefixesOverlap(pfx, dst) {
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
