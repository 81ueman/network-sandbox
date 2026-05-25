package model

import "net/netip"

type NodeID string
type LinkID string
type PolicyID string
type RoutePolicyID string
type PrefixListID string
type DeviceKind string

const (
	KindFRR     DeviceKind = "frr"
	KindCEOS    DeviceKind = "ceos"
	KindSRLinux DeviceKind = "srlinux"
)

type NextHop struct {
	Node NodeID
	Addr netip.Addr
}

func NodeNextHop(node NodeID) NextHop {
	return NextHop{Node: node}
}

func AddrNextHop(addr netip.Addr) NextHop {
	return NextHop{Addr: addr}
}

func (h NextHop) IsZero() bool {
	return h.Node == "" && !h.Addr.IsValid()
}

func (h NextHop) String() string {
	if h.Addr.IsValid() {
		return h.Addr.String()
	}
	return string(h.Node)
}
