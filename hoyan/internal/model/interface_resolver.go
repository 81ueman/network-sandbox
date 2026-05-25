package model

import (
	"net/netip"
	"strings"
)

type InterfaceRef struct {
	Node       NodeID
	Link       LinkID
	ClabName   string
	ConfigName string
	Address    netip.Prefix
}

type InterfaceResolver struct {
	Index *TopologyIndex
}

func InterfaceAliases(kind DeviceKind, clabName string) []string {
	names := uniqueStrings(clabName)
	base, hasUnit := strings.CutSuffix(clabName, ".0")
	if hasUnit {
		names = uniqueStrings(append(names, base)...)
	}
	switch kind {
	case KindCEOS:
		if strings.HasPrefix(clabName, "eth") {
			names = uniqueStrings(append(names, "Ethernet"+strings.TrimPrefix(clabName, "eth"))...)
		}
	case KindSRLinux:
		switch {
		case strings.HasPrefix(clabName, "e1-"):
			port := strings.TrimPrefix(clabName, "e1-")
			names = uniqueStrings(append(names, "ethernet-1/"+port, "ethernet-1/"+port+".0")...)
		case strings.HasPrefix(clabName, "ethernet-1/"):
			if hasUnit {
				names = uniqueStrings(append(names, base)...)
			} else {
				names = uniqueStrings(append(names, clabName+".0")...)
			}
		}
	}
	return names
}

func ResolveInterface(node Node, clabName string) (InterfaceRef, bool) {
	return resolveInterface(node, "", clabName)
}

func EquivalentInterfaceName(kind DeviceKind, a, b string) bool {
	aliases := map[string]bool{}
	for _, alias := range InterfaceAliases(kind, a) {
		aliases[alias] = true
	}
	for _, alias := range InterfaceAliases(kind, b) {
		if aliases[alias] {
			return true
		}
	}
	return false
}

func InterfaceAddress(kind DeviceKind, interfaces []Interface, name string) (netip.Prefix, bool) {
	for _, alias := range InterfaceAliases(kind, name) {
		for _, iface := range interfaces {
			if iface.Name != alias {
				continue
			}
			pfx, err := netip.ParsePrefix(iface.Address)
			return pfx, err == nil
		}
	}
	return netip.Prefix{}, false
}

func (r InterfaceResolver) ResolveInterface(node Node, link LinkID, clabName string) (InterfaceRef, bool) {
	return resolveInterface(node, link, clabName)
}

func resolveInterface(node Node, link LinkID, clabName string) (InterfaceRef, bool) {
	for _, alias := range InterfaceAliases(node.Kind, clabName) {
		for _, iface := range node.Interfaces {
			if iface.Name != alias {
				continue
			}
			pfx, err := netip.ParsePrefix(iface.Address)
			if err != nil {
				return InterfaceRef{}, false
			}
			return InterfaceRef{
				Node:       NodeID(node.Name),
				Link:       link,
				ClabName:   clabName,
				ConfigName: iface.Name,
				Address:    pfx,
			}, true
		}
	}
	return InterfaceRef{}, false
}

func uniqueStrings(xs ...string) []string {
	out := make([]string, 0, len(xs))
	seen := map[string]bool{}
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}
