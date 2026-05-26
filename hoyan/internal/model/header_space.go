package model

import (
	"fmt"
	"sort"
	"strings"
)

type PacketClassID int
type HeaderPredicateID int

type HeaderPredicate struct {
	ID               HeaderPredicateID
	Source           string
	Protocol         string
	SrcSet           PrefixSet
	DstSet           PrefixSet
	SrcPort          PortSet
	DstPort          PortSet
	IngressInterface string
	EgressInterface  string
}

type PacketClass struct {
	ID                 PacketClassID
	PrefixClassID      PrefixClassID
	DstSet             PrefixSet
	Protocol           string
	SrcPort            PortSet
	DstPort            PortSet
	IngressInterface   string
	EgressInterface    string
	MatchingPredicates []HeaderPredicateID
}

type HeaderSpace struct {
	Classes    []PacketClass
	Predicates []HeaderPredicate
}

func (c PacketClass) Spec() PacketSpec {
	return PacketSpec{
		DstSet:           c.DstSet,
		Protocol:         c.Protocol,
		SrcPort:          c.SrcPort,
		DstPort:          c.DstPort,
		IngressInterface: c.IngressInterface,
		EgressInterface:  c.EgressInterface,
	}
}

func CollectHeaderPredicates(topo *Topology, queries *Queries) []HeaderPredicate {
	var out []HeaderPredicate
	add := func(predicate HeaderPredicate) {
		if predicate.Protocol == "" &&
			predicate.SrcSet == nil &&
			predicate.DstSet == nil &&
			predicate.SrcPort == nil &&
			predicate.DstPort == nil &&
			predicate.IngressInterface == "" &&
			predicate.EgressInterface == "" {
			return
		}
		predicate.ID = HeaderPredicateID(len(out))
		predicate.Protocol = strings.ToLower(strings.TrimSpace(predicate.Protocol))
		out = append(out, predicate)
	}
	if topo != nil {
		for _, binding := range topo.ACLBindings {
			acl, ok := aclByName(topo.ACLs, binding.Node, binding.ACLName)
			if !ok {
				continue
			}
			for _, rule := range acl.Rules {
				predicate := HeaderPredicate{
					Source:   "acl:" + acl.Name,
					Protocol: rule.Match.Protocol,
					SrcSet:   rule.Match.SrcSet,
					DstSet:   rule.Match.DstSet,
					SrcPort:  rule.Match.SrcPort,
					DstPort:  rule.Match.DstPort,
				}
				switch binding.Direction {
				case "ingress":
					predicate.IngressInterface = binding.Interface
				case "egress":
					predicate.EgressInterface = binding.Interface
				}
				add(predicate)
			}
		}
		for _, acl := range topo.ACLs {
			if aclHasBinding(topo.ACLBindings, acl.Node, acl.Name) {
				continue
			}
			for _, rule := range acl.Rules {
				predicate := HeaderPredicate{
					Source:   "acl:" + acl.Name,
					Protocol: rule.Match.Protocol,
					SrcSet:   rule.Match.SrcSet,
					DstSet:   rule.Match.DstSet,
					SrcPort:  rule.Match.SrcPort,
					DstPort:  rule.Match.DstPort,
				}
				add(predicate)
			}
		}
	}
	if queries != nil {
		for _, check := range queries.PacketChecks {
			for _, port := range check.DstPortValues() {
				predicate := HeaderPredicate{
					Source:   "query-packet:" + check.Name,
					Protocol: check.Protocol,
					DstPort:  ExactPort(port),
				}
				for _, set := range destinationPrefixSets(topo, check.To) {
					predicate.DstSet = set
					add(predicate)
				}
				if predicate.DstSet == nil {
					add(predicate)
				}
			}
		}
		for _, check := range queries.FailureChecks {
			for _, port := range check.DstPortValues() {
				predicate := HeaderPredicate{
					Source:   "query-failure:" + check.Name,
					Protocol: check.Protocol,
					DstPort:  ExactPort(port),
				}
				if !check.Prefix.IsZero() {
					predicate.DstSet = ExactPrefixSet{Prefix: check.Prefix}
					add(predicate)
					continue
				}
				for _, set := range destinationPrefixSets(topo, check.To) {
					predicate.DstSet = set
					add(predicate)
				}
				if predicate.DstSet == nil {
					add(predicate)
				}
			}
		}
	}
	return out
}

func NewHeaderSpace(topo *Topology, queries *Queries, universe PrefixUniverse) HeaderSpace {
	return BuildHeaderSpaceFromPredicates(universe, CollectHeaderPredicates(topo, queries))
}

func aclByName(acls []ACL, node, name string) (ACL, bool) {
	for _, acl := range acls {
		if acl.Node == node && acl.Name == name {
			return acl, true
		}
	}
	return ACL{}, false
}

func aclHasBinding(bindings []ACLBinding, node, name string) bool {
	for _, binding := range bindings {
		if binding.Node == node && binding.ACLName == name {
			return true
		}
	}
	return false
}

func BuildHeaderSpaceFromPredicates(universe PrefixUniverse, predicates []HeaderPredicate) HeaderSpace {
	space := HeaderSpace{}
	for _, predicate := range predicates {
		predicate.ID = HeaderPredicateID(len(space.Predicates))
		predicate.Protocol = strings.ToLower(strings.TrimSpace(predicate.Protocol))
		space.Predicates = append(space.Predicates, predicate)
	}
	if len(universe.Classes) == 0 || len(space.Predicates) == 0 {
		return space
	}
	seen := map[string]bool{}
	for _, prefixClass := range universe.Classes {
		prefixPredicates := headerPredicatesForPrefix(space.Predicates, prefixClass.Space)
		protocols := headerProtocolClasses(prefixPredicates)
		for _, protocol := range protocols {
			protocolPredicates := headerPredicatesForProtocol(prefixPredicates, protocol)
			srcPorts := headerPortClasses(protocolPredicates, func(p HeaderPredicate) PortSet { return p.SrcPort })
			for _, srcPort := range srcPorts {
				srcPortPredicates := headerPredicatesForPort(protocolPredicates, srcPort, func(p HeaderPredicate) PortSet { return p.SrcPort })
				dstPorts := headerPortClasses(srcPortPredicates, func(p HeaderPredicate) PortSet { return p.DstPort })
				for _, dstPort := range dstPorts {
					dstPortPredicates := headerPredicatesForPort(srcPortPredicates, dstPort, func(p HeaderPredicate) PortSet { return p.DstPort })
					ingressInterfaces := headerInterfaceClasses(dstPortPredicates, func(p HeaderPredicate) string { return p.IngressInterface })
					for _, ingressInterface := range ingressInterfaces {
						ingressPredicates := headerPredicatesForInterface(dstPortPredicates, ingressInterface, func(p HeaderPredicate) string { return p.IngressInterface })
						egressInterfaces := headerInterfaceClasses(ingressPredicates, func(p HeaderPredicate) string { return p.EgressInterface })
						for _, egressInterface := range egressInterfaces {
							class := PacketClass{
								ID:               PacketClassID(len(space.Classes)),
								PrefixClassID:    prefixClass.ID,
								DstSet:           prefixClass.Space,
								Protocol:         protocol,
								SrcPort:          srcPort,
								DstPort:          dstPort,
								IngressInterface: ingressInterface,
								EgressInterface:  egressInterface,
							}
							matches := matchingHeaderPredicateIDs(class, space.Predicates)
							if len(matches) == 0 {
								continue
							}
							class.MatchingPredicates = matches
							key := packetClassKey(class)
							if seen[key] {
								continue
							}
							seen[key] = true
							class.ID = PacketClassID(len(space.Classes))
							space.Classes = append(space.Classes, class)
						}
					}
				}
			}
		}
	}
	return space
}

func matchingHeaderPredicateIDs(class PacketClass, predicates []HeaderPredicate) []HeaderPredicateID {
	var out []HeaderPredicateID
	for _, predicate := range predicates {
		if !headerPredicateMatchesClass(predicate, class) {
			continue
		}
		out = append(out, predicate.ID)
	}
	return out
}

func headerPredicatesForPrefix(predicates []HeaderPredicate, dst PrefixSet) []HeaderPredicate {
	var out []HeaderPredicate
	for _, predicate := range predicates {
		if predicate.DstSet != nil && (dst == nil || !AddressSpaceOverlaps(predicate.DstSet, dst)) {
			continue
		}
		out = append(out, predicate)
	}
	return out
}

func headerPredicatesForProtocol(predicates []HeaderPredicate, protocol string) []HeaderPredicate {
	var out []HeaderPredicate
	for _, predicate := range predicates {
		if predicate.Protocol != "" && protocol != "" && predicate.Protocol != protocol {
			continue
		}
		out = append(out, predicate)
	}
	return out
}

func headerPredicatesForPort(predicates []HeaderPredicate, classSet PortSet, get func(HeaderPredicate) PortSet) []HeaderPredicate {
	var out []HeaderPredicate
	for _, predicate := range predicates {
		predicateSet := get(predicate)
		if predicateSet != nil && !portSetsOverlap(predicateSet, classSet) {
			continue
		}
		out = append(out, predicate)
	}
	return out
}

func headerPredicatesForInterface(predicates []HeaderPredicate, classInterface string, get func(HeaderPredicate) string) []HeaderPredicate {
	var out []HeaderPredicate
	for _, predicate := range predicates {
		predicateInterface := get(predicate)
		if predicateInterface != "" && classInterface != "" && predicateInterface != classInterface {
			continue
		}
		out = append(out, predicate)
	}
	return out
}

func headerPredicateMatchesClass(predicate HeaderPredicate, class PacketClass) bool {
	if predicate.Protocol != "" && class.Protocol != "" && predicate.Protocol != class.Protocol {
		return false
	}
	if predicate.DstSet != nil && (class.DstSet == nil || !AddressSpaceOverlaps(predicate.DstSet, class.DstSet)) {
		return false
	}
	if predicate.SrcPort != nil && !portSetsOverlap(predicate.SrcPort, class.SrcPort) {
		return false
	}
	if predicate.DstPort != nil && !portSetsOverlap(predicate.DstPort, class.DstPort) {
		return false
	}
	if predicate.IngressInterface != "" && class.IngressInterface != "" && predicate.IngressInterface != class.IngressInterface {
		return false
	}
	if predicate.EgressInterface != "" && class.EgressInterface != "" && predicate.EgressInterface != class.EgressInterface {
		return false
	}
	return true
}

func headerProtocolClasses(predicates []HeaderPredicate) []string {
	seen := map[string]bool{}
	var out []string
	for _, predicate := range predicates {
		if predicate.Protocol == "" || seen[predicate.Protocol] {
			continue
		}
		seen[predicate.Protocol] = true
		out = append(out, predicate.Protocol)
	}
	if len(out) == 0 {
		return []string{""}
	}
	sort.Strings(out)
	return out
}

func headerPortClasses(predicates []HeaderPredicate, get func(HeaderPredicate) PortSet) []PortSet {
	seen := map[string]bool{}
	var out []PortSet
	for _, predicate := range predicates {
		set := get(predicate)
		if set == nil {
			continue
		}
		key := set.String()
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, set)
	}
	if len(out) == 0 {
		return []PortSet{nil}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func headerInterfaceClasses(predicates []HeaderPredicate, get func(HeaderPredicate) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, predicate := range predicates {
		iface := get(predicate)
		if iface == "" || seen[iface] {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	if len(out) == 0 {
		return []string{""}
	}
	sort.Strings(out)
	return out
}

func portSetsOverlap(a, b PortSet) bool {
	if a == nil || b == nil {
		return true
	}
	return a.Overlaps(b)
}

func packetClassKey(class PacketClass) string {
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		class.PrefixClassID,
		class.Protocol,
		portSetString(class.SrcPort),
		portSetString(class.DstPort),
		class.IngressInterface,
		class.EgressInterface,
	)
}

func portSetString(set PortSet) string {
	if set == nil {
		return "any"
	}
	return set.String()
}
