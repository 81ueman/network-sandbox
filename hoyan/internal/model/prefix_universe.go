package model

import (
	"fmt"
	"strings"
)

type PrefixClassID int

type PrefixClass struct {
	ID    PrefixClassID
	Space PrefixSet
}

type PrefixUniverse struct {
	Classes []PrefixClass
}

type OverlappingPrefixPredicateError struct {
	Existing  PrefixSet
	Candidate PrefixSet
}

func (e OverlappingPrefixPredicateError) Error() string {
	return fmt.Sprintf("overlapping prefix predicates are not supported yet: %s overlaps %s", e.Candidate.String(), e.Existing.String())
}

func CollectPrefixPredicates(topo *Topology, queries *Queries) []PrefixSet {
	var out []PrefixSet
	if topo != nil {
		for _, node := range topo.Nodes {
			for _, prefix := range node.Prefixes {
				if !prefix.IsZero() {
					out = append(out, ExactPrefixSet{Prefix: prefix})
				}
			}
			for _, list := range node.PrefixLists {
				for _, rule := range list.Rules {
					if rule.Match != nil {
						out = append(out, rule.Match)
						continue
					}
					set, err := NewPrefixSet(rule.Prefix, rule.Ge, rule.Le)
					if err == nil {
						out = append(out, set)
					}
				}
			}
		}
		for _, policy := range topo.Policies {
			if !policy.DstPrefix.IsZero() {
				out = append(out, ExactPrefixSet{Prefix: policy.DstPrefix})
			}
		}
	}
	if queries != nil {
		for _, check := range queries.RouteChecks {
			if !check.Prefix.IsZero() {
				out = append(out, ExactPrefixSet{Prefix: check.Prefix})
			}
		}
		for _, check := range queries.PacketChecks {
			out = append(out, destinationPrefixSets(topo, check.To)...)
		}
		for _, check := range queries.FailureChecks {
			if !check.Prefix.IsZero() {
				out = append(out, ExactPrefixSet{Prefix: check.Prefix})
				continue
			}
			out = append(out, destinationPrefixSets(topo, check.To)...)
		}
	}
	return out
}

func BuildPrefixUniverse(predicates []PrefixSet) (PrefixUniverse, error) {
	universe := PrefixUniverse{}
	seen := map[string]bool{}
	for _, predicate := range predicates {
		if predicate == nil {
			continue
		}
		key := prefixSetKey(predicate)
		if seen[key] {
			continue
		}
		for _, class := range universe.Classes {
			if class.Space.Overlaps(predicate) {
				return PrefixUniverse{}, OverlappingPrefixPredicateError{Existing: class.Space, Candidate: predicate}
			}
		}
		seen[key] = true
		universe.Classes = append(universe.Classes, PrefixClass{
			ID:    PrefixClassID(len(universe.Classes)),
			Space: predicate,
		})
	}
	return universe, nil
}

func NewPrefixUniverse(topo *Topology, queries *Queries) (PrefixUniverse, error) {
	return BuildPrefixUniverse(CollectPrefixPredicates(topo, queries))
}

func (u PrefixUniverse) ClassForPrefix(prefix Prefix) (PrefixClassID, bool) {
	for _, class := range u.Classes {
		if class.Space.ContainsPrefix(prefix) {
			return class.ID, true
		}
	}
	return 0, false
}

func (u PrefixUniverse) ClassesMatching(set PrefixSet) []PrefixClassID {
	if set == nil {
		return nil
	}
	var out []PrefixClassID
	for _, class := range u.Classes {
		if class.Space.Overlaps(set) {
			out = append(out, class.ID)
		}
	}
	return out
}

func destinationPrefixSets(topo *Topology, destination string) []PrefixSet {
	if topo == nil || destination == "" {
		return nil
	}
	node, ok := topo.Node(destination)
	if !ok {
		return nil
	}
	out := make([]PrefixSet, 0, len(node.Prefixes))
	for _, prefix := range node.Prefixes {
		if !prefix.IsZero() {
			out = append(out, ExactPrefixSet{Prefix: prefix})
		}
	}
	return out
}

func prefixSetKey(set PrefixSet) string {
	return strings.TrimSpace(set.String())
}
