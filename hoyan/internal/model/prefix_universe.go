package model

import (
	"fmt"
	"math/bits"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type PrefixClassID int
type PrefixPredicateID int

type PrefixPredicateKind string

const (
	PredicateAddressSpace PrefixPredicateKind = "address_space"
	PredicateNLRI         PrefixPredicateKind = "nlri"
)

type PrefixPredicate struct {
	ID     PrefixPredicateID
	Source string
	Set    PrefixSet
	Kind   PrefixPredicateKind
}

type PrefixClass struct {
	ID                 PrefixClassID
	Space              PrefixSet
	MatchingPredicates []PrefixPredicateID
}

type PrefixUniverse struct {
	Classes    []PrefixClass
	Predicates []PrefixPredicate
	Stats      PrefixUniverseStats
}

type PrefixUniverseStats struct {
	PredicateCount       int            `json:"predicate_count"`
	UniquePredicateCount int            `json:"unique_predicate_count"`
	ClassCount           int            `json:"class_count"`
	BuildDuration        time.Duration  `json:"build_duration"`
	PredicateSources     map[string]int `json:"predicate_sources,omitempty"`
	MaxClassCIDRs        int            `json:"max_class_cidrs"`
}

type OverlappingPrefixPredicateError struct {
	Existing  PrefixSet
	Candidate PrefixSet
}

func (e OverlappingPrefixPredicateError) Error() string {
	return fmt.Sprintf("overlapping prefix predicates are not supported yet: %s overlaps %s", e.Candidate.String(), e.Existing.String())
}

func CollectPrefixPredicates(topo *Topology, queries *Queries) []PrefixSet {
	predicates := CollectPrefixPredicateMetadata(topo, queries)
	out := make([]PrefixSet, 0, len(predicates))
	for _, predicate := range predicates {
		out = append(out, predicate.Set)
	}
	return out
}

func CollectPrefixPredicateMetadata(topo *Topology, queries *Queries) []PrefixPredicate {
	var out []PrefixPredicate
	add := func(source string, kind PrefixPredicateKind, set PrefixSet) {
		if set == nil {
			return
		}
		out = append(out, PrefixPredicate{
			ID:     PrefixPredicateID(len(out)),
			Source: source,
			Set:    set,
			Kind:   normalizedPrefixPredicateKind(kind),
		})
	}
	if topo != nil {
		for _, node := range topo.Nodes {
			for _, prefix := range node.Prefixes {
				if !prefix.IsZero() {
					add("route:"+node.Name, PredicateNLRI, ExactPrefixSet{Prefix: prefix})
				}
			}
			for _, route := range node.Routes {
				if !route.Prefix.IsZero() {
					add(fmt.Sprintf("route-source:%s:%s", node.Name, route.Kind), PredicateNLRI, ExactPrefixSet{Prefix: route.Prefix})
				}
			}
			for _, list := range node.PrefixLists {
				for _, rule := range list.Rules {
					if rule.Match != nil {
						add(fmt.Sprintf("prefix-list:%s:%s:%d", node.Name, list.Name, rule.Seq), PredicateNLRI, rule.Match)
						continue
					}
					set, err := NewPrefixSet(rule.Prefix, rule.Ge, rule.Le)
					if err == nil {
						add(fmt.Sprintf("prefix-list:%s:%s:%d", node.Name, list.Name, rule.Seq), PredicateNLRI, set)
					}
				}
			}
		}
		for _, acl := range topo.ACLs {
			for _, rule := range acl.Rules {
				if rule.Match.DstSet != nil {
					add("acl:"+acl.Name, PredicateAddressSpace, rule.Match.DstSet)
				}
				if rule.Match.SrcSet != nil {
					add("acl:"+acl.Name+":src", PredicateAddressSpace, rule.Match.SrcSet)
				}
			}
		}
	}
	if queries != nil {
		for _, check := range queries.RouteChecks {
			if !check.Prefix.IsZero() {
				add("query-route:"+check.Name, PredicateNLRI, ExactPrefixSet{Prefix: check.Prefix})
			}
		}
		for _, check := range queries.PacketChecks {
			for _, set := range destinationPrefixSets(topo, check.To) {
				add("query-packet:"+check.Name, PredicateAddressSpace, set)
			}
		}
		for _, check := range queries.FailureChecks {
			if !check.Prefix.IsZero() {
				add("query-failure:"+check.Name, PredicateAddressSpace, ExactPrefixSet{Prefix: check.Prefix})
				continue
			}
			for _, set := range destinationPrefixSets(topo, check.To) {
				add("query-failure:"+check.Name, PredicateAddressSpace, set)
			}
		}
	}
	return out
}

func BuildPrefixUniverse(predicates []PrefixSet) (PrefixUniverse, error) {
	withMetadata := make([]PrefixPredicate, 0, len(predicates))
	for _, set := range predicates {
		if set == nil {
			continue
		}
		withMetadata = append(withMetadata, PrefixPredicate{
			ID:     PrefixPredicateID(len(withMetadata)),
			Source: "predicate",
			Set:    set,
			Kind:   PredicateAddressSpace,
		})
	}
	return BuildPrefixUniverseFromPredicates(withMetadata)
}

func BuildPrefixUniverseFromPredicates(predicates []PrefixPredicate) (PrefixUniverse, error) {
	start := time.Now()
	universe := PrefixUniverse{}
	seen := map[string]bool{}
	var boundaries []uint64
	for _, predicate := range predicates {
		if predicate.Set == nil {
			continue
		}
		predicate.ID = PrefixPredicateID(len(universe.Predicates))
		predicate.Kind = normalizedPrefixPredicateKind(predicate.Kind)
		universe.Predicates = append(universe.Predicates, predicate)
		key := prefixSetKey(predicate)
		if seen[key] {
			continue
		}
		seen[key] = true
		setIntervals, err := prefixSetIPv4Intervals(predicate.Set)
		if err != nil {
			return PrefixUniverse{}, err
		}
		for _, interval := range setIntervals {
			boundaries = append(boundaries, uint64(interval.lo), uint64(interval.hi)+1)
		}
	}
	universe.Stats.PredicateCount = len(universe.Predicates)
	universe.Stats.UniquePredicateCount = len(seen)
	universe.Stats.PredicateSources = predicateSourceCounts(universe.Predicates)
	if len(boundaries) == 0 {
		universe.Stats.BuildDuration = time.Since(start)
		return universe, nil
	}
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	boundaries = compactUint64s(boundaries)
	for i := 0; i+1 < len(boundaries); i++ {
		lo, hi := boundaries[i], boundaries[i+1]-1
		if lo > hi || hi > uint64(^uint32(0)) {
			continue
		}
		space := prefixInterval{lo: uint32(lo), hi: uint32(hi)}
		matches := matchingPredicateIDs(space, universe.Predicates)
		if len(matches) == 0 {
			continue
		}
		universe.Classes = append(universe.Classes, PrefixClass{
			ID:                 PrefixClassID(len(universe.Classes)),
			Space:              prefixSetForInterval(space),
			MatchingPredicates: matches,
		})
	}
	universe.Stats.ClassCount = len(universe.Classes)
	universe.Stats.MaxClassCIDRs = maxClassCIDRs(universe.Classes)
	universe.Stats.BuildDuration = time.Since(start)
	return universe, nil
}

func NewPrefixUniverse(topo *Topology, queries *Queries) (PrefixUniverse, error) {
	return BuildPrefixUniverseFromPredicates(CollectPrefixPredicateMetadata(topo, queries))
}

func (u PrefixUniverse) ClassForPrefix(prefix Prefix) (PrefixClassID, bool) {
	for _, class := range u.Classes {
		if prefixSetContainsPrefixSpace(class.Space, prefix) {
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
		if AddressSpaceOverlaps(class.Space, set) {
			out = append(out, class.ID)
		}
	}
	return out
}

func (u PrefixUniverse) PredicatesForClass(id PrefixClassID) []PrefixPredicateID {
	for _, class := range u.Classes {
		if class.ID == id {
			return append([]PrefixPredicateID(nil), class.MatchingPredicates...)
		}
	}
	return nil
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

func normalizedPrefixPredicateKind(kind PrefixPredicateKind) PrefixPredicateKind {
	if kind == PredicateNLRI {
		return PredicateNLRI
	}
	return PredicateAddressSpace
}

func prefixSetKey(predicate PrefixPredicate) string {
	return string(normalizedPrefixPredicateKind(predicate.Kind)) + ":" + strings.TrimSpace(predicate.Set.String())
}

func PrefixPredicateSourceCategory(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "unknown"
	}
	category, _, found := strings.Cut(source, ":")
	if !found || category == "" {
		return source
	}
	return category
}

func predicateSourceCounts(predicates []PrefixPredicate) map[string]int {
	counts := map[string]int{}
	for _, predicate := range predicates {
		counts[PrefixPredicateSourceCategory(predicate.Source)]++
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func maxClassCIDRs(classes []PrefixClass) int {
	maxCIDRs := 0
	for _, class := range classes {
		if count := prefixSetCIDRCount(class.Space); count > maxCIDRs {
			maxCIDRs = count
		}
	}
	return maxCIDRs
}

func prefixSetCIDRCount(set PrefixSet) int {
	switch s := set.(type) {
	case nil:
		return 0
	case UnionPrefixSet:
		count := 0
		for _, child := range s.Sets {
			count += prefixSetCIDRCount(child)
		}
		return count
	default:
		return 1
	}
}

type prefixInterval struct {
	lo uint32
	hi uint32
}

func prefixSetIPv4Intervals(set PrefixSet) ([]prefixInterval, error) {
	switch s := set.(type) {
	case AnyPrefixSet:
		return []prefixInterval{{lo: 0, hi: ^uint32(0)}}, nil
	case ExactPrefixSet:
		return prefixIPv4Interval(s.Prefix)
	case PrefixRangeSet:
		return prefixIPv4Interval(s.Base)
	case UnionPrefixSet:
		var out []prefixInterval
		for _, child := range s.Sets {
			intervals, err := prefixSetIPv4Intervals(child)
			if err != nil {
				return nil, err
			}
			out = append(out, intervals...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported prefix set type %T", set)
	}
}

func prefixIPv4Interval(prefix Prefix) ([]prefixInterval, error) {
	if prefix.IsZero() {
		return nil, nil
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return nil, fmt.Errorf("prefix universe supports IPv4 only: %s", prefix.String())
	}
	lo := ipv4ToUint32(addr)
	size := uint64(1) << uint(32-prefix.Bits())
	return []prefixInterval{{lo: lo, hi: lo + uint32(size-1)}}, nil
}

func matchingPredicateIDs(space prefixInterval, predicates []PrefixPredicate) []PrefixPredicateID {
	spaceSet := prefixSetForInterval(space)
	var out []PrefixPredicateID
	for _, predicate := range predicates {
		if prefixClassMatchesPredicate(spaceSet, predicate) {
			out = append(out, predicate.ID)
		}
	}
	return out
}

func prefixClassMatchesPredicate(spaceSet PrefixSet, predicate PrefixPredicate) bool {
	switch normalizedPrefixPredicateKind(predicate.Kind) {
	case PredicateNLRI:
		return prefixSpaceMatchesNLRIPredicate(spaceSet, predicate.Set)
	default:
		return AddressSpaceOverlaps(spaceSet, predicate.Set)
	}
}

func prefixSpaceMatchesNLRIPredicate(space, predicate PrefixSet) bool {
	if space == nil || predicate == nil {
		return false
	}
	switch s := space.(type) {
	case AnyPrefixSet:
		return NLRIPredicateOverlaps(AnyPrefixSet{}, predicate)
	case ExactPrefixSet:
		return prefixMatchesNLRIPredicateSpace(s.Prefix, predicate)
	case PrefixRangeSet:
		return prefixMatchesNLRIPredicateSpace(s.Base, predicate)
	case UnionPrefixSet:
		for _, child := range s.Sets {
			if prefixSpaceMatchesNLRIPredicate(child, predicate) {
				return true
			}
		}
		return false
	default:
		return NLRIPredicateOverlaps(space, predicate)
	}
}

func prefixMatchesNLRIPredicateSpace(space Prefix, predicate PrefixSet) bool {
	if space.IsZero() {
		return false
	}
	switch p := predicate.(type) {
	case AnyPrefixSet:
		return true
	case ExactPrefixSet:
		return p.Prefix.Overlaps(space)
	case PrefixRangeSet:
		if p.Base.IsZero() || p.Base.Addr().BitLen() != space.Addr().BitLen() || !p.Base.Overlaps(space) {
			return false
		}
		minLen := max(p.MinLen, p.Base.Bits(), space.Bits())
		return minLen <= p.MaxLen
	case UnionPrefixSet:
		for _, child := range p.Sets {
			if prefixMatchesNLRIPredicateSpace(space, child) {
				return true
			}
		}
		return false
	default:
		return predicate.ContainsPrefix(space)
	}
}

func prefixSetForInterval(interval prefixInterval) PrefixSet {
	prefixes := prefixesForIPv4Range(interval.lo, interval.hi)
	sets := make([]PrefixSet, 0, len(prefixes))
	for _, prefix := range prefixes {
		sets = append(sets, ExactPrefixSet{Prefix: prefix})
	}
	if len(sets) == 1 {
		return sets[0]
	}
	return UnionPrefixSet{Sets: sets}
}

func prefixesForIPv4Range(lo, hi uint32) []Prefix {
	var out []Prefix
	for current := uint64(lo); current <= uint64(hi); {
		remaining := uint64(hi) - current + 1
		size := uint64(1)
		if current == 0 {
			size = uint64(1) << 32
		} else {
			size = uint64(current & -current)
		}
		for size > remaining {
			size >>= 1
		}
		prefixLen := 32 - bits.TrailingZeros64(size)
		out = append(out, PrefixFromNetIP(netip.PrefixFrom(uint32ToIPv4(uint32(current)), prefixLen)))
		current += size
	}
	return out
}

func compactUint64s(in []uint64) []uint64 {
	out := in[:0]
	var prev uint64
	for i, value := range in {
		if i == 0 || value != prev {
			out = append(out, value)
			prev = value
		}
	}
	return out
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	raw := addr.As4()
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
}

func uint32ToIPv4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
