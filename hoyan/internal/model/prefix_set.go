package model

import (
	"fmt"
	"net/netip"
	"strings"
)

type PrefixSet interface {
	// ContainsPrefix reports whether a route prefix/NLRI matches this predicate.
	// PrefixRangeSet applies its ge/le prefix-length constraints here.
	ContainsPrefix(prefix Prefix) bool
	// ContainsAddr reports whether a packet address is inside this set's address
	// space. PrefixRangeSet ge/le constraints are not applied to addresses.
	ContainsAddr(addr netip.Addr) bool
	// Overlaps reports address-space overlap. Use NLRIPredicateOverlaps when
	// comparing route prefix/NLRI predicates with ge/le semantics.
	Overlaps(other PrefixSet) bool
	String() string
}

type AnyPrefixSet struct{}

func (AnyPrefixSet) ContainsPrefix(prefix Prefix) bool {
	return !prefix.IsZero()
}

func (AnyPrefixSet) ContainsAddr(addr netip.Addr) bool {
	return addr.IsValid()
}

func (AnyPrefixSet) Overlaps(other PrefixSet) bool {
	return AddressSpaceOverlaps(AnyPrefixSet{}, other)
}

func (AnyPrefixSet) String() string {
	return "any"
}

type ExactPrefixSet struct {
	Prefix Prefix
}

func (s ExactPrefixSet) ContainsPrefix(prefix Prefix) bool {
	return s.Prefix.Equal(prefix)
}

func (s ExactPrefixSet) ContainsAddr(addr netip.Addr) bool {
	return s.Prefix.Contains(addr)
}

func (s ExactPrefixSet) Overlaps(other PrefixSet) bool {
	return AddressSpaceOverlaps(s, other)
}

func (s ExactPrefixSet) String() string {
	return s.Prefix.String()
}

type PrefixRangeSet struct {
	Base   Prefix
	MinLen int
	MaxLen int
}

func (s PrefixRangeSet) ContainsPrefix(prefix Prefix) bool {
	if prefix.IsZero() || s.Base.IsZero() || prefix.Addr().BitLen() != s.Base.Addr().BitLen() {
		return false
	}
	return s.Base.Contains(prefix.Addr()) && prefix.Bits() >= s.MinLen && prefix.Bits() <= s.MaxLen
}

func (s PrefixRangeSet) ContainsAddr(addr netip.Addr) bool {
	if !addr.IsValid() || s.Base.IsZero() || addr.BitLen() != s.Base.Addr().BitLen() {
		return false
	}
	return s.Base.Contains(addr)
}

func (s PrefixRangeSet) Overlaps(other PrefixSet) bool {
	return AddressSpaceOverlaps(s, other)
}

func (s PrefixRangeSet) String() string {
	out := s.Base.String()
	if s.MinLen != s.Base.Bits() {
		out += fmt.Sprintf(" ge %d", s.MinLen)
	}
	if s.MaxLen != s.Base.Addr().BitLen() {
		out += fmt.Sprintf(" le %d", s.MaxLen)
	}
	return out
}

type UnionPrefixSet struct {
	Sets []PrefixSet
}

func (s UnionPrefixSet) ContainsPrefix(prefix Prefix) bool {
	for _, set := range s.Sets {
		if prefixSetContainsPrefixSpace(set, prefix) {
			return true
		}
	}
	return false
}

func (s UnionPrefixSet) ContainsAddr(addr netip.Addr) bool {
	for _, set := range s.Sets {
		if set != nil && set.ContainsAddr(addr) {
			return true
		}
	}
	return false
}

func (s UnionPrefixSet) Overlaps(other PrefixSet) bool {
	return AddressSpaceOverlaps(s, other)
}

func (s UnionPrefixSet) String() string {
	parts := make([]string, 0, len(s.Sets))
	for _, set := range s.Sets {
		if set != nil {
			parts = append(parts, set.String())
		}
	}
	return strings.Join(parts, ",")
}

func NewPrefixSet(prefix string, ge, le int) (PrefixSet, error) {
	if prefix == "any" {
		if ge != 0 || le != 0 {
			return nil, fmt.Errorf("any prefix-list rule cannot use ge/le")
		}
		return AnyPrefixSet{}, nil
	}
	base, err := ParsePrefix(prefix)
	if err != nil {
		return nil, err
	}
	if ge == 0 && le == 0 {
		return ExactPrefixSet{Prefix: base}, nil
	}
	minLen := base.Bits()
	maxLen := base.Addr().BitLen()
	if ge != 0 {
		minLen = ge
	}
	if le != 0 {
		maxLen = le
	}
	if minLen < base.Bits() || maxLen > base.Addr().BitLen() || minLen > maxLen {
		return nil, fmt.Errorf("invalid prefix range %s ge %d le %d", prefix, ge, le)
	}
	return PrefixRangeSet{Base: base, MinLen: minLen, MaxLen: maxLen}, nil
}

func AddressSpaceContains(set PrefixSet, addr netip.Addr) bool {
	return set != nil && set.ContainsAddr(addr)
}

func MatchesNLRI(set PrefixSet, prefix Prefix) bool {
	return set != nil && set.ContainsPrefix(prefix)
}

func AddressSpaceOverlaps(a, b PrefixSet) bool {
	if a == nil || b == nil {
		return false
	}
	switch aa := a.(type) {
	case AnyPrefixSet:
		return true
	case ExactPrefixSet:
		return prefixAddressSpaceOverlaps(b, aa.Prefix)
	case PrefixRangeSet:
		return prefixAddressSpaceOverlaps(b, aa.Base)
	case UnionPrefixSet:
		for _, child := range aa.Sets {
			if AddressSpaceOverlaps(child, b) {
				return true
			}
		}
		return false
	default:
		return b.ContainsAddr(firstAddressForSet(a))
	}
}

func NLRIPredicateOverlaps(a, b PrefixSet) bool {
	if a == nil || b == nil {
		return false
	}
	switch aa := a.(type) {
	case AnyPrefixSet:
		return true
	case ExactPrefixSet:
		return b.ContainsPrefix(aa.Prefix)
	case PrefixRangeSet:
		switch bb := b.(type) {
		case AnyPrefixSet:
			return true
		case ExactPrefixSet:
			return aa.ContainsPrefix(bb.Prefix)
		case PrefixRangeSet:
			return prefixRangeSetsOverlap(aa, bb)
		case UnionPrefixSet:
			return NLRIPredicateOverlaps(bb, aa)
		default:
			return b.ContainsPrefix(aa.Base)
		}
	case UnionPrefixSet:
		for _, child := range aa.Sets {
			if NLRIPredicateOverlaps(child, b) {
				return true
			}
		}
		return false
	default:
		return b.ContainsPrefix(firstPrefixForSet(a))
	}
}

func prefixAddressSpaceOverlaps(set PrefixSet, prefix Prefix) bool {
	if prefix.IsZero() {
		return false
	}
	switch s := set.(type) {
	case AnyPrefixSet:
		return true
	case ExactPrefixSet:
		return s.Prefix.Overlaps(prefix)
	case PrefixRangeSet:
		return s.Base.Overlaps(prefix)
	case UnionPrefixSet:
		for _, child := range s.Sets {
			if prefixAddressSpaceOverlaps(child, prefix) {
				return true
			}
		}
		return false
	default:
		return set.ContainsAddr(prefix.Addr())
	}
}

func firstAddressForSet(set PrefixSet) netip.Addr {
	switch s := set.(type) {
	case ExactPrefixSet:
		return s.Prefix.Addr()
	case PrefixRangeSet:
		return s.Base.Addr()
	case UnionPrefixSet:
		for _, child := range s.Sets {
			addr := firstAddressForSet(child)
			if addr.IsValid() {
				return addr
			}
		}
	}
	return netip.Addr{}
}

func firstPrefixForSet(set PrefixSet) Prefix {
	switch s := set.(type) {
	case ExactPrefixSet:
		return s.Prefix
	case PrefixRangeSet:
		return s.Base
	case UnionPrefixSet:
		for _, child := range s.Sets {
			prefix := firstPrefixForSet(child)
			if !prefix.IsZero() {
				return prefix
			}
		}
	}
	return Prefix{}
}

func prefixRangeSetsOverlap(a, b PrefixRangeSet) bool {
	if a.Base.IsZero() || b.Base.IsZero() || a.Base.Addr().BitLen() != b.Base.Addr().BitLen() {
		return false
	}
	if !a.Base.Overlaps(b.Base) {
		return false
	}
	intersectionBits := a.Base.Bits()
	if b.Base.Bits() > intersectionBits {
		intersectionBits = b.Base.Bits()
	}
	minLen := max(a.MinLen, b.MinLen, intersectionBits)
	maxLen := min(a.MaxLen, b.MaxLen)
	return minLen <= maxLen
}

func prefixSetContainsPrefixSpace(set PrefixSet, prefix Prefix) bool {
	if set == nil || prefix.IsZero() {
		return false
	}
	switch s := set.(type) {
	case AnyPrefixSet:
		return true
	case ExactPrefixSet:
		return !s.Prefix.IsZero() && s.Prefix.Contains(prefix.Addr()) && prefix.Bits() >= s.Prefix.Bits()
	case PrefixRangeSet:
		return s.ContainsPrefix(prefix)
	case UnionPrefixSet:
		return s.ContainsPrefix(prefix)
	default:
		return set.ContainsPrefix(prefix)
	}
}
