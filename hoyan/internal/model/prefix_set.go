package model

import (
	"fmt"
	"net/netip"
	"strings"
)

type PrefixSet interface {
	ContainsPrefix(prefix Prefix) bool
	ContainsAddr(addr netip.Addr) bool
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
	return other != nil
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
	if other == nil {
		return false
	}
	return prefixesOverlapWith(other, s.Prefix)
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
	bits := addr.BitLen()
	return s.Base.Contains(addr) && bits >= s.MinLen && bits <= s.MaxLen
}

func (s PrefixRangeSet) Overlaps(other PrefixSet) bool {
	if other == nil {
		return false
	}
	switch o := other.(type) {
	case AnyPrefixSet:
		return true
	case ExactPrefixSet:
		return s.ContainsPrefix(o.Prefix)
	case PrefixRangeSet:
		return prefixRangeSetsOverlap(s, o)
	default:
		return prefixesOverlapWith(other, s.Base)
	}
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
	if other == nil {
		return false
	}
	for _, set := range s.Sets {
		if set != nil && set.Overlaps(other) {
			return true
		}
	}
	return false
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

func prefixesOverlapWith(set PrefixSet, prefix Prefix) bool {
	if set.ContainsPrefix(prefix) {
		return true
	}
	if r, ok := set.(PrefixRangeSet); ok {
		return r.Base.Overlaps(prefix)
	}
	if e, ok := set.(ExactPrefixSet); ok {
		return e.Prefix.Overlaps(prefix)
	}
	return set.ContainsAddr(prefix.Addr())
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
