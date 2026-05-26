package model

import (
	"net/netip"
	"testing"
)

func TestExactPrefixSetContainsOnlyExactPrefix(t *testing.T) {
	set := ExactPrefixSet{Prefix: MustPrefix("10.0.0.0/24")}
	if !set.ContainsPrefix(MustPrefix("10.0.0.0/24")) {
		t.Fatalf("exact set should contain identical prefix")
	}
	if set.ContainsPrefix(MustPrefix("10.0.0.0/25")) {
		t.Fatalf("exact set should not contain more-specific prefix")
	}
	if !set.ContainsAddr(netip.MustParseAddr("10.0.0.1")) {
		t.Fatalf("exact set should contain address inside the prefix")
	}
}

func TestPrefixRangeSetContainsPrefixByContainmentAndLength(t *testing.T) {
	set := PrefixRangeSet{Base: MustPrefix("10.0.0.0/8"), MinLen: 16, MaxLen: 24}
	if !set.ContainsPrefix(MustPrefix("10.1.0.0/16")) {
		t.Fatalf("range set should contain permitted child prefix")
	}
	if !set.ContainsPrefix(MustPrefix("10.1.2.0/24")) {
		t.Fatalf("range set should contain permitted more-specific prefix")
	}
	if set.ContainsPrefix(MustPrefix("10.0.0.0/8")) {
		t.Fatalf("range set should reject prefixes shorter than min length")
	}
	if set.ContainsPrefix(MustPrefix("10.1.2.128/25")) {
		t.Fatalf("range set should reject prefixes longer than max length")
	}
	if set.ContainsPrefix(MustPrefix("192.0.2.0/24")) {
		t.Fatalf("range set should reject prefixes outside the base")
	}
}

func TestPrefixRangeSetContainsAddrIgnoresPrefixLengthBounds(t *testing.T) {
	set := PrefixRangeSet{Base: MustPrefix("10.0.0.0/8"), MinLen: 16, MaxLen: 24}
	if !set.ContainsAddr(netip.MustParseAddr("10.4.1.10")) {
		t.Fatalf("range set should contain packet address inside base prefix")
	}
	if set.ContainsAddr(netip.MustParseAddr("192.0.2.10")) {
		t.Fatalf("range set should reject packet address outside base prefix")
	}
}

func TestNewPrefixSetBuildsExactAnyAndRangeSets(t *testing.T) {
	exact, err := NewPrefixSet("10.0.0.0/24", 0, 0)
	if err != nil {
		t.Fatalf("NewPrefixSet(exact) error = %v", err)
	}
	if _, ok := exact.(ExactPrefixSet); !ok {
		t.Fatalf("NewPrefixSet(exact) = %T, want ExactPrefixSet", exact)
	}
	any, err := NewPrefixSet("any", 0, 0)
	if err != nil {
		t.Fatalf("NewPrefixSet(any) error = %v", err)
	}
	if !any.ContainsPrefix(MustPrefix("203.0.113.0/24")) {
		t.Fatalf("any set should contain valid prefixes")
	}
	ranged, err := NewPrefixSet("10.0.0.0/8", 16, 24)
	if err != nil {
		t.Fatalf("NewPrefixSet(range) error = %v", err)
	}
	if !ranged.ContainsPrefix(MustPrefix("10.2.0.0/16")) || ranged.ContainsPrefix(MustPrefix("10.2.3.128/25")) {
		t.Fatalf("range set did not enforce ge/le bounds")
	}
}

func TestPrefixSetOverlaps(t *testing.T) {
	a := PrefixRangeSet{Base: MustPrefix("10.0.0.0/8"), MinLen: 16, MaxLen: 24}
	b := ExactPrefixSet{Prefix: MustPrefix("10.1.0.0/16")}
	c := ExactPrefixSet{Prefix: MustPrefix("192.0.2.0/24")}
	if !a.Overlaps(b) || !b.Overlaps(a) {
		t.Fatalf("overlapping prefix sets should overlap")
	}
	if a.Overlaps(c) || c.Overlaps(a) {
		t.Fatalf("disjoint prefix sets should not overlap")
	}
}

func TestPrefixSetAddressSpaceAndNLRIPredicateOverlapDiffer(t *testing.T) {
	ranged := PrefixRangeSet{Base: MustPrefix("10.0.0.0/8"), MinLen: 16, MaxLen: 24}
	base := ExactPrefixSet{Prefix: MustPrefix("10.0.0.0/8")}
	packetHost := ExactPrefixSet{Prefix: MustPrefix("10.4.1.10/32")}

	if !AddressSpaceOverlaps(ranged, base) {
		t.Fatalf("address-space overlap should ignore ge/le bounds")
	}
	if NLRIPredicateOverlaps(ranged, base) {
		t.Fatalf("NLRI predicate overlap should reject prefixes shorter than ge")
	}
	if !AddressSpaceOverlaps(ranged, packetHost) {
		t.Fatalf("address-space overlap should include host inside range base")
	}
	if NLRIPredicateOverlaps(ranged, packetHost) {
		t.Fatalf("NLRI predicate overlap should reject host prefix longer than le")
	}
}
