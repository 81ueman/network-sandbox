package model

import (
	"reflect"
	"testing"
)

func TestPrefixUniverseFromAdvertisedAndQueryPrefixes(t *testing.T) {
	topo := &Topology{Nodes: []Node{
		{Name: "src"},
		{Name: "dst", Prefixes: MustPrefixes("10.0.0.0/24", "10.0.1.0/24")},
	}}
	queries := &Queries{
		RouteChecks:  []RouteCheck{{Name: "route", From: "src", Prefix: MustPrefix("10.0.1.0/24")}},
		PacketChecks: []PacketCheck{{Name: "packet", From: "src", To: "dst"}},
	}
	universe, err := NewPrefixUniverse(topo, queries)
	if err != nil {
		t.Fatalf("NewPrefixUniverse() error = %v", err)
	}
	if got, want := len(universe.Classes), 2; got != want {
		t.Fatalf("len(Classes) = %d, want %d", got, want)
	}
	id, ok := universe.ClassForPrefix(MustPrefix("10.0.1.0/24"))
	if !ok {
		t.Fatalf("ClassForPrefix() did not find advertised/query prefix")
	}
	if got, want := id, PrefixClassID(1); got != want {
		t.Fatalf("ClassForPrefix() ID = %d, want %d", got, want)
	}
	if _, ok := universe.ClassForPrefix(MustPrefix("10.0.2.0/24")); ok {
		t.Fatalf("ClassForPrefix() found an unknown prefix")
	}
}

func TestPrefixUniverseCollectsPrefixListAndPolicyPredicates(t *testing.T) {
	rangeSet, err := NewPrefixSet("10.0.0.0/16", 24, 24)
	if err != nil {
		t.Fatalf("NewPrefixSet() error = %v", err)
	}
	topo := &Topology{
		Nodes: []Node{{
			Name: "r1",
			PrefixLists: []PrefixList{{
				Name:  "PL",
				Rules: []PrefixListRule{{Seq: 10, Action: "permit", Prefix: "10.0.0.0/16", Ge: 24, Le: 24, Match: rangeSet}},
			}},
		}},
		Policies: []Policy{{Name: "deny-dst", Node: "r1", Action: "deny", DstPrefix: MustPrefix("192.0.2.0/24")}},
	}
	universe, err := NewPrefixUniverse(topo, nil)
	if err != nil {
		t.Fatalf("NewPrefixUniverse() error = %v", err)
	}
	if got, want := len(universe.Classes), 2; got != want {
		t.Fatalf("len(Classes) = %d, want %d", got, want)
	}
	ids := universe.ClassesMatching(ExactPrefixSet{Prefix: MustPrefix("10.0.12.0/24")})
	if !reflect.DeepEqual(ids, []PrefixClassID{0}) {
		t.Fatalf("ClassesMatching(range member) = %#v, want [0]", ids)
	}
	ids = universe.ClassesMatching(ExactPrefixSet{Prefix: MustPrefix("192.0.2.0/24")})
	if !reflect.DeepEqual(ids, []PrefixClassID{1}) {
		t.Fatalf("ClassesMatching(policy prefix) = %#v, want [1]", ids)
	}
}

func TestBuildPrefixUniverseSplitsOverlappingPredicates(t *testing.T) {
	rangeSet, err := NewPrefixSet("10.0.0.0/16", 24, 24)
	if err != nil {
		t.Fatalf("NewPrefixSet() error = %v", err)
	}
	universe, err := BuildPrefixUniverse([]PrefixSet{
		ExactPrefixSet{Prefix: MustPrefix("10.0.1.0/24")},
		rangeSet,
	})
	if err != nil {
		t.Fatalf("BuildPrefixUniverse() error = %v", err)
	}
	if got, want := len(universe.Classes), 3; got != want {
		t.Fatalf("len(Classes) = %d, want %d", got, want)
	}
	id, ok := universe.ClassForPrefix(MustPrefix("10.0.1.0/24"))
	if !ok {
		t.Fatalf("ClassForPrefix() did not find overlapping exact prefix")
	}
	if got, want := universe.PredicatesForClass(id), []PrefixPredicateID{0, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PredicatesForClass(overlap) = %#v, want %#v", got, want)
	}
	ids := universe.ClassesMatching(ExactPrefixSet{Prefix: MustPrefix("10.0.0.0/16")})
	if got, want := len(ids), 3; got != want {
		t.Fatalf("ClassesMatching(10.0.0.0/16) = %#v, want %d classes", ids, want)
	}
}

func TestBuildPrefixUniverseAllowsDefaultAndSpecificRoute(t *testing.T) {
	universe, err := BuildPrefixUniverse([]PrefixSet{
		ExactPrefixSet{Prefix: MustPrefix("0.0.0.0/0")},
		ExactPrefixSet{Prefix: MustPrefix("10.4.0.0/16")},
	})
	if err != nil {
		t.Fatalf("BuildPrefixUniverse() error = %v", err)
	}
	id, ok := universe.ClassForPrefix(MustPrefix("10.4.1.0/24"))
	if !ok {
		t.Fatalf("ClassForPrefix() did not find specific route class")
	}
	if got, want := universe.PredicatesForClass(id), []PrefixPredicateID{0, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PredicatesForClass(specific) = %#v, want %#v", got, want)
	}
}

func TestBuildPrefixUniverseRangeAndSpecificPredicateMatches(t *testing.T) {
	rangeSet, err := NewPrefixSet("10.0.0.0/8", 16, 24)
	if err != nil {
		t.Fatalf("NewPrefixSet() error = %v", err)
	}
	universe, err := BuildPrefixUniverse([]PrefixSet{
		rangeSet,
		ExactPrefixSet{Prefix: MustPrefix("10.4.0.0/16")},
	})
	if err != nil {
		t.Fatalf("BuildPrefixUniverse() error = %v", err)
	}
	id, ok := universe.ClassForPrefix(MustPrefix("10.4.1.0/24"))
	if !ok {
		t.Fatalf("ClassForPrefix() did not find class for 10.4.1.0/24")
	}
	if got, want := universe.PredicatesForClass(id), []PrefixPredicateID{0, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PredicatesForClass(10.4.1.0/24) = %#v, want %#v", got, want)
	}
	ids := universe.ClassesMatching(ExactPrefixSet{Prefix: MustPrefix("10.4.0.0/16")})
	if got, want := len(ids), 1; got != want {
		t.Fatalf("ClassesMatching(10.4.0.0/16) = %#v, want %d class", ids, want)
	}
}

func TestPrefixUniverseSeparatesAddressSpaceAndNLRIPredicateKinds(t *testing.T) {
	rangeSet, err := NewPrefixSet("10.0.0.0/8", 16, 24)
	if err != nil {
		t.Fatalf("NewPrefixSet() error = %v", err)
	}
	packetHost := ExactPrefixSet{Prefix: MustPrefix("10.4.1.10/32")}
	universe, err := BuildPrefixUniverseFromPredicates([]PrefixPredicate{
		{ID: 0, Source: "prefix-list:PL:10", Kind: PredicateNLRI, Set: rangeSet},
		{ID: 1, Source: "query-packet:packet", Kind: PredicateAddressSpace, Set: packetHost},
	})
	if err != nil {
		t.Fatalf("BuildPrefixUniverseFromPredicates() error = %v", err)
	}
	id, ok := universe.ClassForPrefix(MustPrefix("10.4.1.10/32"))
	if !ok {
		t.Fatalf("ClassForPrefix() did not find packet host class")
	}
	if got, want := universe.PredicatesForClass(id), []PrefixPredicateID{1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PredicatesForClass(packet host) = %#v, want %#v", got, want)
	}
	foundRangeClass := false
	for _, class := range universe.Classes {
		matches := universe.PredicatesForClass(class.ID)
		if containsPrefixPredicateID(matches, 0) && !containsPrefixPredicateID(matches, 1) {
			foundRangeClass = true
			break
		}
	}
	if !foundRangeClass {
		t.Fatalf("universe classes = %#v, want at least one class matching only the NLRI range predicate", universe.Classes)
	}
}

func TestBuildPrefixUniverseRejectsIPv6Explicitly(t *testing.T) {
	_, err := BuildPrefixUniverse([]PrefixSet{
		ExactPrefixSet{Prefix: MustPrefix("2001:db8::/32")},
	})
	if err == nil {
		t.Fatalf("BuildPrefixUniverse() error = nil, want IPv4-only error")
	}
}

func containsPrefixPredicateID(ids []PrefixPredicateID, want PrefixPredicateID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestCollectPrefixPredicateMetadataSources(t *testing.T) {
	topo := &Topology{
		Nodes:    []Node{{Name: "dst", Prefixes: MustPrefixes("10.0.0.0/24")}},
		Policies: []Policy{{Name: "deny-dst", DstPrefix: MustPrefix("192.0.2.0/24")}},
	}
	queries := &Queries{RouteChecks: []RouteCheck{{Name: "route", Prefix: MustPrefix("10.0.0.0/24")}}}
	predicates := CollectPrefixPredicateMetadata(topo, queries)
	var sources []string
	for _, predicate := range predicates {
		sources = append(sources, predicate.Source)
	}
	want := []string{"route:dst", "policy:deny-dst", "query-route:route"}
	if !reflect.DeepEqual(sources, want) {
		t.Fatalf("sources = %#v, want %#v", sources, want)
	}
}
