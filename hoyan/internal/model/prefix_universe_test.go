package model

import (
	"errors"
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

func TestBuildPrefixUniverseRejectsOverlappingPredicates(t *testing.T) {
	rangeSet, err := NewPrefixSet("10.0.0.0/16", 24, 24)
	if err != nil {
		t.Fatalf("NewPrefixSet() error = %v", err)
	}
	_, err = BuildPrefixUniverse([]PrefixSet{
		ExactPrefixSet{Prefix: MustPrefix("10.0.1.0/24")},
		rangeSet,
	})
	var overlapErr OverlappingPrefixPredicateError
	if !errors.As(err, &overlapErr) {
		t.Fatalf("BuildPrefixUniverse() error = %T %v, want OverlappingPrefixPredicateError", err, err)
	}
}
