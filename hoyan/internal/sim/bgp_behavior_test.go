package sim

import (
	"reflect"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestBaseBGPExportRoute(t *testing.T) {
	behavior := NewGenericBehavior("generic")
	ebgpFrom := model.Node{Name: "r1", ASN: 65001}
	ebgpTo := model.Node{Name: "r2", ASN: 65002}
	ibgpTo := model.Node{Name: "r3", ASN: 65001}

	tests := []struct {
		name       string
		from       model.Node
		to         model.Node
		session    model.BGPNeighbor
		route      RIBEntry
		accept     bool
		nextHop    string
		asPath     []uint32
		learnedIBG bool
	}{
		{
			name:    "ebgp prepends local ASN and rewrites next-hop",
			from:    ebgpFrom,
			to:      ebgpTo,
			route:   RIBEntry{Prefix: "10.0.0.0/24", NextHop: "original", ASPath: []uint32{65100}},
			accept:  true,
			nextHop: "r1",
			asPath:  []uint32{65001, 65100},
		},
		{
			name:       "ibgp preserves next-hop",
			from:       ebgpFrom,
			to:         ibgpTo,
			route:      RIBEntry{Prefix: "10.0.0.0/24", NextHop: "edge", ASPath: []uint32{65100}},
			accept:     true,
			nextHop:    "edge",
			asPath:     []uint32{65100},
			learnedIBG: true,
		},
		{
			name:       "ibgp next-hop-self rewrites next-hop",
			from:       ebgpFrom,
			to:         ibgpTo,
			session:    model.BGPNeighbor{NextHopSelf: true},
			route:      RIBEntry{Prefix: "10.0.0.0/24", NextHop: "edge", ASPath: []uint32{65100}},
			accept:     true,
			nextHop:    "r1",
			asPath:     []uint32{65100},
			learnedIBG: true,
		},
		{
			name:       "ibgp empty next-hop is set to exporter",
			from:       ebgpFrom,
			to:         ibgpTo,
			route:      RIBEntry{Prefix: "10.0.0.0/24", ASPath: []uint32{65100}},
			accept:     true,
			nextHop:    "r1",
			asPath:     []uint32{65100},
			learnedIBG: true,
		},
		{
			name:   "ibgp learned route is not readvertised to ibgp",
			from:   ebgpFrom,
			to:     ibgpTo,
			route:  RIBEntry{Prefix: "10.0.0.0/24", LearnedIBGP: true, NextHop: "edge", ASPath: []uint32{65100}},
			accept: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := behavior.ExportRoute(tt.from, tt.to, tt.session, tt.route)
			if got.Accept != tt.accept {
				t.Fatalf("Accept = %v, want %v, reason=%s", got.Accept, tt.accept, got.Reason)
			}
			if !tt.accept {
				return
			}
			if got.Route.NextHop != tt.nextHop {
				t.Fatalf("NextHop = %q, want %q", got.Route.NextHop, tt.nextHop)
			}
			if !reflect.DeepEqual(got.Route.ASPath, tt.asPath) {
				t.Fatalf("ASPath = %v, want %v", got.Route.ASPath, tt.asPath)
			}
			if got.Route.LearnedIBGP != tt.learnedIBG {
				t.Fatalf("LearnedIBGP = %v, want %v", got.Route.LearnedIBGP, tt.learnedIBG)
			}
		})
	}
}

func TestBaseBGPImportRoute(t *testing.T) {
	behavior := NewGenericBehavior("generic")
	to := model.Node{Name: "r2", ASN: 65002}
	from := model.Node{Name: "r1", ASN: 65001}

	rejected := behavior.ImportRoute(to, from, model.BGPNeighbor{}, RIBEntry{ASPath: []uint32{65001, 65002}})
	if rejected.Accept {
		t.Fatalf("route containing receiver ASN was accepted")
	}

	accepted := behavior.ImportRoute(to, from, model.BGPNeighbor{}, RIBEntry{ASPath: []uint32{65001, 65100}})
	if !accepted.Accept {
		t.Fatalf("route without receiver ASN was rejected: %s", accepted.Reason)
	}
	if !reflect.DeepEqual(accepted.Route.ASPath, []uint32{65001, 65100}) {
		t.Fatalf("accepted route mutated: %#v", accepted.Route)
	}
}

func TestDefaultBGPDecisionProcessOrdering(t *testing.T) {
	receiver := model.Node{Name: "rx", ASN: 65000}
	decision := DefaultBGPDecisionProcess()

	assertLess := func(name string, better, worse RIBEntry) {
		t.Helper()
		if !decision.Less(receiver, better, worse) {
			t.Fatalf("%s: better route was not ordered first", name)
		}
		if decision.Less(receiver, worse, better) {
			t.Fatalf("%s: worse route was ordered first", name)
		}
	}

	assertLess("local-pref", RIBEntry{LocalPref: 200}, RIBEntry{LocalPref: 100})
	assertLess("local-origin", RIBEntry{Origin: "rx", LocalPref: 100}, RIBEntry{Origin: "remote", LocalPref: 100})
	assertLess("as-path-length", RIBEntry{ASPath: []uint32{65100}}, RIBEntry{ASPath: []uint32{65100, 65200}})
	assertLess("med", RIBEntry{ASPath: []uint32{65100}, MED: 10}, RIBEntry{ASPath: []uint32{65100}, MED: 20})
	assertLess("ebgp-over-ibgp", RIBEntry{ASPath: []uint32{65100}}, RIBEntry{ASPath: []uint32{65100}, LearnedIBGP: true})
	assertLess("shorter-link-path", RIBEntry{ASPath: []uint32{65100}, Links: []string{"a"}}, RIBEntry{ASPath: []uint32{65100}, Links: []string{"a", "b"}})
	assertLess("vendor-tie-break", RIBEntry{ASPath: []uint32{65100}, Nodes: []string{"a"}}, RIBEntry{ASPath: []uint32{65100}, Nodes: []string{"b"}})
}

func TestDefaultBGPDecisionProcessEquivalent(t *testing.T) {
	receiver := model.Node{Name: "rx", ASN: 65000}
	decision := DefaultBGPDecisionProcess()
	a := RIBEntry{LocalPref: 100, ASPath: []uint32{65100}, MED: 10, Links: []string{"a"}, Nodes: []string{"a"}}
	b := RIBEntry{LocalPref: 100, ASPath: []uint32{65200}, MED: 10, Links: []string{"b"}, Nodes: []string{"b"}}
	if !decision.Equivalent(receiver, a, b) {
		t.Fatalf("routes should be equivalent before tie-break")
	}
	c := RIBEntry{LocalPref: 100, ASPath: []uint32{65100}, MED: 10, LearnedIBGP: true}
	if decision.Equivalent(receiver, a, c) {
		t.Fatalf("eBGP and iBGP routes should not be equivalent")
	}
	d := RIBEntry{LocalPref: 100, ASPath: []uint32{65300}, MED: 10, Links: []string{"d", "e"}}
	if !decision.Equivalent(receiver, a, d) {
		t.Fatalf("routes with equal BGP attributes before tie-break should be equivalent")
	}
}

func TestCEOSSelectRoutesKeepsUnreachableNextHopForBgpRIB(t *testing.T) {
	behavior := NewCEOSBehavior()
	device := model.Node{Name: "ceos", ASN: 65000}
	routes := []RIBEntry{
		{Prefix: "10.0.0.0/24", From: "peer1", NextHop: "remote", LocalPref: 300},
		{Prefix: "10.0.0.0/24", From: "peer2", NextHop: "peer2", LocalPref: 200},
		{Prefix: "10.0.0.0/24", From: "peer3", NextHop: "", LocalPref: 100},
	}
	selected := behavior.SelectRoutes(device, routes)
	if len(selected) != 3 {
		t.Fatalf("selected routes = %#v, want all BGP RIB routes", selected)
	}
	if selected[0].From != "peer1" || selected[1].From != "peer2" || selected[2].From != "peer3" {
		t.Fatalf("selected routes = %#v", selected)
	}
}

func TestRegisterBehaviorReturnsRestoreFunction(t *testing.T) {
	restore := RegisterBehavior("test-kind", NewGenericBehavior("registered-kind"))
	if BehaviorFor("test-kind").Kind() != "registered-kind" {
		t.Fatalf("registered behavior was not returned")
	}
	restore()
	if BehaviorFor("test-kind").Kind() != "test-kind" {
		t.Fatalf("fallback generic behavior was not restored")
	}

	old := BehaviorFor("frr")
	restore = RegisterBehavior("frr", NewGenericBehavior("temporary-frr"))
	if BehaviorFor("frr").Kind() != "temporary-frr" {
		t.Fatalf("replacement behavior was not returned")
	}
	restore()
	if BehaviorFor("frr") != old {
		t.Fatalf("original behavior was not restored")
	}
}
