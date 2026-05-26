package controlplane

import (
	"reflect"
	"testing"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func TestRIBEntryNormalizeSeparatesRouteModelFields(t *testing.T) {
	prefix := model.MustPrefix("10.0.0.0/24")
	route := RIBEntry{
		NLRI:              RouteNLRI{Prefix: prefix},
		Attrs:             BGPAttributes{ASPath: []uint32{65100}, OriginCode: BGPOriginEGP, LocalPref: 150, MED: 20, LearnedIBGP: true},
		Provenance:        RouteProvenance{OriginNode: "origin-node", FromNode: "peer-node", PathNodes: []string{"origin-node", "peer-node", "rx"}, PathLinks: []string{"a", "b"}},
		ForwardingNextHop: RouteNextHop{Node: "peer-node"},
	}.Normalize()

	if route.Origin != "origin-node" || route.OriginCode != "egp" {
		t.Fatalf("origin node/code = %q/%q, want separated origin-node/egp", route.Origin, route.OriginCode)
	}
	if route.Provenance.OriginNode == string(route.Attrs.OriginCode) {
		t.Fatalf("provenance origin node was mixed with BGP origin-code: %#v", route)
	}
	if route.Prefix.String() != prefix.String() || route.ForwardingNextHop.Node != "peer-node" || route.NextHop != "peer-node" {
		t.Fatalf("route model compatibility fields not synchronized: %#v", route)
	}
	if !reflect.DeepEqual(route.ASPath, []uint32{65100}) || route.LocalPref != 150 || route.MED != 20 || !route.LearnedIBGP {
		t.Fatalf("BGP attributes not synchronized: %#v", route)
	}
}

func TestInterfaceMatchesAliases(t *testing.T) {
	for _, tt := range []struct {
		policy string
		packet string
	}{
		{policy: "eth5", packet: "Ethernet5"},
		{policy: "Ethernet5", packet: "eth5"},
		{policy: "ethernet-1/4.0", packet: "e1-4"},
		{policy: "e1-4", packet: "ethernet-1/4.0"},
	} {
		if !interfaceMatches(tt.policy, tt.packet) {
			t.Fatalf("interfaceMatches(%q, %q) = false, want true", tt.policy, tt.packet)
		}
	}
	if interfaceMatches("eth1", "eth2") {
		t.Fatalf("interfaceMatches(eth1, eth2) = true, want false")
	}
}

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
			route:   RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), NextHop: "original", ASPath: []uint32{65100}},
			accept:  true,
			nextHop: "r1",
			asPath:  []uint32{65001, 65100},
		},
		{
			name:       "ibgp preserves next-hop",
			from:       ebgpFrom,
			to:         ibgpTo,
			route:      RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), NextHop: "edge", ASPath: []uint32{65100}},
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
			route:      RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), NextHop: "edge", ASPath: []uint32{65100}},
			accept:     true,
			nextHop:    "r1",
			asPath:     []uint32{65100},
			learnedIBG: true,
		},
		{
			name:       "ibgp empty next-hop is set to exporter",
			from:       ebgpFrom,
			to:         ibgpTo,
			route:      RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), ASPath: []uint32{65100}},
			accept:     true,
			nextHop:    "r1",
			asPath:     []uint32{65100},
			learnedIBG: true,
		},
		{
			name:   "ibgp learned route is not readvertised to ibgp",
			from:   ebgpFrom,
			to:     ibgpTo,
			route:  RIBEntry{Prefix: model.MustPrefix("10.0.0.0/24"), LearnedIBGP: true, NextHop: "edge", ASPath: []uint32{65100}},
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
			if got.Route.ForwardingNextHop.Node != tt.nextHop {
				t.Fatalf("ForwardingNextHop.Node = %q, want %q", got.Route.ForwardingNextHop.Node, tt.nextHop)
			}
			if !reflect.DeepEqual(got.Route.Attrs.ASPath, tt.asPath) || got.Route.Attrs.LearnedIBGP != tt.learnedIBG {
				t.Fatalf("structured BGP attrs = %#v, want ASPath %v LearnedIBGP %v", got.Route.Attrs, tt.asPath, tt.learnedIBG)
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

	accepted := behavior.ImportRoute(to, from, model.BGPNeighbor{}, RIBEntry{ASPath: []uint32{65001, 65100}, LocalPref: 200})
	if !accepted.Accept {
		t.Fatalf("route without receiver ASN was rejected: %s", accepted.Reason)
	}
	if !reflect.DeepEqual(accepted.Route.ASPath, []uint32{65001, 65100}) {
		t.Fatalf("accepted route mutated: %#v", accepted.Route)
	}
	if accepted.Route.LocalPref != 0 {
		t.Fatalf("eBGP import LocalPref = %d, want stripped before receiver default/import policy", accepted.Route.LocalPref)
	}
	ibgp := behavior.ImportRoute(model.Node{Name: "r3", ASN: 65001}, from, model.BGPNeighbor{}, RIBEntry{ASPath: []uint32{65100}, LocalPref: 200})
	if !ibgp.Accept || ibgp.Route.LocalPref != 200 {
		t.Fatalf("iBGP import = %#v, want local-pref preserved", ibgp)
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
	assertLess("origin-code", RIBEntry{ASPath: []uint32{65100}, OriginCode: string(BGPOriginIGP), MED: 20}, RIBEntry{ASPath: []uint32{65100}, OriginCode: string(BGPOriginIncomplete), MED: 10})
	assertLess("med", RIBEntry{ASPath: []uint32{65100}, MED: 10}, RIBEntry{ASPath: []uint32{65100}, MED: 20})
	assertLess("ebgp-over-ibgp", RIBEntry{ASPath: []uint32{65100}}, RIBEntry{ASPath: []uint32{65100}, LearnedIBGP: true})
	assertLess("shorter-link-path", RIBEntry{ASPath: []uint32{65100}, Links: []string{"a"}}, RIBEntry{ASPath: []uint32{65100}, Links: []string{"a", "b"}})
	assertLess("vendor-tie-break", RIBEntry{ASPath: []uint32{65100}, Nodes: []string{"a"}}, RIBEntry{ASPath: []uint32{65100}, Nodes: []string{"b"}})
}

func TestBGPDecisionOptionsControlMEDScope(t *testing.T) {
	receiver := model.Node{Name: "rx", ASN: 65000}
	always := NewBGPDecisionProcess(BGPDecisionOptions{AlwaysCompareMED: true})
	sameNeighborOnly := NewBGPDecisionProcess(BGPDecisionOptions{})

	lowMEDDifferentNeighbor := RIBEntry{ASPath: []uint32{65100}, MED: 10, Nodes: []string{"z"}}
	highMEDDifferentNeighbor := RIBEntry{ASPath: []uint32{65200}, MED: 20, Nodes: []string{"a"}}
	if !always.Less(receiver, lowMEDDifferentNeighbor, highMEDDifferentNeighbor) {
		t.Fatalf("AlwaysCompareMED should compare MED across different neighboring ASNs")
	}
	if sameNeighborOnly.Less(receiver, lowMEDDifferentNeighbor, highMEDDifferentNeighbor) {
		t.Fatalf("MED should be skipped across different neighboring ASNs when AlwaysCompareMED is false")
	}

	lowMEDSameNeighbor := RIBEntry{ASPath: []uint32{65100}, MED: 10, Nodes: []string{"z"}}
	highMEDSameNeighbor := RIBEntry{ASPath: []uint32{65100}, MED: 20, Nodes: []string{"a"}}
	if !sameNeighborOnly.Less(receiver, lowMEDSameNeighbor, highMEDSameNeighbor) {
		t.Fatalf("MED should be compared within the same neighboring AS")
	}
}

func TestBGPDecisionOptionsDocumentUnsupportedRouterIDTieBreak(t *testing.T) {
	behavior := NewFRRBehavior()
	options := behavior.DecisionOptions()
	if options.CompareRouterID {
		t.Fatalf("router-id tie-break should remain explicitly unsupported until routes carry router-id attributes")
	}
	if !options.PreferLowerRouterID {
		t.Fatalf("router-id tie-break direction should be documented for future implementation")
	}
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
	e := RIBEntry{LocalPref: 100, ASPath: []uint32{65100}, OriginCode: string(BGPOriginIncomplete), MED: 10}
	if decision.Equivalent(receiver, a, e) {
		t.Fatalf("routes with different origin-code should not be equivalent")
	}
}

func TestCEOSSelectRoutesKeepsUnreachableNextHopForBgpRIB(t *testing.T) {
	behavior := NewCEOSBehavior()
	device := model.Node{Name: "ceos", ASN: 65000}
	routes := []RIBEntry{
		{Prefix: model.MustPrefix("10.0.0.0/24"), From: "peer1", NextHop: "remote", LocalPref: 300},
		{Prefix: model.MustPrefix("10.0.0.0/24"), From: "peer2", NextHop: "peer2", LocalPref: 200},
		{Prefix: model.MustPrefix("10.0.0.0/24"), From: "peer3", NextHop: "", LocalPref: 100},
	}
	selected := behavior.SelectRoutes(device, routes)
	if len(selected) != 3 {
		t.Fatalf("selected routes = %#v, want all BGP RIB routes", selected)
	}
	if selected[0].From != "peer1" || selected[1].From != "peer2" || selected[2].From != "peer3" {
		t.Fatalf("selected routes = %#v", selected)
	}
}

func TestDeviceBehaviorRouteValidityHooks(t *testing.T) {
	prefix := model.MustPrefix("10.0.0.0/24")
	generic := NewGenericBehavior(model.DeviceKind("generic"))
	genericDevice := model.Node{Name: "generic", Kind: model.DeviceKind("generic"), ASN: 65000}
	validRoute := RIBEntry{Prefix: prefix, From: "peer", NextHop: "remote"}
	invalidRoute := validRoute
	invalidRoute.Invalid = true

	if !generic.RouteValidForRIB(genericDevice, validRoute) {
		t.Fatalf("generic valid route was marked invalid")
	}
	if generic.RouteEligibleForAdvertisement(genericDevice, invalidRoute) {
		t.Fatalf("generic invalid route should not be advertised")
	}
	if generic.RouteInstallableInFIB(genericDevice, nil, invalidRoute) {
		t.Fatalf("generic invalid route should not be installed in FIB")
	}

	ceos := NewCEOSBehavior()
	ceosDevice := model.Node{Name: "ceos", Kind: model.KindCEOS, ASN: 65000}
	unresolved := RIBEntry{Prefix: prefix, From: "peer", NextHop: "remote"}
	direct := RIBEntry{Prefix: prefix, From: "peer", NextHop: "peer"}
	local := RIBEntry{Prefix: prefix, From: "", NextHop: ""}
	if ceos.RouteValidForRIB(ceosDevice, unresolved) {
		t.Fatalf("cEOS unresolved next-hop route should be invalid")
	}
	if !ceos.RouteValidForRIB(ceosDevice, direct) {
		t.Fatalf("cEOS direct next-hop route should be valid")
	}
	if !ceos.RouteValidForRIB(ceosDevice, local) {
		t.Fatalf("cEOS local route should be valid")
	}

	srl := NewSRLinuxBehavior()
	imported := srl.ImportRoute(model.Node{Name: "rx", ASN: 65000}, model.Node{Name: "tx", ASN: 65100}, model.BGPNeighbor{}, RIBEntry{Prefix: prefix, ASPath: []uint32{65100, 65000}})
	if !imported.Accept || !imported.Route.Invalid {
		t.Fatalf("SR Linux AS-loop route should be retained as invalid: %#v", imported)
	}
	if srl.RouteEligibleForAdvertisement(model.Node{Name: "rx", Kind: model.KindSRLinux}, imported.Route) {
		t.Fatalf("SR Linux invalid retained route should not be advertised")
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
