package model

import (
	"reflect"
	"testing"
)

func TestHeaderSpaceSplitsTCPDstPorts(t *testing.T) {
	pfx := MustPrefix("10.0.0.0/24")
	topo := aclTestTopology("WEB", "r1", "eth1", "egress",
		ACLRule{Seq: 10, Action: ACLDeny, Match: PacketSpec{Protocol: "tcp", DstSet: ExactPrefixSet{Prefix: pfx}, DstPort: ExactPort(80)}},
		ACLRule{Seq: 20, Action: ACLPermit, Match: PacketSpec{Protocol: "tcp", DstSet: ExactPrefixSet{Prefix: pfx}, DstPort: ExactPort(443)}},
	)
	universe, err := NewPrefixUniverse(topo, nil)
	if err != nil {
		t.Fatalf("NewPrefixUniverse() error = %v", err)
	}
	headerSpace := NewHeaderSpace(topo, nil, universe)
	if got, want := len(headerSpace.Classes), 2; got != want {
		t.Fatalf("len(Classes) = %d, want %d: %#v", got, want, headerSpace.Classes)
	}
	gotPorts := []string{headerSpace.Classes[0].DstPort.String(), headerSpace.Classes[1].DstPort.String()}
	if !reflect.DeepEqual(gotPorts, []string{"443", "80"}) {
		t.Fatalf("dst ports = %#v, want [443 80]", gotPorts)
	}
}

func TestHeaderSpaceLinksDstPrefixToPrefixClass(t *testing.T) {
	topo := &Topology{
		Nodes: []Node{{Name: "dst", Prefixes: MustPrefixes("10.0.0.0/24", "10.0.1.0/24")}},
		ACLs: []ACL{{Name: "DENY-DST", Node: "r1", DefaultAction: ACLDefaultPermit, Rules: []ACLRule{{
			Seq: 10, Action: ACLDeny, Match: PacketSpec{Protocol: "tcp", DstSet: ExactPrefixSet{Prefix: MustPrefix("10.0.1.0/24")}},
		}}}},
	}
	universe, err := NewPrefixUniverse(topo, nil)
	if err != nil {
		t.Fatalf("NewPrefixUniverse() error = %v", err)
	}
	headerSpace := NewHeaderSpace(topo, nil, universe)
	if got, want := len(headerSpace.Classes), 1; got != want {
		t.Fatalf("len(Classes) = %d, want %d: %#v", got, want, headerSpace.Classes)
	}
	classID, ok := universe.ClassForPrefix(MustPrefix("10.0.1.0/24"))
	if !ok {
		t.Fatalf("ClassForPrefix() did not find policy prefix")
	}
	if got := headerSpace.Classes[0].PrefixClassID; got != classID {
		t.Fatalf("PrefixClassID = %d, want %d", got, classID)
	}
}

func TestHeaderSpaceSplitsIngressInterface(t *testing.T) {
	pfx := MustPrefix("10.0.0.0/24")
	topo := &Topology{
		ACLs: []ACL{{Name: "DENY-IN", Node: "r1", DefaultAction: ACLDefaultPermit, Rules: []ACLRule{{
			Seq: 10, Action: ACLDeny, Match: PacketSpec{Protocol: "tcp", DstSet: ExactPrefixSet{Prefix: pfx}},
		}}}},
		ACLBindings: []ACLBinding{
			{Node: "r1", Interface: "eth1", Direction: "ingress", ACLName: "DENY-IN"},
			{Node: "r1", Interface: "eth2", Direction: "ingress", ACLName: "DENY-IN"},
		},
	}
	universe, err := NewPrefixUniverse(topo, nil)
	if err != nil {
		t.Fatalf("NewPrefixUniverse() error = %v", err)
	}
	headerSpace := NewHeaderSpace(topo, nil, universe)
	if got, want := len(headerSpace.Classes), 2; got != want {
		t.Fatalf("len(Classes) = %d, want %d: %#v", got, want, headerSpace.Classes)
	}
	gotIfaces := []string{headerSpace.Classes[0].IngressInterface, headerSpace.Classes[1].IngressInterface}
	if !reflect.DeepEqual(gotIfaces, []string{"eth1", "eth2"}) {
		t.Fatalf("ingress interfaces = %#v, want [eth1 eth2]", gotIfaces)
	}
}

func TestHeaderSpaceAvoidsUnusedDimensionCrossProduct(t *testing.T) {
	topo := &Topology{ACLs: []ACL{{Name: "DENY", Node: "r1", DefaultAction: ACLDefaultPermit, Rules: []ACLRule{
		{Seq: 10, Action: ACLDeny, Match: PacketSpec{DstSet: ExactPrefixSet{Prefix: MustPrefix("10.0.0.0/24")}}},
		{Seq: 20, Action: ACLDeny, Match: PacketSpec{DstSet: ExactPrefixSet{Prefix: MustPrefix("10.0.1.0/24")}}},
	}}}}
	universe, err := NewPrefixUniverse(topo, nil)
	if err != nil {
		t.Fatalf("NewPrefixUniverse() error = %v", err)
	}
	headerSpace := NewHeaderSpace(topo, nil, universe)
	if got, want := len(headerSpace.Classes), 2; got != want {
		t.Fatalf("len(Classes) = %d, want %d: %#v", got, want, headerSpace.Classes)
	}
	for _, class := range headerSpace.Classes {
		if class.Protocol != "" || class.DstPort != nil || class.IngressInterface != "" || class.EgressInterface != "" {
			t.Fatalf("class contains an unnecessary dimension: %#v", class)
		}
	}
}

func TestCollectHeaderPredicatesIncludesQueries(t *testing.T) {
	topo := &Topology{Nodes: []Node{{Name: "dst", Prefixes: MustPrefixes("10.0.0.0/24")}}}
	queries := &Queries{PacketChecks: []PacketCheck{{Name: "web", To: "dst", Protocol: "tcp", DstPorts: []int{80, 443}}}}
	predicates := CollectHeaderPredicates(topo, queries)
	if got, want := len(predicates), 2; got != want {
		t.Fatalf("len(predicates) = %d, want %d", got, want)
	}
	if got, want := predicates[0].Source, "query-packet:web"; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}
	if !predicates[0].DstPort.Contains(80) || !predicates[1].DstPort.Contains(443) {
		t.Fatalf("DstPorts = %#v, %#v; want 80 and 443", predicates[0].DstPort, predicates[1].DstPort)
	}
}

func aclTestTopology(name, node, iface, direction string, rules ...ACLRule) *Topology {
	return &Topology{
		ACLs:        []ACL{{Name: name, Node: node, DefaultAction: ACLDefaultPermit, Rules: rules}},
		ACLBindings: []ACLBinding{{Node: node, Interface: iface, Direction: direction, ACLName: name}},
	}
}
