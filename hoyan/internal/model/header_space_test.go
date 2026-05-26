package model

import (
	"reflect"
	"testing"
)

func TestHeaderSpaceSplitsTCPDstPorts(t *testing.T) {
	pfx := MustPrefix("10.0.0.0/24")
	topo := &Topology{Policies: []Policy{
		{Name: "DENY-HTTP", Plane: "data", Stage: "egress", Action: "deny", Protocol: "tcp", DstPrefix: pfx, DstPort: ExactPort(80)},
		{Name: "ALLOW-HTTPS", Plane: "data", Stage: "egress", Action: "permit", Protocol: "tcp", DstPrefix: pfx, DstPort: ExactPort(443)},
	}}
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
		Policies: []Policy{{
			Name:      "DENY-DST",
			Plane:     "data",
			Stage:     "egress",
			Action:    "deny",
			Protocol:  "tcp",
			DstPrefix: MustPrefix("10.0.1.0/24"),
		}},
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
	topo := &Topology{Policies: []Policy{
		{Name: "DENY-IN-1", Plane: "data", Stage: "ingress", Interface: "eth1", Action: "deny", Protocol: "tcp", DstPrefix: pfx},
		{Name: "DENY-IN-2", Plane: "data", Stage: "ingress", Interface: "eth2", Action: "deny", Protocol: "tcp", DstPrefix: pfx},
	}}
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
	topo := &Topology{Policies: []Policy{
		{Name: "DENY-A", Plane: "data", Stage: "egress", Action: "deny", DstPrefix: MustPrefix("10.0.0.0/24")},
		{Name: "DENY-B", Plane: "data", Stage: "egress", Action: "deny", DstPrefix: MustPrefix("10.0.1.0/24")},
	}}
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
