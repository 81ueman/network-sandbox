package model

import "testing"

func TestInterfaceAliasesByDeviceKind(t *testing.T) {
	tests := []struct {
		name string
		kind DeviceKind
		in   string
		want []string
	}{
		{name: "frr eth", kind: KindFRR, in: "eth1", want: []string{"eth1"}},
		{name: "ceos eth", kind: KindCEOS, in: "eth1", want: []string{"eth1", "Ethernet1"}},
		{name: "ceos ethernet", kind: KindCEOS, in: "Ethernet1", want: []string{"Ethernet1"}},
		{name: "srl clab", kind: KindSRLinux, in: "e1-1", want: []string{"e1-1", "ethernet-1/1", "ethernet-1/1.0"}},
		{name: "srl base", kind: KindSRLinux, in: "ethernet-1/1", want: []string{"ethernet-1/1", "ethernet-1/1.0"}},
		{name: "srl subinterface", kind: KindSRLinux, in: "ethernet-1/1.0", want: []string{"ethernet-1/1.0", "ethernet-1/1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InterfaceAliases(tt.kind, tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("InterfaceAliases(%s, %q) = %#v, want %#v", tt.kind, tt.in, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("InterfaceAliases(%s, %q) = %#v, want %#v", tt.kind, tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestResolveInterfaceByAlias(t *testing.T) {
	tests := []struct {
		name       string
		node       Node
		clab       string
		configName string
		addr       string
	}{
		{
			name:       "frr",
			node:       Node{Name: "frr", Kind: KindFRR, Interfaces: []Interface{{Name: "eth1", Address: "192.0.2.1/24"}}},
			clab:       "eth1",
			configName: "eth1",
			addr:       "192.0.2.1/24",
		},
		{
			name:       "ceos",
			node:       Node{Name: "ceos", Kind: KindCEOS, Interfaces: []Interface{{Name: "Ethernet1", Address: "192.0.2.2/24"}}},
			clab:       "eth1",
			configName: "Ethernet1",
			addr:       "192.0.2.2/24",
		},
		{
			name:       "srl",
			node:       Node{Name: "srl", Kind: KindSRLinux, Interfaces: []Interface{{Name: "ethernet-1/1.0", Address: "192.0.2.3/24"}}},
			clab:       "e1-1",
			configName: "ethernet-1/1.0",
			addr:       "192.0.2.3/24",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ResolveInterface(tt.node, tt.clab)
			if !ok {
				t.Fatalf("ResolveInterface(%s, %q) not found", tt.node.Name, tt.clab)
			}
			if got.ConfigName != tt.configName || got.ClabName != tt.clab || got.Address.String() != tt.addr {
				t.Fatalf("ResolveInterface() = %#v, want config %q clab %q addr %q", got, tt.configName, tt.clab, tt.addr)
			}
		})
	}
}

func TestEquivalentInterfaceName(t *testing.T) {
	if !EquivalentInterfaceName(KindSRLinux, "e1-1", "ethernet-1/1.0") {
		t.Fatalf("SR Linux e1-1 should match ethernet-1/1.0")
	}
	if EquivalentInterfaceName(KindFRR, "eth1", "Ethernet1") {
		t.Fatalf("FRR eth1 should not match Ethernet1")
	}
}
