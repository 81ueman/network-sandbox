package model

import (
	"path/filepath"
	"testing"
)

func TestLoadLabTopology(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	if len(topo.Nodes) != 18 {
		t.Fatalf("nodes = %d, want 18", len(topo.Nodes))
	}
	if len(topo.Links) < 25 {
		t.Fatalf("links = %d, want at least 25", len(topo.Links))
	}
	if _, ok := topo.Node("core-sh"); !ok {
		t.Fatalf("core-sh not found")
	}
	core, _ := topo.Node("core-bj")
	if core.ASN != 65100 {
		t.Fatalf("core-bj ASN = %d, want parsed 65100", core.ASN)
	}
	if len(core.Neighbors) == 0 {
		t.Fatalf("core-bj neighbors were not parsed from config")
	}
}

func TestOriginLookups(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"), filepath.Join("..", "..", "intent", "policies.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	node, ok := topo.OriginForPrefix("10.4.0.0/16")
	if !ok || node != "hz-edge1" {
		t.Fatalf("OriginForPrefix() = %q, %v", node, ok)
	}
	node, pfx, ok := topo.OriginForIP("10.4.1.10")
	if !ok || node != "cust-hz" || pfx.String() != "10.4.1.10/32" {
		t.Fatalf("OriginForIP() = %q %s %v", node, pfx, ok)
	}
}

func TestParseFRRConfig(t *testing.T) {
	cfg, err := ParseConfig("frr", filepath.Join("..", "..", "configs", "frr", "bj-edge1", "frr.conf"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65001 || cfg.RouterID != "10.255.1.1" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Interfaces) != 4 {
		t.Fatalf("interfaces = %d, want 4", len(cfg.Interfaces))
	}
	if len(cfg.Neighbors) != 3 {
		t.Fatalf("neighbors = %d, want 3", len(cfg.Neighbors))
	}
}

func TestParseCEOSConfig(t *testing.T) {
	cfg, err := ParseConfig("ceos", filepath.Join("..", "..", "configs", "ceos", "core-sh.cfg"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65100 || cfg.RouterID != "10.255.100.2" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Neighbors) != 6 {
		t.Fatalf("neighbors = %d, want 6", len(cfg.Neighbors))
	}
	var found bool
	for _, iface := range cfg.Interfaces {
		if iface.Name == "Ethernet1" && iface.Address == "198.18.10.5/31" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Ethernet1 address not parsed: %#v", cfg.Interfaces)
	}
}

func TestParseSRLinuxConfig(t *testing.T) {
	cfg, err := ParseConfig("srlinux", filepath.Join("..", "..", "configs", "srlinux", "core-gz.cfg"))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if cfg.ASN != 65100 || cfg.RouterID != "10.255.100.3" {
		t.Fatalf("BGP = ASN %d router-id %s", cfg.ASN, cfg.RouterID)
	}
	if len(cfg.Interfaces) != 6 || len(cfg.Neighbors) != 6 {
		t.Fatalf("interfaces/neighbors = %d/%d, want 6/6", len(cfg.Interfaces), len(cfg.Neighbors))
	}
}
