package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderIsolatedTopologyUsesSuffixForNamesAndMgmtSubnet(t *testing.T) {
	data := []byte(`
name: hoyan-wan
prefix: ""
mgmt:
  network: hoyan-wan
  ipv4-subnet: 172.86.86.0/24
topology:
  nodes:
    r1:
      kind: linux
      mgmt-ipv4: 172.86.86.11
  links: []
`)
	out, err := RenderIsolatedTopology(data, TopologyRenderOptions{Suffix: "issue-123"})
	if err != nil {
		t.Fatalf("RenderIsolatedTopology() error = %v", err)
	}
	rendered := string(out)
	for _, want := range []string{
		"name: hoyan-wan-issue-123",
		"network: hoyan-wan-issue-123",
		"ipv4-subnet: 172.86.123.0/24",
		"mgmt-ipv4: 172.86.123.11",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered topology missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "prefix:") {
		t.Fatalf("rendered topology should omit prefix for containerlab default naming:\n%s", rendered)
	}
}

func TestRenderIsolatedTopologyPreservesRelativeConfigPathsByDefault(t *testing.T) {
	data := []byte(`
name: hoyan-wan
mgmt:
  ipv4-subnet: 172.86.86.0/24
topology:
  nodes:
    frr:
      kind: linux
      binds:
        - configs/frr/r1/frr.conf:/etc/frr/frr.conf:ro
    ceos:
      kind: arista_ceos
      startup-config: configs/ceos/r1.cfg
  links: []
`)
	out, err := RenderIsolatedTopology(data, TopologyRenderOptions{Suffix: "issue-123"})
	if err != nil {
		t.Fatalf("RenderIsolatedTopology() error = %v", err)
	}
	rendered := string(out)
	for _, want := range []string{
		"configs/frr/r1/frr.conf:/etc/frr/frr.conf:ro",
		"startup-config: configs/ceos/r1.cfg",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered topology missing relative path %q:\n%s", want, rendered)
		}
	}
}

func TestLoadLabTopologyContainerNames(t *testing.T) {
	topo, err := LoadLabTopology(filepath.Join("..", "..", "hoyan.clab.yml"))
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	node, ok := topo.Node("bj-edge1")
	if !ok {
		t.Fatalf("bj-edge1 not found")
	}
	if node.ContainerName != "clab-hoyan-wan-bj-edge1" {
		t.Fatalf("original topology container name = %q, want containerlab default name", node.ContainerName)
	}

	sourceDir := absPath(t, filepath.Join("..", ".."))
	data, err := RenderIsolatedTopology(mustReadFile(t, filepath.Join("..", "..", "hoyan.clab.yml")), TopologyRenderOptions{Suffix: "issue-21", SourceDir: sourceDir})
	if err != nil {
		t.Fatalf("RenderIsolatedTopology() error = %v", err)
	}
	if !strings.Contains(string(data), filepath.Join(sourceDir, "configs", "frr", "bj-edge1", "frr.conf")) {
		t.Fatalf("rendered topology did not absolute config paths")
	}
	path := writeTempTopology(t, data)
	topo, err = LoadLabTopology(path)
	if err != nil {
		t.Fatalf("LoadLabTopology(rendered) error = %v", err)
	}
	node, ok = topo.Node("bj-edge1")
	if !ok {
		t.Fatalf("bj-edge1 not found in rendered topology")
	}
	if node.ContainerName != "clab-hoyan-wan-issue-21-bj-edge1" {
		t.Fatalf("rendered topology container name = %q", node.ContainerName)
	}
	if node.MgmtIPv4 != "172.86.21.11" {
		t.Fatalf("rendered topology management IP = %q", node.MgmtIPv4)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return data
}

func writeTempTopology(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "generated.clab.yml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
	return path
}

func absPath(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("Abs(%s) error = %v", path, err)
	}
	return abs
}
