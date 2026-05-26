package livesnapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

func TestSnapshotMarshalLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	snap := &Snapshot{
		Version:     Version,
		Lab:         "unit",
		CollectedAt: time.Date(2026, 5, 26, 1, 2, 3, 0, time.UTC),
		Nodes: map[string]NodeSnapshot{
			"r1": {
				Kind: model.KindFRR,
				BGPRIB: []ribcompare.NormalizedRoute{{
					Node:            "r1",
					NetworkInstance: "default",
					AFI:             "ipv4",
					Prefix:          "10.0.0.0/24",
					Protocol:        "bgp",
				}},
			},
		},
	}
	if err := Save(path, snap); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Version != Version || loaded.Lab != "unit" {
		t.Fatalf("loaded snapshot = %#v", loaded)
	}
	if got := BGPRoutes(loaded); len(got) != 1 || got[0].Prefix != "10.0.0.0/24" {
		t.Fatalf("BGPRoutes() = %#v", got)
	}
}

func TestInputHashesAndCheckHashesReportConfigMismatch(t *testing.T) {
	topologyPath, configPath := writeHashLab(t)
	hashes, err := InputHashes(topologyPath)
	if err != nil {
		t.Fatalf("InputHashes() error = %v", err)
	}
	if hashes.TopologyHash == "" {
		t.Fatalf("TopologyHash is empty")
	}
	if _, ok := hashes.ConfigHashes["frr.conf"]; !ok {
		t.Fatalf("ConfigHashes missing frr.conf: %#v", hashes.ConfigHashes)
	}
	snap := &Snapshot{
		Version:      Version,
		TopologyHash: hashes.TopologyHash,
		ConfigHashes: hashes.ConfigHashes,
		CollectedAt:  time.Now().UTC(),
		Nodes:        map[string]NodeSnapshot{},
	}
	appendConfig(t, configPath, "\ninterface lo\n")
	result, err := CheckHashes(topologyPath, snap)
	if err != nil {
		t.Fatalf("CheckHashes() error = %v", err)
	}
	if len(result.Mismatches) != 1 || result.Mismatches[0].Path != "frr.conf" {
		t.Fatalf("mismatches = %#v, want frr.conf mismatch", result.Mismatches)
	}
}

func writeHashLab(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frr.conf")
	writeFile(t, configPath, "hostname r1\nrouter bgp 65001\n")
	topologyPath := filepath.Join(dir, "lab.clab.yml")
	writeFile(t, topologyPath, `name: hash-test
topology:
  nodes:
    r1:
      kind: linux
      binds:
        - frr.conf:/etc/frr/frr.conf:ro
`)
	return topologyPath, configPath
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := osWriteFile(path, body); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := osAppendFile(path, body); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

func osWriteFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}

func osAppendFile(path, body string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strings.TrimPrefix(body, "\n") + "\n")
	return err
}
