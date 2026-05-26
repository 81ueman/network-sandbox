package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootHelpListsSubcommands(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	help := out.String()
	for _, want := range []string{"verify", "live-check", "rib-compare", "render-topology", "model"} {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q:\n%s", want, help)
		}
	}
}

func TestLiveCheckRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "timeout", args: []string{"--timeout", "0s"}, want: "--timeout must be greater than zero"},
		{name: "poll interval", args: []string{"--poll-interval", "0s"}, want: "--poll-interval must be greater than zero"},
		{name: "max polls", args: []string{"--max-polls", "0"}, want: "--max-polls must be greater than zero"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewLiveCheckCommand()
			cmd.SetOut(ioDiscard{})
			cmd.SetErr(ioDiscard{})
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("Execute() error = nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestVerifyStrictConfigRejectsUnsupportedStatements(t *testing.T) {
	topologyPath, _ := writeUnsupportedConfigLab(t)
	cmd := NewVerifyCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{"--topology", topologyPath, "--strict-config"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil")
	}
	for _, want := range []string{"unsupported config statements", "vendor=frr", "line=4", `raw="match source-protocol bgp"`, "reason=unsupported FRR route-map match statement"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q:\n%s", want, err.Error())
		}
	}
}

func TestLiveCheckStrictConfigRejectsUnsupportedStatementsBeforeDeploy(t *testing.T) {
	topologyPath, _ := writeUnsupportedConfigLab(t)
	cmd := NewLiveCheckCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{"--topology", topologyPath, "--strict-config"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil")
	}
	if !strings.Contains(err.Error(), "unsupported config statements") || !strings.Contains(err.Error(), "vendor=frr") {
		t.Fatalf("error = %v, want strict config error", err)
	}
}

func TestModelRIBStrictConfigRejectsUnsupportedStatements(t *testing.T) {
	topologyPath, _ := writeUnsupportedConfigLab(t)
	cmd := NewModelRIBCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{"--topology", topologyPath, "--strict-config"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil")
	}
	if !strings.Contains(err.Error(), "unsupported config statements") || !strings.Contains(err.Error(), `raw="match source-protocol bgp"`) {
		t.Fatalf("error = %v, want strict config error", err)
	}
}

func TestNormalizeLegacyLongFlags(t *testing.T) {
	got := normalizeLegacyLongFlags([]string{"render-topology", "-suffix", "issue-38", "-output=out.yml", "-h", "--topology", "x.yml", "-1s"})
	want := []string{"render-topology", "--suffix", "issue-38", "--output=out.yml", "-h", "--topology", "x.yml", "-1s"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("normalizeLegacyLongFlags() = %#v, want %#v", got, want)
	}
}

func writeUnsupportedConfigLab(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(configPath, []byte(`
hostname r1
route-map RM permit 10
 match source-protocol bgp
 set local-preference 200
`), 0o644); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	topologyPath := filepath.Join(dir, "lab.clab.yml")
	if err := os.WriteFile(topologyPath, []byte(`name: strict-test
topology:
  nodes:
    r1:
      kind: linux
      binds:
        - frr.conf:/etc/frr/frr.conf
`), 0o644); err != nil {
		t.Fatalf("WriteFile(topology) error = %v", err)
	}
	return topologyPath, configPath
}

func TestRenderTopologyCommandAcceptsIsolationFlags(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.clab.yml")
	output := filepath.Join(dir, "generated.clab.yml")
	input := []byte(`name: hoyan-wan
mgmt:
    ipv4-subnet: 172.86.86.0/24
topology:
    nodes:
        r1:
            kind: linux
            mgmt-ipv4: 172.86.86.11
`)
	if err := os.WriteFile(source, input, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cmd := NewRenderTopologyCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", source,
		"--output", output,
		"--suffix", "issue-38",
		"--lab-name", "hoyan-custom",
		"--mgmt-network", "hoyan-custom",
		"--mgmt-subnet", "172.86.38.0/24",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	rendered := string(data)
	for _, want := range []string{"name: hoyan-custom", "network: hoyan-custom", "ipv4-subnet: 172.86.38.0/24", "mgmt-ipv4: 172.86.38.11"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered topology missing %q:\n%s", want, rendered)
		}
	}
}

func TestVerifyCommandOutputsPrefixClassJSON(t *testing.T) {
	var out bytes.Buffer
	cmd := NewVerifyCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "intent", "queries.yml"),
		"--prefix-classes",
		"--no-collapse",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if len(rows) <= 13 {
		t.Fatalf("rows = %d, want class-expanded results", len(rows))
	}
	first := rows[0]
	for _, key := range []string{"class_id", "space", "matched_predicates", "reachable_condition", "unreachable_condition"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("verify JSON missing %q: %#v", key, first)
		}
	}
	var foundRIB, foundFIB bool
	for _, row := range rows {
		predicates, _ := row["matched_predicates"].([]any)
		for _, raw := range predicates {
			source, _ := raw.(string)
			if strings.HasPrefix(source, "rib:") {
				foundRIB = true
			}
			if strings.HasPrefix(source, "fib:") {
				foundFIB = true
			}
		}
	}
	if !foundRIB || !foundFIB {
		t.Fatalf("verify JSON missing RIB/FIB predicates: rib=%v fib=%v", foundRIB, foundFIB)
	}
}

func TestVerifyCommandCollapsesPrefixClassOutputByDefault(t *testing.T) {
	var collapsed, raw bytes.Buffer
	collapsedCmd := NewVerifyCommand()
	collapsedCmd.SetOut(&collapsed)
	collapsedCmd.SetErr(ioDiscard{})
	collapsedCmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "intent", "queries.yml"),
		"--prefix-classes",
		"--format", "json",
	})
	if err := collapsedCmd.Execute(); err != nil {
		t.Fatalf("collapsed Execute() error = %v", err)
	}
	rawCmd := NewVerifyCommand()
	rawCmd.SetOut(&raw)
	rawCmd.SetErr(ioDiscard{})
	rawCmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "intent", "queries.yml"),
		"--prefix-classes",
		"--no-collapse",
		"--format", "json",
	})
	if err := rawCmd.Execute(); err != nil {
		t.Fatalf("raw Execute() error = %v", err)
	}
	var collapsedRows, rawRows []map[string]any
	if err := json.Unmarshal(collapsed.Bytes(), &collapsedRows); err != nil {
		t.Fatalf("collapsed json.Unmarshal() error = %v\n%s", err, collapsed.String())
	}
	if err := json.Unmarshal(raw.Bytes(), &rawRows); err != nil {
		t.Fatalf("raw json.Unmarshal() error = %v\n%s", err, raw.String())
	}
	if len(collapsedRows) >= len(rawRows) {
		t.Fatalf("collapsed rows = %d, raw rows = %d; want fewer collapsed rows", len(collapsedRows), len(rawRows))
	}
	if _, ok := collapsedRows[0]["class_ids"]; !ok {
		t.Fatalf("collapsed JSON missing class_ids: %#v", collapsedRows[0])
	}
}

func TestModelRIBCommandOutputsJSONAndFiltersPrefix(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelRIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--node", "bj-edge1",
		"--prefix", "10.4.0.0/16",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if len(rows) == 0 {
		t.Fatalf("rows = 0, want modeled RIB entries")
	}
	for _, row := range rows {
		if row["node"] != "bj-edge1" || row["prefix"] != "10.4.0.0/16" {
			t.Fatalf("unexpected row filter result: %#v", row)
		}
		if row["condition"] == "" || row["selected_condition"] == "" {
			t.Fatalf("row missing conditions: %#v", row)
		}
	}
}

func TestModelFIBCommandOutputsTable(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelFIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--node", "bj-edge1",
		"--prefix", "10.4.0.0/16",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"NODE", "PREFIX", "NEXT-HOP", "RANK", "GROUP", "EQUIV", "bj-edge1", "10.4.0.0/16"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "CONDITION") || strings.Contains(got, "link:") || strings.Contains(got, "node:") {
		t.Fatalf("default table output should hide conditions:\n%s", got)
	}
}

func TestModelFIBCommandShowsConditionsWhenRequested(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelFIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--node", "bj-edge1",
		"--prefix", "10.4.0.0/16",
		"--show-conditions",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"CONDITION", "link:", "node:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestModelFIBCommandOutputsECMPMetadataJSON(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelFIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--node", "bj-edge1",
		"--prefix", "10.4.0.0/16",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if len(rows) == 0 {
		t.Fatalf("rows = 0, want modeled FIB entries")
	}
	first := rows[0]
	for _, key := range []string{"rank", "group_id", "equivalent"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("FIB JSON missing %q metadata: %#v", key, first)
		}
	}
}

func TestModelPrefixClassesCommandOutputsJSONAndFiltersPrefix(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelPrefixClassesCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--prefix", "10.4.0.0/16",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if len(rows) < 2 {
		t.Fatalf("rows = %d, want prefix split into multiple classes", len(rows))
	}
	for _, row := range rows {
		if _, ok := row["class_id"]; !ok {
			t.Fatalf("row missing class_id: %#v", row)
		}
		if row["space"] == "" {
			t.Fatalf("row missing space: %#v", row)
		}
		predicates, ok := row["matched_predicates"].([]any)
		if !ok || len(predicates) == 0 {
			t.Fatalf("row missing matched_predicates: %#v", row)
		}
	}
	var foundRIB, foundFIB bool
	for _, row := range rows {
		predicates, _ := row["matched_predicates"].([]any)
		for _, raw := range predicates {
			source, _ := raw.(string)
			if strings.HasPrefix(source, "rib:") {
				foundRIB = true
			}
			if strings.HasPrefix(source, "fib:") {
				foundFIB = true
			}
		}
	}
	if !foundRIB || !foundFIB {
		t.Fatalf("prefix-classes JSON missing RIB/FIB predicates: rib=%v fib=%v", foundRIB, foundFIB)
	}
}

func TestModelPrefixClassesCommandOutputsTable(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelPrefixClassesCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--prefix", "10.4.1.10/32",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"CLASS", "SPACE", "MATCHED-PREDICATES", "pc-", "10.4.1.10/32"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestModelCommandRejectsUnknownNode(t *testing.T) {
	cmd := NewModelRIBCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--node", "missing-node",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `unknown node "missing-node"`) {
		t.Fatalf("Execute() error = %v, want unknown node", err)
	}
}

func TestModelSymbolicPacketCommandOutputsJSON(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelSymbolicPacketCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--from", "cust-bj",
		"--to", "10.4.1.10",
		"--protocol", "tcp",
		"--dst-port", "80",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if result["from"] != "cust-bj" || result["to"] != "10.4.1.10" || result["protocol"] != "tcp" {
		t.Fatalf("unexpected symbolic packet metadata: %#v", result)
	}
	if result["dst_port"] != float64(80) {
		t.Fatalf("unexpected symbolic packet dst_port: %#v", result)
	}
	if result["reachable_condition"] == "" || result["unreachable_condition"] == "" {
		t.Fatalf("missing reachability conditions: %#v", result)
	}
	blocked, ok := result["blocked_paths"].([]any)
	if !ok || len(blocked) == 0 {
		t.Fatalf("missing symbolic policy blocked paths: %#v", result)
	}
	first, ok := blocked[0].(map[string]any)
	if !ok || first["policy"] != "BLOCK-HTTP-TO-HZ" || first["node"] != "core-hz" {
		t.Fatalf("unexpected symbolic blocked path metadata: %#v", first)
	}
	source, ok := first["source"].(map[string]any)
	if !ok || source["vendor"] != "nftables" || source["file"] == "" || source["raw"] == "" {
		t.Fatalf("missing symbolic blocked path source: %#v", first)
	}
}

func TestModelSymbolicRouteCommandOutputsJSON(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelSymbolicRouteCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--from", "bj-edge1",
		"--prefix", "10.4.0.0/16",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var results []map[string]any
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if len(results) < 2 {
		t.Fatalf("results = %d, want prefix split into multiple classes", len(results))
	}
	result := results[0]
	if result["from"] != "bj-edge1" || result["prefix"] != "10.4.0.0/16" {
		t.Fatalf("unexpected symbolic route metadata: %#v", result)
	}
	if _, ok := result["class_id"]; !ok {
		t.Fatalf("missing class_id: %#v", result)
	}
	if result["space"] == "" {
		t.Fatalf("missing class space: %#v", result)
	}
	predicates, ok := result["matched_predicates"].([]any)
	if !ok || len(predicates) == 0 {
		t.Fatalf("missing matched predicates: %#v", result)
	}
	if result["reachable_condition"] == "" || result["unreachable_condition"] == "" {
		t.Fatalf("missing reachability conditions: %#v", result)
	}
	paths, ok := result["paths"].([]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("missing symbolic route paths: %#v", result)
	}
}

func TestModelSymbolicRouteCommandOutputsClassTable(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelSymbolicRouteCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--from", "bj-edge1",
		"--prefix", "10.4.0.0/16",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"class: pc-", "space:", "matched predicates:", "PATH"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	for _, hidden := range []string{"reachable:", "unreachable:", "CONDITION", "link:", "node:"} {
		if strings.Contains(got, hidden) {
			t.Fatalf("default table output should hide %q:\n%s", hidden, got)
		}
	}
}

func TestModelSymbolicRouteCommandShowsConditionsWhenRequested(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelSymbolicRouteCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "hoyan.clab.yml"),
		"--from", "bj-edge1",
		"--prefix", "10.4.0.0/16",
		"--show-conditions",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"reachable:", "unreachable:", "CONDITION", "link:", "node:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
