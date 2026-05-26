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
	for _, want := range []string{"verify", "live", "live-check", "rib-compare", "fib-compare", "render-topology", "labs", "model"} {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q:\n%s", want, help)
		}
	}
}

func TestLabFlagResolvesDefaultInputs(t *testing.T) {
	dir := t.TempDir()
	labDir := filepath.Join(dir, "labs", "base-wan")
	if err := os.MkdirAll(filepath.Join(labDir, "intent"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(labDir, "lab.yml"), []byte("name: base-wan\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(lab.yml) error = %v", err)
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	cmd := NewVerifyCommand()
	cmd.SetArgs([]string{"--lab", "base-wan"})
	if err := cmd.ParseFlags([]string{"--lab", "base-wan"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	topology := defaultTopologyPath
	queries := defaultQueriesPath
	if err := resolveLabInputs(cmd, "base-wan", &topology, &queries); err != nil {
		t.Fatalf("resolveLabInputs() error = %v", err)
	}
	if want := filepath.Join("labs", "base-wan", "hoyan.clab.yml"); topology != want {
		t.Fatalf("topology = %q, want %q", topology, want)
	}
	if want := filepath.Join("labs", "base-wan", "intent", "queries.yml"); queries != want {
		t.Fatalf("queries = %q, want %q", queries, want)
	}
}

func TestLabFlagKeepsExplicitTopology(t *testing.T) {
	dir := t.TempDir()
	labDir := filepath.Join(dir, "labs", "base-wan")
	if err := os.MkdirAll(labDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	cmd := NewVerifyCommand()
	if err := cmd.ParseFlags([]string{"--lab", "base-wan", "--topology", "custom.yml"}); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	topology := "custom.yml"
	queries := defaultQueriesPath
	if err := resolveLabInputs(cmd, "base-wan", &topology, &queries); err != nil {
		t.Fatalf("resolveLabInputs() error = %v", err)
	}
	if topology != "custom.yml" {
		t.Fatalf("topology = %q, want explicit custom.yml", topology)
	}
	if want := filepath.Join("labs", "base-wan", "intent", "queries.yml"); queries != want {
		t.Fatalf("queries = %q, want %q", queries, want)
	}
}

func TestModelHelpListsPacketClasses(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "packet-classes") {
		t.Fatalf("help output missing packet-classes:\n%s", out.String())
	}
}

func TestLabsHelpListsLiveCheck(t *testing.T) {
	var out bytes.Buffer
	cmd := NewLabsCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "live-check") {
		t.Fatalf("help output missing live-check:\n%s", out.String())
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

func TestLiveCheckFIBCompareDefaultsOn(t *testing.T) {
	cmd := NewLiveCheckCommand()
	flag := cmd.Flags().Lookup("check-fib")
	if flag == nil || flag.DefValue != "true" {
		t.Fatalf("--check-fib default = %v, want true", flag)
	}
	if cmd.Flags().Lookup("no-check-fib") == nil {
		t.Fatalf("--no-check-fib flag missing")
	}
	unresolved := cmd.Flags().Lookup("fib-unresolved-policy")
	if unresolved == nil || unresolved.DefValue != "warn" {
		t.Fatalf("--fib-unresolved-policy default = %v, want warn", unresolved)
	}
}

func TestFIBCompareUnresolvedPolicyFlagDefault(t *testing.T) {
	cmd := NewFIBCompareCommand()
	flag := cmd.Flags().Lookup("unresolved-policy")
	if flag == nil || flag.DefValue != "warn" {
		t.Fatalf("--unresolved-policy default = %v, want warn", flag)
	}
}

func TestSelectedLabDescriptorsDefaultsToAllLabsSorted(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"z-lab", "a-lab"} {
		labDir := filepath.Join(dir, "labs", name)
		if err := os.MkdirAll(labDir, 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(labDir, "lab.yml"), []byte("name: "+name+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(lab.yml) error = %v", err)
		}
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	labs, err := selectedLabDescriptors(nil)
	if err != nil {
		t.Fatalf("selectedLabDescriptors() error = %v", err)
	}
	got := []string{labs[0].Name, labs[1].Name}
	want := []string{"a-lab", "z-lab"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("labs = %v, want %v", got, want)
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

func TestVerifyCommandOutputsStructuredPrefixClassJSON(t *testing.T) {
	var out bytes.Buffer
	cmd := NewVerifyCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "labs", "base-wan", "intent", "queries.yml"),
		"--prefix-classes",
		"--no-collapse",
		"--format", "json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var report struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, out.String())
	}
	if len(report.Results) <= 13 {
		t.Fatalf("structured results = %d, want class-expanded results", len(report.Results))
	}
	required := map[string]string{
		"route":   "route",
		"packet":  "packet",
		"failure": "failure",
	}
	var foundRIB, foundFIB bool
	for _, row := range report.Results {
		typ, _ := row["type"].(string)
		nested := required[typ]
		if nested == "" {
			continue
		}
		if _, ok := row["metadata"].(map[string]any); !ok {
			t.Fatalf("%s result missing metadata: %#v", typ, row)
		}
		if _, ok := row[nested].(map[string]any); !ok {
			t.Fatalf("%s result missing nested payload %q: %#v", typ, nested, row)
		}
		if prefixClass, ok := row["prefix_class"].(map[string]any); !ok || prefixClass["matched_predicates"] == nil {
			t.Fatalf("%s result missing prefix_class metadata: %#v", typ, row)
		}
		prefixClass := row["prefix_class"].(map[string]any)
		predicates, _ := prefixClass["matched_predicates"].([]any)
		for _, raw := range predicates {
			source, _ := raw.(string)
			if strings.HasPrefix(source, "rib:") {
				foundRIB = true
			}
			if strings.HasPrefix(source, "fib:") {
				foundFIB = true
			}
		}
		delete(required, typ)
	}
	if len(required) != 0 {
		t.Fatalf("structured JSON missing query types: %#v", required)
	}
	if !foundRIB || !foundFIB {
		t.Fatalf("verify JSON missing RIB/FIB predicates: rib=%v fib=%v", foundRIB, foundFIB)
	}
	var foundSolver bool
	for _, row := range report.Results {
		rawSolver, ok := row["solver"].(map[string]any)
		if !ok {
			continue
		}
		foundSolver = true
		if _, ok := rawSolver["mode"]; ok {
			t.Fatalf("verify JSON solver trace should not include redundant mode: %#v", rawSolver)
		}
		if _, ok := rawSolver["used_symbolic"]; ok {
			t.Fatalf("verify JSON solver trace should not include redundant used_symbolic: %#v", rawSolver)
		}
		if rawSolver["backend"] == "" || rawSolver["elements"] == nil || rawSolver["max_failures"] == nil {
			t.Fatalf("verify JSON solver trace incomplete: %#v", rawSolver)
		}
	}
	if !foundSolver {
		t.Fatalf("verify JSON missing solver trace in failure-search results")
	}
}

func TestVerifyCommandPrefixClassThresholdFails(t *testing.T) {
	var out bytes.Buffer
	cmd := NewVerifyCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "labs", "base-wan", "intent", "queries.yml"),
		"--prefix-classes",
		"--max-prefix-classes", "1",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil")
	}
	got := out.String() + err.Error()
	for _, want := range []string{"prefix universe class count", "exceeds --max-prefix-classes 1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("threshold output missing %q:\n%s", want, got)
		}
	}
}

func TestVerifyCommandShowsPrefixUniverseStats(t *testing.T) {
	var out bytes.Buffer
	cmd := NewVerifyCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "labs", "base-wan", "intent", "queries.yml"),
		"--prefix-classes",
		"--show-prefix-universe-stats",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"predicates=", "unique=", "classes=", "build=", "sources:", "  route:", "  prefix-list:", "  rib:", "  fib:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("stats output missing %q:\n%s", want, got)
		}
	}
}

func TestVerifyCommandCollapsesPrefixClassOutputByDefault(t *testing.T) {
	var collapsed, raw bytes.Buffer
	collapsedCmd := NewVerifyCommand()
	collapsedCmd.SetOut(&collapsed)
	collapsedCmd.SetErr(ioDiscard{})
	collapsedCmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "labs", "base-wan", "intent", "queries.yml"),
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--queries", filepath.Join("..", "..", "labs", "base-wan", "intent", "queries.yml"),
		"--prefix-classes",
		"--no-collapse",
		"--format", "json",
	})
	if err := rawCmd.Execute(); err != nil {
		t.Fatalf("raw Execute() error = %v", err)
	}
	var collapsedReport, rawReport struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(collapsed.Bytes(), &collapsedReport); err != nil {
		t.Fatalf("collapsed json.Unmarshal() error = %v\n%s", err, collapsed.String())
	}
	if err := json.Unmarshal(raw.Bytes(), &rawReport); err != nil {
		t.Fatalf("raw json.Unmarshal() error = %v\n%s", err, raw.String())
	}
	if len(collapsedReport.Results) >= len(rawReport.Results) {
		t.Fatalf("collapsed rows = %d, raw rows = %d; want fewer collapsed rows", len(collapsedReport.Results), len(rawReport.Results))
	}
	prefixClass, ok := collapsedReport.Results[0]["prefix_class"].(map[string]any)
	if !ok || prefixClass["class_ids"] == nil {
		t.Fatalf("collapsed JSON missing prefix_class.class_ids: %#v", collapsedReport.Results[0])
	}
}

func TestModelRIBCommandOutputsJSONAndFiltersPrefix(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelRIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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

func TestModelRIBCommandFiltersProtocolArgument(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelRIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--node", "bj-edge1",
		"connected",
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
		t.Fatalf("rows = 0, want connected RIB entries")
	}
	for _, row := range rows {
		if row["source_kind"] != "connected" {
			t.Fatalf("unexpected protocol filter result: %#v", row)
		}
		for _, unexpected := range []string{"as_path", "origin_code", "local_pref", "med", "learned_ibgp", "invalid"} {
			if _, ok := row[unexpected]; ok {
				t.Fatalf("connected row should not include BGP field %q: %#v", unexpected, row)
			}
		}
	}
}

func TestModelRIBCommandUsesRouteSourceTableForNonBGPProtocol(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelRIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--node", "bj-edge1",
		"connected",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	if strings.Contains(got, "AS-PATH") || strings.Contains(got, "LOCAL-PREF") || strings.Contains(got, "ORIGIN-CODE") || strings.Contains(got, "IBGP") {
		t.Fatalf("connected table should not include BGP columns:\n%s", got)
	}
	for _, want := range []string{"NODE", "PREFIX", "SOURCE", "IFACE", "connected"} {
		if !strings.Contains(got, want) {
			t.Fatalf("connected table missing %q:\n%s", want, got)
		}
	}
}

func TestModelRIBCommandRejectsInvalidProtocolArgument(t *testing.T) {
	cmd := NewModelRIBCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{"bogus"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil")
	}
	if !strings.Contains(err.Error(), "protocol must be one of bgp, connected, static, aggregate, or blackhole") {
		t.Fatalf("error = %q, want protocol validation", err.Error())
	}
}

func TestModelFIBCommandOutputsTable(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelFIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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

func TestModelFIBCommandOutputsDiscardJSON(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelFIBCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--node", "hz-edge1",
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
	if len(rows) != 1 {
		t.Fatalf("rows = %#v, want one local discard FIB entry", rows)
	}
	if rows[0]["source_kind"] != "blackhole" || rows[0]["discard"] != true || rows[0]["interface"] != "Null0" {
		t.Fatalf("discard FIB JSON = %#v, want blackhole discard via Null0", rows[0])
	}
}

func TestModelPrefixClassesCommandOutputsJSONAndFiltersPrefix(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelPrefixClassesCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--prefix", "10.4.1.10/32",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"CLASS", "SPACE", "pc-", "10.4.1.10/32"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "MATCHED-PREDICATES") || strings.Contains(got, "request:prefix-classes:") {
		t.Fatalf("default table output should hide matched predicates:\n%s", got)
	}
}

func TestModelPrefixClassesCommandShowsPredicatesWhenRequested(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelPrefixClassesCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--prefix", "10.4.1.10/32",
		"--show-predicates",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"MATCHED-PREDICATES", "request:prefix-classes:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestModelPrefixClassesCommandSummary(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelPrefixClassesCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--prefix", "10.4.0.0/16",
		"--summary",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"predicates=", "unique=", "classes=", "sources:", "CLASS", "SPACE"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary output missing %q:\n%s", want, got)
		}
	}
}

func TestModelPrefixClassesCommandThresholdFails(t *testing.T) {
	cmd := NewModelPrefixClassesCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--max-prefix-classes", "1",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil")
	}
	if !strings.Contains(err.Error(), "prefix universe class count") || !strings.Contains(err.Error(), "exceeds --max-prefix-classes 1") {
		t.Fatalf("error = %v, want threshold error", err)
	}
}

func TestModelCommandRejectsUnknownNode(t *testing.T) {
	cmd := NewModelRIBCommand()
	cmd.SetOut(ioDiscard{})
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
	if !ok || first["acl"] != "BLOCK-HTTP-TO-HZ" || first["node"] != "core-hz" {
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--from", "bj-edge1",
		"--prefix", "10.4.0.0/16",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	for _, want := range []string{"class: pc-", "space:", "PATH"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	for _, hidden := range []string{"matched predicates:", "reachable:", "unreachable:", "CONDITION", "link:", "node:"} {
		if strings.Contains(got, hidden) {
			t.Fatalf("default table output should hide %q:\n%s", hidden, got)
		}
	}
}

func TestModelSymbolicRouteCommandShowsPredicatesWhenRequested(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelSymbolicRouteCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
		"--from", "bj-edge1",
		"--prefix", "10.4.0.0/16",
		"--show-predicates",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "matched predicates:") {
		t.Fatalf("output missing matched predicates:\n%s", got)
	}
}

func TestModelSymbolicRouteCommandShowsConditionsWhenRequested(t *testing.T) {
	var out bytes.Buffer
	cmd := NewModelSymbolicRouteCommand()
	cmd.SetOut(&out)
	cmd.SetErr(ioDiscard{})
	cmd.SetArgs([]string{
		"--topology", filepath.Join("..", "..", "labs", "base-wan", "hoyan.clab.yml"),
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
