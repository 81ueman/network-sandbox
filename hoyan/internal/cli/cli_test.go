package cli

import (
	"bytes"
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
	for _, want := range []string{"verify", "live-check", "rib-compare", "render-topology"} {
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

func TestNormalizeLegacyLongFlags(t *testing.T) {
	got := normalizeLegacyLongFlags([]string{"render-topology", "-suffix", "issue-38", "-output=out.yml", "-h", "--topology", "x.yml", "-1s"})
	want := []string{"render-topology", "--suffix", "issue-38", "--output=out.yml", "-h", "--topology", "x.yml", "-1s"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("normalizeLegacyLongFlags() = %#v, want %#v", got, want)
	}
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

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
