//go:build clab

package livecheck

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

func TestContainerlabRIBsMatchSimulationUnderFailures(t *testing.T) {
	if _, err := exec.LookPath("containerlab"); err != nil {
		t.Skipf("containerlab not found: %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not found: %v", err)
	}

	topologyPath := filepath.Join("..", "..", "hoyan.clab.yml")
	policiesPath := filepath.Join("..", "..", "intent", "policies.yml")
	topo, err := model.LoadLabTopology(topologyPath, policiesPath)
	if err != nil {
		t.Fatalf("LoadLabTopology() error = %v", err)
	}
	runner := ribcompare.ExecRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	deploy := func() {
		t.Helper()
		if _, err := runner.Run(ctx, "containerlab", "deploy", "--reconfigure", "-t", topologyPath); err != nil {
			t.Fatalf("containerlab deploy: %v", err)
		}
		if err := WaitForFRRContainers(ctx, runner, ribcompare.FRRNodes(topo.Nodes), 5*time.Second); err != nil {
			t.Fatalf("FRR containers did not become ready: %v", err)
		}
	}
	destroy := func() {
		t.Helper()
		if _, err := runner.Run(context.Background(), "containerlab", "destroy", "--cleanup", "-t", topologyPath); err != nil {
			t.Logf("containerlab destroy: %v", err)
		}
	}
	t.Cleanup(destroy)

	deploy()
	if err := CompareRIBsWithFailures(ctx, runner, topo, RIBFailureScenario{
		Name:        "baseline",
		ActiveNodes: ribcompare.FRRNodes(topo.Nodes),
	}, RIBFailureCheckOptions{Interval: 5 * time.Second, MaxPolls: 24, Out: testLogWriter{t: t}}); err != nil {
		t.Fatalf("baseline RIB comparison failed: %v", err)
	}

	linkScenario, err := LinkFailureScenario(topo, "core-hz-eth4--core-bj-eth4")
	if err != nil {
		t.Fatalf("LinkFailureScenario() error = %v", err)
	}
	linkScenario.ActiveNodes = ribcompare.FRRNodes(topo.Nodes)
	if err := CompareRIBsWithFailures(ctx, runner, topo, linkScenario, RIBFailureCheckOptions{Interval: 5 * time.Second, MaxPolls: 18, Out: testLogWriter{t: t}}); err != nil {
		t.Fatalf("link-failure RIB comparison failed: %v", err)
	}

	destroy()
	deploy()
	nodeScenario, err := NodeFailureScenario(topo, "transit-north")
	if err != nil {
		t.Fatalf("NodeFailureScenario() error = %v", err)
	}
	if err := CompareRIBsWithFailures(ctx, runner, topo, nodeScenario, RIBFailureCheckOptions{Interval: 5 * time.Second, MaxPolls: 18, Out: testLogWriter{t: t}}); err != nil {
		t.Fatalf("node-failure RIB comparison failed: %v", err)
	}
}

type testLogWriter struct {
	t *testing.T
}

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
