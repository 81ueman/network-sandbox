package livecheck

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

type fakeRunner struct {
	calls []string
	fn    func(name string, args ...string) ([]byte, error)
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.fn(name, args...)
}

func TestHasExpectedRoutes(t *testing.T) {
	expected := []ribcompare.NormalizedBgpRoute{
		{Node: "r1", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.0.0.0/24"},
		{Node: "r2", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.1.0.0/24"},
	}
	actual := []ribcompare.NormalizedBgpRoute{{Node: "r1", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.0.0.0/24"}}
	if HasExpectedRoutes(expected, actual) {
		t.Fatalf("routes should be incomplete")
	}
	actual = append(actual, ribcompare.NormalizedBgpRoute{Node: "r2", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.1.0.0/24"})
	if !HasExpectedRoutes(expected, actual) {
		t.Fatalf("routes should be complete")
	}
	if got := CountExpectedRoutes(expected, actual); got != 2 {
		t.Fatalf("CountExpectedRoutes() = %d, want 2", got)
	}
}

func TestWaitForFRRContainers(t *testing.T) {
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		if name != "docker" || args[0] != "inspect" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte("true\n"), nil
	}}
	nodes := []model.Node{{Name: "r1", Kind: "frr"}, {Name: "r2", Kind: "frr"}}
	if err := WaitForFRRContainers(context.Background(), runner, nodes, time.Millisecond); err != nil {
		t.Fatalf("WaitForFRRContainers() error = %v", err)
	}
}

func TestRunDestroysOnSuccess(t *testing.T) {
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch {
		case strings.HasPrefix(cmd, "containerlab deploy"):
			return []byte("deployed"), nil
		case strings.HasPrefix(cmd, "containerlab destroy"):
			return []byte("destroyed"), nil
		case strings.HasPrefix(cmd, "docker inspect"):
			return []byte("true\n"), nil
		case strings.Contains(cmd, "show ip bgp json"):
			return []byte(`{"10.1.1.10/32":[{"valid":true,"bestpath":true,"nexthops":[{"ip":""}]}]}`), nil
		default:
			return nil, errors.New("unexpected command: " + cmd)
		}
	}}
	opts := Options{
		Topology:     "testdata/live.clab.yml",
		Policies:     "",
		Timeout:      time.Second,
		PollInterval: time.Millisecond,
	}
	if err := Run(context.Background(), opts, runner); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var destroyed bool
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "containerlab destroy") {
			destroyed = true
		}
	}
	if !destroyed {
		t.Fatalf("destroy was not called: %v", runner.calls)
	}
}

func TestWaitForExpectedRoutesStopsAfterMaxPolls(t *testing.T) {
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		return []byte(`{"10.0.0.0/24":[{"valid":true,"bestpath":true,"nexthops":[{"ip":"192.0.2.1"}]}]}`), nil
	}}
	nodes := []model.Node{{Name: "r1", Kind: "frr"}}
	expected := []ribcompare.NormalizedBgpRoute{{Node: "r1", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.0.0.0/24"}, {Node: "r1", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.1.0.0/24"}}
	actual, err := WaitForExpectedRoutes(context.Background(), runner, nodes, expected, time.Millisecond, 2)
	if err == nil {
		t.Fatalf("WaitForExpectedRoutes() succeeded unexpectedly")
	}
	if len(actual) != 1 {
		t.Fatalf("actual routes = %d, want last successful collection", len(actual))
	}
	if len(runner.calls) != 2 {
		t.Fatalf("polls = %d, want 2", len(runner.calls))
	}
}

func TestWaitForMatchingRIBsPollsUntilDiffsClear(t *testing.T) {
	polls := 0
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		polls++
		if polls == 1 {
			return []byte(`{"10.0.0.0/24":[{"valid":true,"bestpath":true,"nexthops":[{"ip":"192.0.2.1"}]}]}`), nil
		}
		return []byte(`{"10.0.0.0/24":[{"valid":true,"bestpath":true,"nexthops":[{"ip":"198.51.100.1"}]}]}`), nil
	}}
	nodes := []model.Node{{Name: "r1", Kind: "frr"}}
	expected := []ribcompare.NormalizedBgpRoute{{Node: "r1", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Paths: []ribcompare.NormalizedBgpPath{{Best: true, Valid: true, NextHop: "198.51.100.1", Origin: "igp", LocalPref: 100}}}}
	_, diffs, err := WaitForMatchingRIBs(context.Background(), runner, nodes, expected, time.Millisecond, 2, ribcompare.DefaultBgpRibCompareOptions())
	if err != nil {
		t.Fatalf("WaitForMatchingRIBs() error = %v", err)
	}
	if !diffs.OK {
		t.Fatalf("diffs = %v, want none", diffs)
	}
	if polls != 2 {
		t.Fatalf("polls = %d, want 2", polls)
	}
}

func TestWaitForMatchingRIBsReportsBestMismatchAndExtraPaths(t *testing.T) {
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		return []byte(`{"10.0.0.0/24":[
			{"valid":true,"bestpath":false,"nexthops":[{"ip":"192.0.2.1"}]},
			{"valid":true,"bestpath":false,"nexthops":[{"ip":"192.0.2.2"}]}
		]}`), nil
	}}
	nodes := []model.Node{{Name: "r1", Kind: "frr"}}
	expected := []ribcompare.NormalizedBgpRoute{{Node: "r1", NetworkInstance: "default", AFI: "ipv4", Prefix: "10.0.0.0/24", Paths: []ribcompare.NormalizedBgpPath{{Best: true, Valid: true, NextHop: "192.0.2.1", Origin: "igp", LocalPref: 100}}}}
	_, diffs, err := WaitForMatchingRIBs(context.Background(), runner, nodes, expected, time.Millisecond, 1, ribcompare.DefaultBgpRibCompareOptions())
	if err == nil {
		t.Fatalf("WaitForMatchingRIBs() succeeded unexpectedly")
	}
	if diffs.OK || len(diffs.UnexpectedPaths) != 1 || len(diffs.Mismatched) != 1 || diffs.Mismatched[0].Field != "best" {
		t.Fatalf("diffs = %#v", diffs)
	}
}

func TestLinkFailureScenarioInjectsAndCleansBothEndpoints(t *testing.T) {
	topo := &model.Topology{
		Name: "test-lab",
		Links: []model.Link{
			{Name: "a-b", A: "a", B: "b", AIntf: "eth1", BIntf: "eth2"},
		},
	}
	scenario, err := LinkFailureScenario(topo, "a-b")
	if err != nil {
		t.Fatalf("LinkFailureScenario() error = %v", err)
	}
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}}
	if err := scenario.Inject(context.Background(), runner); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}
	if err := scenario.Cleanup(context.Background(), runner); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	want := []string{
		"containerlab tools netem set --name test-lab -n a -i eth1 --loss 100",
		"containerlab tools netem set --name test-lab -n b -i eth2 --loss 100",
		"containerlab tools netem reset --name test-lab -n a -i eth1",
		"containerlab tools netem reset --name test-lab -n b -i eth2",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %v, want %v", runner.calls, want)
	}
	if !scenario.Failures.Links["a-b"] {
		t.Fatalf("scenario failures = %#v, want link a-b", scenario.Failures)
	}
}

func TestNodeFailureScenarioStopsNodeAndFiltersActiveFRRNodes(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "r1", Kind: "frr"},
			{Name: "r2", Kind: "frr"},
			{Name: "s1", Kind: "srlinux"},
		},
	}
	scenario, err := NodeFailureScenario(topo, "r1")
	if err != nil {
		t.Fatalf("NodeFailureScenario() error = %v", err)
	}
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}}
	if err := scenario.Inject(context.Background(), runner); err != nil {
		t.Fatalf("Inject() error = %v", err)
	}
	if got, want := runner.calls, []string{"docker stop r1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	if !scenario.Failures.Nodes["r1"] {
		t.Fatalf("scenario failures = %#v, want node r1", scenario.Failures)
	}
	if got, want := scenario.ActiveNodes, []model.Node{{Name: "r2", Kind: "frr"}, {Name: "s1", Kind: "srlinux"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active nodes = %#v, want %#v", got, want)
	}
}

func TestCompareRIBsWithFailuresUsesFailureAwareExpectedRoutes(t *testing.T) {
	topo := &model.Topology{
		Nodes: []model.Node{
			{Name: "r1", Kind: "frr", Prefixes: []string{"10.0.0.0/24"}},
			{Name: "r2", Kind: "frr", Prefixes: []string{"10.1.0.0/24"}},
		},
	}
	runner := &fakeRunner{fn: func(name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "show ip bgp json") {
			return []byte(`{"10.1.0.0/24":[{"valid":true,"bestpath":true,"nexthops":[{"ip":"0.0.0.0"}]}]}`), nil
		}
		return []byte("ok"), nil
	}}
	err := CompareRIBsWithFailures(context.Background(), runner, topo, RIBFailureScenario{
		Name:        "node-r1",
		Failures:    sim.NodeFailures("r1"),
		ActiveNodes: []model.Node{{Name: "r2", Kind: "frr", Prefixes: []string{"10.1.0.0/24"}}},
	}, RIBFailureCheckOptions{Interval: time.Millisecond, MaxPolls: 1})
	if err != nil {
		t.Fatalf("CompareRIBsWithFailures() error = %v", err)
	}
	if len(runner.calls) != 1 || !strings.Contains(runner.calls[0], "docker exec -i r2") {
		t.Fatalf("calls = %v, want only r2 collection", runner.calls)
	}
}
