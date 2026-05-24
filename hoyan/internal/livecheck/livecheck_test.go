package livecheck

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
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
	expected := []ribcompare.ExpectedRoute{
		{Node: "r1", Prefix: "10.0.0.0/24"},
		{Node: "r2", Prefix: "10.1.0.0/24"},
	}
	actual := []ribcompare.ActualRoute{{Node: "r1", Prefix: "10.0.0.0/24"}}
	if HasExpectedRoutes(expected, actual) {
		t.Fatalf("routes should be incomplete")
	}
	actual = append(actual, ribcompare.ActualRoute{Node: "r2", Prefix: "10.1.0.0/24"})
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
	expected := []ribcompare.ExpectedRoute{{Node: "r1", Prefix: "10.0.0.0/24"}, {Node: "r1", Prefix: "10.1.0.0/24"}}
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
