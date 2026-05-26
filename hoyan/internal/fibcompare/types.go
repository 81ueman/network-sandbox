package fibcompare

import (
	"context"
	"fmt"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type NormalizedFIBRoute struct {
	Node       string                 `json:"node"`
	VRF        string                 `json:"vrf"`
	AFI        string                 `json:"afi"`
	Prefix     string                 `json:"prefix"`
	NextHops   []NormalizedFIBNextHop `json:"next_hops,omitempty"`
	Protocol   string                 `json:"protocol,omitempty"`
	Preference int                    `json:"preference,omitempty"`
	Metric     int                    `json:"metric,omitempty"`
	Installed  bool                   `json:"installed"`
}

type NormalizedFIBNextHop struct {
	Address   string `json:"address,omitempty"`
	Interface string `json:"interface,omitempty"`
	Weight    int    `json:"weight,omitempty"`
}

type Collector interface {
	Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedFIBRoute, error)
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type Options struct {
	AllowUnsupported bool
}

type RouteDiff struct {
	RouteKey string
}

type NextHopDiff struct {
	RouteKey   string
	NextHopKey string
}

type AttributeMismatch struct {
	RouteKey string
	Field    string
	Expected any
	Actual   any
}

type Result struct {
	OK                 bool
	UnsupportedNodes   []string
	MissingRoutes      []string
	UnexpectedRoutes   []string
	MissingNextHops    []NextHopDiff
	UnexpectedNextHops []NextHopDiff
	Mismatched         []AttributeMismatch
}

type UnsupportedNodesError struct {
	Nodes []string
}

func (e UnsupportedNodesError) Error() string {
	return fmt.Sprintf("unsupported live FIB collector for node(s): %s", strings.Join(e.Nodes, ", "))
}
