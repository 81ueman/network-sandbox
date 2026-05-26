package ribcompare

import (
	"context"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type NormalizedRoute struct {
	Node            string
	NetworkInstance string
	AFI             string
	Prefix          string
	Protocol        string
	Paths           []NormalizedBgpPath
}

type NormalizedBgpRoute = NormalizedRoute

type NormalizedBgpPath struct {
	Best             bool
	Valid            bool
	NextHop          string
	ASPath           []uint32
	Origin           string
	LocalPref        int
	MED              int
	Weight           int
	Communities      []string
	LargeCommunities []string
	OriginatorID     string
	ClusterList      []string
	Peer             string
	PeerAS           uint32
}

type BgpRibCollector interface {
	Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error)
}

type RouteTableCollector interface {
	CollectRouteTables(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error)
}

type Collector interface {
	BgpRibCollector
	RouteTableCollector
}

type RouteSources string

const (
	RouteSourcesBGP RouteSources = "bgp"
	RouteSourcesAll RouteSources = "all"
)

type BgpRibCompareOptions struct {
	CompareBest             bool
	CompareValid            bool
	CompareNextHop          bool
	CompareASPath           bool
	CompareOrigin           bool
	CompareLocalPref        bool
	CompareMED              bool
	CompareWeight           bool
	CompareCommunities      bool
	CompareLargeCommunities bool
	CompareOriginatorID     bool
	CompareClusterList      bool
	ComparePeer             bool
	ComparePeerAS           bool
	AllowExtraPrefixes      bool
	AllowExtraPaths         bool
}

type PathDiff struct {
	RouteKey string
	PathKey  string
}

type AttributeMismatch struct {
	RouteKey string
	PathKey  string
	Field    string
	Expected any
	Actual   any
}

type DuplicatePathConflict struct {
	RouteKey string
	PathKey  string
	Side     string
	Paths    []NormalizedBgpPath
}

type BgpRibCompareResult struct {
	OK                     bool
	MissingPrefixes        []string
	UnexpectedPrefixes     []string
	MissingPaths           []PathDiff
	UnexpectedPaths        []PathDiff
	Mismatched             []AttributeMismatch
	DuplicatePathConflicts []DuplicatePathConflict
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

func DefaultBgpRibCompareOptions() BgpRibCompareOptions {
	return BgpRibCompareOptions{
		CompareBest:      true,
		CompareValid:     true,
		CompareNextHop:   true,
		CompareASPath:    true,
		CompareOrigin:    true,
		CompareLocalPref: true,
		CompareMED:       true,
	}
}
