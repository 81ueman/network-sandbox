package ribcompare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
)

type NormalizedBgpRoute struct {
	Node            string
	NetworkInstance string
	AFI             string
	Prefix          string
	Paths           []NormalizedBgpPath
}

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

type BgpRibCompareResult struct {
	OK                 bool
	MissingPrefixes    []string
	UnexpectedPrefixes []string
	MissingPaths       []PathDiff
	UnexpectedPaths    []PathDiff
	Mismatched         []AttributeMismatch
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

func Expected(topo *model.Topology) []NormalizedBgpRoute {
	return ExpectedWithFailureSet(topo, sim.NoFailures())
}

func ExpectedForNodes(topo *model.Topology, nodes []model.Node) []NormalizedBgpRoute {
	return ExpectedForNodesWithFailureSet(topo, nodes, sim.NoFailures())
}

func ExpectedForNodesWithFailureSet(topo *model.Topology, nodes []model.Node, failures sim.FailureSet) []NormalizedBgpRoute {
	allowed := map[string]bool{}
	for _, n := range nodes {
		allowed[n.Name] = true
	}
	return expected(topo, allowed, failures)
}

func ExpectedWithFailureSet(topo *model.Topology, failures sim.FailureSet) []NormalizedBgpRoute {
	return expected(topo, nil, failures)
}

func expected(topo *model.Topology, allowed map[string]bool, failures sim.FailureSet) []NormalizedBgpRoute {
	g := sim.NewGraph(topo)
	ctx := g.FailureContext(failures)
	var out []NormalizedBgpRoute
	for _, n := range topo.Nodes {
		if allowed != nil && !allowed[n.Name] {
			continue
		}
		if ctx.NodeFailed(model.NodeID(n.Name)) {
			continue
		}
		for prefix, rib := range g.RIBTable(n.Name) {
			var paths []NormalizedBgpPath
			for _, route := range rib {
				if route.Condition == nil || !route.Condition.Eval(ctx) {
					continue
				}
				paths = append(paths, expectedPath(topo, n, route, ctx))
			}
			if len(paths) == 0 {
				continue
			}
			sortPaths(paths, DefaultBgpRibCompareOptions())
			out = append(out, NormalizedBgpRoute{
				Node:            n.Name,
				NetworkInstance: "default",
				AFI:             "ipv4",
				Prefix:          prefix,
				Paths:           paths,
			})
		}
	}
	sortRoutes(out)
	return out
}

func expectedPath(topo *model.Topology, node model.Node, route sim.RIBEntry, ctx sim.FailureContext) NormalizedBgpPath {
	return NormalizedBgpPath{
		Best:      route.SelectedCond != nil && route.SelectedCond.Eval(ctx),
		Valid:     expectedRouteValid(node, route),
		NextHop:   routeNextHopAddress(topo, node.Name, route),
		ASPath:    append([]uint32(nil), route.ASPath...),
		Origin:    expectedRouteOrigin(route),
		LocalPref: defaultLocalPref(route.LocalPref),
		MED:       route.MED,
	}
}

func expectedRouteOrigin(route sim.RIBEntry) string {
	if route.OriginCode != "" {
		return route.OriginCode
	}
	return "igp"
}

func CompareBgpRib(expected []NormalizedBgpRoute, actual []NormalizedBgpRoute, opts BgpRibCompareOptions) BgpRibCompareResult {
	opts = fillCompareDefaults(opts)
	exp := map[string]NormalizedBgpRoute{}
	act := map[string]NormalizedBgpRoute{}
	for _, r := range expected {
		exp[routeKey(r)] = normalizeRoute(r)
	}
	for _, r := range actual {
		act[routeKey(r)] = normalizeRoute(r)
	}
	keys := sortedUnionKeys(exp, act)
	var result BgpRibCompareResult
	for _, key := range keys {
		e, eok := exp[key]
		a, aok := act[key]
		switch {
		case !eok:
			if !opts.AllowExtraPrefixes {
				result.UnexpectedPrefixes = append(result.UnexpectedPrefixes, key)
			}
			continue
		case !aok:
			result.MissingPrefixes = append(result.MissingPrefixes, key)
			continue
		}
		comparePaths(key, e.Paths, a.Paths, opts, &result)
	}
	sortPathDiffs(result.MissingPaths)
	sortPathDiffs(result.UnexpectedPaths)
	sort.Slice(result.Mismatched, func(i, j int) bool {
		return mismatchSortKey(result.Mismatched[i]) < mismatchSortKey(result.Mismatched[j])
	})
	result.OK = len(result.MissingPrefixes) == 0 &&
		len(result.UnexpectedPrefixes) == 0 &&
		len(result.MissingPaths) == 0 &&
		len(result.UnexpectedPaths) == 0 &&
		len(result.Mismatched) == 0
	return result
}

func Compare(expected []NormalizedBgpRoute, actual []NormalizedBgpRoute) BgpRibCompareResult {
	return CompareBgpRib(expected, actual, DefaultBgpRibCompareOptions())
}

func Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	collectors := collectorsByKind()
	for _, kind := range []model.DeviceKind{model.KindFRR, model.KindCEOS, model.KindSRLinux} {
		collector := collectors[kind]
		selected := NodesByKind(nodes, kind)
		if len(selected) == 0 {
			continue
		}
		routes, err := collector.Collect(ctx, runner, selected)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func CollectWithRunner(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return Collect(ctx, runner, nodes)
}

func CollectFRR(nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return CollectFRRWithRunner(context.Background(), ExecRunner{}, nodes)
}

func CollectFRRWithRunner(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	return frrCollector{}.Collect(ctx, runner, nodes)
}

func SupportedNodes(nodes []model.Node) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if _, ok := collectorsByKind()[n.Kind]; ok {
			out = append(out, n)
		}
	}
	return out
}

func FRRNodes(nodes []model.Node) []model.Node {
	return NodesByKind(nodes, model.KindFRR)
}

func NodesByKind(nodes []model.Node, kind model.DeviceKind) []model.Node {
	var out []model.Node
	for _, n := range nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func FormatDiffs(result BgpRibCompareResult) []string {
	var out []string
	for _, k := range result.MissingPrefixes {
		out = append(out, fmt.Sprintf("[DIFF] %s prefix missing", k))
	}
	for _, k := range result.UnexpectedPrefixes {
		out = append(out, fmt.Sprintf("[DIFF] %s prefix unexpected", k))
	}
	for _, d := range result.MissingPaths {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s missing", d.RouteKey, d.PathKey))
	}
	for _, d := range result.UnexpectedPaths {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s unexpected", d.RouteKey, d.PathKey))
	}
	for _, m := range result.Mismatched {
		out = append(out, fmt.Sprintf("[DIFF] %s path %s field=%s expected=%v actual=%v", m.RouteKey, m.PathKey, m.Field, m.Expected, m.Actual))
	}
	return out
}

type frrCollector struct{}
type ceosCollector struct{}
type srlinuxCollector struct{}

func collectorsByKind() map[model.DeviceKind]BgpRibCollector {
	return map[model.DeviceKind]BgpRibCollector{
		model.KindFRR:     frrCollector{},
		model.KindCEOS:    ceosCollector{},
		model.KindSRLinux: srlinuxCollector{},
	}
}

func (frrCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "vtysh", "-c", "show ip bgp json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s vtysh -c %q: %w", containerName, "show ip bgp json", err)
		}
		routes, err := ParseFRR(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s FRR BGP RIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (ceosCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "Cli", "-p", "15", "-c", "show ip bgp | json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s Cli -p 15 -c %q: %w", containerName, "show ip bgp | json", err)
		}
		routes, err := ParseCEOS(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s cEOS BGP RIB: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (srlinuxCollector) Collect(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		summary, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "sr_cli", "--output-format", "json", "--pagination", "off", "--", "show", "network-instance", "default", "protocols", "bgp", "routes", "ipv4", "summary")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s sr_cli BGP ipv4 summary: %w", containerName, err)
		}
		prefixes, err := ParseSRLinuxSummary(summary)
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux BGP RIB summary: %w", n.Name, err)
		}
		for _, prefix := range prefixes {
			detail, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "sr_cli", "--output-format", "json", "--pagination", "off", "--", "show", "network-instance", "default", "protocols", "bgp", "routes", "ipv4", "prefix", prefix, "detail")
			if err != nil {
				return nil, fmt.Errorf("docker exec -i %s sr_cli BGP ipv4 prefix %s detail: %w", containerName, prefix, err)
			}
			routes, err := ParseSRLinuxDetail(n.Name, prefix, detail)
			if err != nil {
				return nil, fmt.Errorf("%s SR Linux BGP RIB prefix %s detail: %w", n.Name, prefix, err)
			}
			out = append(out, routes...)
		}
	}
	sortRoutes(out)
	return out, nil
}

func ParseFRR(node string, data []byte) ([]NormalizedBgpRoute, error) {
	type frrPath struct {
		Valid            bool     `json:"valid"`
		Best             bool     `json:"bestpath"`
		Multipath        bool     `json:"multipath"`
		Path             string   `json:"path"`
		Origin           string   `json:"origin"`
		LocalPref        int      `json:"locPrf"`
		MED              int      `json:"metric"`
		Weight           int      `json:"weight"`
		Peer             string   `json:"peerId"`
		Communities      []string `json:"community"`
		LargeCommunities []string `json:"largeCommunity"`
		Nexthops         []struct {
			IP string `json:"ip"`
		} `json:"nexthops"`
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if payload, ok := raw["routes"]; ok {
		if err := json.Unmarshal(payload, &raw); err != nil {
			return nil, err
		}
	}
	var out []NormalizedBgpRoute
	for prefix, payload := range raw {
		if !strings.Contains(prefix, "/") {
			continue
		}
		var paths []frrPath
		if err := json.Unmarshal(payload, &paths); err != nil {
			continue
		}
		route := NormalizedBgpRoute{Node: node, NetworkInstance: "default", AFI: "ipv4", Prefix: prefix}
		for _, p := range paths {
			nextHop := ""
			if len(p.Nexthops) > 0 {
				nextHop = p.Nexthops[0].IP
				if nextHop == "0.0.0.0" {
					nextHop = ""
				}
			}
			route.Paths = append(route.Paths, NormalizedBgpPath{
				Best:             p.Best || p.Multipath,
				Valid:            p.Valid,
				NextHop:          nextHop,
				ASPath:           parseASPath(p.Path),
				Origin:           normalizeOrigin(p.Origin),
				LocalPref:        defaultLocalPref(p.LocalPref),
				MED:              p.MED,
				Weight:           p.Weight,
				Communities:      sortedStrings(p.Communities),
				LargeCommunities: sortedStrings(p.LargeCommunities),
				Peer:             p.Peer,
			})
		}
		if len(route.Paths) > 0 {
			sortPaths(route.Paths, DefaultBgpRibCompareOptions())
			out = append(out, route)
		}
	}
	sortRoutes(out)
	return out, nil
}

func ParseCEOS(node string, data []byte) ([]NormalizedBgpRoute, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	vrfs := asMap(root["vrfs"])
	if len(vrfs) == 0 {
		vrfs = map[string]any{"default": root}
	}
	var out []NormalizedBgpRoute
	for ni, rawVRF := range vrfs {
		vrf := asMap(rawVRF)
		entries := asMap(vrf["bgpRouteEntries"])
		for prefix, rawEntry := range entries {
			entry := asMap(rawEntry)
			route := NormalizedBgpRoute{Node: node, NetworkInstance: ni, AFI: "ipv4", Prefix: prefix}
			for _, rawPath := range asSlice(entry["bgpRoutePaths"]) {
				p := asMap(rawPath)
				routeType := asMap(p["routeType"])
				peer := asMap(p["peerEntry"])
				asPathEntry := asMap(p["asPathEntry"])
				route.Paths = append(route.Paths, NormalizedBgpPath{
					Best:      boolValue(routeType["active"]),
					Valid:     boolValue(routeType["valid"]),
					NextHop:   normalizeLocalNextHop(stringValue(p["nextHop"])),
					ASPath:    parseASPath(stringValue(asPathEntry["asPath"])),
					Origin:    normalizeOrigin(firstString(p, "routeOrigin", "origin")),
					LocalPref: defaultLocalPref(intValue(p["localPreference"])),
					MED:       intValue(p["med"]),
					Weight:    intValue(p["weight"]),
					Communities: sortedStrings(appendCommunities(nil,
						firstPresent(p, "community", "communities", "communityList"),
						firstPresent(asPathEntry, "community", "communities", "communityList"),
					)),
					LargeCommunities: sortedStrings(appendCommunities(nil,
						firstPresent(p, "largeCommunity", "largeCommunities", "largeCommunityList"),
						firstPresent(asPathEntry, "largeCommunity", "largeCommunities", "largeCommunityList"),
					)),
					Peer:   stringValue(peer["peerAddr"]),
					PeerAS: uint32(intValue(peer["peerAS"])),
				})
			}
			if len(route.Paths) > 0 {
				sortPaths(route.Paths, DefaultBgpRibCompareOptions())
				out = append(out, route)
			}
		}
	}
	sortRoutes(out)
	return out, nil
}

func ParseSRLinuxSummary(data []byte) ([]string, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	found := map[string]bool{}
	walkJSON(root, func(key string, value any) {
		if strings.EqualFold(key, "prefix") || strings.EqualFold(key, "route") || strings.EqualFold(key, "network") {
			if s := stringValue(value); isPrefix(s) {
				found[s] = true
			}
		}
		if isPrefix(key) {
			found[key] = true
		}
	})
	var out []string
	for prefix := range found {
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out, nil
}

func ParseSRLinuxDetail(node, prefix string, data []byte) ([]NormalizedBgpRoute, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var routeMaps []map[string]any
	walkSRLinuxRouteSections(root, false, &routeMaps)
	if len(routeMaps) == 0 {
		if m := asMap(root); len(m) > 0 {
			routeMaps = append(routeMaps, m)
		}
	}
	route := NormalizedBgpRoute{Node: node, NetworkInstance: "default", AFI: "ipv4", Prefix: prefix}
	for _, m := range routeMaps {
		status := firstString(m, "status", "route status", "route-status")
		asPath := parseASPath(firstString(m, "as path", "as-path", "asPath"))
		nextHop := normalizeLocalNextHop(firstString(m, "next-hop", "nextHop", "next hop"))
		peer := firstString(m, "neighbor", "peer")
		if nextHop == "" && peer == "0.0.0.0" && len(asPath) == 0 {
			continue
		}
		route.Paths = append(route.Paths, NormalizedBgpPath{
			Best:        strings.Contains(strings.ToLower(status), "best"),
			Valid:       strings.Contains(strings.ToLower(status), "valid"),
			NextHop:     nextHop,
			ASPath:      asPath,
			Origin:      normalizeOrigin(firstString(m, "origin")),
			LocalPref:   defaultLocalPref(intValue(firstPresent(m, "local pref", "local-pref", "localPreference"))),
			MED:         intValue(firstPresent(m, "med")),
			Communities: appendCommunities(nil, firstPresent(m, "community", "communities")),
			Peer:        peer,
			PeerAS:      uint32(intValue(firstPresent(m, "peer-as", "peer as", "peerAS"))),
		})
	}
	if len(route.Paths) == 0 {
		return nil, nil
	}
	sortPaths(route.Paths, DefaultBgpRibCompareOptions())
	return []NormalizedBgpRoute{route}, nil
}

func fillCompareDefaults(opts BgpRibCompareOptions) BgpRibCompareOptions {
	if !opts.CompareBest && !opts.CompareValid && !opts.CompareNextHop && !opts.CompareASPath &&
		!opts.CompareOrigin && !opts.CompareLocalPref && !opts.CompareMED && !opts.CompareWeight &&
		!opts.CompareCommunities && !opts.CompareLargeCommunities && !opts.CompareOriginatorID &&
		!opts.CompareClusterList && !opts.ComparePeer && !opts.ComparePeerAS {
		return DefaultBgpRibCompareOptions()
	}
	return opts
}

func comparePaths(routeKey string, expected, actual []NormalizedBgpPath, opts BgpRibCompareOptions, result *BgpRibCompareResult) {
	exp := map[string]NormalizedBgpPath{}
	act := map[string]NormalizedBgpPath{}
	for _, p := range expected {
		key := pathKey(p, opts)
		exp[key] = mergeDuplicatePath(exp[key], normalizePath(p))
	}
	for _, p := range actual {
		key := pathKey(p, opts)
		act[key] = mergeDuplicatePath(act[key], normalizePath(p))
	}
	keys := sortedUnionKeys(exp, act)
	for _, key := range keys {
		e, eok := exp[key]
		a, aok := act[key]
		switch {
		case !eok:
			if !opts.AllowExtraPaths {
				result.UnexpectedPaths = append(result.UnexpectedPaths, PathDiff{RouteKey: routeKey, PathKey: key})
			}
		case !aok:
			result.MissingPaths = append(result.MissingPaths, PathDiff{RouteKey: routeKey, PathKey: key})
		default:
			appendMismatches(routeKey, key, e, a, opts, result)
		}
	}
}

func mergeDuplicatePath(existing, next NormalizedBgpPath) NormalizedBgpPath {
	if reflect.DeepEqual(existing, NormalizedBgpPath{}) {
		return next
	}
	existing.Best = existing.Best || next.Best
	existing.Valid = existing.Valid || next.Valid
	return existing
}

func appendMismatches(routeKey, pathKey string, e, a NormalizedBgpPath, opts BgpRibCompareOptions, result *BgpRibCompareResult) {
	check := func(enabled bool, field string, expected, actual any) {
		if enabled && !reflect.DeepEqual(expected, actual) {
			result.Mismatched = append(result.Mismatched, AttributeMismatch{RouteKey: routeKey, PathKey: pathKey, Field: field, Expected: expected, Actual: actual})
		}
	}
	check(opts.CompareBest, "best", e.Best, a.Best)
	check(opts.CompareValid, "valid", e.Valid, a.Valid)
	check(opts.CompareNextHop, "next_hop", e.NextHop, a.NextHop)
	check(opts.CompareASPath, "as_path", e.ASPath, a.ASPath)
	check(opts.CompareOrigin, "origin", e.Origin, a.Origin)
	check(opts.CompareLocalPref, "local_pref", e.LocalPref, a.LocalPref)
	check(opts.CompareMED, "med", e.MED, a.MED)
	check(opts.CompareWeight, "weight", e.Weight, a.Weight)
	check(opts.CompareCommunities, "communities", e.Communities, a.Communities)
	check(opts.CompareLargeCommunities, "large_communities", e.LargeCommunities, a.LargeCommunities)
	check(opts.CompareOriginatorID, "originator_id", e.OriginatorID, a.OriginatorID)
	check(opts.CompareClusterList, "cluster_list", e.ClusterList, a.ClusterList)
	check(opts.ComparePeer, "peer", e.Peer, a.Peer)
	check(opts.ComparePeerAS, "peer_as", e.PeerAS, a.PeerAS)
}

func normalizeRoute(r NormalizedBgpRoute) NormalizedBgpRoute {
	if r.NetworkInstance == "" {
		r.NetworkInstance = "default"
	}
	if r.AFI == "" {
		r.AFI = "ipv4"
	}
	for i := range r.Paths {
		r.Paths[i] = normalizePath(r.Paths[i])
	}
	return r
}

func normalizePath(p NormalizedBgpPath) NormalizedBgpPath {
	p.Origin = normalizeOrigin(p.Origin)
	p.Communities = sortedStrings(p.Communities)
	p.LargeCommunities = sortedStrings(p.LargeCommunities)
	p.ClusterList = sortedStrings(p.ClusterList)
	return p
}

func routeKey(r NormalizedBgpRoute) string {
	r = normalizeRoute(r)
	return r.Node + "|" + r.NetworkInstance + "|" + r.AFI + "|" + r.Prefix
}

func pathKey(p NormalizedBgpPath, opts BgpRibCompareOptions) string {
	parts := []string{"nh=" + p.NextHop, "as=" + formatASPath(p.ASPath)}
	if opts.ComparePeer && p.Peer != "" {
		parts = append(parts, "peer="+p.Peer)
	}
	if opts.ComparePeerAS && p.PeerAS != 0 {
		parts = append(parts, fmt.Sprintf("peer_as=%d", p.PeerAS))
	}
	return strings.Join(parts, "|")
}

func sortRoutes(routes []NormalizedBgpRoute) {
	sort.Slice(routes, func(i, j int) bool {
		return routeKey(routes[i]) < routeKey(routes[j])
	})
}

func sortPaths(paths []NormalizedBgpPath, opts BgpRibCompareOptions) {
	sort.Slice(paths, func(i, j int) bool {
		return pathKey(paths[i], opts) < pathKey(paths[j], opts)
	})
}

func sortPathDiffs(diffs []PathDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].RouteKey == diffs[j].RouteKey {
			return diffs[i].PathKey < diffs[j].PathKey
		}
		return diffs[i].RouteKey < diffs[j].RouteKey
	})
}

func sortedUnionKeys[A any, B any](a map[string]A, b map[string]B) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mismatchSortKey(m AttributeMismatch) string {
	return m.RouteKey + "|" + m.PathKey + "|" + m.Field
}

func parseASPath(raw string) []uint32 {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, ",", " "))
	if raw == "" || raw == "-" {
		return nil
	}
	var out []uint32
	for _, f := range strings.Fields(raw) {
		f = strings.Trim(f, "{}[]()")
		asn, err := strconv.ParseUint(f, 10, 32)
		if err == nil {
			out = append(out, uint32(asn))
		}
	}
	return out
}

func formatASPath(path []uint32) string {
	parts := make([]string, 0, len(path))
	for _, asn := range path {
		parts = append(parts, fmt.Sprint(asn))
	}
	return strings.Join(parts, " ")
}

func normalizeOrigin(origin string) string {
	switch strings.ToLower(strings.TrimSpace(origin)) {
	case "", "i", "igp":
		return "igp"
	case "e", "egp":
		return "egp"
	case "?", "incomplete":
		return "incomplete"
	default:
		return strings.ToLower(strings.TrimSpace(origin))
	}
}

func defaultLocalPref(v int) int {
	if v == 0 {
		return 100
	}
	return v
}

func peerAddress(topo *model.Topology, node, peer string) string {
	if peer == "" {
		return ""
	}
	for _, l := range topo.Links {
		a, b := linkAddresses(l.Subnet)
		switch {
		case l.A == node && l.B == peer:
			return trimMask(b)
		case l.B == node && l.A == peer:
			return trimMask(a)
		}
	}
	return peer
}

func routeNextHopAddress(topo *model.Topology, node string, route sim.RIBEntry) string {
	if route.NextHop == "" {
		return ""
	}
	if direct := peerAddress(topo, node, route.NextHop); direct != route.NextHop {
		return direct
	}
	for i := 0; i+1 < len(route.Nodes); i++ {
		if route.Nodes[i] != route.NextHop {
			continue
		}
		if addr := peerAddress(topo, route.Nodes[i+1], route.NextHop); addr != route.NextHop {
			return addr
		}
	}
	return route.NextHop
}

func expectedRouteValid(node model.Node, route sim.RIBEntry) bool {
	if route.Invalid {
		return false
	}
	if node.Kind == model.KindCEOS && route.NextHop != "" && route.NextHop != route.From {
		return false
	}
	return true
}

func linkAddresses(raw string) (string, string) {
	parts := strings.Split(raw, "/")
	prefixLen := ""
	if len(parts) == 2 {
		prefixLen = "/" + parts[1]
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return raw, raw
	}
	last := 0
	fmt.Sscanf(octets[3], "%d", &last)
	a := parts[0] + prefixLen
	octets[3] = fmt.Sprint(last + 1)
	b := strings.Join(octets, ".") + prefixLen
	return a, b
}

func trimMask(addr string) string {
	return strings.Split(addr, "/")[0]
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func asSlice(v any) []any {
	if xs, ok := v.([]any); ok {
		return xs
	}
	return nil
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case fmt.Stringer:
		return strings.TrimSpace(x.String())
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%.0f", x)
		}
		return fmt.Sprint(x)
	default:
		return ""
	}
}

func intValue(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	case string:
		if x == "" || x == "-" {
			return 0
		}
		i, _ := strconv.Atoi(strings.TrimSpace(x))
		return i
	default:
		return 0
	}
}

func boolValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || strings.EqualFold(x, "yes") || strings.EqualFold(x, "active") || strings.EqualFold(x, "valid")
	default:
		return false
	}
}

func firstPresent(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return nil
}

func firstString(m map[string]any, keys ...string) string {
	return stringValue(firstPresent(m, keys...))
}

func sortedStrings(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func splitCommunities(raw string) []string {
	raw = strings.ReplaceAll(raw, ",", " ")
	if raw == "" || raw == "-" {
		return nil
	}
	return sortedStrings(strings.Fields(raw))
}

func appendCommunities(out []string, values ...any) []string {
	for _, value := range values {
		switch x := value.(type) {
		case nil:
			continue
		case []any:
			for _, item := range x {
				out = appendCommunities(out, item)
			}
		case []string:
			for _, item := range x {
				out = appendCommunities(out, item)
			}
		default:
			out = append(out, splitCommunities(stringValue(x))...)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return sortedStrings(out)
}

func normalizeLocalNextHop(nextHop string) string {
	if nextHop == "0.0.0.0" {
		return ""
	}
	return nextHop
}

func walkJSON(v any, visit func(key string, value any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			visit(k, v)
			walkJSON(v, visit)
		}
	case []any:
		for _, v := range x {
			walkJSON(v, visit)
		}
	}
}

func walkSRLinuxRouteSections(v any, ignored bool, out *[]map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			nextIgnored := ignored || isIgnoredSRLinuxRouteSection(k)
			if !nextIgnored && strings.EqualFold(k, "routes") {
				for _, item := range asSlice(v) {
					if m := asMap(item); len(m) > 0 {
						*out = append(*out, m)
					}
				}
			}
			walkSRLinuxRouteSections(v, nextIgnored, out)
		}
	case []any:
		for _, v := range x {
			walkSRLinuxRouteSections(v, ignored, out)
		}
	}
}

func isIgnoredSRLinuxRouteSection(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "advertised") || strings.Contains(key, "non-route")
}

func isPrefix(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}
