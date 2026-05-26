package livesnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/fibcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
	"gopkg.in/yaml.v3"
)

const Version = "hoyan.live_snapshot.v1"

type Snapshot struct {
	Version      string                  `json:"version"`
	Lab          string                  `json:"lab,omitempty"`
	TopologyPath string                  `json:"topology_path,omitempty"`
	TopologyHash string                  `json:"topology_hash,omitempty"`
	ConfigHashes map[string]string       `json:"config_hashes,omitempty"`
	GitCommit    string                  `json:"git_commit,omitempty"`
	CollectedAt  time.Time               `json:"collected_at"`
	Nodes        map[string]NodeSnapshot `json:"nodes"`
	Warnings     []string                `json:"warnings,omitempty"`
}

type NodeSnapshot struct {
	Kind          model.DeviceKind                `json:"kind"`
	BGPRIB        []ribcompare.NormalizedRoute    `json:"bgp_rib,omitempty"`
	RouteTable    []ribcompare.NormalizedRoute    `json:"route_table,omitempty"`
	FIB           []fibcompare.NormalizedFIBRoute `json:"fib,omitempty"`
	UnresolvedFIB []fibcompare.UnresolvedRoute    `json:"unresolved_fib,omitempty"`
	Raw           map[string]json.RawMessage      `json:"raw,omitempty"`
}

type HashPolicy string

const (
	HashPolicyWarn   HashPolicy = "warn"
	HashPolicyFail   HashPolicy = "fail"
	HashPolicyIgnore HashPolicy = "ignore"
)

type HashMismatch struct {
	Path string
	Want string
	Got  string
}

type HashCheckResult struct {
	Mismatches []HashMismatch
	Missing    []string
}

func ParseHashPolicy(raw string) (HashPolicy, bool) {
	switch HashPolicy(strings.ToLower(strings.TrimSpace(raw))) {
	case "", HashPolicyWarn:
		return HashPolicyWarn, true
	case HashPolicyFail:
		return HashPolicyFail, true
	case HashPolicyIgnore:
		return HashPolicyIgnore, true
	default:
		return HashPolicy(raw), false
	}
}

func Load(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap.Version == "" {
		return nil, fmt.Errorf("snapshot %s has no version", path)
	}
	if snap.Nodes == nil {
		snap.Nodes = map[string]NodeSnapshot{}
	}
	return &snap, nil
}

func Save(path string, snap *Snapshot) error {
	if path == "" || path == "-" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := Marshal(snap)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func Marshal(snap *Snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Build(ctx context.Context, topologyPath, lab string, runner ribcompare.Runner, rawDir string, fibOpts fibcompare.Options) (*Snapshot, error) {
	topo, warnings, err := model.LoadLabTopologyWithOptions(topologyPath, model.LoadLabTopologyOptions{CollectWarnings: true})
	if err != nil {
		return nil, err
	}
	if lab == "" {
		lab = topo.Name
	}
	effectiveRunner := runner
	if rawDir != "" {
		effectiveRunner = &rawRecordingRunner{Runner: runner, Dir: rawDir}
	}
	nodes := ribcompare.SupportedNodes(topo.Nodes)
	bgp, err := ribcompare.CollectBGPOnlyWithRunner(ctx, effectiveRunner, nodes)
	if err != nil {
		return nil, err
	}
	routes, err := collectRouteTables(ctx, effectiveRunner, nodes)
	if err != nil {
		return nil, err
	}
	fibNodes := fibcompare.SupportedNodes(topo.Nodes)
	fib, err := fibcompare.Collect(ctx, effectiveRunner, fibNodes, fibOpts)
	if err != nil {
		return nil, err
	}
	fibResult := fibcompare.AnalyzeComparableRoutes(topo, fib, fibOpts)
	hashes, err := InputHashes(topologyPath)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{
		Version:      Version,
		Lab:          lab,
		TopologyPath: filepath.ToSlash(topologyPath),
		TopologyHash: hashes.TopologyHash,
		ConfigHashes: hashes.ConfigHashes,
		GitCommit:    gitCommit(),
		CollectedAt:  time.Now().UTC(),
		Nodes:        map[string]NodeSnapshot{},
		Warnings:     warningStrings(warnings),
	}
	for _, node := range topo.Nodes {
		snap.Nodes[node.Name] = NodeSnapshot{Kind: node.Kind}
	}
	addRIBRoutes(snap.Nodes, bgp, func(ns NodeSnapshot, routes []ribcompare.NormalizedRoute) NodeSnapshot {
		ns.BGPRIB = routes
		return ns
	})
	addRIBRoutes(snap.Nodes, routes, func(ns NodeSnapshot, routes []ribcompare.NormalizedRoute) NodeSnapshot {
		ns.RouteTable = routes
		return ns
	})
	addFIBRoutes(snap.Nodes, fib)
	addUnresolvedFIB(snap.Nodes, fibResult.Unresolved)
	return snap, nil
}

func BGPRoutes(snap *Snapshot) []ribcompare.NormalizedRoute {
	var out []ribcompare.NormalizedRoute
	for _, name := range sortedNodeNames(snap.Nodes) {
		out = append(out, snap.Nodes[name].BGPRIB...)
	}
	return out
}

func AllRIBRoutes(snap *Snapshot) []ribcompare.NormalizedRoute {
	var out []ribcompare.NormalizedRoute
	for _, name := range sortedNodeNames(snap.Nodes) {
		out = append(out, snap.Nodes[name].BGPRIB...)
		out = append(out, snap.Nodes[name].RouteTable...)
	}
	return out
}

func FIBRoutes(snap *Snapshot) []fibcompare.NormalizedFIBRoute {
	var out []fibcompare.NormalizedFIBRoute
	for _, name := range sortedNodeNames(snap.Nodes) {
		out = append(out, snap.Nodes[name].FIB...)
	}
	return out
}

func UnresolvedFIB(snap *Snapshot) []fibcompare.UnresolvedRoute {
	var out []fibcompare.UnresolvedRoute
	for _, name := range sortedNodeNames(snap.Nodes) {
		out = append(out, snap.Nodes[name].UnresolvedFIB...)
	}
	return out
}

func CheckHashes(topologyPath string, snap *Snapshot) (HashCheckResult, error) {
	hashes, err := InputHashes(topologyPath)
	if err != nil {
		return HashCheckResult{}, err
	}
	var result HashCheckResult
	if snap.TopologyHash != "" && hashes.TopologyHash != snap.TopologyHash {
		result.Mismatches = append(result.Mismatches, HashMismatch{Path: topologyPath, Want: snap.TopologyHash, Got: hashes.TopologyHash})
	}
	for path, want := range snap.ConfigHashes {
		got, ok := hashes.ConfigHashes[path]
		if !ok {
			result.Missing = append(result.Missing, path)
			continue
		}
		if got != want {
			result.Mismatches = append(result.Mismatches, HashMismatch{Path: path, Want: want, Got: got})
		}
	}
	sort.Slice(result.Mismatches, func(i, j int) bool { return result.Mismatches[i].Path < result.Mismatches[j].Path })
	sort.Strings(result.Missing)
	return result, nil
}

type InputHashSet struct {
	TopologyHash string
	ConfigHashes map[string]string
}

func InputHashes(topologyPath string) (InputHashSet, error) {
	topoHash, err := fileSHA256(topologyPath)
	if err != nil {
		return InputHashSet{}, err
	}
	configs, err := configPaths(topologyPath)
	if err != nil {
		return InputHashSet{}, err
	}
	hashes := map[string]string{}
	root := filepath.Dir(topologyPath)
	for _, path := range configs {
		full := path
		if !filepath.IsAbs(full) {
			full = filepath.Join(root, path)
		}
		sum, err := fileSHA256(full)
		if err != nil {
			return InputHashSet{}, err
		}
		hashes[filepath.ToSlash(path)] = sum
	}
	return InputHashSet{TopologyHash: topoHash, ConfigHashes: hashes}, nil
}

type clabHashFile struct {
	Topology struct {
		Nodes map[string]struct {
			Binds         []string `yaml:"binds"`
			StartupConfig string   `yaml:"startup-config"`
		} `yaml:"nodes"`
	} `yaml:"topology"`
}

func configPaths(topologyPath string) ([]string, error) {
	data, err := os.ReadFile(topologyPath)
	if err != nil {
		return nil, err
	}
	var raw clabHashFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, node := range raw.Topology.Nodes {
		if node.StartupConfig != "" {
			seen[filepath.Clean(node.StartupConfig)] = true
		}
		for _, bind := range node.Binds {
			parts := strings.Split(bind, ":")
			if len(parts) < 2 {
				continue
			}
			target := parts[1]
			if target == "/etc/frr/frr.conf" || target == "/etc/frr/daemons" || target == "/etc/frr/vtysh.conf" || target == "/etc/hoyan/nftables.conf" {
				seen[filepath.Clean(parts[0])] = true
			}
		}
	}
	var out []string
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func collectRouteTables(ctx context.Context, runner ribcompare.Runner, nodes []model.Node) ([]ribcompare.NormalizedRoute, error) {
	var out []ribcompare.NormalizedRoute
	collectors := map[model.DeviceKind]ribcompare.RouteTableCollector{
		model.KindFRR:     frrRouteTableCollector{},
		model.KindCEOS:    ceosRouteTableCollector{},
		model.KindSRLinux: srlinuxRouteTableCollector{},
	}
	for _, kind := range []model.DeviceKind{model.KindFRR, model.KindCEOS, model.KindSRLinux} {
		var selected []model.Node
		for _, node := range nodes {
			if node.Kind == kind {
				selected = append(selected, node)
			}
		}
		if len(selected) == 0 {
			continue
		}
		routes, err := collectors[kind].CollectRouteTables(ctx, runner, selected)
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

type frrRouteTableCollector struct{}
type ceosRouteTableCollector struct{}
type srlinuxRouteTableCollector struct{}

func (frrRouteTableCollector) CollectRouteTables(ctx context.Context, runner ribcompare.Runner, nodes []model.Node) ([]ribcompare.NormalizedRoute, error) {
	return routeTablesByKind(ctx, runner, nodes, model.KindFRR)
}

func (ceosRouteTableCollector) CollectRouteTables(ctx context.Context, runner ribcompare.Runner, nodes []model.Node) ([]ribcompare.NormalizedRoute, error) {
	return routeTablesByKind(ctx, runner, nodes, model.KindCEOS)
}

func (srlinuxRouteTableCollector) CollectRouteTables(ctx context.Context, runner ribcompare.Runner, nodes []model.Node) ([]ribcompare.NormalizedRoute, error) {
	return routeTablesByKind(ctx, runner, nodes, model.KindSRLinux)
}

func routeTablesByKind(ctx context.Context, runner ribcompare.Runner, nodes []model.Node, kind model.DeviceKind) ([]ribcompare.NormalizedRoute, error) {
	switch kind {
	case model.KindFRR:
		var out []ribcompare.NormalizedRoute
		for _, n := range nodes {
			data, err := runner.Run(ctx, "docker", "exec", "-i", n.RuntimeName(), "vtysh", "-c", "show ip route json")
			if err != nil {
				return nil, err
			}
			routes, err := ribcompare.ParseFRRRouteTable(n.Name, data)
			if err != nil {
				return nil, err
			}
			out = append(out, routes...)
		}
		return out, nil
	case model.KindCEOS:
		var out []ribcompare.NormalizedRoute
		for _, n := range nodes {
			data, err := runner.Run(ctx, "docker", "exec", "-i", n.RuntimeName(), "Cli", "-p", "15", "-c", "show ip route vrf default | json")
			if err != nil {
				return nil, err
			}
			routes, err := ribcompare.ParseCEOSRouteTable(n.Name, data)
			if err != nil {
				return nil, err
			}
			out = append(out, routes...)
		}
		return out, nil
	case model.KindSRLinux:
		var out []ribcompare.NormalizedRoute
		for _, n := range nodes {
			data, err := ribcompare.RunSRLinuxJSON(ctx, runner, n.RuntimeName(), "show", "network-instance", "default", "route-table", "ipv4-unicast", "summary")
			if err != nil {
				return nil, err
			}
			routes, err := ribcompare.ParseSRLinuxRouteTable(n.Name, data)
			if err != nil {
				return nil, err
			}
			out = append(out, routes...)
		}
		return out, nil
	default:
		return nil, nil
	}
}

func addRIBRoutes(nodes map[string]NodeSnapshot, routes []ribcompare.NormalizedRoute, update func(NodeSnapshot, []ribcompare.NormalizedRoute) NodeSnapshot) {
	byNode := map[string][]ribcompare.NormalizedRoute{}
	for _, route := range routes {
		byNode[route.Node] = append(byNode[route.Node], route)
	}
	for name, routes := range byNode {
		ns := nodes[name]
		nodes[name] = update(ns, routes)
	}
}

func addFIBRoutes(nodes map[string]NodeSnapshot, routes []fibcompare.NormalizedFIBRoute) {
	for _, route := range routes {
		ns := nodes[route.Node]
		ns.FIB = append(ns.FIB, route)
		nodes[route.Node] = ns
	}
}

func addUnresolvedFIB(nodes map[string]NodeSnapshot, routes []fibcompare.UnresolvedRoute) {
	for _, route := range routes {
		ns := nodes[route.Node]
		ns.UnresolvedFIB = append(ns.UnresolvedFIB, route)
		nodes[route.Node] = ns
	}
}

func sortedNodeNames(nodes map[string]NodeSnapshot) []string {
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func warningStrings(warnings []model.UnsupportedStatement) []string {
	out := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		out = append(out, warning.String())
	}
	return out
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func gitCommit() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

type rawRecordingRunner struct {
	Runner ribcompare.Runner
	Dir    string
	seq    int
}

func (r *rawRecordingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	data, err := r.Runner.Run(ctx, name, args...)
	if err == nil {
		r.seq++
		_ = os.MkdirAll(r.Dir, 0o755)
		_ = os.WriteFile(filepath.Join(r.Dir, fmt.Sprintf("%03d.%s.raw", r.seq, sanitizeRawName(append([]string{name}, args...)))), data, 0o644)
	}
	return data, err
}

func sanitizeRawName(parts []string) string {
	joined := strings.Join(parts, ".")
	var b strings.Builder
	lastDot := false
	for _, r := range joined {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDot = false
			continue
		}
		if !lastDot {
			b.WriteByte('.')
			lastDot = true
		}
	}
	return strings.Trim(b.String(), ".")
}
