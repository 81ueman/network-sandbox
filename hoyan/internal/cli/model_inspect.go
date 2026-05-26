package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/81ueman/network-sandbox/hoyan/internal/failure"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
	"github.com/spf13/cobra"
)

const (
	modelFormatTable = "table"
	modelFormatJSON  = "json"
)

type modelInspectOptions struct {
	topologyPath     string
	queriesPath      string
	node             string
	prefix           string
	format           string
	from             string
	to               string
	protocol         string
	dstPort          int
	strictConfig     bool
	showCond         bool
	showPreds        bool
	summary          bool
	maxPrefixClasses int
}

type prefixClassInspectRow struct {
	ClassID           model.PrefixClassID `json:"class_id"`
	Space             string              `json:"space"`
	MatchedPredicates []string            `json:"matched_predicates,omitempty"`
}

type packetClassInspectRow struct {
	ClassID           model.PacketClassID `json:"class_id"`
	PrefixClassID     model.PrefixClassID `json:"prefix_class_id"`
	Space             string              `json:"space"`
	Protocol          string              `json:"protocol,omitempty"`
	SrcPort           string              `json:"src_port,omitempty"`
	DstPort           string              `json:"dst_port,omitempty"`
	IngressInterface  string              `json:"ingress_interface,omitempty"`
	EgressInterface   string              `json:"egress_interface,omitempty"`
	MatchedPredicates []string            `json:"matched_predicates,omitempty"`
}

type ribInspectRow struct {
	Node                  string   `json:"node"`
	Prefix                string   `json:"prefix"`
	SourceKind            string   `json:"source_kind,omitempty"`
	ConnectedClass        string   `json:"connected_class,omitempty"`
	RouteInterface        string   `json:"interface,omitempty"`
	NextHopNode           string   `json:"next_hop_node,omitempty"`
	NextHopAddr           string   `json:"next_hop_addr,omitempty"`
	OriginNode            string   `json:"origin_node,omitempty"`
	FromNode              string   `json:"from_node,omitempty"`
	PathNodes             []string `json:"path_nodes,omitempty"`
	PathLinks             []string `json:"path_links,omitempty"`
	ASPath                []uint32 `json:"as_path,omitempty"`
	Communities           []string `json:"communities,omitempty"`
	OriginCode            *string  `json:"origin_code,omitempty"`
	LocalPref             *int     `json:"local_pref,omitempty"`
	MED                   *int     `json:"med,omitempty"`
	LearnedIBGP           *bool    `json:"learned_ibgp,omitempty"`
	Invalid               *bool    `json:"invalid,omitempty"`
	AggregateContributors []string `json:"aggregate_contributors,omitempty"`
	Condition             string   `json:"condition,omitempty"`
	SelectedCondition     string   `json:"selected_condition,omitempty"`
	BaseCondition         string   `json:"base_condition,omitempty"`
}

type fibInspectRow struct {
	Node           string   `json:"node"`
	Prefix         string   `json:"prefix"`
	SourceKind     string   `json:"source_kind,omitempty"`
	ConnectedClass string   `json:"connected_class,omitempty"`
	Interface      string   `json:"interface,omitempty"`
	NextHop        string   `json:"next_hop_node,omitempty"`
	Rank           int      `json:"rank"`
	GroupID        string   `json:"group_id,omitempty"`
	Equivalent     bool     `json:"equivalent"`
	PathNodes      []string `json:"path_nodes,omitempty"`
	PathLinks      []string `json:"path_links,omitempty"`
	Cost           int      `json:"cost"`
	Condition      string   `json:"condition,omitempty"`
}

type symbolicPacketInspect struct {
	From               string                               `json:"from"`
	To                 string                               `json:"to"`
	Protocol           string                               `json:"protocol"`
	DstPort            int                                  `json:"dst_port,omitempty"`
	Reachable          string                               `json:"reachable_condition"`
	Unreachable        string                               `json:"unreachable_condition"`
	Reason             string                               `json:"reason,omitempty"`
	Paths              []symbolicPacketInspectPath          `json:"paths,omitempty"`
	Blocked            []symbolicPacketBlockedPath          `json:"blocked_paths,omitempty"`
	UnreachableReasons []symbolicPacketInspectBlockedReason `json:"unreachable_reasons,omitempty"`
}

type symbolicPacketInspectPath struct {
	PathNodes []string                     `json:"path_nodes,omitempty"`
	PathLinks []string                     `json:"path_links,omitempty"`
	Cost      int                          `json:"cost"`
	Condition string                       `json:"condition,omitempty"`
	States    []symbolicPacketInspectState `json:"states,omitempty"`
}

type symbolicPacketInspectState struct {
	Node             string   `json:"node"`
	IngressInterface string   `json:"ingress_interface,omitempty"`
	Condition        string   `json:"condition,omitempty"`
	PathNodes        []string `json:"path_nodes,omitempty"`
	PathLinks        []string `json:"path_links,omitempty"`
	Cost             int      `json:"cost"`
}

type symbolicPacketBlockedPath struct {
	PathNodes []string           `json:"path_nodes,omitempty"`
	PathLinks []string           `json:"path_links,omitempty"`
	Cost      int                `json:"cost"`
	Condition string             `json:"condition,omitempty"`
	Reason    string             `json:"reason,omitempty"`
	Policy    string             `json:"policy,omitempty"`
	Node      string             `json:"node,omitempty"`
	Interface string             `json:"interface,omitempty"`
	Stage     string             `json:"stage,omitempty"`
	Source    model.PolicySource `json:"source,omitempty"`
}

type symbolicPacketInspectBlockedReason struct {
	Kind       string   `json:"kind"`
	Node       string   `json:"node,omitempty"`
	Link       string   `json:"link,omitempty"`
	Interface  string   `json:"interface,omitempty"`
	PolicyName string   `json:"policy_name,omitempty"`
	PolicyRaw  string   `json:"policy_raw,omitempty"`
	PathNodes  []string `json:"path_nodes,omitempty"`
	PathLinks  []string `json:"path_links,omitempty"`
	Cost       int      `json:"cost"`
	Condition  string   `json:"condition,omitempty"`
	Message    string   `json:"message,omitempty"`
}

type symbolicRouteInspect struct {
	From              string                     `json:"from"`
	Prefix            string                     `json:"prefix"`
	ClassID           model.PrefixClassID        `json:"class_id"`
	Space             string                     `json:"space"`
	MatchedPredicates []string                   `json:"matched_predicates,omitempty"`
	Reachable         string                     `json:"reachable_condition"`
	Unreachable       string                     `json:"unreachable_condition"`
	Reason            string                     `json:"reason,omitempty"`
	Paths             []symbolicRouteInspectPath `json:"paths,omitempty"`
}

type symbolicRouteInspectPath struct {
	PathNodes []string `json:"path_nodes,omitempty"`
	PathLinks []string `json:"path_links,omitempty"`
	Cost      int      `json:"cost"`
	Condition string   `json:"condition,omitempty"`
}

func NewModelCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "model",
		Short:         "Inspect modeled RIB, FIB, and symbolic reachability",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(NewModelRIBCommand(), NewModelFIBCommand(), NewModelSymbolicPacketCommand(), NewModelSymbolicRouteCommand(), NewModelPrefixClassesCommand(), NewModelPacketClassesCommand())
	return cmd
}

func NewModelPrefixClassesCommand() *cobra.Command {
	var opts modelInspectOptions
	cmd := &cobra.Command{
		Use:           "prefix-classes",
		Short:         "Inspect PrefixUniverse prefix classes",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return runModelPrefixClasses(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().StringVar(&opts.prefix, "prefix", "", "prefix overlap filter")
	cmd.Flags().StringVar(&opts.format, "format", modelFormatTable, "output format: table or json")
	cmd.Flags().BoolVar(&opts.showPreds, "show-predicates", false, "show matched prefix predicates in table output")
	cmd.Flags().BoolVar(&opts.summary, "summary", false, "show PrefixUniverse build statistics before table output")
	cmd.Flags().IntVar(&opts.maxPrefixClasses, "max-prefix-classes", 10000, "maximum PrefixUniverse classes before failing; 0 disables the guard")
	return cmd
}

func NewModelPacketClassesCommand() *cobra.Command {
	var opts modelInspectOptions
	cmd := &cobra.Command{
		Use:           "packet-classes",
		Short:         "Inspect HeaderSpace packet classes",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return runModelPacketClasses(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	addQueriesFlag(cmd, &opts.queriesPath, "query YAML for packet predicates")
	cmd.Flags().StringVar(&opts.prefix, "prefix", "", "destination prefix overlap filter")
	cmd.Flags().StringVar(&opts.protocol, "protocol", "", "protocol filter")
	cmd.Flags().IntVar(&opts.dstPort, "dst-port", 0, "destination transport port filter")
	cmd.Flags().StringVar(&opts.format, "format", modelFormatTable, "output format: table or json")
	cmd.Flags().BoolVar(&opts.showPreds, "show-predicates", false, "show matched header predicates in table output")
	return cmd
}

func NewModelRIBCommand() *cobra.Command {
	var opts modelInspectOptions
	cmd := &cobra.Command{
		Use:           "rib [bgp|connected|static|aggregate|blackhole]",
		Short:         "Inspect modeled RIB entries",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if len(args) == 1 {
				opts.protocol = args[0]
			}
			return runModelRIB(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addModelCommonFlags(cmd, &opts)
	return cmd
}

func NewModelFIBCommand() *cobra.Command {
	var opts modelInspectOptions
	cmd := &cobra.Command{
		Use:           "fib",
		Short:         "Inspect modeled FIB entries",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return runModelFIB(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addModelCommonFlags(cmd, &opts)
	return cmd
}

func NewModelSymbolicPacketCommand() *cobra.Command {
	var opts modelInspectOptions
	cmd := &cobra.Command{
		Use:           "symbolic-packet",
		Short:         "Inspect symbolic packet reachability",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return runModelSymbolicPacket(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().StringVar(&opts.format, "format", modelFormatTable, "output format: table or json")
	cmd.Flags().StringVar(&opts.from, "from", "", "source node")
	cmd.Flags().StringVar(&opts.to, "to", "", "destination IP address")
	cmd.Flags().StringVar(&opts.protocol, "protocol", "tcp", "packet protocol")
	cmd.Flags().IntVar(&opts.dstPort, "dst-port", 0, "destination transport port")
	cmd.Flags().BoolVar(&opts.showCond, "show-conditions", false, "show symbolic conditions in table output")
	return cmd
}

func NewModelSymbolicRouteCommand() *cobra.Command {
	var opts modelInspectOptions
	cmd := &cobra.Command{
		Use:           "symbolic-route",
		Short:         "Inspect symbolic route reachability",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return runModelSymbolicRoute(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().StringVar(&opts.format, "format", modelFormatTable, "output format: table or json")
	cmd.Flags().StringVar(&opts.from, "from", "", "source node")
	cmd.Flags().StringVar(&opts.prefix, "prefix", "", "destination prefix")
	cmd.Flags().BoolVar(&opts.showCond, "show-conditions", false, "show symbolic conditions in table output")
	cmd.Flags().BoolVar(&opts.showPreds, "show-predicates", false, "show matched prefix predicates in table output")
	return cmd
}

func addModelCommonFlags(cmd *cobra.Command, opts *modelInspectOptions) {
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().StringVar(&opts.node, "node", "", "node name filter")
	cmd.Flags().StringVar(&opts.prefix, "prefix", "", "prefix filter")
	cmd.Flags().StringVar(&opts.format, "format", modelFormatTable, "output format: table or json")
	cmd.Flags().BoolVar(&opts.showCond, "show-conditions", false, "show symbolic conditions in table output")
}

func runModelRIB(_ context.Context, opts modelInspectOptions, out io.Writer) error {
	protocol, err := canonicalRouteProtocol(opts.protocol)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	topo, graph, err := loadModelGraph(opts.topologyPath, opts.strictConfig)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	nodes, err := inspectNodes(topo, opts.node)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	prefix, err := canonicalPrefix(opts.prefix)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	rows := collectRIBRows(graph, nodes, prefix, protocol)
	switch opts.format {
	case modelFormatTable:
		return writeRIBTable(out, rows, opts.showCond, protocol)
	case modelFormatJSON:
		return writeJSON(out, rows)
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("--format must be %q or %q", modelFormatTable, modelFormatJSON)}
	}
}

func runModelFIB(_ context.Context, opts modelInspectOptions, out io.Writer) error {
	topo, graph, err := loadModelGraph(opts.topologyPath, opts.strictConfig)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	nodes, err := inspectNodes(topo, opts.node)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	prefix, err := canonicalPrefix(opts.prefix)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	rows := collectFIBRows(graph, nodes, prefix)
	switch opts.format {
	case modelFormatTable:
		return writeFIBTable(out, rows, opts.showCond)
	case modelFormatJSON:
		return writeJSON(out, rows)
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("--format must be %q or %q", modelFormatTable, modelFormatJSON)}
	}
}

func runModelPrefixClasses(_ context.Context, opts modelInspectOptions, out io.Writer) error {
	topo, err := model.LoadLabTopology(opts.topologyPath)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	graph := sim.NewGraph(topo)
	var filter model.PrefixSet
	var request []model.PrefixPredicate
	if opts.prefix != "" {
		prefix, err := model.ParsePrefix(opts.prefix)
		if err != nil {
			return ExitError{Code: 2, Err: fmt.Errorf("--prefix %q: %w", opts.prefix, err)}
		}
		filter = model.ExactPrefixSet{Prefix: prefix}
		request = append(request, model.PrefixPredicate{Source: "request:prefix-classes:" + prefix.String(), Set: filter})
	}
	universe, err := modelPrefixUniverse(topo, graph, request)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if opts.maxPrefixClasses > 0 && universe.Stats.ClassCount > opts.maxPrefixClasses {
		return ExitError{Code: 2, Err: fmt.Errorf("prefix universe class count %d exceeds --max-prefix-classes %d", universe.Stats.ClassCount, opts.maxPrefixClasses)}
	}
	rows := collectPrefixClassRows(universe, filter)
	switch opts.format {
	case modelFormatTable:
		if opts.summary {
			writePrefixUniverseStats(out, universe.Stats)
		}
		return writePrefixClassTable(out, rows, opts.showPreds)
	case modelFormatJSON:
		if opts.summary {
			return writeJSON(out, struct {
				Stats   model.PrefixUniverseStats `json:"prefix_universe_stats"`
				Classes []prefixClassInspectRow   `json:"classes"`
			}{
				Stats:   universe.Stats,
				Classes: rows,
			})
		}
		return writeJSON(out, rows)
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("--format must be %q or %q", modelFormatTable, modelFormatJSON)}
	}
}

func runModelPacketClasses(_ context.Context, opts modelInspectOptions, out io.Writer) error {
	topo, graph, err := loadModelGraph(opts.topologyPath, opts.strictConfig)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	queries, err := model.LoadQueries(opts.queriesPath)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	var filter model.PrefixSet
	var request []model.PrefixPredicate
	if opts.prefix != "" {
		prefix, err := model.ParsePrefix(opts.prefix)
		if err != nil {
			return ExitError{Code: 2, Err: fmt.Errorf("--prefix %q: %w", opts.prefix, err)}
		}
		filter = model.ExactPrefixSet{Prefix: prefix}
		request = append(request, model.PrefixPredicate{Source: "request:packet-classes:" + prefix.String(), Set: filter})
	}
	universe, err := modelPrefixUniverseWithQueries(topo, queries, graph, request)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	headerSpace := model.NewHeaderSpace(topo, queries, universe)
	rows := collectPacketClassRows(headerSpace, filter, opts.protocol, opts.dstPort)
	switch opts.format {
	case modelFormatTable:
		return writePacketClassTable(out, rows, opts.showPreds)
	case modelFormatJSON:
		return writeJSON(out, rows)
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("--format must be %q or %q", modelFormatTable, modelFormatJSON)}
	}
}

func runModelSymbolicPacket(_ context.Context, opts modelInspectOptions, out io.Writer) error {
	if opts.from == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--from is required")}
	}
	if opts.to == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--to is required")}
	}
	topo, graph, err := loadModelGraph(opts.topologyPath, opts.strictConfig)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if _, ok := topo.Node(opts.from); !ok {
		return ExitError{Code: 2, Err: fmt.Errorf("unknown node %q", opts.from)}
	}
	if _, err := netip.ParseAddr(opts.to); err != nil {
		return ExitError{Code: 2, Err: fmt.Errorf("--to must be an IP address: %w", err)}
	}
	spec := model.PacketSpec{Protocol: opts.protocol, DstPort: model.ExactPort(opts.dstPort)}
	result := buildSymbolicPacketInspect(opts, graph.SymbolicPacketReachabilitySpec(opts.from, opts.to, spec))
	switch opts.format {
	case modelFormatTable:
		return writeSymbolicPacketTable(out, result, opts.showCond)
	case modelFormatJSON:
		return writeJSON(out, result)
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("--format must be %q or %q", modelFormatTable, modelFormatJSON)}
	}
}

func runModelSymbolicRoute(_ context.Context, opts modelInspectOptions, out io.Writer) error {
	if opts.from == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--from is required")}
	}
	if opts.prefix == "" {
		return ExitError{Code: 2, Err: fmt.Errorf("--prefix is required")}
	}
	topo, graph, err := loadModelGraph(opts.topologyPath, opts.strictConfig)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if _, ok := topo.Node(opts.from); !ok {
		return ExitError{Code: 2, Err: fmt.Errorf("unknown node %q", opts.from)}
	}
	prefix, err := canonicalPrefix(opts.prefix)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	parsedPrefix, err := model.ParsePrefix(prefix)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	filter := model.ExactPrefixSet{Prefix: parsedPrefix}
	universe, err := modelPrefixUniverse(topo, graph, []model.PrefixPredicate{{
		Source: "request:symbolic-route:" + parsedPrefix.String(),
		Set:    filter,
	}})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	results := buildSymbolicRouteClassInspects(opts.from, prefix, universe, filter, graph.SymbolicRouteReachability(opts.from, prefix))
	switch opts.format {
	case modelFormatTable:
		return writeSymbolicRouteTable(out, results, opts.showCond, opts.showPreds)
	case modelFormatJSON:
		return writeJSON(out, results)
	default:
		return ExitError{Code: 2, Err: fmt.Errorf("--format must be %q or %q", modelFormatTable, modelFormatJSON)}
	}
}

func loadModelGraph(topologyPath string, strictConfig bool) (*model.Topology, *sim.Graph, error) {
	topo, _, err := model.LoadLabTopologyWithOptions(topologyPath, model.LoadLabTopologyOptions{StrictConfig: strictConfig})
	if err != nil {
		return nil, nil, err
	}
	return topo, sim.NewGraph(topo), nil
}

func inspectNodes(topo *model.Topology, node string) ([]string, error) {
	if node != "" {
		if _, ok := topo.Node(node); !ok {
			return nil, fmt.Errorf("unknown node %q", node)
		}
		return []string{node}, nil
	}
	nodes := make([]string, 0, len(topo.Nodes))
	for _, n := range topo.Nodes {
		nodes = append(nodes, n.Name)
	}
	sort.Strings(nodes)
	return nodes, nil
}

func canonicalPrefix(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	prefix, err := model.ParsePrefix(raw)
	if err != nil {
		return "", fmt.Errorf("--prefix %q: %w", raw, err)
	}
	return prefix.String(), nil
}

func canonicalRouteProtocol(raw string) (model.RouteSourceKind, error) {
	protocol := model.RouteSourceKind(strings.ToLower(strings.TrimSpace(raw)))
	switch protocol {
	case "":
		return "", nil
	case model.RouteSourceBGP, model.RouteSourceConnected, model.RouteSourceStatic, model.RouteSourceAggregate, model.RouteSourceBlackhole:
		return protocol, nil
	default:
		return "", fmt.Errorf("protocol must be one of bgp, connected, static, aggregate, or blackhole")
	}
}

func ptr[T any](v T) *T {
	return &v
}

func modelPrefixUniverse(topo *model.Topology, graph *sim.Graph, request []model.PrefixPredicate) (model.PrefixUniverse, error) {
	return modelPrefixUniverseWithQueries(topo, nil, graph, request)
}

func modelPrefixUniverseWithQueries(topo *model.Topology, queries *model.Queries, graph *sim.Graph, request []model.PrefixPredicate) (model.PrefixUniverse, error) {
	predicates := model.CollectPrefixPredicateMetadata(topo, queries)
	predicates = append(predicates, sim.CollectRIBPrefixPredicates(graph)...)
	predicates = append(predicates, sim.CollectFIBPrefixPredicates(graph)...)
	predicates = append(predicates, request...)
	return model.BuildPrefixUniverseFromPredicates(predicates)
}

func collectPrefixClassRows(universe model.PrefixUniverse, filter model.PrefixSet) []prefixClassInspectRow {
	var rows []prefixClassInspectRow
	for _, class := range universe.Classes {
		if filter != nil && !model.AddressSpaceOverlaps(class.Space, filter) {
			continue
		}
		rows = append(rows, prefixClassInspectRow{
			ClassID:           class.ID,
			Space:             class.Space.String(),
			MatchedPredicates: matchedPrefixPredicates(universe, class),
		})
	}
	return rows
}

func collectPacketClassRows(headerSpace model.HeaderSpace, filter model.PrefixSet, protocol string, dstPort int) []packetClassInspectRow {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	var rows []packetClassInspectRow
	for _, class := range headerSpace.Classes {
		if filter != nil && !model.AddressSpaceOverlaps(class.DstSet, filter) {
			continue
		}
		if protocol != "" && class.Protocol != "" && class.Protocol != protocol {
			continue
		}
		if dstPort > 0 && class.DstPort != nil && !class.DstPort.Contains(dstPort) {
			continue
		}
		rows = append(rows, packetClassInspectRow{
			ClassID:           class.ID,
			PrefixClassID:     class.PrefixClassID,
			Space:             prefixSetString(class.DstSet),
			Protocol:          class.Protocol,
			SrcPort:           portSetInspectString(class.SrcPort),
			DstPort:           portSetInspectString(class.DstPort),
			IngressInterface:  class.IngressInterface,
			EgressInterface:   class.EgressInterface,
			MatchedPredicates: matchedHeaderPredicates(headerSpace, class),
		})
	}
	return rows
}

func collectRIBRows(graph *sim.Graph, nodes []string, prefix string, protocol model.RouteSourceKind) []ribInspectRow {
	var rows []ribInspectRow
	for _, node := range nodes {
		if prefix != "" {
			rows = append(rows, ribRowsForRoutes(node, graph.RIB(node, prefix), protocol)...)
			continue
		}
		table := graph.RIBTable(node)
		prefixes := make([]string, 0, len(table))
		for p := range table {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		for _, p := range prefixes {
			rows = append(rows, ribRowsForRoutes(node, table[p], protocol)...)
		}
	}
	return rows
}

func ribRowsForRoutes(node string, routes []sim.RIBEntry, protocol model.RouteSourceKind) []ribInspectRow {
	rows := make([]ribInspectRow, 0, len(routes))
	for _, route := range routes {
		route = route.Normalize()
		if protocol != "" && route.SourceKind != protocol {
			continue
		}
		rows = append(rows, ribInspectRow{
			Node:                  node,
			Prefix:                route.NLRI.Prefix.String(),
			SourceKind:            string(route.SourceKind),
			ConnectedClass:        string(route.RouteSource.ConnectedClass),
			RouteInterface:        route.RouteSource.Interface,
			NextHopNode:           route.ForwardingNextHop.Node,
			NextHopAddr:           route.ForwardingNextHop.Addr,
			OriginNode:            route.Provenance.OriginNode,
			FromNode:              route.Provenance.FromNode,
			PathNodes:             append([]string(nil), route.Provenance.PathNodes...),
			PathLinks:             append([]string(nil), route.Provenance.PathLinks...),
			AggregateContributors: append([]string(nil), route.AggregateContributors...),
			Condition:             condString(route.Condition),
			SelectedCondition:     condString(route.SelectedCond),
			BaseCondition:         condString(route.BaseCond),
		})
		if route.SourceKind == model.RouteSourceBGP {
			last := &rows[len(rows)-1]
			last.ASPath = append([]uint32(nil), route.Attrs.ASPath...)
			last.Communities = append([]string(nil), route.Attrs.Communities...)
			last.OriginCode = ptr(string(route.Attrs.OriginCode))
			last.LocalPref = ptr(route.Attrs.LocalPref)
			last.MED = ptr(route.Attrs.MED)
			last.LearnedIBGP = ptr(route.Attrs.LearnedIBGP)
			last.Invalid = ptr(route.Attrs.Invalid)
		}
	}
	return rows
}

func collectFIBRows(graph *sim.Graph, nodes []string, prefix string) []fibInspectRow {
	var rows []fibInspectRow
	for _, node := range nodes {
		for _, entry := range graph.FIB(node) {
			if prefix != "" && entry.Prefix.String() != prefix {
				continue
			}
			rows = append(rows, fibInspectRow{
				Node:           node,
				Prefix:         entry.Prefix.String(),
				SourceKind:     string(entry.SourceKind),
				ConnectedClass: string(entry.ConnectedClass),
				Interface:      entry.Interface,
				NextHop:        entry.NextHop,
				Rank:           entry.Rank,
				GroupID:        entry.GroupID,
				Equivalent:     entry.Equivalent,
				PathNodes:      append([]string(nil), entry.Path.Nodes...),
				PathLinks:      append([]string(nil), entry.Path.Links...),
				Cost:           entry.Path.Cost,
				Condition:      condString(entry.Condition),
			})
		}
	}
	return rows
}

func buildSymbolicPacketInspect(opts modelInspectOptions, result sim.SymbolicReachabilityResult) symbolicPacketInspect {
	out := symbolicPacketInspect{
		From:        opts.from,
		To:          opts.to,
		Protocol:    opts.protocol,
		DstPort:     opts.dstPort,
		Reachable:   condString(result.Reachable),
		Unreachable: condString(result.Unreachable),
		Reason:      result.Reason,
	}
	for _, path := range result.Paths {
		row := symbolicPacketInspectPath{
			PathNodes: append([]string(nil), path.Path.Nodes...),
			PathLinks: append([]string(nil), path.Path.Links...),
			Cost:      path.Path.Cost,
			Condition: condString(path.Cond),
		}
		for _, state := range path.States {
			row.States = append(row.States, symbolicPacketInspectState{
				Node:             state.Node,
				IngressInterface: state.IngressInterface,
				Condition:        condString(state.Cond),
				PathNodes:        append([]string(nil), state.Path.Nodes...),
				PathLinks:        append([]string(nil), state.Path.Links...),
				Cost:             state.Path.Cost,
			})
		}
		out.Paths = append(out.Paths, row)
	}
	for _, path := range result.Blocked {
		out.Blocked = append(out.Blocked, symbolicPacketBlockedPath{
			PathNodes: append([]string(nil), path.Path.Nodes...),
			PathLinks: append([]string(nil), path.Path.Links...),
			Cost:      path.Path.Cost,
			Condition: condString(path.Cond),
			Reason:    path.Reason,
			Policy:    path.Policy,
			Node:      path.Node,
			Interface: path.Interface,
			Stage:     path.Stage,
			Source:    path.Source,
		})
	}
	for _, reason := range result.UnreachableReasons {
		out.UnreachableReasons = append(out.UnreachableReasons, symbolicPacketInspectBlockedReason{
			Kind:       string(reason.Kind),
			Node:       reason.Node,
			Link:       reason.Link,
			Interface:  reason.Interface,
			PolicyName: reason.PolicyName,
			PolicyRaw:  reason.PolicyRaw,
			PathNodes:  append([]string(nil), reason.Path.Nodes...),
			PathLinks:  append([]string(nil), reason.Path.Links...),
			Cost:       reason.Path.Cost,
			Condition:  condString(reason.Cond),
			Message:    reason.Message,
		})
	}
	return out
}

func buildSymbolicRouteClassInspects(from, prefix string, universe model.PrefixUniverse, filter model.PrefixSet, result sim.SymbolicRouteReachabilityResult) []symbolicRouteInspect {
	var out []symbolicRouteInspect
	for _, class := range universe.Classes {
		if filter != nil && !model.AddressSpaceOverlaps(class.Space, filter) {
			continue
		}
		out = append(out, buildSymbolicRouteInspect(from, prefix, class, matchedPrefixPredicates(universe, class), result))
	}
	return out
}

func buildSymbolicRouteInspect(from, prefix string, class model.PrefixClass, matched []string, result sim.SymbolicRouteReachabilityResult) symbolicRouteInspect {
	out := symbolicRouteInspect{
		From:              from,
		Prefix:            prefix,
		ClassID:           class.ID,
		Space:             class.Space.String(),
		MatchedPredicates: matched,
		Reachable:         condString(result.Reachable),
		Unreachable:       condString(result.Unreachable),
		Reason:            result.Reason,
	}
	for _, path := range result.Paths {
		out.Paths = append(out.Paths, symbolicRouteInspectPath{
			PathNodes: append([]string(nil), path.Path.Nodes...),
			PathLinks: append([]string(nil), path.Path.Links...),
			Cost:      path.Path.Cost,
			Condition: condString(path.Cond),
		})
	}
	return out
}

func matchedPrefixPredicates(universe model.PrefixUniverse, class model.PrefixClass) []string {
	byID := map[model.PrefixPredicateID]string{}
	for _, predicate := range universe.Predicates {
		byID[predicate.ID] = predicate.Source
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(class.MatchingPredicates))
	for _, id := range class.MatchingPredicates {
		source := byID[id]
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

func matchedHeaderPredicates(headerSpace model.HeaderSpace, class model.PacketClass) []string {
	byID := map[model.HeaderPredicateID]string{}
	for _, predicate := range headerSpace.Predicates {
		byID[predicate.ID] = predicate.Source
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(class.MatchingPredicates))
	for _, id := range class.MatchingPredicates {
		source := byID[id]
		if source == "" || seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

func writePrefixClassTable(out io.Writer, rows []prefixClassInspectRow, showPreds bool) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showPreds {
		fmt.Fprintln(tw, "CLASS\tSPACE\tMATCHED-PREDICATES")
	} else {
		fmt.Fprintln(tw, "CLASS\tSPACE")
	}
	for _, row := range rows {
		fmt.Fprintf(tw, "pc-%d\t%s",
			row.ClassID,
			row.Space,
		)
		if showPreds {
			fmt.Fprintf(tw, "\t%s", strings.Join(row.MatchedPredicates, ","))
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func writePacketClassTable(out io.Writer, rows []packetClassInspectRow, showPreds bool) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showPreds {
		fmt.Fprintln(tw, "CLASS\tPREFIX-CLASS\tSPACE\tPROTOCOL\tSRC-PORT\tDST-PORT\tINGRESS\tEGRESS\tMATCHED-PREDICATES")
	} else {
		fmt.Fprintln(tw, "CLASS\tPREFIX-CLASS\tSPACE\tPROTOCOL\tSRC-PORT\tDST-PORT\tINGRESS\tEGRESS")
	}
	for _, row := range rows {
		fmt.Fprintf(tw, "pkt-%d\tpc-%d\t%s\t%s\t%s\t%s\t%s\t%s",
			row.ClassID,
			row.PrefixClassID,
			row.Space,
			row.Protocol,
			row.SrcPort,
			row.DstPort,
			row.IngressInterface,
			row.EgressInterface,
		)
		if showPreds {
			fmt.Fprintf(tw, "\t%s", strings.Join(row.MatchedPredicates, ","))
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func writeRIBTable(out io.Writer, rows []ribInspectRow, showCond bool, protocol model.RouteSourceKind) error {
	if protocol != "" && protocol != model.RouteSourceBGP {
		return writeRouteSourceRIBTable(out, rows, showCond)
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showCond {
		fmt.Fprintln(tw, "NODE\tPREFIX\tSOURCE\tCLASS\tNEXT-HOP\tIFACE\tORIGIN\tFROM\tAS-PATH\tLOCAL-PREF\tMED\tORIGIN-CODE\tIBGP\tINVALID\tPATH\tCONDITION\tSELECTED")
	} else {
		fmt.Fprintln(tw, "NODE\tPREFIX\tSOURCE\tCLASS\tNEXT-HOP\tIFACE\tORIGIN\tFROM\tAS-PATH\tLOCAL-PREF\tMED\tORIGIN-CODE\tIBGP\tINVALID\tPATH")
	}
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			row.Node,
			row.Prefix,
			row.SourceKind,
			row.ConnectedClass,
			row.NextHopNode,
			row.RouteInterface,
			row.OriginNode,
			row.FromNode,
			formatASPath(row.ASPath),
			formatIntPtr(row.LocalPref),
			formatIntPtr(row.MED),
			formatStringPtr(row.OriginCode),
			formatBoolPtr(row.LearnedIBGP),
			formatBoolPtr(row.Invalid),
			strings.Join(row.PathNodes, "->"),
		)
		if showCond {
			fmt.Fprintf(tw, "\t%s\t%s", row.Condition, row.SelectedCondition)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func writeRouteSourceRIBTable(out io.Writer, rows []ribInspectRow, showCond bool) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showCond {
		fmt.Fprintln(tw, "NODE\tPREFIX\tSOURCE\tCLASS\tNEXT-HOP\tIFACE\tORIGIN\tFROM\tPATH\tCONDITION\tSELECTED")
	} else {
		fmt.Fprintln(tw, "NODE\tPREFIX\tSOURCE\tCLASS\tNEXT-HOP\tIFACE\tORIGIN\tFROM\tPATH")
	}
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			row.Node,
			row.Prefix,
			row.SourceKind,
			row.ConnectedClass,
			row.NextHopNode,
			row.RouteInterface,
			row.OriginNode,
			row.FromNode,
			strings.Join(row.PathNodes, "->"),
		)
		if showCond {
			fmt.Fprintf(tw, "\t%s\t%s", row.Condition, row.SelectedCondition)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func formatStringPtr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func formatIntPtr(v *int) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", *v)
}

func formatBoolPtr(v *bool) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%t", *v)
}

func writeFIBTable(out io.Writer, rows []fibInspectRow, showCond bool) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showCond {
		fmt.Fprintln(tw, "NODE\tPREFIX\tSOURCE\tCLASS\tNEXT-HOP\tIFACE\tRANK\tGROUP\tEQUIV\tCOST\tPATH\tLINKS\tCONDITION")
	} else {
		fmt.Fprintln(tw, "NODE\tPREFIX\tSOURCE\tCLASS\tNEXT-HOP\tIFACE\tRANK\tGROUP\tEQUIV\tCOST\tPATH\tLINKS")
	}
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%t\t%d\t%s\t%s",
			row.Node,
			row.Prefix,
			row.SourceKind,
			row.ConnectedClass,
			row.NextHop,
			row.Interface,
			row.Rank,
			row.GroupID,
			row.Equivalent,
			row.Cost,
			strings.Join(row.PathNodes, "->"),
			strings.Join(row.PathLinks, "->"),
		)
		if showCond {
			fmt.Fprintf(tw, "\t%s", row.Condition)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func writeSymbolicPacketTable(out io.Writer, result symbolicPacketInspect, showCond bool) error {
	fmt.Fprintf(out, "from: %s\n", result.From)
	fmt.Fprintf(out, "to: %s\n", result.To)
	fmt.Fprintf(out, "protocol: %s\n", result.Protocol)
	if showCond {
		fmt.Fprintf(out, "reachable: %s\n", result.Reachable)
		fmt.Fprintf(out, "unreachable: %s\n", result.Unreachable)
	}
	if result.Reason != "" {
		fmt.Fprintf(out, "reason: %s\n", result.Reason)
	}
	if len(result.UnreachableReasons) > 0 {
		fmt.Fprintln(out, "blocked/unreachable reasons:")
		rtw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		if showCond {
			fmt.Fprintln(rtw, "KIND\tNODE\tLINK\tINTERFACE\tPOLICY\tCONDITION\tPATH\tMESSAGE")
		} else {
			fmt.Fprintln(rtw, "KIND\tNODE\tLINK\tINTERFACE\tPOLICY\tPATH\tMESSAGE")
		}
		for _, reason := range result.UnreachableReasons {
			fmt.Fprintf(rtw, "%s\t%s\t%s\t%s\t%s",
				reason.Kind,
				reason.Node,
				reason.Link,
				reason.Interface,
				reason.PolicyName,
			)
			if showCond {
				fmt.Fprintf(rtw, "\t%s", reason.Condition)
			}
			fmt.Fprintf(rtw, "\t%s\t%s\n",
				strings.Join(reason.PathNodes, "->"),
				reason.Message,
			)
		}
		if err := rtw.Flush(); err != nil {
			return err
		}
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showCond {
		fmt.Fprintln(tw, "PATH\tCOST\tCONDITION\tHOPS")
	} else {
		fmt.Fprintln(tw, "PATH\tCOST\tHOPS")
	}
	for _, path := range result.Paths {
		var hops []string
		for _, state := range path.States {
			hop := state.Node
			if state.IngressInterface != "" {
				hop += "(" + state.IngressInterface + ")"
			}
			hops = append(hops, hop)
		}
		fmt.Fprintf(tw, "%s\t%d",
			strings.Join(path.PathNodes, "->"),
			path.Cost,
		)
		if showCond {
			fmt.Fprintf(tw, "\t%s", path.Condition)
		}
		fmt.Fprintf(tw, "\t%s\n", strings.Join(hops, "->"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(result.Blocked) == 0 {
		return nil
	}
	fmt.Fprintln(out, "blocked:")
	blockedTW := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if showCond {
		fmt.Fprintln(blockedTW, "PATH\tCOST\tCONDITION\tPOLICY\tNODE\tINTERFACE\tSTAGE\tSOURCE\tREASON")
	} else {
		fmt.Fprintln(blockedTW, "PATH\tCOST\tPOLICY\tNODE\tINTERFACE\tSTAGE\tSOURCE\tREASON")
	}
	for _, path := range result.Blocked {
		fmt.Fprintf(blockedTW, "%s\t%d",
			strings.Join(path.PathNodes, "->"),
			path.Cost,
		)
		if showCond {
			fmt.Fprintf(blockedTW, "\t%s", path.Condition)
		}
		fmt.Fprintf(blockedTW, "\t%s\t%s\t%s\t%s\t%s\t%s\n",
			path.Policy,
			path.Node,
			path.Interface,
			path.Stage,
			formatPolicySource(path.Source),
			path.Reason,
		)
	}
	return blockedTW.Flush()
}

func formatPolicySource(src model.PolicySource) string {
	var parts []string
	if src.Vendor != "" {
		parts = append(parts, src.Vendor)
	}
	if src.File != "" {
		file := src.File
		if src.Line > 0 {
			file = fmt.Sprintf("%s:%d", file, src.Line)
		}
		parts = append(parts, file)
	}
	if src.Raw != "" {
		parts = append(parts, src.Raw)
	}
	return strings.Join(parts, " ")
}

func writeSymbolicRouteTable(out io.Writer, results []symbolicRouteInspect, showCond bool, showPreds bool) error {
	for i, result := range results {
		if i > 0 {
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "from: %s\n", result.From)
		fmt.Fprintf(out, "prefix: %s\n", result.Prefix)
		fmt.Fprintf(out, "class: pc-%d\n", result.ClassID)
		fmt.Fprintf(out, "space: %s\n", result.Space)
		if showPreds && len(result.MatchedPredicates) > 0 {
			fmt.Fprintf(out, "matched predicates: %s\n", strings.Join(result.MatchedPredicates, ", "))
		}
		if showCond {
			fmt.Fprintf(out, "reachable: %s\n", result.Reachable)
			fmt.Fprintf(out, "unreachable: %s\n", result.Unreachable)
		}
		if result.Reason != "" {
			fmt.Fprintf(out, "reason: %s\n", result.Reason)
		}
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		if showCond {
			fmt.Fprintln(tw, "PATH\tCOST\tLINKS\tCONDITION")
		} else {
			fmt.Fprintln(tw, "PATH\tCOST\tLINKS")
		}
		for _, path := range result.Paths {
			fmt.Fprintf(tw, "%s\t%d\t%s",
				strings.Join(path.PathNodes, "->"),
				path.Cost,
				strings.Join(path.PathLinks, "->"),
			)
			if showCond {
				fmt.Fprintf(tw, "\t%s", path.Condition)
			}
			fmt.Fprintln(tw)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func condString(cond failure.Cond) string {
	if cond == nil {
		return ""
	}
	return cond.String()
}

func prefixSetString(set model.PrefixSet) string {
	if set == nil {
		return ""
	}
	return set.String()
}

func portSetInspectString(set model.PortSet) string {
	if set == nil {
		return "any"
	}
	return set.String()
}

func formatASPath(path []uint32) string {
	if len(path) == 0 {
		return ""
	}
	parts := make([]string, 0, len(path))
	for _, asn := range path {
		parts = append(parts, fmt.Sprint(asn))
	}
	return strings.Join(parts, " ")
}
