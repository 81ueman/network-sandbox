package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/fibcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/livecheck"
	"github.com/81ueman/network-sandbox/hoyan/internal/livesnapshot"
	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/sim"
	"github.com/81ueman/network-sandbox/hoyan/internal/verify"
	"github.com/spf13/cobra"
)

type ExitError struct {
	Code int
	Err  error
}

func (e ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func Execute(cmd *cobra.Command) int {
	cmd.SetArgs(normalizeLegacyLongFlags(os.Args[1:]))
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), err)
		var exitErr ExitError
		if asExitError(err, &exitErr) {
			return exitErr.Code
		}
		return 2
	}
	return 0
}

func normalizeLegacyLongFlags(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = arg
		if len(arg) < 3 || arg[0] != '-' || arg[1] == '-' {
			continue
		}
		if arg[1] < 'A' || (arg[1] > 'Z' && arg[1] < 'a') || arg[1] > 'z' {
			continue
		}
		out[i] = "-" + arg
	}
	return out
}

func asExitError(err error, target *ExitError) bool {
	return errors.As(err, target)
}

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "hoyan",
		Short:         "Hoyan WAN lab verification tools",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(
		NewVerifyCommand(),
		NewLiveCommand(),
		NewLiveCheckCommand(),
		NewRIBCompareCommand(),
		NewFIBCompareCommand(),
		NewRenderTopologyCommand(),
		NewLabsCommand(),
		NewModelCommand(),
	)
	return cmd
}

func NewLiveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "live",
		Short:         "Collect reusable live device state",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(NewLiveSnapshotCommand())
	return cmd
}

func NewLiveSnapshotCommand() *cobra.Command {
	var opts liveSnapshotOptions
	cmd := &cobra.Command{
		Use:           "snapshot",
		Short:         "Collect live RIB and FIB state into a snapshot JSON file",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := resolveLabInputs(cmd, opts.labPath, &opts.topologyPath, nil); err != nil {
				return err
			}
			if err := runLiveSnapshot(cmd.Context(), opts, cmd.OutOrStdout()); err != nil {
				return err
			}
			return nil
		},
	}
	addLabFlag(cmd, &opts.labPath)
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "live-state.json", "snapshot JSON output path, or - for stdout")
	cmd.Flags().StringVar(&opts.rawDir, "raw-dir", "", "optional directory for raw vendor command output")
	cmd.Flags().BoolVar(&opts.fibAllowUnsupported, "fib-allow-unsupported", true, "skip nodes without a live FIB collector")
	cmd.Flags().StringVar(&opts.fibUnresolvedPolicy, "fib-unresolved-policy", string(fibcompare.UnresolvedPolicyWarn), "handling for unresolved live BGP FIB routes: warn, fail, or ignore")
	return cmd
}

type liveSnapshotOptions struct {
	labPath             string
	topologyPath        string
	outputPath          string
	rawDir              string
	fibAllowUnsupported bool
	fibUnresolvedPolicy string
}

func runLiveSnapshot(ctx context.Context, opts liveSnapshotOptions, out io.Writer) error {
	if err := validateFIBUnresolvedPolicy(opts.fibUnresolvedPolicy); err != nil {
		return ExitError{Code: 2, Err: err}
	}
	snap, err := livesnapshot.Build(ctx, opts.topologyPath, opts.labPath, ribcompare.ExecRunner{}, opts.rawDir, fibcompare.Options{
		AllowUnsupported: opts.fibAllowUnsupported,
		UnresolvedPolicy: fibcompare.UnresolvedPolicy(opts.fibUnresolvedPolicy),
	})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if opts.outputPath == "" || opts.outputPath == "-" {
		data, err := livesnapshot.Marshal(snap)
		if err != nil {
			return ExitError{Code: 2, Err: err}
		}
		_, err = out.Write(data)
		return err
	}
	if err := livesnapshot.Save(opts.outputPath, snap); err != nil {
		return ExitError{Code: 2, Err: err}
	}
	fmt.Fprintf(out, "wrote live snapshot %s\n", opts.outputPath)
	if opts.rawDir != "" {
		fmt.Fprintf(out, "wrote raw command output under %s\n", opts.rawDir)
	}
	return nil
}

func NewVerifyCommand() *cobra.Command {
	var opts verifyOptions
	cmd := &cobra.Command{
		Use:           "verify",
		Short:         "Run offline route, packet, and failure reachability checks",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := resolveLabInputs(cmd, opts.labPath, &opts.topologyPath, &opts.queriesPath); err != nil {
				return err
			}
			if err := runVerify(cmd.Context(), opts, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return err
			}
			return nil
		},
	}
	addLabFlag(cmd, &opts.labPath)
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	addQueriesFlag(cmd, &opts.queriesPath, "query YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.prefixClasses, "prefix-classes", false, "expand verification by PrefixUniverse prefix classes")
	cmd.Flags().IntVar(&opts.maxPrefixClasses, "max-prefix-classes", 10000, "maximum PrefixUniverse classes before failing; 0 disables the guard")
	cmd.Flags().BoolVar(&opts.showPrefixUniverseStats, "show-prefix-universe-stats", false, "show PrefixUniverse build statistics with --prefix-classes")
	cmd.Flags().BoolVar(&opts.noCollapse, "no-collapse", false, "show raw prefix-class results instead of collapsed equivalent groups")
	cmd.Flags().StringVar(&opts.format, "format", "table", "output format: table or json")
	return cmd
}

type verifyOptions struct {
	labPath                 string
	topologyPath            string
	queriesPath             string
	strictConfig            bool
	prefixClasses           bool
	maxPrefixClasses        int
	showPrefixUniverseStats bool
	noCollapse              bool
	format                  string
}

func runVerify(_ context.Context, opts verifyOptions, out, errOut io.Writer) error {
	topo, warnings, err := model.LoadLabTopologyWithOptions(opts.topologyPath, model.LoadLabTopologyOptions{
		CollectWarnings: true,
		StrictConfig:    opts.strictConfig,
	})
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Fprintf(errOut, "warning: %s\n", warning)
	}
	queries, err := model.LoadQueries(opts.queriesPath)
	if err != nil {
		return err
	}
	verifyOpts := verify.VerifyOptions{
		UsePrefixUniverse:         opts.prefixClasses,
		CollapseEquivalentResults: opts.prefixClasses && !opts.noCollapse,
		MaxPrefixClasses:          opts.maxPrefixClasses,
	}
	report := verify.RunWithOptions(topo, queries, verifyOpts)
	if opts.format == "json" {
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		jsonReport := report
		if !opts.showPrefixUniverseStats {
			jsonReport.Stats = nil
		}
		if err := enc.Encode(jsonReport); err != nil {
			return err
		}
		if !report.OK() {
			return ExitError{Code: 1, Err: fmt.Errorf("verification failed")}
		}
		return nil
	}
	if opts.format != "" && opts.format != "table" {
		return fmt.Errorf("unsupported --format %q", opts.format)
	}
	if opts.showPrefixUniverseStats && opts.prefixClasses && report.Stats != nil {
		writePrefixUniverseStats(out, *report.Stats)
	}
	for _, result := range report.Results {
		status := "PASS"
		if result.Metadata.Reachable != result.Metadata.Expected {
			status = "FAIL"
		}
		fmt.Fprintf(out, "[%s] %s reachable=%v expected=%v\n", status, result.Name, result.Metadata.Reachable, result.Metadata.Expected)
		if result.PrefixClass != nil && len(result.PrefixClass.ClassIDs) > 0 {
			fmt.Fprintf(out, "  classes: %s\n", formatClassIDs(result.PrefixClass.ClassIDs))
		}
		if result.PrefixClass != nil && len(result.PrefixClass.Spaces) > 0 {
			fmt.Fprintf(out, "  spaces: %s\n", strings.Join(result.PrefixClass.Spaces, ", "))
		} else if result.PrefixClass != nil && result.PrefixClass.Space != "" {
			fmt.Fprintf(out, "  space: %s\n", result.PrefixClass.Space)
		}
		if result.PrefixClass != nil && len(result.PrefixClass.MatchedPredicates) > 0 {
			fmt.Fprintf(out, "  matched predicates: %s\n", strings.Join(result.PrefixClass.MatchedPredicates, ", "))
		}
		if path := result.Path(); len(path.Nodes) > 0 {
			fmt.Fprintf(out, "  path: %s\n", sim.FormatPath(path))
		}
		if counterexample := result.Counterexample(); len(counterexample) > 0 {
			fmt.Fprintf(out, "  counterexample: %s\n", strings.Join(counterexample, ", "))
		}
		if result.Metadata.Reason != "" {
			fmt.Fprintf(out, "  reason: %s\n", result.Metadata.Reason)
		}
	}
	if !report.OK() {
		return ExitError{Code: 1, Err: fmt.Errorf("verification failed")}
	}
	return nil
}

func writePrefixUniverseStats(out io.Writer, stats model.PrefixUniverseStats) {
	fmt.Fprintf(out, "predicates=%d unique=%d classes=%d build=%s max_class_cidrs=%d\n",
		stats.PredicateCount,
		stats.UniquePredicateCount,
		stats.ClassCount,
		stats.BuildDuration,
		stats.MaxClassCIDRs,
	)
	if len(stats.PredicateSources) == 0 {
		return
	}
	fmt.Fprintln(out, "sources:")
	categories := make([]string, 0, len(stats.PredicateSources))
	for category := range stats.PredicateSources {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		fmt.Fprintf(out, "  %s: %d\n", category, stats.PredicateSources[category])
	}
}

func formatClassIDs(ids []model.PrefixClassID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("pc-%d", id))
	}
	return strings.Join(parts, ", ")
}

func NewLiveCheckCommand() *cobra.Command {
	var opts liveCheckOptions
	cmd := &cobra.Command{
		Use:           "live-check",
		Short:         "Deploy the lab and compare live device state with the model",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := opts.validate(); err != nil {
				return err
			}
			if err := resolveLabInputs(cmd, opts.labPath, &opts.topologyPath, &opts.queriesPath); err != nil {
				return err
			}
			err := livecheck.Run(cmd.Context(), livecheck.Options{
				Topology:      opts.topologyPath,
				Queries:       opts.queriesPath,
				Snapshot:      opts.snapshotPath,
				HashPolicy:    livecheck.HashPolicy(opts.snapshotHashPolicy),
				Offline:       opts.offline,
				StrictConfig:  opts.strictConfig,
				Timeout:       opts.timeout,
				PollInterval:  opts.pollInterval,
				MaxPolls:      opts.maxPolls,
				KeepOnFailure: opts.keepOnFailure,
				SkipDestroy:   opts.skipDestroy,
				CheckFIB:      opts.checkFIB && !opts.noCheckFIB,
				FIBOptions:    fibcompare.Options{AllowUnsupported: opts.fibAllowUnsupported, UnresolvedPolicy: fibcompare.UnresolvedPolicy(opts.fibUnresolvedPolicy)},
				Out:           cmd.OutOrStdout(),
			}, ribcompare.ExecRunner{})
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return nil
		},
	}
	addLabFlag(cmd, &opts.labPath)
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	addQueriesFlag(cmd, &opts.queriesPath, "query YAML for live dataplane checks")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 5*time.Minute, "overall wait timeout")
	cmd.Flags().DurationVar(&opts.pollInterval, "poll-interval", 25*time.Second, "poll interval")
	cmd.Flags().IntVar(&opts.maxPolls, "max-polls", livecheck.DefaultMaxPolls, "maximum BGP collection polls before reporting diffs")
	cmd.Flags().BoolVar(&opts.keepOnFailure, "keep-on-failure", false, "leave lab running when the check fails")
	cmd.Flags().BoolVar(&opts.skipDestroy, "skip-destroy", false, "leave lab running after the check")
	cmd.Flags().StringVar(&opts.snapshotPath, "snapshot", "", "live snapshot JSON to use instead of collecting RIB/FIB from devices")
	cmd.Flags().StringVar(&opts.snapshotHashPolicy, "snapshot-hash-policy", string(livesnapshot.HashPolicyWarn), "handling for snapshot topology/config hash mismatch: warn, fail, or ignore")
	cmd.Flags().BoolVar(&opts.offline, "offline", false, "with --snapshot, skip deploy and live dataplane probes")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.checkFIB, "check-fib", true, "compare modeled FIB with live installed FIB after BGP convergence")
	cmd.Flags().BoolVar(&opts.noCheckFIB, "no-check-fib", false, "skip modeled-vs-live installed FIB comparison")
	cmd.Flags().BoolVar(&opts.fibAllowUnsupported, "fib-allow-unsupported", false, "skip nodes without a live FIB collector when FIB comparison is enabled")
	cmd.Flags().StringVar(&opts.fibUnresolvedPolicy, "fib-unresolved-policy", string(fibcompare.UnresolvedPolicyWarn), "handling for unresolved live BGP FIB routes: warn, fail, or ignore")
	return cmd
}

type liveCheckOptions struct {
	labPath             string
	topologyPath        string
	queriesPath         string
	strictConfig        bool
	timeout             time.Duration
	pollInterval        time.Duration
	maxPolls            int
	keepOnFailure       bool
	skipDestroy         bool
	snapshotPath        string
	snapshotHashPolicy  string
	offline             bool
	checkFIB            bool
	noCheckFIB          bool
	fibAllowUnsupported bool
	fibUnresolvedPolicy string
}

func (o liveCheckOptions) validate() error {
	if o.timeout <= 0 {
		return fmt.Errorf("--timeout must be greater than zero")
	}
	if o.pollInterval <= 0 {
		return fmt.Errorf("--poll-interval must be greater than zero")
	}
	if o.maxPolls <= 0 {
		return fmt.Errorf("--max-polls must be greater than zero")
	}
	if err := validateFIBUnresolvedPolicy(o.fibUnresolvedPolicy); err != nil {
		return err
	}
	if _, ok := livesnapshot.ParseHashPolicy(o.snapshotHashPolicy); !ok {
		return fmt.Errorf("snapshot hash policy must be one of warn, fail, or ignore")
	}
	if o.offline && o.snapshotPath == "" {
		return fmt.Errorf("--offline requires --snapshot")
	}
	return nil
}

func NewRIBCompareCommand() *cobra.Command {
	var opts ribCompareOptions
	cmd := &cobra.Command{
		Use:           "rib-compare",
		Short:         "Compare modeled RIBs with live device RIBs",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := resolveLabInputs(cmd, opts.labPath, &opts.topologyPath, nil); err != nil {
				return err
			}
			if err := runRIBCompare(cmd.Context(), opts, cmd.OutOrStdout()); err != nil {
				return err
			}
			return nil
		},
	}
	addLabFlag(cmd, &opts.labPath)
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().StringVar(&opts.snapshotPath, "snapshot", "", "live snapshot JSON to use instead of collecting from devices")
	cmd.Flags().StringVar(&opts.snapshotHashPolicy, "snapshot-hash-policy", string(livesnapshot.HashPolicyWarn), "handling for snapshot topology/config hash mismatch: warn, fail, or ignore")
	return cmd
}

type ribCompareOptions struct {
	labPath            string
	topologyPath       string
	strictConfig       bool
	snapshotPath       string
	snapshotHashPolicy string
}

func runRIBCompare(ctx context.Context, opts ribCompareOptions, out io.Writer) error {
	if _, ok := livesnapshot.ParseHashPolicy(opts.snapshotHashPolicy); !ok {
		return ExitError{Code: 2, Err: fmt.Errorf("snapshot hash policy must be one of warn, fail, or ignore")}
	}
	topo, _, err := model.LoadLabTopologyWithOptions(opts.topologyPath, model.LoadLabTopologyOptions{StrictConfig: opts.strictConfig})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	nodes := ribcompare.SupportedNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, nodes)
	fmt.Fprintf(out, "comparing RIB routes (sources: %s)\n", ribcompare.FormatSourceSummary(ribcompare.SourceSummary(expected)))
	var actual []ribcompare.NormalizedRoute
	if opts.snapshotPath != "" {
		snap, err := livesnapshot.Load(opts.snapshotPath)
		if err != nil {
			return ExitError{Code: 2, Err: err}
		}
		if err := checkSnapshotHashes(opts.topologyPath, snap, opts.snapshotHashPolicy, out); err != nil {
			return err
		}
		actual = livesnapshot.AllRIBRoutes(snap)
	} else {
		actual, err = ribcompare.Collect(ctx, ribcompare.ExecRunner{}, nodes)
		if err != nil {
			return ExitError{Code: 2, Err: err}
		}
	}
	result := ribcompare.CompareBgpRib(expected, actual, ribcompare.DefaultBgpRibCompareOptions())
	for _, line := range ribcompare.FormatDiffs(result) {
		fmt.Fprintln(out, line)
	}
	if !result.OK {
		return ExitError{Code: 1, Err: fmt.Errorf("RIB comparison found diff(s)")}
	}
	fmt.Fprintln(out, "RIBs match expected modeled paths")
	return nil
}

func NewFIBCompareCommand() *cobra.Command {
	var opts fibCompareOptions
	cmd := &cobra.Command{
		Use:           "fib-compare",
		Short:         "Compare modeled FIBs with live installed kernel FIBs",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := resolveLabInputs(cmd, opts.labPath, &opts.topologyPath, nil); err != nil {
				return err
			}
			return runFIBCompare(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addLabFlag(cmd, &opts.labPath)
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.allowUnsupported, "allow-unsupported", false, "skip nodes without a live FIB collector")
	cmd.Flags().StringVar(&opts.unresolvedPolicy, "unresolved-policy", string(fibcompare.UnresolvedPolicyWarn), "handling for unresolved live BGP FIB routes: warn, fail, or ignore")
	cmd.Flags().StringVar(&opts.snapshotPath, "snapshot", "", "live snapshot JSON to use instead of collecting from devices")
	cmd.Flags().StringVar(&opts.snapshotHashPolicy, "snapshot-hash-policy", string(livesnapshot.HashPolicyWarn), "handling for snapshot topology/config hash mismatch: warn, fail, or ignore")
	return cmd
}

type fibCompareOptions struct {
	labPath            string
	topologyPath       string
	strictConfig       bool
	allowUnsupported   bool
	unresolvedPolicy   string
	snapshotPath       string
	snapshotHashPolicy string
}

func runFIBCompare(ctx context.Context, opts fibCompareOptions, out io.Writer) error {
	if err := validateFIBUnresolvedPolicy(opts.unresolvedPolicy); err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if _, ok := livesnapshot.ParseHashPolicy(opts.snapshotHashPolicy); !ok {
		return ExitError{Code: 2, Err: fmt.Errorf("snapshot hash policy must be one of warn, fail, or ignore")}
	}
	topo, _, err := model.LoadLabTopologyWithOptions(opts.topologyPath, model.LoadLabTopologyOptions{StrictConfig: opts.strictConfig})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	nodes := topo.Nodes
	if opts.allowUnsupported {
		nodes = fibcompare.SupportedNodes(nodes)
	}
	fibOpts := fibcompare.Options{AllowUnsupported: opts.allowUnsupported, UnresolvedPolicy: fibcompare.UnresolvedPolicy(opts.unresolvedPolicy)}
	expected := fibcompare.AnalyzeComparableRoutes(topo, fibcompare.ExpectedForNodes(topo, nodes), fibOpts)
	var actualFiltered fibcompare.FilterResult
	if opts.snapshotPath != "" {
		snap, err := livesnapshot.Load(opts.snapshotPath)
		if err != nil {
			return ExitError{Code: 2, Err: err}
		}
		if err := checkSnapshotHashes(opts.topologyPath, snap, opts.snapshotHashPolicy, out); err != nil {
			return err
		}
		actualFiltered = fibcompare.AnalyzeComparableRoutes(topo, livesnapshot.FIBRoutes(snap), fibOpts)
	} else {
		actual, err := fibcompare.Collect(ctx, ribcompare.ExecRunner{}, nodes, fibOpts)
		if err != nil {
			return ExitError{Code: 2, Err: err}
		}
		actualFiltered = fibcompare.AnalyzeComparableRoutes(topo, actual, fibOpts)
	}
	for _, line := range fibcompare.FormatWarnings(fibcompare.WarningDiagnostics(actualFiltered, fibOpts)) {
		fmt.Fprintln(out, line)
	}
	result := fibcompare.CompareFilterResults(expected, actualFiltered, fibOpts)
	for _, line := range fibcompare.FormatDiffs(result) {
		fmt.Fprintln(out, line)
	}
	if !result.OK {
		return ExitError{Code: 1, Err: fmt.Errorf("FIB comparison found diff(s)")}
	}
	fmt.Fprintln(out, "FIBs match expected modeled forwarding entries")
	return nil
}

func checkSnapshotHashes(topologyPath string, snap *livesnapshot.Snapshot, policyRaw string, out io.Writer) error {
	policy, ok := livesnapshot.ParseHashPolicy(policyRaw)
	if !ok {
		return ExitError{Code: 2, Err: fmt.Errorf("snapshot hash policy must be one of warn, fail, or ignore")}
	}
	if policy == livesnapshot.HashPolicyIgnore {
		return nil
	}
	result, err := livesnapshot.CheckHashes(topologyPath, snap)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	if len(result.Mismatches) == 0 && len(result.Missing) == 0 {
		return nil
	}
	var lines []string
	for _, mismatch := range result.Mismatches {
		lines = append(lines, fmt.Sprintf("snapshot hash mismatch: %s snapshot=%s current=%s", mismatch.Path, mismatch.Want, mismatch.Got))
	}
	for _, missing := range result.Missing {
		lines = append(lines, fmt.Sprintf("snapshot hash missing current input: %s", missing))
	}
	if policy == livesnapshot.HashPolicyFail {
		return ExitError{Code: 2, Err: errors.New(strings.Join(lines, "; "))}
	}
	for _, line := range lines {
		fmt.Fprintf(out, "warning: %s\n", line)
	}
	return nil
}

func validateFIBUnresolvedPolicy(policy string) error {
	if _, ok := fibcompare.ParseUnresolvedPolicy(policy); ok {
		return nil
	}
	return fmt.Errorf("FIB unresolved policy must be one of warn, fail, or ignore")
}

func NewRenderTopologyCommand() *cobra.Command {
	var opts renderTopologyOptions
	cmd := &cobra.Command{
		Use:           "render-topology",
		Short:         "Render an isolated containerlab topology",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := runRenderTopology(opts, cmd.OutOrStdout()); err != nil {
				return ExitError{Code: 2, Err: err}
			}
			return nil
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "source containerlab topology YAML")
	cmd.Flags().StringVar(&opts.outputPath, "output", "-", "generated topology path, or - for stdout")
	cmd.Flags().StringVar(&opts.suffix, "suffix", "", "isolation suffix appended to the lab name")
	cmd.Flags().StringVar(&opts.labName, "lab-name", "", "generated lab name")
	cmd.Flags().StringVar(&opts.mgmtNetwork, "mgmt-network", "", "generated Docker management network name")
	cmd.Flags().StringVar(&opts.mgmtSubnet, "mgmt-subnet", "", "generated Docker management IPv4 /24 subnet")
	return cmd
}

type renderTopologyOptions struct {
	topologyPath string
	outputPath   string
	suffix       string
	labName      string
	mgmtNetwork  string
	mgmtSubnet   string
}

func runRenderTopology(opts renderTopologyOptions, out io.Writer) error {
	data, err := os.ReadFile(opts.topologyPath)
	if err != nil {
		return err
	}
	sourceDir, err := filepath.Abs(filepath.Dir(opts.topologyPath))
	if err != nil {
		return err
	}
	renderOpts := model.TopologyRenderOptions{
		Suffix:      opts.suffix,
		LabName:     opts.labName,
		MgmtNetwork: opts.mgmtNetwork,
		MgmtSubnet:  opts.mgmtSubnet,
	}
	if shouldRewriteConfigPaths(sourceDir, opts.outputPath) {
		renderOpts.SourceDir = sourceDir
	}
	rendered, err := model.RenderIsolatedTopology(data, renderOpts)
	if err != nil {
		return err
	}
	if opts.outputPath == "" || opts.outputPath == "-" {
		_, err := out.Write(rendered)
		return err
	}
	return os.WriteFile(opts.outputPath, rendered, 0o644)
}

func shouldRewriteConfigPaths(sourceDir, outputPath string) bool {
	if outputPath == "" || outputPath == "-" {
		return false
	}
	outputDir, err := filepath.Abs(filepath.Dir(outputPath))
	if err != nil {
		return true
	}
	return outputDir != sourceDir
}
