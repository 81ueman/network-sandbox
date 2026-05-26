package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/fibcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/livecheck"
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
		NewLiveCheckCommand(),
		NewRIBCompareCommand(),
		NewFIBCompareCommand(),
		NewRenderTopologyCommand(),
		NewModelCommand(),
	)
	return cmd
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
			if err := runVerify(cmd.Context(), opts, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return err
			}
			return nil
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	addQueriesFlag(cmd, &opts.queriesPath, "query YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.prefixClasses, "prefix-classes", false, "expand verification by PrefixUniverse prefix classes")
	cmd.Flags().BoolVar(&opts.noCollapse, "no-collapse", false, "show raw prefix-class results instead of collapsed equivalent groups")
	cmd.Flags().StringVar(&opts.format, "format", "table", "output format: table or json")
	return cmd
}

type verifyOptions struct {
	topologyPath  string
	queriesPath   string
	strictConfig  bool
	prefixClasses bool
	noCollapse    bool
	format        string
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
	}
	report := verify.RunWithOptions(topo, queries, verifyOpts)
	if opts.format == "json" {
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report.Results); err != nil {
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
	for _, result := range report.Results {
		status := "PASS"
		if result.Reachable != result.Expected {
			status = "FAIL"
		}
		fmt.Fprintf(out, "[%s] %s reachable=%v expected=%v\n", status, result.Name, result.Reachable, result.Expected)
		if len(result.PrefixClassIDs) > 0 {
			fmt.Fprintf(out, "  classes: %s\n", formatClassIDs(result.PrefixClassIDs))
		}
		if len(result.PrefixSpaces) > 0 {
			fmt.Fprintf(out, "  spaces: %s\n", strings.Join(result.PrefixSpaces, ", "))
		} else if result.PrefixSpace != "" {
			fmt.Fprintf(out, "  space: %s\n", result.PrefixSpace)
		}
		if len(result.MatchedPredicates) > 0 {
			fmt.Fprintf(out, "  matched predicates: %s\n", strings.Join(result.MatchedPredicates, ", "))
		}
		if len(result.Path.Nodes) > 0 {
			fmt.Fprintf(out, "  path: %s\n", sim.FormatPath(result.Path))
		}
		if len(result.Counterexample) > 0 {
			fmt.Fprintf(out, "  counterexample: %s\n", strings.Join(result.Counterexample, ", "))
		}
		if result.Reason != "" {
			fmt.Fprintf(out, "  reason: %s\n", result.Reason)
		}
	}
	if !report.OK() {
		return ExitError{Code: 1, Err: fmt.Errorf("verification failed")}
	}
	return nil
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
			err := livecheck.Run(cmd.Context(), livecheck.Options{
				Topology:      opts.topologyPath,
				Queries:       opts.queriesPath,
				StrictConfig:  opts.strictConfig,
				Timeout:       opts.timeout,
				PollInterval:  opts.pollInterval,
				MaxPolls:      opts.maxPolls,
				KeepOnFailure: opts.keepOnFailure,
				SkipDestroy:   opts.skipDestroy,
				CheckFIB:      opts.checkFIB && !opts.noCheckFIB,
				FIBOptions:    fibcompare.Options{AllowUnsupported: opts.fibAllowUnsupported},
				Out:           cmd.OutOrStdout(),
			}, ribcompare.ExecRunner{})
			if err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return nil
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	addQueriesFlag(cmd, &opts.queriesPath, "query YAML for live dataplane checks")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 5*time.Minute, "overall wait timeout")
	cmd.Flags().DurationVar(&opts.pollInterval, "poll-interval", 25*time.Second, "poll interval")
	cmd.Flags().IntVar(&opts.maxPolls, "max-polls", livecheck.DefaultMaxPolls, "maximum BGP collection polls before reporting diffs")
	cmd.Flags().BoolVar(&opts.keepOnFailure, "keep-on-failure", false, "leave lab running when the check fails")
	cmd.Flags().BoolVar(&opts.skipDestroy, "skip-destroy", false, "leave lab running after the check")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.checkFIB, "check-fib", true, "compare modeled FIB with live installed FIB after BGP convergence")
	cmd.Flags().BoolVar(&opts.noCheckFIB, "no-check-fib", false, "skip modeled-vs-live installed FIB comparison")
	cmd.Flags().BoolVar(&opts.fibAllowUnsupported, "fib-allow-unsupported", false, "skip nodes without a live FIB collector when FIB comparison is enabled")
	return cmd
}

type liveCheckOptions struct {
	topologyPath        string
	queriesPath         string
	strictConfig        bool
	timeout             time.Duration
	pollInterval        time.Duration
	maxPolls            int
	keepOnFailure       bool
	skipDestroy         bool
	checkFIB            bool
	noCheckFIB          bool
	fibAllowUnsupported bool
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
	return nil
}

func NewRIBCompareCommand() *cobra.Command {
	var opts ribCompareOptions
	cmd := &cobra.Command{
		Use:           "rib-compare",
		Short:         "Compare modeled BGP RIBs with live device RIBs",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			if err := runRIBCompare(cmd.Context(), opts, cmd.OutOrStdout()); err != nil {
				return err
			}
			return nil
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	return cmd
}

type ribCompareOptions struct {
	topologyPath string
	strictConfig bool
}

func runRIBCompare(ctx context.Context, opts ribCompareOptions, out io.Writer) error {
	topo, _, err := model.LoadLabTopologyWithOptions(opts.topologyPath, model.LoadLabTopologyOptions{StrictConfig: opts.strictConfig})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	nodes := ribcompare.SupportedNodes(topo.Nodes)
	expected := ribcompare.ExpectedForNodes(topo, nodes)
	actual, err := ribcompare.Collect(ctx, ribcompare.ExecRunner{}, nodes)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	result := ribcompare.CompareBgpRib(expected, actual, ribcompare.DefaultBgpRibCompareOptions())
	for _, line := range ribcompare.FormatDiffs(result) {
		fmt.Fprintln(out, line)
	}
	if !result.OK {
		return ExitError{Code: 1, Err: fmt.Errorf("BGP RIB comparison found diff(s)")}
	}
	fmt.Fprintln(out, "BGP RIBs match expected modeled paths")
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
			return runFIBCompare(cmd.Context(), opts, cmd.OutOrStdout())
		},
	}
	addTopologyFlag(cmd, &opts.topologyPath, "containerlab topology YAML")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.allowUnsupported, "allow-unsupported", false, "skip nodes without a live FIB collector")
	return cmd
}

type fibCompareOptions struct {
	topologyPath     string
	strictConfig     bool
	allowUnsupported bool
}

func runFIBCompare(ctx context.Context, opts fibCompareOptions, out io.Writer) error {
	topo, _, err := model.LoadLabTopologyWithOptions(opts.topologyPath, model.LoadLabTopologyOptions{StrictConfig: opts.strictConfig})
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	nodes := topo.Nodes
	if opts.allowUnsupported {
		nodes = fibcompare.SupportedNodes(nodes)
	}
	fibOpts := fibcompare.Options{AllowUnsupported: opts.allowUnsupported}
	expected := fibcompare.ComparableRoutes(topo, fibcompare.ExpectedForNodes(topo, nodes), fibOpts)
	actual, err := fibcompare.Collect(ctx, ribcompare.ExecRunner{}, nodes, fibOpts)
	if err != nil {
		return ExitError{Code: 2, Err: err}
	}
	actual = fibcompare.ComparableRoutes(topo, actual, fibOpts)
	result := fibcompare.Compare(expected, actual)
	for _, line := range fibcompare.FormatDiffs(result) {
		fmt.Fprintln(out, line)
	}
	if !result.OK {
		return ExitError{Code: 1, Err: fmt.Errorf("FIB comparison found diff(s)")}
	}
	fmt.Fprintln(out, "FIBs match expected modeled forwarding entries")
	return nil
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

func addTopologyFlag(cmd *cobra.Command, value *string, usage string) {
	cmd.Flags().StringVar(value, "topology", "hoyan.clab.yml", usage)
}

func addQueriesFlag(cmd *cobra.Command, value *string, usage string) {
	cmd.Flags().StringVar(value, "queries", "intent/queries.yml", usage)
}
