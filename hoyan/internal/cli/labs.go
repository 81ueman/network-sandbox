package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/81ueman/network-sandbox/hoyan/internal/fibcompare"
	"github.com/81ueman/network-sandbox/hoyan/internal/livecheck"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	labTopologyFile     = "hoyan.clab.yml"
	labQueriesPath      = "intent/queries.yml"
	defaultLabsDir      = "labs"
	defaultLabDir       = "labs/base-wan"
	defaultTopologyPath = defaultLabDir + "/" + labTopologyFile
	defaultQueriesPath  = defaultLabDir + "/" + labQueriesPath
)

type labDescriptor struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description,omitempty"`
	NOS         []string `yaml:"nos" json:"nos,omitempty"`
	Checks      []string `yaml:"checks" json:"checks,omitempty"`
	Features    []string `yaml:"features" json:"features,omitempty"`
	Path        string   `yaml:"-" json:"path"`
}

func NewLabsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "labs",
		Short:         "List and describe scenario labs",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(NewLabsListCommand(), NewLabsDescribeCommand(), NewLabsLiveCheckCommand())
	return cmd
}

func NewLabsListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "list",
		Short:         "List scenario labs",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
			}
			return runLabsList(cmd.OutOrStdout())
		},
	}
	return cmd
}

func NewLabsDescribeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "describe <name-or-path>",
		Short:         "Describe a scenario lab",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLabsDescribe(args[0], cmd.OutOrStdout())
		},
	}
	return cmd
}

func NewLabsLiveCheckCommand() *cobra.Command {
	var opts labsLiveCheckOptions
	cmd := &cobra.Command{
		Use:           "live-check [name-or-path...]",
		Short:         "Run live-check serially for scenario labs",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.validate(); err != nil {
				return err
			}
			if err := runLabsLiveCheck(cmd.Context(), args, opts, cmd.OutOrStdout(), ribcompare.ExecRunner{}); err != nil {
				return ExitError{Code: 1, Err: err}
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 5*time.Minute, "overall wait timeout per lab")
	cmd.Flags().DurationVar(&opts.pollInterval, "poll-interval", 25*time.Second, "poll interval")
	cmd.Flags().IntVar(&opts.maxPolls, "max-polls", livecheck.DefaultMaxPolls, "maximum BGP collection polls per lab before reporting diffs")
	cmd.Flags().BoolVar(&opts.keepOnFailure, "keep-on-failure", false, "leave a lab running when that lab check fails")
	cmd.Flags().BoolVar(&opts.skipDestroy, "skip-destroy", false, "leave each lab running after its check")
	cmd.Flags().BoolVar(&opts.strictConfig, "strict-config", false, "fail on unsupported config parser statements")
	cmd.Flags().BoolVar(&opts.checkFIB, "check-fib", true, "compare modeled FIB with live installed FIB after BGP convergence")
	cmd.Flags().BoolVar(&opts.noCheckFIB, "no-check-fib", false, "skip modeled-vs-live installed FIB comparison")
	cmd.Flags().BoolVar(&opts.fibAllowUnsupported, "fib-allow-unsupported", false, "skip nodes without a live FIB collector when FIB comparison is enabled")
	cmd.Flags().StringVar(&opts.fibUnresolvedPolicy, "fib-unresolved-policy", string(fibcompare.UnresolvedPolicyWarn), "handling for unresolved live BGP FIB routes: warn, fail, or ignore")
	cmd.Flags().BoolVar(&opts.continueOnError, "continue-on-error", false, "continue running later labs after a lab fails")
	return cmd
}

type labsLiveCheckOptions struct {
	strictConfig        bool
	timeout             time.Duration
	pollInterval        time.Duration
	maxPolls            int
	keepOnFailure       bool
	skipDestroy         bool
	checkFIB            bool
	noCheckFIB          bool
	fibAllowUnsupported bool
	fibUnresolvedPolicy string
	continueOnError     bool
}

func (o labsLiveCheckOptions) validate() error {
	return liveCheckOptions{
		timeout:             o.timeout,
		pollInterval:        o.pollInterval,
		maxPolls:            o.maxPolls,
		fibUnresolvedPolicy: o.fibUnresolvedPolicy,
	}.validate()
}

func runLabsLiveCheck(ctx context.Context, args []string, opts labsLiveCheckOptions, out io.Writer, runner ribcompare.Runner) error {
	labs, err := selectedLabDescriptors(args)
	if err != nil {
		return err
	}
	if len(labs) == 0 {
		return fmt.Errorf("no labs found")
	}
	var failures []string
	for _, lab := range labs {
		topologyPath := filepath.Join(lab.Path, labTopologyFile)
		queriesPath := filepath.Join(lab.Path, labQueriesPath)
		fmt.Fprintf(out, "==> live-check %s (%s)\n", lab.Name, lab.Path)
		err := livecheck.Run(ctx, livecheck.Options{
			Topology:      topologyPath,
			Queries:       queriesPath,
			StrictConfig:  opts.strictConfig,
			Timeout:       opts.timeout,
			PollInterval:  opts.pollInterval,
			MaxPolls:      opts.maxPolls,
			KeepOnFailure: opts.keepOnFailure,
			SkipDestroy:   opts.skipDestroy,
			CheckFIB:      opts.checkFIB && !opts.noCheckFIB,
			FIBOptions:    fibcompare.Options{AllowUnsupported: opts.fibAllowUnsupported, UnresolvedPolicy: fibcompare.UnresolvedPolicy(opts.fibUnresolvedPolicy)},
			Out:           out,
		}, runner)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", lab.Name, err))
			fmt.Fprintf(out, "[FAIL] %s: %v\n", lab.Name, err)
			if !opts.continueOnError {
				return fmt.Errorf("live-check failed for %s: %w", lab.Name, err)
			}
			continue
		}
		fmt.Fprintf(out, "[PASS] %s\n", lab.Name)
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d lab live-check(s) failed: %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

func selectedLabDescriptors(args []string) ([]labDescriptor, error) {
	if len(args) == 0 {
		return loadLabDescriptors(defaultLabsDir)
	}
	labs := make([]labDescriptor, 0, len(args))
	for _, arg := range args {
		labDir, err := resolveLabDir(arg)
		if err != nil {
			return nil, err
		}
		desc, err := loadLabDescriptor(labDir)
		if err != nil {
			return nil, err
		}
		labs = append(labs, desc)
	}
	return labs, nil
}

func runLabsList(out io.Writer) error {
	labs, err := loadLabDescriptors(defaultLabsDir)
	if err != nil {
		return err
	}
	if len(labs) == 0 {
		fmt.Fprintln(out, "no labs found")
		return nil
	}
	for _, lab := range labs {
		fmt.Fprintf(out, "%s\t%s\t%s\n", lab.Name, lab.Path, lab.Description)
	}
	return nil
}

func runLabsDescribe(raw string, out io.Writer) error {
	labDir, err := resolveLabDir(raw)
	if err != nil {
		return err
	}
	desc, err := loadLabDescriptor(labDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "name: %s\n", desc.Name)
	fmt.Fprintf(out, "path: %s\n", desc.Path)
	if desc.Description != "" {
		fmt.Fprintf(out, "description: %s\n", desc.Description)
	}
	writeStringList(out, "nos", desc.NOS)
	writeStringList(out, "checks", desc.Checks)
	writeStringList(out, "features", desc.Features)
	fmt.Fprintf(out, "topology: %s\n", filepath.Join(desc.Path, labTopologyFile))
	if _, err := os.Stat(filepath.Join(desc.Path, labQueriesPath)); err == nil {
		fmt.Fprintf(out, "queries: %s\n", filepath.Join(desc.Path, labQueriesPath))
	}
	return nil
}

func writeStringList(out io.Writer, name string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(out, "%s: %s\n", name, strings.Join(values, ", "))
}

func loadLabDescriptors(root string) ([]labDescriptor, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	labs := make([]labDescriptor, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		desc, err := loadLabDescriptor(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		labs = append(labs, desc)
	}
	sort.Slice(labs, func(i, j int) bool {
		return labs[i].Name < labs[j].Name
	})
	return labs, nil
}

func loadLabDescriptor(labDir string) (labDescriptor, error) {
	path := filepath.Join(labDir, "lab.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return labDescriptor{}, err
	}
	var desc labDescriptor
	if err := yaml.Unmarshal(data, &desc); err != nil {
		return labDescriptor{}, fmt.Errorf("%s: %w", path, err)
	}
	if desc.Name == "" {
		desc.Name = filepath.Base(labDir)
	}
	desc.Path = filepath.Clean(labDir)
	return desc, nil
}

func addLabFlag(cmd *cobra.Command, value *string) {
	cmd.Flags().StringVar(value, "lab", "", "scenario lab directory or name under labs/")
}

func addTopologyFlag(cmd *cobra.Command, value *string, usage string) {
	cmd.Flags().StringVar(value, "topology", defaultTopologyPath, usage)
}

func addQueriesFlag(cmd *cobra.Command, value *string, usage string) {
	cmd.Flags().StringVar(value, "queries", defaultQueriesPath, usage)
}

func resolveLabInputs(cmd *cobra.Command, labPath string, topologyPath *string, queriesPath *string) error {
	if labPath == "" {
		return nil
	}
	labDir, err := resolveLabDir(labPath)
	if err != nil {
		return err
	}
	if topologyPath != nil && !cmd.Flags().Changed("topology") {
		*topologyPath = filepath.Join(labDir, labTopologyFile)
	}
	if queriesPath != nil && !cmd.Flags().Changed("queries") {
		*queriesPath = filepath.Join(labDir, labQueriesPath)
	}
	return nil
}

func resolveLabDir(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("--lab is empty")
	}
	candidates := []string{raw}
	if !strings.ContainsRune(raw, filepath.Separator) && !filepath.IsAbs(raw) {
		candidates = append(candidates, filepath.Join(defaultLabsDir, raw))
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return filepath.Clean(candidate), nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("lab %q not found", raw)
}
