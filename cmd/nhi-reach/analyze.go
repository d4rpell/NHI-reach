package main

import (
	"context"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/d4rpell/nhi-reach/internal/graph"
	"github.com/d4rpell/nhi-reach/internal/hops"
	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/report"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
	"github.com/d4rpell/nhi-reach/internal/version"
	"github.com/spf13/cobra"
)

// targetClusterAdmin, targetSecrets and targetNode are the values of --target
// (spec §2.5). cluster-admin and secrets are evaluated; node is not, until the
// workload-effect representation is decided (D-027), and it is reported as a Gap
// instead of being silently dropped.
const (
	targetClusterAdmin = "cluster-admin"
	targetSecrets      = "secrets"
	targetNode         = "node"
)

type analyzeOptions struct {
	fromDir       string
	live          bool
	kubeconfig    string
	context       string
	output        string
	outFile       string
	maxDepth      int
	pathsPerPair  int
	fromIdentity  string
	targets       []string
	sensitiveNS   string
	systemNS      string
	includeSystem bool
	failOn        string
}

func newAnalyzeCmd() *cobra.Command {
	var opts analyzeOptions

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Trace escalation paths from non-human identities to privileged targets",
		Long: "Trace escalation paths from non-human identities to privileged targets.\n" +
			"This version reads an offline snapshot and renders a table, the versioned\n" +
			"JSON schema or a self-contained HTML report:\n\n" +
			"  nhi-reach analyze --from DIR -o table\n" +
			"  nhi-reach analyze --from DIR -o json --out report.json\n" +
			"  nhi-reach analyze --from DIR -o html --out report.html",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(cmd.OutOrStdout(), opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.fromDir, "from", "", "directory holding a snapshot written by `nhi-reach snapshot`")
	f.BoolVar(&opts.live, "live", false, "analyze a live cluster (read-only: get/list only)")
	f.StringVar(&opts.kubeconfig, "kubeconfig", "", "path to the kubeconfig file for --live (defaults to the standard locations)")
	f.StringVar(&opts.context, "context", "", "kubeconfig context to use for --live (defaults to the current one)")
	f.StringVarP(&opts.output, "output", "o", "table", "output format: table|json|html")
	f.StringVar(&opts.outFile, "out", "", "write the report to FILE instead of stdout")
	f.IntVar(&opts.maxDepth, "max-depth", graph.DefaultMaxDepth, "maximum hop depth")
	f.IntVar(&opts.pathsPerPair, "paths-per-pair", graph.DefaultPathsPerPair, "maximum number of paths reported per origin/target pair")
	f.StringVar(&opts.fromIdentity, "from-identity", "", "restrict the origin to a single ns/sa")
	f.StringArrayVar(&opts.targets, "target", []string{targetClusterAdmin, targetNode, targetSecrets},
		"target to evaluate: cluster-admin|node|secrets (repeatable)")
	f.StringVar(&opts.sensitiveNS, "sensitive-ns", "", "comma-separated namespaces added to the sensitive list (kube-system, openshift-*)")
	f.StringVar(&opts.systemNS, "system-ns", "", "comma-separated namespaces that replace the system list")
	f.BoolVar(&opts.includeSystem, "include-system", false, "include system identities as origins")
	f.StringVar(&opts.failOn, "fail-on", "none", "exit non-zero on findings: none|any")
	return cmd
}

func runAnalyze(w io.Writer, opts analyzeOptions) error {
	return runAnalyzeContext(context.Background(), w, opts)
}

// runAnalyzeContext is runAnalyze with an explicit context, so tests can bound
// the live client. The offline path ignores it.
func runAnalyzeContext(ctx context.Context, w io.Writer, opts analyzeOptions) error {
	if err := validateOptions(opts); err != nil {
		return err
	}

	ix, err := loadSource(ctx, opts)
	if err != nil {
		return err
	}

	system := systemNamespaces(opts.systemNS)
	sensitive := sensitiveNamespaces(opts.sensitiveNS)

	hopOpts := hops.Options{SensitiveNamespace: sensitive.Matches}
	edges, err := hops.EdgesWith(ix, hopOpts)
	if err != nil {
		return exitf(3, "%v", err)
	}

	origins, err := resolveOrigins(ix, opts, system)
	if err != nil {
		return err
	}

	gaps := ix.Gaps()

	requested := requestedTargets(opts.targets)
	graphTargets := evaluableTargets(requested)
	if len(graphTargets) == 0 || len(origins) == 0 {
		// Nothing to solve: no evaluable target was requested, or there is no
		// origin identity. The report still states the snapshot gaps and the
		// node goal.
		if requested[targetNode] {
			gaps = append(gaps, nodeTargetGap())
		}
		return emitReport(w, opts, buildReport(opts, ix, system, sensitive, nil, gaps))
	}

	sources := make([]string, 0, len(origins))
	for _, origin := range origins {
		sources = append(sources, hops.IdentityID(origin))
	}

	model := graph.New(edges, func(removed []model.Grant) ([]model.Edge, error) {
		return hops.RebuildWith(ix, removed, hopOpts)
	})
	result, err := model.Analyze(graph.Options{
		Sources:      sources,
		Targets:      graphTargets,
		MaxDepth:     opts.maxDepth,
		PathsPerPair: opts.pathsPerPair,
		System:       system,
		Sensitive:    sensitive,
	})
	if err != nil {
		return exitf(3, "%v", err)
	}
	gaps = append(gaps, result.Gaps...)
	if requested[targetNode] {
		gaps = append(gaps, nodeTargetGap())
	}

	return emitReport(w, opts, buildReport(opts, ix, system, sensitive, &result, gaps))
}

// buildReport maps a graph result to the renderer-independent report.
func buildReport(opts analyzeOptions, ix *snapshot.Index, system, sensitive graph.SystemNamespaces, result *graph.Result, gaps []model.Gap) report.Report {
	rep := report.Report{
		SchemaVersion: report.SchemaVersion,
		Params: report.Params{
			MaxDepth:            opts.maxDepth,
			PathsPerPair:        opts.pathsPerPair,
			Targets:             requestedTargetList(opts.targets),
			FromIdentity:        opts.fromIdentity,
			IncludeSystem:       opts.includeSystem,
			SystemNamespaces:    []string(system),
			SensitiveNamespaces: []string(sensitive),
		},
		InputManifestSHA256: ix.Manifest().SHA256,
		RulesCatalogSHA256:  hops.CatalogSHA256(),
		Gaps:                toGapViews(gaps),
	}

	if result != nil {
		for _, routed := range result.Paths {
			rep.Paths = append(rep.Paths, toPathView(routed, system))
			for _, cut := range routed.Path.Cuts {
				rep.Cuts = append(rep.Cuts, toCutView(routed.Path.ID, cut))
			}
		}
		rep.CoverComplete = result.Cover.Complete
		for _, step := range result.Cover.Steps {
			rep.Bottlenecks = append(rep.Bottlenecks, toBottleneck(step))
		}
	}
	return rep.Normalize()
}

func toPathView(routed graph.RoutedPath, system graph.SystemNamespaces) report.PathView {
	path := routed.Path
	view := report.PathView{
		ID:           path.ID,
		Source:       path.Source,
		Target:       path.Target,
		Hops:         len(path.Edges),
		Confidence:   report.ConfidenceOf(path.Edges),
		ViaSystem:    routed.ViaSystem,
		SystemOrigin: isSystemOrigin(path.Source, system),
	}
	for _, edge := range path.Edges {
		view.Route = append(view.Route, report.StepView{
			From:       edge.From,
			To:         edge.To,
			HopID:      edge.HopID,
			Confidence: edge.Confidence,
			Evidence:   toRefViews(edge.Evidence),
		})
	}
	return view
}

func toCutView(pathID string, cut model.Cut) report.CutView {
	return report.CutView{
		PathID:         pathID,
		Grant:          toGrantView(cut.Grant),
		Change:         cut.Change,
		Verified:       cut.Verified,
		RemainingPaths: cut.RemainingPaths,
	}
}

func toBottleneck(step graph.Bottleneck) report.Bottleneck {
	out := report.Bottleneck{Change: step.Change}
	for _, pair := range step.Eliminated {
		out.Eliminated = append(out.Eliminated, report.PairView{Source: pair.Source, Target: pair.Target})
	}
	return out
}

func toGrantView(grant model.Grant) report.GrantView {
	return report.GrantView{Object: toRefView(grant.Object), Kind: grant.Kind, Detail: grant.Detail}
}

func toRefViews(refs []model.ObjectRef) []report.RefView {
	out := make([]report.RefView, 0, len(refs))
	for _, ref := range refs {
		out = append(out, toRefView(ref))
	}
	return out
}

func toRefView(ref model.ObjectRef) report.RefView {
	return report.RefView{
		APIVersion: ref.APIVersion,
		Kind:       ref.Kind,
		Namespace:  ref.Namespace,
		Name:       ref.Name,
		SHA256:     ref.SHA256,
	}
}

func toGapViews(gaps []model.Gap) []report.GapView {
	out := make([]report.GapView, 0, len(gaps))
	for _, gap := range gaps {
		out = append(out, report.GapView{Kind: gap.Kind, Subject: gap.Subject, Message: gap.Message})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Message < out[j].Message
	})
	return out
}

// emitReport renders the report to --out or to w and applies --fail-on.
func emitReport(w io.Writer, opts analyzeOptions, rep report.Report) error {
	var htmlOpts report.HTMLOptions
	if opts.output == "html" {
		var err error
		if htmlOpts, err = buildHTMLOptions(); err != nil {
			return exitf(3, "%v", err)
		}
	}

	render := func(dst io.Writer) error {
		switch opts.output {
		case "json":
			return report.JSON(dst, rep)
		case "html":
			return report.HTML(dst, rep, htmlOpts)
		default:
			return report.Table(dst, rep)
		}
	}

	if opts.outFile == "" {
		if err := render(w); err != nil {
			return err
		}
	} else {
		file, err := os.Create(opts.outFile)
		if err != nil {
			// A write failure is an unclassified runtime error (exit 1), and it
			// prevails over --fail-on: there is no report to be non-zero about.
			return err
		}
		if err := render(file); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}

	if opts.failOn == "any" && len(rep.Paths) > 0 {
		return exitf(2, "%d escalation path(s) found", len(rep.Paths))
	}
	return nil
}

// buildHTMLOptions collects what the HTML renderer needs: the build metadata and
// the official reference of every catalog hop. An unreadable catalog is an input
// error, never a report rendered without references.
func buildHTMLOptions() (report.HTMLOptions, error) {
	entries, err := hops.Catalog()
	if err != nil {
		return report.HTMLOptions{}, err
	}
	opts := report.HTMLOptions{
		Tool: report.ToolInfo{
			Version:       version.Version,
			Commit:        version.Commit,
			Date:          version.Date,
			CatalogSHA256: hops.CatalogSHA256(),
		},
	}
	for _, entry := range entries {
		opts.References = append(opts.References, report.HopReference{ID: entry.ID, Reference: entry.Reference})
	}
	return opts, nil
}

// validateOptions rejects, with exit code 3, the flags whose behaviour this
// version does not implement and the values it cannot interpret. Silently
// ignoring them would misreport the analysis.
func validateOptions(opts analyzeOptions) error {
	switch {
	case opts.live && opts.fromDir != "":
		return exitf(3, "--live and --from DIR are mutually exclusive")
	case !opts.live && opts.fromDir == "":
		return exitf(3, "--from DIR is required (or --live)")
	case !opts.live && (opts.kubeconfig != "" || opts.context != ""):
		return exitf(3, "--kubeconfig and --context only apply to --live")
	case opts.output != "table" && opts.output != "json" && opts.output != "html":
		return exitf(3, "-o %s is not supported; expected table, json or html", opts.output)
	case opts.maxDepth < 1:
		return exitf(3, "--max-depth must be at least 1")
	case opts.pathsPerPair < 1:
		return exitf(3, "--paths-per-pair must be at least 1")
	case opts.failOn != "none" && opts.failOn != "any":
		return exitf(3, "--fail-on %s is not supported; expected none or any", opts.failOn)
	}
	return validateTargets(opts.targets)
}

// loadSource builds the index from the requested source: a live cluster through
// the read-only client, or an offline snapshot directory. Both paths converge on
// the same index contract, so the rest of the analysis is source-independent. A
// configuration, transport or authentication failure is an input error (exit 3).
func loadSource(ctx context.Context, opts analyzeOptions) (*snapshot.Index, error) {
	if !opts.live {
		ix, err := snapshot.Load(opts.fromDir)
		if err != nil {
			return nil, exitf(3, "%v", err)
		}
		return ix, nil
	}
	cfg, _, err := snapshot.RESTConfig(opts.kubeconfig, opts.context)
	if err != nil {
		return nil, exitf(3, "%v", err)
	}
	client, err := snapshot.NewLiveClient(cfg)
	if err != nil {
		return nil, exitf(3, "%v", err)
	}
	ix, err := snapshot.LoadLive(ctx, client)
	if err != nil {
		return nil, exitf(3, "%v", err)
	}
	return ix, nil
}

// validateTargets rejects the goals of spec §2.5 this version does not know and
// an empty target list. node is a known goal, so it is accepted and reported as
// a Gap, not rejected.
func validateTargets(targets []string) error {
	if len(targets) == 0 {
		return exitf(3, "--target needs at least one value")
	}
	for _, target := range targets {
		switch target {
		case targetClusterAdmin, targetSecrets, targetNode:
		default:
			return exitf(3, "unknown target %q; expected %s, %s or %s", target, targetClusterAdmin, targetNode, targetSecrets)
		}
	}
	return nil
}

// requestedTargets is the set of the requested goals, de-duplicated.
func requestedTargets(targets []string) map[string]bool {
	set := map[string]bool{}
	for _, target := range targets {
		set[target] = true
	}
	return set
}

// requestedTargetList is the requested goals in a stable order.
func requestedTargetList(targets []string) []string {
	set := requestedTargets(targets)
	out := make([]string, 0, len(set))
	for _, target := range []string{targetClusterAdmin, targetNode, targetSecrets} {
		if set[target] {
			out = append(out, target)
		}
	}
	return out
}

// evaluableTargets maps the requested goals to the node ids the graph solves:
// node has no node id, so it is left out (its Gap is emitted by the caller).
func evaluableTargets(requested map[string]bool) []string {
	var out []string
	if requested[targetClusterAdmin] {
		out = append(out, hops.TargetClusterAdmin)
	}
	if requested[targetSecrets] {
		out = append(out, hops.TargetSecrets)
	}
	return out
}

// nodeTargetGap states, as a Gap, that the node goal is not evaluated yet.
func nodeTargetGap() model.Gap {
	return model.Gap{
		Kind:    "missing-input",
		Subject: "target:node",
		Message: "the node target is not evaluated: the workload-effect representation is not decided yet, so no hop reaches it (in the model and up to --max-depth)",
	}
}

// systemNamespaces returns the system-namespace list of §2.6: the default list,
// or the one given with --system-ns, which replaces it.
func systemNamespaces(value string) graph.SystemNamespaces {
	if value == "" {
		return graph.DefaultSystemNamespaces()
	}
	return graph.SystemNamespaces(splitList(value))
}

// sensitiveNamespaces returns the sensitive-namespace list of §2.5: the defaults
// (kube-system, openshift-*) plus any namespace added with --sensitive-ns, which
// extends rather than replaces them. The result is de-duplicated, defaults
// first.
func sensitiveNamespaces(value string) graph.SystemNamespaces {
	list := append(graph.SystemNamespaces(nil), graph.DefaultSensitiveNamespaces()...)
	seen := map[string]bool{}
	for _, entry := range list {
		seen[entry] = true
	}
	for _, entry := range splitList(value) {
		if seen[entry] {
			continue
		}
		seen[entry] = true
		list = append(list, entry)
	}
	return list
}

// isSystemOrigin reports whether a path origin is a system identity.
func isSystemOrigin(nodeID string, system graph.SystemNamespaces) bool {
	namespace, ok := graph.IdentityNamespace(nodeID)
	return ok && system.Matches(namespace)
}

// resolveOrigins returns the identities the search starts from: the one named
// with --from-identity, or every non-system ServiceAccount (spec §2.6).
func resolveOrigins(ix *snapshot.Index, opts analyzeOptions, system graph.SystemNamespaces) ([]model.ObjectRef, error) {
	if opts.fromIdentity != "" {
		namespace, name, ok := strings.Cut(opts.fromIdentity, "/")
		if !ok || namespace == "" || name == "" {
			return nil, exitf(3, "--from-identity must be ns/name, got %q", opts.fromIdentity)
		}
		ref, ok := ix.Get("ServiceAccount", namespace, name)
		if !ok {
			return nil, exitf(3, "--from-identity: snapshot has no ServiceAccount %s", opts.fromIdentity)
		}
		return []model.ObjectRef{ref}, nil
	}

	var origins []model.ObjectRef
	for _, sa := range ix.List("ServiceAccount", "") {
		if opts.includeSystem || !system.Matches(sa.Namespace) {
			origins = append(origins, sa)
		}
	}
	return origins, nil
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
