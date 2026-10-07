package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strings"

	"github.com/d4rpell/nhi-reach/internal/graph"
	"github.com/d4rpell/nhi-reach/internal/hops"
	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/rbac"
	"github.com/d4rpell/nhi-reach/internal/report"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
	"github.com/spf13/cobra"
)

// defaultSystemNamespaces is the default system-identity list of spec §2.6. An
// entry ending in "*" matches by prefix.
var defaultSystemNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"openshift",
	"openshift-*",
}

// evaluatedTarget is the only goal this version computes paths to. The other
// targets of spec §2.5 are rejected with exit code 3 rather than silently left
// out: a run that answered a different question than the one asked would
// misstate the analysis. T2-01 restores the full `--target` surface.
const evaluatedTarget = "cluster-admin"

type analyzeOptions struct {
	fromDir       string
	live          bool
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
			"This version reads an offline snapshot, traces the shortest path per origin\n" +
			"and renders a table:\n\n" +
			"  nhi-reach analyze --from DIR -o table",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(cmd.OutOrStdout(), opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.fromDir, "from", "", "directory holding a snapshot written by `nhi-reach snapshot`")
	f.BoolVar(&opts.live, "live", false, "analyze a live cluster (read-only: get/list only)")
	f.StringVarP(&opts.output, "output", "o", "table", "output format: table|json|html")
	f.StringVar(&opts.outFile, "out", "", "write the report to FILE instead of stdout")
	f.IntVar(&opts.maxDepth, "max-depth", 4, "maximum hop depth")
	f.IntVar(&opts.pathsPerPair, "paths-per-pair", 3, "maximum number of paths reported per origin/target pair")
	f.StringVar(&opts.fromIdentity, "from-identity", "", "restrict the origin to a single ns/sa")
	f.StringArrayVar(&opts.targets, "target", []string{evaluatedTarget}, "target to evaluate: cluster-admin (node and secrets are not implemented yet)")
	f.StringVar(&opts.sensitiveNS, "sensitive-ns", "", "comma-separated namespaces treated as sensitive")
	f.StringVar(&opts.systemNS, "system-ns", "", "comma-separated namespaces treated as system")
	f.BoolVar(&opts.includeSystem, "include-system", false, "include system identities as origins")
	f.StringVar(&opts.failOn, "fail-on", "none", "exit non-zero on findings: none|any")
	return cmd
}

func runAnalyze(w io.Writer, opts analyzeOptions) error {
	if err := validateOptions(opts); err != nil {
		return err
	}

	ix, err := snapshot.Load(opts.fromDir)
	if err != nil {
		return exitf(3, "%v", err)
	}
	gaps := ix.Gaps()
	sortGaps(gaps)

	edges, err := buildEdges(ix)
	if err != nil {
		return err
	}

	origins, err := resolveOrigins(ix, opts)
	if err != nil {
		return err
	}

	paths := make([]model.Path, 0, len(origins))
	for _, origin := range origins {
		pathEdges, ok := graph.ShortestPath(edges, hops.IdentityID(origin), hops.TargetClusterAdmin, opts.maxDepth)
		if !ok {
			continue
		}
		paths = append(paths, model.Path{
			ID:     pathID(pathEdges),
			Source: hops.IdentityID(origin),
			Target: hops.TargetClusterAdmin,
			Edges:  pathEdges,
		})
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Source < paths[j].Source })

	return report.Table(w, paths, gaps)
}

// validateOptions rejects, with exit code 3, the flags whose behaviour this
// version does not implement. Silently ignoring them would misreport the
// analysis.
func validateOptions(opts analyzeOptions) error {
	switch {
	case opts.live:
		return exitf(3, "--live is not supported in this version; pass --from DIR")
	case opts.fromDir == "":
		return exitf(3, "--from DIR is required")
	case opts.output != "table":
		return exitf(3, "-o %s is not supported in this version; only -o table", opts.output)
	case opts.outFile != "":
		return exitf(3, "--out is not supported in this version")
	case opts.pathsPerPair != 3:
		return exitf(3, "--paths-per-pair is not supported in this version")
	case opts.sensitiveNS != "":
		return exitf(3, "--sensitive-ns is not supported in this version")
	case opts.failOn != "none":
		return exitf(3, "--fail-on %s is not supported in this version", opts.failOn)
	case opts.maxDepth < 1:
		return exitf(3, "--max-depth must be at least 1")
	}
	return validateTargets(opts.targets)
}

// validateTargets rejects the goals this version does not evaluate. Leaving
// them out silently would return paths to a target the caller never asked for.
func validateTargets(targets []string) error {
	if len(targets) == 0 {
		return exitf(3, "--target needs at least one value")
	}
	for _, target := range targets {
		if target == evaluatedTarget {
			continue
		}
		switch target {
		case "node", "secrets":
			return exitf(3, "--target %s is not supported in this version; only %s is evaluated", target, evaluatedTarget)
		default:
			return exitf(3, "unknown target %q; expected %s", target, evaluatedTarget)
		}
	}
	return nil
}

// buildEdges runs every edge builder over every ServiceAccount of the snapshot.
func buildEdges(ix *snapshot.Index) ([]model.Edge, error) {
	var edges []model.Edge
	for _, sa := range ix.List("ServiceAccount", "") {
		granted, err := rbac.Effective(ix, rbac.ServiceAccount(sa))
		if err != nil {
			return nil, exitf(3, "%v", err)
		}
		edges = append(edges, hops.ClusterAdminEdges(sa, granted)...)
		edges = append(edges, hops.WorkloadCreation(ix, sa, granted)...)
	}
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.HopID < b.HopID
	})
	return edges, nil
}

// resolveOrigins returns the identities the search starts from: the one named
// with --from-identity, or every non-system ServiceAccount (spec §2.6).
func resolveOrigins(ix *snapshot.Index, opts analyzeOptions) ([]model.ObjectRef, error) {
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

	system := defaultSystemNamespaces
	if opts.systemNS != "" {
		system = splitList(opts.systemNS)
	}
	var origins []model.ObjectRef
	for _, sa := range ix.List("ServiceAccount", "") {
		if opts.includeSystem || !isSystemNamespace(sa.Namespace, system) {
			origins = append(origins, sa)
		}
	}
	return origins, nil
}

func isSystemNamespace(namespace string, system []string) bool {
	for _, entry := range system {
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			if strings.HasPrefix(namespace, prefix) {
				return true
			}
			continue
		}
		if namespace == entry {
			return true
		}
	}
	return false
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

func sortGaps(gaps []model.Gap) {
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Subject != gaps[j].Subject {
			return gaps[i].Subject < gaps[j].Subject
		}
		return gaps[i].Message < gaps[j].Message
	})
}

// pathID identifies a path by its edge sequence, so the same route always gets
// the same identifier.
func pathID(edges []model.Edge) string {
	hash := sha256.New()
	for _, edge := range edges {
		_, _ = hash.Write([]byte(edge.From + "\x00" + edge.To + "\x00" + edge.HopID + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
