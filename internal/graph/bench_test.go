package graph

import (
	"fmt"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/hops"
	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// This file holds the synthetic large fixture and the benchmarks of the analysis
// engine (T3-02). The fixture is generated in memory by versioned code so no
// multi-megabyte snapshot has to be committed and no object can look like one
// taken from a real cluster. The benchmarks measure steps 4-7 of spec §3 and the
// cost of cut verification, which the spec asks T3-02 to record; they only run
// under `go test -bench`, so the regular suite is untouched.

// benchScale is one fixture size. The benchmark sub-benchmarks are keyed by it,
// so every recorded number says which graph produced it.
type benchScale struct {
	name     string
	names    int // independent namespaces; each contributes one (origin, target) pair
	depth    int // impersonation layers per namespace
	width    int // branches per layer
	maxDepth int // explicit hop limit; 0 means the layered-graph limit (depth+1)
	perPair  int
}

// hopLimit is the hop limit the scale measures at: the explicit one, or the
// layered-graph limit depth+1, which enumerates exactly the intended routes
// without letting the longer routes the cluster-admin terminals open slip in.
func (s benchScale) hopLimit() int {
	if s.maxDepth > 0 {
		return s.maxDepth
	}
	return s.depth + 1
}

// The scales are frozen before measuring (design T3-02 §3-§4). The exploratory
// ones only show the growth; base and stress are the ones the --verify-cuts
// decision reads.
var (
	benchExploratory = []benchScale{
		{name: "n4_d2_w3", names: 4, depth: 2, width: 3, perPair: DefaultPathsPerPair},
		{name: "n8_d3_w3", names: 8, depth: 3, width: 3, perPair: DefaultPathsPerPair},
		{name: "n16_d3_w4", names: 16, depth: 3, width: 4, perPair: DefaultPathsPerPair},
	}
	benchBase   = benchScale{name: "base_n8_d3_w3", names: 8, depth: 3, width: 3, maxDepth: DefaultMaxDepth, perPair: DefaultPathsPerPair}
	benchStress = []benchScale{
		{name: "stress_n16_d3_w4", names: 16, depth: 3, width: 4, maxDepth: DefaultMaxDepth, perPair: DefaultPathsPerPair},
		{name: "stress_n8_d4_w3", names: 8, depth: 4, width: 3, maxDepth: 5, perPair: DefaultPathsPerPair},
	}
)

func saName(layer, branch int) string { return fmt.Sprintf("n%d-%d", layer, branch) }

func benchAPIVersion(kind string) string {
	switch kind {
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		return "rbac.authorization.k8s.io/v1"
	default:
		return "v1"
	}
}

// largeFixture builds a synthetic snapshot with `names` independent namespaces,
// each a layered graph of `depth` impersonation layers and `width` branches.
//
// Per namespace `bench-<ns>`:
//   - a Namespace object;
//   - ServiceAccounts n<i>-<j> for layer i in [0, depth] and branch j in [0, width);
//   - for each layer i < depth, a Role impersonator-<ns>-<i> granting impersonate
//     on serviceaccounts restricted with resourceNames to the next layer, and one
//     RoleBinding per SA of that layer;
//   - a ClusterRole admin-<ns> equivalent to "*/*/*" and one ClusterRoleBinding per
//     terminal SA n<depth>-<j>, the direct cluster-admin edge of spec §2.6.
//
// From sa:bench-<ns>/n0-0 the shortest route to cluster-admin has depth+1 hops
// (depth impersonation hops plus one terminal edge). The terminal SAs are
// cluster-admin over the whole cluster, so each one reaches the target by the
// terminalHops edges an already-cluster-admin identity satisfies (the §2.6 direct
// edge plus NR-004 and NR-005), and it may impersonate every other
// ServiceAccount: those edges are real and produce longer routes, which is why the
// exact count is claimed only at MaxDepth=depth+1.
func largeFixture(tb testing.TB, names, depth, width int) *snapshot.Index {
	tb.Helper()
	ix := snapshot.New()
	add := func(kind, namespace, name string, extra map[string]any) {
		metadata := map[string]any{"name": name}
		if namespace != "" {
			metadata["namespace"] = namespace
		}
		obj := map[string]any{
			"apiVersion": benchAPIVersion(kind),
			"kind":       kind,
			"metadata":   metadata,
		}
		for key, value := range extra {
			obj[key] = value
		}
		if err := ix.Add(obj); err != nil {
			tb.Fatalf("index %s %s/%s: %v", kind, namespace, name, err)
		}
	}

	for ns := 0; ns < names; ns++ {
		nsName := fmt.Sprintf("bench-%d", ns)
		add("Namespace", "", nsName, nil)

		for i := 0; i <= depth; i++ {
			for j := 0; j < width; j++ {
				add("ServiceAccount", nsName, saName(i, j), nil)
			}
		}

		for i := 0; i < depth; i++ {
			named := make([]any, 0, width)
			for j := 0; j < width; j++ {
				named = append(named, saName(i+1, j))
			}
			roleName := fmt.Sprintf("impersonator-%s-%d", nsName, i)
			add("Role", nsName, roleName, map[string]any{
				"rules": []any{map[string]any{
					"apiGroups":     []any{""},
					"resources":     []any{"serviceaccounts"},
					"verbs":         []any{"impersonate"},
					"resourceNames": named,
				}},
			})
			for j := 0; j < width; j++ {
				add("RoleBinding", nsName, fmt.Sprintf("rb-%s-%d-%d", nsName, i, j), map[string]any{
					"roleRef": map[string]any{
						"apiGroup": "rbac.authorization.k8s.io",
						"kind":     "Role",
						"name":     roleName,
					},
					"subjects": []any{map[string]any{
						"kind": "ServiceAccount", "name": saName(i, j), "namespace": nsName,
					}},
				})
			}
		}

		adminRole := fmt.Sprintf("admin-%s", nsName)
		add("ClusterRole", "", adminRole, map[string]any{
			"rules": []any{map[string]any{
				"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"},
			}},
		})
		for j := 0; j < width; j++ {
			add("ClusterRoleBinding", "", fmt.Sprintf("crb-%s-%d", nsName, j), map[string]any{
				"roleRef": map[string]any{
					"apiGroup": "rbac.authorization.k8s.io",
					"kind":     "ClusterRole",
					"name":     adminRole,
				},
				"subjects": []any{map[string]any{
					"kind": "ServiceAccount", "name": saName(depth, j), "namespace": nsName,
				}},
			})
		}
	}
	return ix
}

func originID(namespace, branch int) string {
	return fmt.Sprintf("sa:bench-%d/n0-%d", namespace, branch)
}

// allOriginsOptions is the scenario configuration: one origin per namespace, so
// the number of analysis pairs grows with the scale, which is what the frozen
// scenarios of design T3-02 §4 are about.
func allOriginsOptions(scale benchScale) Options {
	sources := make([]string, 0, scale.names)
	for ns := 0; ns < scale.names; ns++ {
		sources = append(sources, originID(ns, 0))
	}
	return Options{
		Sources:      sources,
		Targets:      []string{hops.TargetClusterAdmin},
		MaxDepth:     scale.hopLimit(),
		PathsPerPair: scale.perPair,
	}
}

// singlePairOptions configures one (origin, target) pair for the micro-benchmarks
// that isolate a single step and say so.
func singlePairOptions(scale benchScale) Options {
	return Options{
		Sources:      []string{originID(0, 0)},
		Targets:      []string{hops.TargetClusterAdmin},
		MaxDepth:     scale.hopLimit(),
		PathsPerPair: scale.perPair,
	}
}

// normalizedOpts returns the options as the engine sees them. verifyCuts and
// greedyCover are internal steps Solve calls with already-normalized options, so
// benchmarking them with the raw Options would run with RemainingCap and
// MaxCoverSteps at zero: a measurement of an empty case, not of the step.
func normalizedOpts(tb testing.TB, opts Options) Options {
	tb.Helper()
	normalized, err := opts.normalized()
	if err != nil {
		tb.Fatalf("normalize options: %v", err)
	}
	return normalized
}

// benchmarkTerminalHops are the HopIDs of the edges an already-cluster-admin
// ServiceAccount holds to the target: the direct §2.6 edge plus NR-004 (bind)
// and NR-005 (widen), all of which an unrestricted cluster-scoped "*/*/*"
// satisfies. Every route at MaxDepth=depth+1 ends with exactly one of them. The
// test checks the composition, not only the count, so a different hop silently
// satisfying the terminal could not pass.
var benchmarkTerminalHops = []string{"rbac-cluster-admin", "NR-004", "NR-005"}

// terminalEdgesOf returns, per terminal ServiceAccount of the benchmark
// namespace, the set of HopIDs of its edges to the target.
func terminalEdgesOf(edges []model.Edge, depth int) map[string][]string {
	prefix := fmt.Sprintf("sa:bench-0/n%d-", depth)
	groups := map[string][]string{}
	for _, edge := range edges {
		if edge.To == hops.TargetClusterAdmin && strings.HasPrefix(edge.From, prefix) {
			groups[edge.From] = append(groups[edge.From], edge.HopID)
		}
	}
	return groups
}

// sameStrings reports whether two string slices hold the same multiset, ignoring
// order, so the terminal-hop check does not depend on edge ordering.
func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	counts := map[string]int{}
	for _, value := range got {
		counts[value]++
	}
	for _, value := range want {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

// countingRebuild wraps a rebuild to count how many hypothetical models were
// built, so a test can prove a benchmark scenario really exercises cut
// verification instead of measuring an empty case.
func countingRebuild(ix *snapshot.Index, calls *int) Rebuild {
	return func(removed []model.Grant) ([]model.Edge, error) {
		*calls++
		return hops.Rebuild(ix, removed)
	}
}

func TestLargeFixtureIsDeterministicAndValid(t *testing.T) {
	first := largeFixture(t, 6, 3, 3).Manifest().SHA256
	second := largeFixture(t, 6, 3, 3).Manifest().SHA256
	if first != second {
		t.Fatalf("two generations of the same fixture hashed %q and %q", first, second)
	}

	// Every required kind is present, so FromSnapshot must not fail: a broken
	// fixture would make every benchmark below measure nothing.
	if _, err := FromSnapshot(largeFixture(t, 4, 2, 3)); err != nil {
		t.Fatalf("FromSnapshot over the large fixture: %v", err)
	}
}

// TestLargeFixtureStructure proves the fixture's shape instead of asserting it:
// the distance, the route count width^depth*terminalHops, the removal units per
// route, the three terminal hops, the longer routes a raised limit opens, and
// that both branches of cut verification occur.
func TestLargeFixtureStructure(t *testing.T) {
	for _, scale := range []benchScale{
		{name: "d2w2", names: 2, depth: 2, width: 2},
		{name: "d3w2", names: 2, depth: 3, width: 2},
	} {
		t.Run(scale.name, func(t *testing.T) {
			ix := largeFixture(t, scale.names, scale.depth, scale.width)
			edges, err := hops.Edges(ix)
			if err != nil {
				t.Fatalf("hops.Edges: %v", err)
			}
			source, target := originID(0, 0), hops.TargetClusterAdmin
			limit := scale.hopLimit()

			if distance, ok := Reach(edges, source, target, limit); !ok || distance != scale.depth+1 {
				t.Fatalf("Reach = (%d, %v), want (%d, true)", distance, ok, scale.depth+1)
			}

			found, _, truncated := SimplePaths(edges, source, target, limit, DefaultBudget)
			if truncated {
				t.Fatal("the enumeration of a small fixture was truncated")
			}

			// Every route at the limit is width^depth branch sequences, each ending
			// at a terminal SA that carries the benchmarkTerminalHops edges to the
			// target (composition checked, not only the count).
			prefixes := 1
			for i := 0; i < scale.depth; i++ {
				prefixes *= scale.width
			}
			groups := terminalEdgesOf(edges, scale.depth)
			if len(groups) != scale.width {
				t.Fatalf("got %d terminal ServiceAccounts, want width=%d", len(groups), scale.width)
			}
			for from, hopIDs := range groups {
				if !sameStrings(hopIDs, benchmarkTerminalHops) {
					t.Fatalf("terminal %s reaches the target through %v, want %v", from, hopIDs, benchmarkTerminalHops)
				}
			}
			if want := prefixes * len(benchmarkTerminalHops); len(found) != want {
				t.Fatalf("enumerated %d routes at MaxDepth=%d, want width^depth*terminalHops=%d", len(found), limit, want)
			}
			for _, route := range found {
				if len(route) != scale.depth+1 {
					t.Fatalf("route of %d hops, want %d", len(route), scale.depth+1)
				}
				// Unidades de retirada por ruta: dos por cada arista de impersonación
				// (sujeto del binding + regla del rol) más dos por la arista terminal.
				if perRoute := len(pathCandidates(model.Path{Edges: route})); perRoute != 2*scale.depth+2 {
					t.Fatalf("route has %d removal units, want 2*depth+2=%d", perRoute, 2*scale.depth+2)
				}
			}

			// Las terminales cluster-admin abren rutas más largas: dentro del
			// límite no aparece ninguna (todas tienen depth+1 saltos), y al
			// subirlo la enumeración encuentra estrictamente más.
			wider, _, _ := SimplePaths(edges, source, target, limit+1, DefaultBudget)
			if len(wider) <= len(found) {
				t.Fatalf("raising MaxDepth to %d found %d routes, want more than %d", limit+1, len(wider), len(found))
			}

			// Ambas ramas de la verificación de cortes deben ocurrir: una unidad
			// que aísla el origen queda Verified, un sujeto intermedio no.
			graph, err := FromSnapshot(ix)
			if err != nil {
				t.Fatalf("FromSnapshot: %v", err)
			}
			analyzed, err := graph.Analyze(Options{
				Sources: []string{source}, Targets: []string{target},
				MaxDepth: limit, PathsPerPair: len(found),
			})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			var verified, unverified int
			for _, routed := range analyzed.Paths {
				for _, cut := range routed.Path.Cuts {
					if cut.Verified {
						verified++
						continue
					}
					unverified++
					if cut.RemainingPaths < 1 {
						t.Errorf("unverified cut %q reports %d remaining routes, want at least 1", cut.Change, cut.RemainingPaths)
					}
				}
			}
			if verified == 0 || unverified == 0 {
				t.Fatalf("cut verification produced %d verified and %d unverified cuts, want both kinds", verified, unverified)
			}
		})
	}
}

// TestBenchmarkScenariosExerciseRealWork proves the decisive scenarios are not
// empty without paying the full cost the benchmarks are meant to measure. Every
// scenario must analyse one pair per namespace and reach the target; the base
// scale must additionally enumerate a route and run at least one hypothetical
// rebuild in each of cut verification and the cover, with the benchmark's own
// options.
func TestBenchmarkScenariosExerciseRealWork(t *testing.T) {
	for _, scale := range append([]benchScale{benchBase}, benchStress...) {
		t.Run(scale.name, func(t *testing.T) {
			ix := largeFixture(t, scale.names, scale.depth, scale.width)
			edges, err := hops.Edges(ix)
			if err != nil {
				t.Fatalf("hops.Edges: %v", err)
			}
			if len(edges) == 0 {
				t.Fatal("the fixture produced no edges")
			}

			opts := normalizedOpts(t, allOriginsOptions(scale))
			if len(opts.Sources) != scale.names {
				t.Fatalf("the scenario analyses %d origins, want one per namespace (%d)", len(opts.Sources), scale.names)
			}

			reachable := 0
			for _, pair := range reachability(edges, opts) {
				if pair.Reachable {
					reachable++
				}
			}
			if reachable != scale.names {
				t.Fatalf("the scenario has %d reachable pairs, want one per namespace (%d)", reachable, scale.names)
			}
		})
	}

	// The rebuild-requiring checks run on the base scale: the cover rebuilds the
	// whole graph per step, so doing it on the stress scales would put the
	// benchmark's cost into the regular suite. One allowed step suffices.
	t.Run("rebuilds", func(t *testing.T) {
		in := prepare(t, benchBase)
		opts := in.opts
		opts.MaxCoverSteps = 1

		calls := 0
		if _, _, err := verifyCuts(opts, countingRebuild(in.ix, &calls), in.route); err != nil {
			t.Fatalf("verifyCuts: %v", err)
		}
		if calls == 0 {
			t.Fatal("cut verification performed no hypothetical rebuild")
		}

		coverCalls := 0
		pairs := []PairReach{{Pair: Pair{Source: in.source, Target: in.target}, Reachable: true}}
		cover, _, err := greedyCover(opts, in.edges, countingRebuild(in.ix, &coverCalls), []RoutedPath{{Path: in.route}}, pairs)
		if err != nil {
			t.Fatalf("greedyCover: %v", err)
		}
		if coverCalls == 0 {
			t.Fatal("the cover performed no hypothetical rebuild")
		}
		if len(cover.Steps) == 0 {
			t.Fatal("the cover proposed no step with the benchmark's own options")
		}
	})
}

// solveControls summarizes one Solve result for the benchmark's own reporting.
type solveControls struct {
	pairs          int
	reachable      int
	routes         int
	verified       int
	unverified     int
	steps          int
	complete       bool
	budgetTrunc    int // enumeration stopped because the global budget ran out
	remainingTrunc int // RemainingPaths counted up to RemainingCap
	coverTrunc     int // the verified cover is partial
	gaps           int
}

// classifyTruncations separates the "truncated-enumeration" gaps by the cause
// each message names, so a reader can tell a budget cut from a RemainingCap cut
// from an incomplete cover instead of one lumped count.
func classifyTruncations(gaps []model.Gap) (budget, remaining, cover int) {
	for _, gap := range gaps {
		if gap.Kind != "truncated-enumeration" {
			continue
		}
		switch {
		case strings.Contains(gap.Message, "global exploration budget"):
			budget++
		case strings.Contains(gap.Message, "counted up to a cap"):
			remaining++
		case strings.Contains(gap.Message, "verified cover is partial"):
			cover++
		}
	}
	return budget, remaining, cover
}

func summarize(result Result) solveControls {
	controls := solveControls{
		pairs:    len(result.Pairs),
		routes:   len(result.Paths),
		steps:    len(result.Cover.Steps),
		complete: result.Cover.Complete,
		gaps:     len(result.Gaps),
	}
	for _, pair := range result.Pairs {
		if pair.Reachable {
			controls.reachable++
		}
	}
	for _, routed := range result.Paths {
		for _, cut := range routed.Path.Cuts {
			if cut.Verified {
				controls.verified++
			} else {
				controls.unverified++
			}
		}
	}
	controls.budgetTrunc, controls.remainingTrunc, controls.coverTrunc = classifyTruncations(result.Gaps)
	return controls
}

// exploredExtensions replays the enumeration accounting of Solve (step 5) over
// the reachable pairs to report, as a control, how much of the global budget the
// scenario actually spent.
func exploredExtensions(edges []model.Edge, opts Options) int {
	budget := opts.Budget
	total := 0
	for _, pair := range reachability(edges, opts) {
		if !pair.Reachable {
			continue
		}
		_, explored, _ := SimplePaths(edges, pair.Pair.Source, pair.Pair.Target, opts.MaxDepth, budget)
		budget -= explored
		total += explored
	}
	return total
}

func reportControls(b *testing.B, controls solveControls) {
	b.ReportMetric(float64(controls.pairs), "pairs")
	b.ReportMetric(float64(controls.reachable), "reachable")
	b.ReportMetric(float64(controls.routes), "routes")
	b.ReportMetric(float64(controls.verified), "verified_cuts")
	b.ReportMetric(float64(controls.unverified), "unverified_cuts")
	b.ReportMetric(float64(controls.steps), "cover_steps")
	b.ReportMetric(float64(controls.budgetTrunc), "budget_trunc")
	b.ReportMetric(float64(controls.remainingTrunc), "remaining_trunc")
	b.ReportMetric(float64(controls.coverTrunc), "cover_trunc")
	b.ReportMetric(float64(controls.gaps), "gaps")
	complete := 0.0
	if controls.complete {
		complete = 1.0
	}
	b.ReportMetric(complete, "cover_complete")
}

// benchmarkInput is prepared once per sub-benchmark: deriving the edges must stay
// outside the timed loop, since what is measured is the analysis.
type benchmarkInput struct {
	ix     *snapshot.Index
	edges  []model.Edge
	opts   Options
	route  model.Path
	source string
	target string
}

// prepare derives the fixture, the edges and one route, and normalizes the
// options so the isolated benchmarks measure the step with the engine's own
// defaults rather than with zeroed ceilings.
func prepare(tb testing.TB, scale benchScale) benchmarkInput {
	tb.Helper()
	ix := largeFixture(tb, scale.names, scale.depth, scale.width)
	edges, err := hops.Edges(ix)
	if err != nil {
		tb.Fatalf("hops.Edges: %v", err)
	}
	source, target := originID(0, 0), hops.TargetClusterAdmin
	found, _, truncated := SimplePaths(edges, source, target, scale.hopLimit(), DefaultBudget)
	if truncated || len(found) == 0 {
		tb.Fatalf("prepare: enumeration truncated=%v, routes=%d", truncated, len(found))
	}
	return benchmarkInput{
		ix:     ix,
		edges:  edges,
		opts:   normalizedOpts(tb, singlePairOptions(scale)),
		route:  model.Path{ID: PathID(found[0]), Source: source, Target: target, Edges: found[0]},
		source: source,
		target: target,
	}
}

func BenchmarkReach(b *testing.B) {
	for _, scale := range benchExploratory {
		in := prepare(b, scale)
		b.Run(scale.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Reach(in.edges, in.source, in.target, scale.hopLimit())
			}
		})
	}
}

func BenchmarkSimplePaths(b *testing.B) {
	for _, scale := range benchExploratory {
		in := prepare(b, scale)
		b.Run(scale.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				SimplePaths(in.edges, in.source, in.target, scale.hopLimit(), DefaultBudget)
			}
		})
	}
}

// BenchmarkVerifyCuts isolates step 6: one route, each candidate rebuilt in the
// hypothetical model through the real hops.Rebuild. The candidate count is
// computed before the timer starts.
func BenchmarkVerifyCuts(b *testing.B) {
	for _, scale := range benchExploratory {
		in := prepare(b, scale)
		candidates := len(pathCandidates(in.route))
		rebuild := func(removed []model.Grant) ([]model.Edge, error) { return hops.Rebuild(in.ix, removed) }
		b.Run(scale.name, func(b *testing.B) {
			b.ReportMetric(float64(candidates), "candidates/op")
			b.ReportMetric(float64(in.opts.RemainingCap), "remaining_cap")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := verifyCuts(in.opts, rebuild, in.route); err != nil {
					b.Fatalf("verifyCuts: %v", err)
				}
			}
		})
	}
}

// BenchmarkGreedyCover isolates step 7 over the routes step 5 already enumerated:
// each step rebuilds the whole graph from the accumulated removal set. The
// baseline Solve (without a rebuild) that supplies the pairs and routes runs
// before the sub-benchmark's timer starts.
func BenchmarkGreedyCover(b *testing.B) {
	for _, scale := range benchExploratory {
		in := prepare(b, scale)
		base, err := Solve(in.opts, in.edges, nil)
		if err != nil {
			b.Fatalf("Solve without rebuild: %v", err)
		}
		rebuild := func(removed []model.Grant) ([]model.Edge, error) { return hops.Rebuild(in.ix, removed) }
		b.Run(scale.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportMetric(float64(in.opts.MaxCoverSteps), "max_steps")
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, err := greedyCover(in.opts, in.edges, rebuild, base.Paths, base.Pairs); err != nil {
					b.Fatalf("greedyCover: %v", err)
				}
			}
		})
	}
}

// BenchmarkSolve is the aggregate of steps 4-7 over precomputed edges (the
// derivation is BenchmarkEdges), with one origin per namespace so the number of
// pairs grows with the scale: what `analyze` does once its graph is built.
func BenchmarkSolve(b *testing.B) {
	for _, scale := range append([]benchScale{benchBase}, benchStress...) {
		in := prepare(b, scale)
		opts := normalizedOpts(b, allOriginsOptions(scale))
		rebuild := func(removed []model.Grant) ([]model.Edge, error) { return hops.Rebuild(in.ix, removed) }
		// One Solve and the enumeration accounting run before the timer reports the
		// reader's controls (pairs, routes, cuts, cover, gaps, extensions) without
		// charging them to the measured loop. ReportMetric must follow ResetTimer:
		// a reset clears metrics registered before it.
		baseline, err := Solve(opts, in.edges, rebuild)
		if err != nil {
			b.Fatalf("Solve baseline: %v", err)
		}
		extensions := exploredExtensions(in.edges, opts)
		b.Run(scale.name, func(b *testing.B) {
			b.ResetTimer()
			reportControls(b, summarize(baseline))
			b.ReportMetric(float64(extensions), "explored_extensions")
			b.ReportMetric(float64(opts.Budget), "budget")
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Solve(opts, in.edges, rebuild); err != nil {
					b.Fatalf("Solve: %v", err)
				}
			}
		})
	}
}

// BenchmarkSolveWithoutRebuild is the reference for the combined overhead of cut
// verification and the cover: with no rebuild function neither step runs.
func BenchmarkSolveWithoutRebuild(b *testing.B) {
	for _, scale := range append([]benchScale{benchBase}, benchStress...) {
		in := prepare(b, scale)
		opts := normalizedOpts(b, allOriginsOptions(scale))
		baseline, err := Solve(opts, in.edges, nil)
		if err != nil {
			b.Fatalf("Solve baseline: %v", err)
		}
		b.Run(scale.name, func(b *testing.B) {
			b.ResetTimer()
			reportControls(b, summarize(baseline))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Solve(opts, in.edges, nil); err != nil {
					b.Fatalf("Solve without rebuild: %v", err)
				}
			}
		})
	}
}

// BenchmarkEdges measures the edge derivation that the Solve benchmarks leave
// outside their timers.
func BenchmarkEdges(b *testing.B) {
	for _, scale := range benchExploratory {
		in := prepare(b, scale)
		b.Run(scale.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := hops.Edges(in.ix); err != nil {
					b.Fatalf("hops.Edges: %v", err)
				}
			}
		})
	}
}
