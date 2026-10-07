package graph

import (
	"reflect"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
)

func granted(from, to, hop string, grants ...model.Grant) model.Edge {
	return model.Edge{From: from, To: to, HopID: hop, Confidence: "definite", Grants: grants}
}

func removal(kind, detail, objectKind, objectNamespace, objectName string) model.Grant {
	return model.Grant{
		Object: model.ObjectRef{Kind: objectKind, Namespace: objectNamespace, Name: objectName},
		Kind:   kind,
		Detail: detail,
	}
}

// stubRebuild returns the same edges whatever is removed, which is enough to
// exercise the pure steps without a model.
func stubRebuild(edges []model.Edge) Rebuild {
	return func([]model.Grant) ([]model.Edge, error) { return edges, nil }
}

func pathString(path []model.Edge) string {
	parts := make([]string, 0, len(path)+1)
	if len(path) > 0 {
		parts = append(parts, path[0].From)
	}
	for _, edge := range path {
		parts = append(parts, edge.To)
	}
	return strings.Join(parts, ">")
}

func TestReachReturnsTheMinimumDistance(t *testing.T) {
	edges := []model.Edge{
		granted("a", "b", "NR-001"),
		granted("b", "c", "NR-002"),
		granted("a", "c", "NR-003"),
		granted("c", "d", "NR-004"),
	}

	if distance, ok := Reach(edges, "a", "c", 4); !ok || distance != 1 {
		t.Errorf("Reach(a, c) = (%d, %v), want (1, true): the direct edge is shorter", distance, ok)
	}
	if distance, ok := Reach(edges, "a", "d", 4); !ok || distance != 2 {
		t.Errorf("Reach(a, d) = (%d, %v), want (2, true)", distance, ok)
	}
	if distance, ok := Reach(edges, "d", "a", 4); ok {
		t.Errorf("Reach(d, a) = (%d, %v), want unreachable: the graph is directed", distance, ok)
	}
	if _, ok := Reach(edges, "a", "d", 1); ok {
		t.Error("Reach(a, d) reported reachable with maxDepth 1")
	}
}

// TestReachDistanceIsIndependentOfEnumerationBudget is the P2-01 property: the
// minimum distance comes from the BFS, not from the paths an enumeration manages
// to produce before its budget runs out.
func TestReachDistanceIsIndependentOfEnumerationBudget(t *testing.T) {
	edges := []model.Edge{
		granted("a", "x1", "NR-001"),
		granted("x1", "y1", "NR-001"),
		granted("x1", "z1", "NR-001"),
		granted("y1", "w1", "NR-001"),
		granted("z1", "w1", "NR-001"),
		granted("w1", "t", "rbac-cluster-admin"),
	}

	if distance, ok := Reach(edges, "a", "t", 8); !ok || distance != 4 {
		t.Fatalf("Reach(a, t) = (%d, %v), want (4, true)", distance, ok)
	}

	// The same question through Solve, with a budget too small to enumerate a
	// single complete path.
	result, err := Solve(Options{
		Sources: []string{"a"},
		Targets: []string{"t"},
		Budget:  1,
		System:  []string{},
	}, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(result.Pairs) != 1 || !result.Pairs[0].Reachable || result.Pairs[0].Distance != 4 {
		t.Errorf("pairs = %+v, want the pair reachable at distance 4 despite the truncated enumeration", result.Pairs)
	}
	if len(result.Paths) != 0 {
		t.Errorf("truncated enumeration returned %d paths, want none with a budget of 1", len(result.Paths))
	}
}

func TestReachTreatsASourceAsItsOwnTarget(t *testing.T) {
	if distance, ok := Reach(nil, "a", "a", 0); !ok || distance != 0 {
		t.Errorf("Reach(a, a) = (%d, %v), want (0, true)", distance, ok)
	}
	if paths, explored, truncated := SimplePaths(nil, "a", "a", 4, 10); paths != nil || explored != 0 || truncated {
		t.Errorf("SimplePaths(a, a) = (%v, %d, %v), want no path", paths, explored, truncated)
	}
}

func TestSimplePathsOrdersByLengthThenID(t *testing.T) {
	edges := []model.Edge{
		granted("a", "d", "NR-004"),
		granted("a", "b", "NR-001"),
		granted("b", "d", "NR-002"),
		granted("a", "c", "NR-003"),
		granted("c", "d", "NR-005"),
	}

	paths, _, truncated := SimplePaths(edges, "a", "d", 4, 100)
	if truncated {
		t.Fatal("enumeration reported truncation with a budget of 100")
	}
	if len(paths) != 3 {
		t.Fatalf("found %d paths, want 3", len(paths))
	}
	if got := pathString(paths[0]); got != "a>d" {
		t.Errorf("first path is %q, want the shortest route a>d", got)
	}
	rest := []string{PathID(paths[1]), PathID(paths[2])}
	if rest[0] >= rest[1] {
		t.Errorf("two-hop paths are not ordered by PathID: %v", rest)
	}
	for _, path := range paths[1:] {
		if len(path) != 2 {
			t.Errorf("path %q has %d hops, want the remaining two to be 2-hop routes", pathString(path), len(path))
		}
	}
}

func TestSimplePathsKeepsRoutesSimple(t *testing.T) {
	edges := []model.Edge{
		granted("a", "b", "NR-001"),
		granted("b", "c", "NR-002"),
		granted("c", "b", "NR-003"),
		granted("c", "d", "NR-004"),
		granted("b", "d", "NR-005"),
	}

	paths, _, _ := SimplePaths(edges, "a", "d", 6, 100)
	if len(paths) != 2 {
		t.Fatalf("found %d paths, want the two acyclic routes (a>b>c>d and a>b>d)", len(paths))
	}
	for _, path := range paths {
		seen := map[string]bool{}
		for _, edge := range path {
			if seen[edge.To] {
				t.Errorf("path %q repeats node %s", pathString(path), edge.To)
			}
			seen[edge.To] = true
		}
	}
}

func TestSimplePathsRespectsMaxDepthBoundary(t *testing.T) {
	edges := []model.Edge{
		granted("a", "b", "NR-001"),
		granted("b", "c", "NR-002"),
		granted("c", "t", "NR-003"),
	}

	short, _, _ := SimplePaths(edges, "a", "t", 2, 100)
	if len(short) != 0 {
		t.Errorf("a 3-hop path was found with maxDepth 2: %v", short)
	}
	if _, ok := Reach(edges, "a", "t", 2); ok {
		t.Error("Reach reported a 3-hop target reachable with maxDepth 2")
	}

	full, _, _ := SimplePaths(edges, "a", "t", 3, 100)
	if len(full) != 1 || len(full[0]) != 3 {
		t.Fatalf("with maxDepth 3 got %d paths of lengths %v, want one 3-hop path", len(full), full)
	}
	if distance, ok := Reach(edges, "a", "t", 3); !ok || distance != 3 {
		t.Errorf("Reach(a, t, 3) = (%d, %v), want (3, true)", distance, ok)
	}
}

func TestSimplePathsStopAtTheBudgetAndReportIt(t *testing.T) {
	edges := []model.Edge{}
	for _, node := range []string{"b", "c", "d"} {
		edges = append(edges, granted("a", node, "NR-001"), granted(node, "t", "NR-002"))
	}

	paths, explored, truncated := SimplePaths(edges, "a", "t", 4, 2)
	if !truncated {
		t.Fatal("budget of 2 reported a complete enumeration")
	}
	if explored > 2 {
		t.Errorf("explored %d extensions with a budget of 2", explored)
	}
	// Two extensions are exactly one complete route: the enumeration stops
	// before exploring the remaining branches, so the list is partial.
	if len(paths) != 1 || len(paths[0]) != 2 {
		t.Errorf("budget of 2 returned %v, want the first complete 2-hop route only", paths)
	}

	if _, explored, truncated := SimplePaths(edges, "a", "t", 4, 0); !truncated || explored != 0 {
		t.Error("a zero budget reported a complete enumeration")
	}

	all, explored, truncated := SimplePaths(edges, "a", "t", 4, 100)
	if truncated || explored != 6 || len(all) != 3 {
		t.Errorf("budget 100: %d paths, %d extensions, truncated=%v; want 3/6/false", len(all), explored, truncated)
	}
}

func TestSolveAppliesTheBudgetAcrossPairsAndGapsEachOne(t *testing.T) {
	edges := []model.Edge{
		granted("s1", "b", "NR-001"),
		granted("b", "t", "NR-002"),
		granted("s2", "c", "NR-001"),
		granted("c", "t", "NR-002"),
	}
	sources := []string{"s1", "s2"}

	truncated, err := Solve(Options{Sources: sources, Targets: []string{"t"}, Budget: 1, System: []string{}}, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(truncated.Paths) != 0 {
		t.Errorf("a budget of 1 produced %d paths", len(truncated.Paths))
	}
	if got := gapSubjects(truncated.Gaps, "truncated-enumeration"); !reflect.DeepEqual(got, []string{"s1 -> t", "s2 -> t"}) {
		t.Errorf("budget 1 left gaps for %v, want one per pair that was not enumerated", got)
	}

	// A budget of 2 is exactly one complete route: it must be spent globally, so
	// the first pair is enumerated and the second is not. Per-pair budgets would
	// enumerate both and is what this case rules out.
	spent, err := Solve(Options{Sources: sources, Targets: []string{"t"}, Budget: 2, System: []string{}}, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(spent.Paths) != 1 {
		t.Fatalf("a budget of 2 produced %d paths, want the first pair's single route", len(spent.Paths))
	}
	if got := spent.Paths[0].Path.Source; got != "s1" {
		t.Errorf("the enumerated route starts at %q, want the first pair in order", got)
	}
	if got := gapSubjects(spent.Gaps, "truncated-enumeration"); !reflect.DeepEqual(got, []string{"s2 -> t"}) {
		t.Errorf("budget 2 left gaps for %v, want only the second pair", got)
	}

	full, err := Solve(Options{Sources: sources, Targets: []string{"t"}, System: []string{}}, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(full.Paths) != 2 {
		t.Errorf("without truncation got %d paths, want 2", len(full.Paths))
	}
	if got := gapSubjects(full.Gaps, "truncated-enumeration"); len(got) != 0 {
		t.Errorf("an untruncated run reported gaps for %v", got)
	}
	// The truncation of the enumeration must not change reachability.
	if full.Pairs[0] != truncated.Pairs[0] || full.Pairs[1] != truncated.Pairs[1] {
		t.Errorf("the enumeration budget changed reachability:\n full      %+v\n truncated %+v", full.Pairs, truncated.Pairs)
	}
}

func TestSolveKeepsOnlyPathsPerPair(t *testing.T) {
	edges := []model.Edge{
		granted("s", "t", "rbac-cluster-admin"),
		granted("s", "b", "NR-001"),
		granted("b", "t", "NR-002"),
		granted("s", "c", "NR-003"),
		granted("c", "t", "NR-004"),
	}

	result, err := Solve(Options{
		Sources:      []string{"s"},
		Targets:      []string{"t"},
		PathsPerPair: 2,
		System:       []string{},
	}, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(result.Paths) != 2 {
		t.Fatalf("kept %d paths, want PathsPerPair (2)", len(result.Paths))
	}
	if got := pathString(result.Paths[0].Path.Edges); got != "s>t" {
		t.Errorf("first kept path is %q, want the shortest one", got)
	}
}

func TestSolveNormalizesOptions(t *testing.T) {
	edges := []model.Edge{granted("s", "t", "NR-001")}

	result, err := Solve(Options{Sources: []string{"s"}, Targets: []string{"t"}}, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve with zero values: %v", err)
	}
	if len(result.Pairs) != 1 {
		t.Fatalf("zero values produced %d pairs", len(result.Pairs))
	}

	if _, err := Solve(Options{Sources: []string{"s"}, Targets: []string{"t"}, MaxDepth: -1}, edges, nil); err == nil {
		t.Error("Solve accepted a negative MaxDepth")
	}
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"no source", Options{Targets: []string{"t"}}},
		{"no target", Options{Sources: []string{"s"}}},
		{"empty source id", Options{Sources: []string{""}, Targets: []string{"t"}}},
		{"negative budget", Options{Sources: []string{"s"}, Targets: []string{"t"}, Budget: -5}},
		{"negative cover steps", Options{Sources: []string{"s"}, Targets: []string{"t"}, MaxCoverSteps: -1}},
		{"negative remaining cap", Options{Sources: []string{"s"}, Targets: []string{"t"}, RemainingCap: -1}},
		{"negative paths per pair", Options{Sources: []string{"s"}, Targets: []string{"t"}, PathsPerPair: -3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Solve(tc.opts, edges, nil); err == nil {
				t.Error("Solve accepted invalid options")
			}
		})
	}

	// Duplicates are dropped keeping the first appearance, so the pair list is
	// reproducible.
	result, err = Solve(Options{Sources: []string{"s", "s"}, Targets: []string{"t", "t"}}, edges, nil)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(result.Pairs) != 1 {
		t.Errorf("duplicated ids produced %d pairs, want 1", len(result.Pairs))
	}
}

func TestSolveWithoutRebuildDeclaresWhatItCouldNotVerify(t *testing.T) {
	edges := []model.Edge{granted("s", "t", "rbac-cluster-admin")}

	result, err := Solve(Options{Sources: []string{"s"}, Targets: []string{"t"}}, edges, nil)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("got %d paths, want the path itself", len(result.Paths))
	}
	if result.Paths[0].Path.Cuts != nil {
		t.Errorf("cuts were reported without a rebuild function: %+v", result.Paths[0].Path.Cuts)
	}
	var declared bool
	for _, gap := range result.Gaps {
		if gap.Subject == "cut-verification" && gap.Kind == "missing-input" {
			declared = true
		}
	}
	if !declared {
		t.Errorf("no Gap declared the missing verification: %+v", result.Gaps)
	}
	if result.Cover.Complete {
		t.Error("the cover claimed completeness while pairs stayed reachable and no rebuild existed")
	}
	if len(result.Cover.Steps) != 0 {
		t.Errorf("cover proposed %d steps without a rebuild function", len(result.Cover.Steps))
	}

	empty, err := Solve(Options{Sources: []string{"s"}, Targets: []string{"nowhere"}}, edges, nil)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if !empty.Cover.Complete || len(empty.Cover.Steps) != 0 {
		t.Errorf("with nothing reachable the empty cover should be complete: %+v", empty.Cover)
	}
}

func TestSolveIsDeterministicAcrossEdgeOrder(t *testing.T) {
	edges := []model.Edge{
		granted("s", "b", "NR-001", removal("binding-subject", "subject ServiceAccount app/s", "ClusterRoleBinding", "", "b1")),
		granted("b", "t", "NR-002"),
		granted("s", "c", "NR-003"),
		granted("c", "t", "NR-004"),
		granted("s", "t", "rbac-cluster-admin"),
	}
	reversed := make([]model.Edge, len(edges))
	for i, edge := range edges {
		reversed[len(edges)-1-i] = edge
	}

	opts := Options{Sources: []string{"s"}, Targets: []string{"t"}, System: []string{}}
	first, err := Solve(opts, edges, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	second, err := Solve(opts, reversed, stubRebuild(edges))
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}

	// The whole result must match, not only the identifiers: cuts with their
	// Verified and RemainingPaths, gaps and the state of the cover included.
	if !reflect.DeepEqual(first, second) {
		t.Errorf("the result depends on the edge order: first %+v, second %+v", first, second)
	}
}

// gapSubjects returns the subjects of the gaps of one kind, in order.
func gapSubjects(gaps []model.Gap, kind string) []string {
	var out []string
	for _, gap := range gaps {
		if gap.Kind == kind {
			out = append(out, gap.Subject)
		}
	}
	return out
}

// TestReachAgreesWithShortestPath keeps the two traversals from drifting: Reach
// answers the distance and ShortestPath returns the route, and both must agree
// with each other for every pair of a graph with parallel edges and a cycle.
// They stay separate implementations because ShortestPath rebuilds the edge
// sequence at every visit, which the cut verification path — where Reach runs
// once per candidate — does not need.
func TestReachAgreesWithShortestPath(t *testing.T) {
	edges := []model.Edge{
		granted("a", "b", "NR-001"),
		granted("b", "c", "NR-002"),
		granted("a", "c", "NR-003"),
		granted("c", "b", "NR-004"),
		granted("c", "t", "NR-005"),
		granted("b", "t", "NR-006"),
		granted("a", "t", "NR-007"),
	}
	nodes := []string{"a", "b", "c", "t", "absent"}

	for _, source := range nodes {
		for _, target := range nodes {
			for _, maxDepth := range []int{1, 2, 3, 8} {
				distance, reachable := Reach(edges, source, target, maxDepth)
				path, ok := ShortestPath(edges, source, target, maxDepth)
				if reachable != ok {
					t.Fatalf("Reach(%s, %s, %d) = %v but ShortestPath = %v", source, target, maxDepth, reachable, ok)
				}
				if !reachable {
					continue
				}
				if distance != len(path) {
					t.Errorf("Reach(%s, %s, %d) says %d hops but ShortestPath returns %d",
						source, target, maxDepth, distance, len(path))
				}
			}
		}
	}
}

func TestSolveNormalizesSensitiveNamespaces(t *testing.T) {
	// nil means the default sensitive list; a non-nil empty list means none.
	// Both are expressible, so neither is guessed.
	opts := Options{Sources: []string{"s"}, Targets: []string{"t"}}
	normalized, err := opts.normalized()
	if err != nil {
		t.Fatalf("normalized: %v", err)
	}
	if len(normalized.Sensitive) == 0 {
		t.Errorf("a nil Sensitive list did not fall back to the default")
	}

	empty := Options{Sources: []string{"s"}, Targets: []string{"t"}, Sensitive: []string{}}
	normalized, err = empty.normalized()
	if err != nil {
		t.Fatalf("normalized: %v", err)
	}
	if len(normalized.Sensitive) != 0 {
		t.Errorf("an empty non-nil Sensitive list was replaced by the default: %v", normalized.Sensitive)
	}
}
