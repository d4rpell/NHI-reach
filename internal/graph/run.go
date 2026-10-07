package graph

import (
	"fmt"
	"sort"

	"github.com/d4rpell/nhi-reach/internal/hops"
	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// Defaults of an analysis run. DefaultMaxDepth and DefaultPathsPerPair are the
// CLI defaults of spec §1; the other three are chosen ceilings, not measured
// figures, and T3-02 measures them on a large fixture.
const (
	// DefaultMaxDepth is the default hop limit (--max-depth, spec §1).
	DefaultMaxDepth = 4
	// DefaultPathsPerPair is the default K of enumerations per pair
	// (--paths-per-pair, spec §1).
	DefaultPathsPerPair = 3
	// DefaultBudget is the default global cap on path extensions explored while
	// enumerating.
	DefaultBudget = 100000
	// DefaultMaxCoverSteps is the default cap on the steps of the greedy
	// bottleneck cover; spec §3 step 7 leaves the number open.
	DefaultMaxCoverSteps = 32
	// DefaultRemainingCap is the default cap on the work spent counting the
	// paths that remain after an unverified cut.
	DefaultRemainingCap = 1000
)

// Options configures one analysis run. Sources and Targets are required; the
// numeric fields and System are normalized by Solve.
type Options struct {
	Sources       []string // origin node ids; at least one
	Targets       []string // target node ids; at least one
	MaxDepth      int      // hop limit per path; 0 means DefaultMaxDepth
	PathsPerPair  int      // paths kept per pair; 0 means DefaultPathsPerPair
	Budget        int      // global cap on explored path extensions; 0 means DefaultBudget
	MaxCoverSteps int      // cap on cover steps; 0 means DefaultMaxCoverSteps
	RemainingCap  int      // cap on the work of RemainingPaths; 0 means DefaultRemainingCap
	System        []string // system namespaces (spec §2.6); nil means the default list
}

// Pair is one (origin, target) pair of the analysis.
type Pair struct {
	Source string
	Target string
}

// PairReach is the reachability of one pair (spec §3 step 4): whether the target
// is reachable from the origin and at what minimum distance, in the model and up
// to --max-depth. It does not depend on the enumeration budget (spec §3 step 5).
type PairReach struct {
	Pair      Pair
	Reachable bool
	Distance  int
}

// RoutedPath is one enumerated path together with the system-identity flag of
// spec §2.6, which the report highlights.
type RoutedPath struct {
	Path      model.Path
	ViaSystem bool
}

// Bottleneck is one step of the greedy verified cover (spec §3 step 7): the
// grant proposed for removal and the pairs that stopped being reachable with it.
// Eliminated is empty for a step that was removed without cutting a pair on its
// own; the step still belongs to the proposed set.
type Bottleneck struct {
	Grant      model.Grant
	Change     string
	Eliminated []Pair
}

// Cover is the proposed set of changes of spec §3 step 7 with an explicit
// completeness flag. Only Complete == true says that applying every Step leaves
// no pair reachable: with false the set is partial and the Gaps say why. Even
// then the set is a verified heuristic, never a minimum (D-011).
type Cover struct {
	Steps    []Bottleneck
	Complete bool
}

// Result is the outcome of one run.
type Result struct {
	Pairs []PairReach  // step 4, ordered by (Source, Target)
	Paths []RoutedPath // step 5, ordered by (Source, Target, length, PathID)
	Cover Cover        // step 7
	Gaps  []model.Gap  // truncated work and verification that could not be done
}

// Rebuild derives the edges of a hypothetical model in which the given grants
// have been removed. It must start from the original snapshot and apply the
// whole set it receives; it must never modify that snapshot.
type Rebuild func(removed []model.Grant) ([]model.Edge, error)

// Model is the reachability graph of one snapshot together with the ability to
// rebuild it after removing grants: cut verification is exactly that, a
// hypothetical model held in memory (spec §3 step 6).
type Model struct {
	edges   []model.Edge
	rebuild Rebuild
}

// New returns a model over an edge set. rebuild derives the edges of a
// hypothetical model after removals; when it is nil the model cannot verify
// cuts, and Analyze says so with a Gap instead of reporting cuts as if they had
// been checked.
func New(edges []model.Edge, rebuild Rebuild) *Model {
	return &Model{edges: edges, rebuild: rebuild}
}

// FromSnapshot derives the edges of a loaded snapshot through hops and wires the
// rebuild that applies a removal to a copy of that snapshot.
func FromSnapshot(ix *snapshot.Index) (*Model, error) {
	edges, err := hops.Edges(ix)
	if err != nil {
		return nil, err
	}
	return New(edges, func(removed []model.Grant) ([]model.Edge, error) {
		return hops.Rebuild(ix, removed)
	}), nil
}

// Edges returns the edge set the model was built over.
func (m *Model) Edges() []model.Edge { return m.edges }

// Analyze runs the reachability, enumeration, cut verification and bottleneck
// coverage of spec §3 steps 4–7 over the model.
func (m *Model) Analyze(opts Options) (Result, error) {
	return Solve(opts, m.edges, m.rebuild)
}

// Solve runs the analysis over an edge set. It is Analyze without the model
// wrapper, so the pure steps can be exercised without a snapshot.
func Solve(opts Options, edges []model.Edge, rebuild Rebuild) (Result, error) {
	normalized, err := opts.normalized()
	if err != nil {
		return Result{}, err
	}

	var gaps []model.Gap
	result := Result{Pairs: reachability(edges, normalized)}

	budget := normalized.Budget
	var paths []RoutedPath
	for _, reach := range result.Pairs {
		if !reach.Reachable {
			continue
		}
		found, explored, truncated := SimplePaths(edges, reach.Pair.Source, reach.Pair.Target, normalized.MaxDepth, budget)
		budget -= explored
		if truncated {
			gaps = append(gaps, gapTruncatedEnumeration(reach.Pair, normalized))
		}
		if len(found) > normalized.PathsPerPair {
			found = found[:normalized.PathsPerPair]
		}
		for _, edgePath := range found {
			path := model.Path{
				ID:     PathID(edgePath),
				Source: reach.Pair.Source,
				Target: reach.Pair.Target,
				Edges:  edgePath,
			}
			paths = append(paths, RoutedPath{Path: path, ViaSystem: ViaSystem(path, SystemNamespaces(normalized.System))})
		}
	}

	if rebuild == nil {
		gaps = append(gaps, gapCutVerificationUnavailable())
	} else {
		for i := range paths {
			cuts, cutGaps, err := verifyCuts(normalized, rebuild, paths[i].Path)
			if err != nil {
				return Result{}, err
			}
			paths[i].Path.Cuts = cuts
			gaps = append(gaps, cutGaps...)
		}
	}
	result.Paths = paths

	cover, coverGaps, err := greedyCover(normalized, edges, rebuild, paths, result.Pairs)
	if err != nil {
		return Result{}, err
	}
	result.Cover = cover
	gaps = append(gaps, coverGaps...)

	result.Gaps = normalizeGaps(gaps)
	return result, nil
}

// normalized applies the defaults of Options and rejects the values that cannot
// be interpreted. It never chooses a meaning silently: a negative figure, an
// empty source or target list and an empty node id are errors, and after it runs
// every numeric field is at least 1.
func (o Options) normalized() (Options, error) {
	sources, err := nodeIDs(o.Sources, "Sources")
	if err != nil {
		return Options{}, err
	}
	targets, err := nodeIDs(o.Targets, "Targets")
	if err != nil {
		return Options{}, err
	}
	o.Sources, o.Targets = sources, targets

	for _, field := range []struct {
		name     string
		value    *int
		fallback int
	}{
		{"MaxDepth", &o.MaxDepth, DefaultMaxDepth},
		{"PathsPerPair", &o.PathsPerPair, DefaultPathsPerPair},
		{"Budget", &o.Budget, DefaultBudget},
		{"MaxCoverSteps", &o.MaxCoverSteps, DefaultMaxCoverSteps},
		{"RemainingCap", &o.RemainingCap, DefaultRemainingCap},
	} {
		switch {
		case *field.value < 0:
			return Options{}, fmt.Errorf("graph: Options.%s cannot be negative (%d)", field.name, *field.value)
		case *field.value == 0:
			*field.value = field.fallback
		}
	}

	// A nil System means the default list of §2.6; an empty but non-nil list
	// means no system namespace at all. Both are expressible, so neither has to
	// be guessed.
	if o.System == nil {
		o.System = append([]string(nil), DefaultSystemNamespaces()...)
	}
	return o, nil
}

// nodeIDs validates and de-duplicates an ordered node id list, keeping the first
// appearance of every duplicate so the pair order stays reproducible.
func nodeIDs(values []string, field string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("graph: Options.%s needs at least one value", field)
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			return nil, fmt.Errorf("graph: Options.%s holds an empty node id", field)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}

// reachability answers spec §3 step 4 for every requested pair, ordered by
// (Source, Target).
func reachability(edges []model.Edge, opts Options) []PairReach {
	pairs := make([]PairReach, 0, len(opts.Sources)*len(opts.Targets))
	for _, source := range opts.Sources {
		for _, target := range opts.Targets {
			distance, ok := Reach(edges, source, target, opts.MaxDepth)
			pairs = append(pairs, PairReach{
				Pair:      Pair{Source: source, Target: target},
				Reachable: ok,
				Distance:  distance,
			})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return lessPair(pairs[i].Pair, pairs[j].Pair) })
	return pairs
}

func lessPair(a, b Pair) bool {
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.Target < b.Target
}

// normalizeGaps drops exact duplicates — one pair can produce the same gap from
// several cuts — and orders the rest by (Kind, Subject, Message).
func normalizeGaps(gaps []model.Gap) []model.Gap {
	if len(gaps) == 0 {
		return nil
	}
	seen := make(map[model.Gap]bool, len(gaps))
	out := make([]model.Gap, 0, len(gaps))
	for _, gap := range gaps {
		if seen[gap] {
			continue
		}
		seen[gap] = true
		out = append(out, gap)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Message < b.Message
	})
	return out
}
