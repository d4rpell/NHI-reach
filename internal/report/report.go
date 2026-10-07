// Package report renders the analysis result.
//
// The renderers depend only on this package's output types, never on the frozen
// types of internal/model directly: those carry no JSON tags, so every field of
// the JSON schema is declared here, in snake_case, and built by the caller. The
// output depends only on its arguments, so equal analyses render equal bytes.
package report

import (
	"sort"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// SchemaVersion is the version of the JSON schema (spec §4). A breaking change
// to the output bumps it.
const SchemaVersion = 1

// Report is the complete, renderer-independent result of one analysis.
type Report struct {
	SchemaVersion       int          `json:"schema_version"`
	Params              Params       `json:"params"`
	Paths               []PathView   `json:"paths"`
	Cuts                []CutView    `json:"cuts"`
	Bottlenecks         []Bottleneck `json:"bottlenecks"`
	CoverComplete       bool         `json:"cover_complete"`
	Gaps                []GapView    `json:"gaps"`
	InputManifestSHA256 string       `json:"input_manifest_sha256"`
	RulesCatalogSHA256  string       `json:"rules_catalog_sha256"`
}

// Params records the parameters of the run. SensitiveNamespaces is the effective
// list (the defaults plus any added with --sensitive-ns), ordered.
type Params struct {
	MaxDepth            int      `json:"max_depth"`
	PathsPerPair        int      `json:"paths_per_pair"`
	Targets             []string `json:"targets"`
	FromIdentity        string   `json:"from_identity"`
	IncludeSystem       bool     `json:"include_system"`
	SystemNamespaces    []string `json:"system_namespaces"`
	SensitiveNamespaces []string `json:"sensitive_namespaces"`
}

// PathView is one escalation route with what the table and the JSON need.
type PathView struct {
	ID           string     `json:"id"`
	Source       string     `json:"source"`
	Target       string     `json:"target"`
	Hops         int        `json:"hops"`
	Confidence   string     `json:"confidence"`
	ViaSystem    bool       `json:"via_system"`
	SystemOrigin bool       `json:"system_origin"`
	Route        []StepView `json:"route"`
}

// StepView is one hop of a path.
type StepView struct {
	From       string    `json:"from"`
	To         string    `json:"to"`
	HopID      string    `json:"hop_id"`
	Confidence string    `json:"confidence"`
	Evidence   []RefView `json:"evidence"`
}

// RefView is one normalized object reference.
type RefView struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
}

// CutView is one proposed cut, tied to its path by PathID.
type CutView struct {
	PathID         string    `json:"path_id"`
	Grant          GrantView `json:"grant"`
	Change         string    `json:"change"`
	Verified       bool      `json:"verified"`
	RemainingPaths int       `json:"remaining_paths"`
}

// GrantView is one removable unit.
type GrantView struct {
	Object RefView `json:"object"`
	Kind   string  `json:"kind"`
	Detail string  `json:"detail"`
}

// Bottleneck is one step of the verified cover (spec §3 step 7).
type Bottleneck struct {
	Change     string     `json:"change"`
	Eliminated []PairView `json:"eliminated"`
}

// PairView is one (origin, target) pair.
type PairView struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// GapView is one missing input or truncated analysis.
type GapView struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// Normalize returns a copy of the report with every slice non-nil and the paths
// in a deterministic order: by target, then application origins before system
// ones, then origin, hop count and path id. It never reorders cuts within a
// path, because graph already ordered them as spec §3 step 6 asks.
func (r Report) Normalize() Report {
	r.Params.Targets = nonNil(r.Params.Targets)
	r.Params.SystemNamespaces = nonNil(r.Params.SystemNamespaces)
	r.Params.SensitiveNamespaces = nonNil(r.Params.SensitiveNamespaces)
	r.Paths = append([]PathView(nil), r.Paths...)
	r.Paths = nonNil(r.Paths)
	for i := range r.Paths {
		r.Paths[i].Route = nonNil(r.Paths[i].Route)
		for j := range r.Paths[i].Route {
			r.Paths[i].Route[j].Evidence = nonNil(r.Paths[i].Route[j].Evidence)
		}
	}
	sort.SliceStable(r.Paths, func(i, j int) bool { return lessPath(r.Paths[i], r.Paths[j]) })
	r.Cuts = nonNil(r.Cuts)
	// Cuts keep the order graph gave them within a path (verified first, then
	// smallest scope, then canonical key, per spec §3 step 6); grouping them by
	// path id is a stable sort, so it never disturbs that order.
	sort.SliceStable(r.Cuts, func(i, j int) bool { return r.Cuts[i].PathID < r.Cuts[j].PathID })
	r.Bottlenecks = nonNil(r.Bottlenecks)
	for i := range r.Bottlenecks {
		r.Bottlenecks[i].Eliminated = nonNil(r.Bottlenecks[i].Eliminated)
	}
	r.Gaps = nonNil(r.Gaps)
	return r
}

func lessPath(a, b PathView) bool {
	if a.Target != b.Target {
		return a.Target < b.Target
	}
	if a.SystemOrigin != b.SystemOrigin {
		return !a.SystemOrigin
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Hops != b.Hops {
		return a.Hops < b.Hops
	}
	return a.ID < b.ID
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// CutsOf returns the cuts of one path in the order the path carries them.
func CutsOf(cuts []CutView, pathID string) []CutView {
	var out []CutView
	for _, cut := range cuts {
		if cut.PathID == pathID {
			out = append(out, cut)
		}
	}
	return out
}

// ConfidenceOf reports the confidence of a path: definite only when every hop is
// definite.
func ConfidenceOf(edges []model.Edge) string {
	for _, edge := range edges {
		if edge.Confidence != "definite" {
			return "conditional"
		}
	}
	return "definite"
}
