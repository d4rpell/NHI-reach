package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// verifyCuts proposes every distinct grant of the path as a cut and records
// whether removing it on its own, in the hypothetical model, makes the target
// unreachable from the source (spec §3 step 6).
//
// A rebuild failure is returned as an error: a cut that could not be evaluated
// is never reported as an unverified one. Every claim holds in the model and up
// to --max-depth only.
func verifyCuts(opts Options, rebuild Rebuild, path model.Path) ([]model.Cut, []model.Gap, error) {
	candidates := pathCandidates(path)
	cuts := make([]model.Cut, 0, len(candidates))
	var gaps []model.Gap

	for _, grant := range candidates {
		hypothetical, err := rebuild([]model.Grant{grant})
		if err != nil {
			return nil, nil, err
		}

		_, reachable := Reach(hypothetical, path.Source, path.Target, opts.MaxDepth)
		cut := model.Cut{Grant: grant, Change: changeText(grant), Verified: !reachable}
		if reachable {
			remaining, _, truncated := SimplePaths(hypothetical, path.Source, path.Target, opts.MaxDepth, opts.RemainingCap)
			cut.RemainingPaths = len(remaining)
			if truncated {
				gaps = append(gaps, gapRemainingPathsCapped(path.Source, path.Target, opts))
			}
		}
		cuts = append(cuts, cut)
	}

	sort.Slice(cuts, func(i, j int) bool { return lessCut(cuts[i], cuts[j]) })
	return cuts, gaps, nil
}

// pathCandidates returns the distinct grants of the path's edges, ordered by
// canonical key so the proposal order does not depend on the edge order.
func pathCandidates(path model.Path) []model.Grant {
	seen := make(map[string]bool)
	var candidates []model.Grant
	for _, edge := range path.Edges {
		for _, grant := range edge.Grants {
			key := grantKey(grant)
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, grant)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return grantKey(candidates[i]) < grantKey(candidates[j]) })
	return candidates
}

// lessCut orders the proposals as spec §3 step 6 asks: verified first, then the
// smallest reach — unit rank before scope, so removing a subject is proposed
// before removing a rule, and a namespaced unit before a cluster-scoped one —
// with the canonical key as the tie-break.
func lessCut(a, b model.Cut) bool {
	if a.Verified != b.Verified {
		return a.Verified
	}
	if rank := grantKindRank(a.Grant.Kind) - grantKindRank(b.Grant.Kind); rank != 0 {
		return rank < 0
	}
	if rank := grantScopeRank(a.Grant) - grantScopeRank(b.Grant); rank != 0 {
		return rank < 0
	}
	return grantKey(a.Grant) < grantKey(b.Grant)
}

// grantKindRank orders the removal units from the most local to the widest: a
// subject of a binding is one grant, a rule of a role is shared by every subject
// that reaches it.
func grantKindRank(kind string) int {
	switch kind {
	case "binding-subject":
		return 0
	case "role-rule":
		return 1
	case "scc-user":
		return 2
	case "scc-group":
		return 3
	default:
		return 4
	}
}

// grantScopeRank orders namespaced units before cluster-scoped ones.
func grantScopeRank(grant model.Grant) int {
	if grant.Object.Namespace == "" {
		return 1
	}
	return 0
}

// greedyCover builds the verified bottleneck cover of spec §3 step 7: it
// repeatedly removes the grant that appears in the most reachable pairs and
// stops when no pair is reachable, when no candidate is left or at
// MaxCoverSteps. A grant already removed is never proposed again, and every step
// rebuilds from the whole removed set, so the sequence is reproducible.
//
// The cover is a heuristic verified in the model and up to --max-depth: it never
// claims to be the smallest set of changes. Complete is decided on the final
// model against every pair that was reachable at the start, not only against the
// ones the loop still tracked: a removal that re-opened a pair can never be
// presented as a complete cover.
func greedyCover(opts Options, edges []model.Edge, rebuild Rebuild, paths []RoutedPath, pairs []PairReach) (Cover, []model.Gap, error) {
	initial := reachablePairs(pairs)
	if len(initial) == 0 {
		// Nothing to cover: the empty set removes every pair there was.
		return Cover{Complete: true}, nil, nil
	}
	if rebuild == nil {
		// Without a rebuild the cover cannot be computed; the caller reports it
		// as a Gap, and Complete stays false because pairs remain reachable.
		return Cover{}, nil, nil
	}

	removed := make([]model.Grant, 0)
	removedKeys := make(map[string]bool)
	var steps []Bottleneck
	reachable := initial

	for len(reachable) > 0 && len(steps) < opts.MaxCoverSteps {
		grant, ok := bestCandidate(paths, reachable, removedKeys)
		if !ok {
			break
		}
		removed = append(removed, grant)
		removedKeys[grantKey(grant)] = true

		hypothetical, err := rebuild(removed)
		if err != nil {
			return Cover{}, nil, err
		}

		eliminated := make([]Pair, 0, len(reachable))
		stillReachable := make([]Pair, 0, len(reachable))
		for _, pair := range reachable {
			if _, ok := Reach(hypothetical, pair.Source, pair.Target, opts.MaxDepth); ok {
				stillReachable = append(stillReachable, pair)
				continue
			}
			eliminated = append(eliminated, pair)
		}
		steps = append(steps, Bottleneck{Grant: grant, Change: changeText(grant), Eliminated: eliminated})
		reachable = stillReachable
	}

	// The verdict comes from the final model over every pair that was reachable
	// at the start, whatever the loop tracked along the way.
	final := edges
	if len(removed) > 0 {
		var err error
		final, err = rebuild(removed)
		if err != nil {
			return Cover{}, nil, err
		}
	}
	var survivors []Pair
	for _, pair := range initial {
		if _, ok := Reach(final, pair.Source, pair.Target, opts.MaxDepth); ok {
			survivors = append(survivors, pair)
		}
	}

	var gaps []model.Gap
	if len(survivors) > 0 {
		// The step bound is the only truncation of this loop; otherwise the
		// enumerated candidates simply do not hold a set that removes every pair.
		kind := "missing-input"
		if len(steps) >= opts.MaxCoverSteps {
			kind = "truncated-enumeration"
		}
		gaps = append(gaps, gapCoverIncomplete(survivors, kind, opts)...)
	}
	return Cover{Steps: steps, Complete: len(survivors) == 0}, gaps, nil
}

// bestCandidate returns the grant of the enumerated paths that appears in the
// most still-reachable pairs, ignoring the grants already removed; ties go to the
// smallest canonical key, so the choice never depends on map iteration order.
func bestCandidate(paths []RoutedPath, reachable []Pair, removedKeys map[string]bool) (model.Grant, bool) {
	type candidate struct {
		grant model.Grant
		pairs map[Pair]bool
	}
	var order []string
	candidates := make(map[string]*candidate)

	for _, routed := range paths {
		pair := Pair{Source: routed.Path.Source, Target: routed.Path.Target}
		if !containsPair(reachable, pair) {
			continue
		}
		for _, edge := range routed.Path.Edges {
			for _, grant := range edge.Grants {
				key := grantKey(grant)
				if removedKeys[key] {
					continue
				}
				found := candidates[key]
				if found == nil {
					found = &candidate{grant: grant, pairs: make(map[Pair]bool)}
					candidates[key] = found
					order = append(order, key)
				}
				found.pairs[pair] = true
			}
		}
	}
	if len(order) == 0 {
		return model.Grant{}, false
	}

	sort.Strings(order)
	best := candidates[order[0]]
	for _, key := range order[1:] {
		if len(candidates[key].pairs) > len(best.pairs) {
			best = candidates[key]
		}
	}
	return best.grant, true
}

func reachablePairs(pairs []PairReach) []Pair {
	out := make([]Pair, 0, len(pairs))
	for _, pair := range pairs {
		if pair.Reachable {
			out = append(out, pair.Pair)
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessPair(out[i], out[j]) })
	return out
}

func containsPair(pairs []Pair, want Pair) bool {
	for _, pair := range pairs {
		if pair == want {
			return true
		}
	}
	return false
}

// grantKey is a total and injective key over every field of a removal unit.
func grantKey(grant model.Grant) string {
	var b strings.Builder
	writeField(&b, grant.Object.APIVersion)
	writeField(&b, grant.Object.Kind)
	writeField(&b, grant.Object.Namespace)
	writeField(&b, grant.Object.Name)
	writeField(&b, grant.Object.SHA256)
	writeField(&b, grant.Kind)
	writeField(&b, grant.Detail)
	return b.String()
}

// changeText renders the proposal of spec §2.3, for instance
// "remove subject ServiceAccount app/ci from RoleBinding app/deployer".
func changeText(grant model.Grant) string {
	where := grant.Object.Kind + " " + grant.Object.Name
	if grant.Object.Namespace != "" {
		where = grant.Object.Kind + " " + grant.Object.Namespace + "/" + grant.Object.Name
	}
	return "remove " + grant.Detail + " from " + where
}

// subjectPair renders the pair a Gap refers to.
func subjectPair(pair Pair) string {
	return pair.Source + " -> " + pair.Target
}

func gapTruncatedEnumeration(pair Pair, opts Options) model.Gap {
	return model.Gap{
		Kind:    "truncated-enumeration",
		Subject: subjectPair(pair),
		Message: fmt.Sprintf(
			"enumeration of the paths from %s to %s stopped because the global exploration budget (%d extensions) was exhausted: the paths reported for that pair are partial, not a complete enumeration (in the model and up to %d hops)",
			pair.Source, pair.Target, opts.Budget, opts.MaxDepth),
	}
}

func gapRemainingPathsCapped(source, target string, opts Options) model.Gap {
	return model.Gap{
		Kind:    "truncated-enumeration",
		Subject: subjectPair(Pair{Source: source, Target: target}),
		Message: fmt.Sprintf(
			"the paths still reaching %s from %s were counted up to a cap of %d explored extensions: RemainingPaths is a lower bound (in the model and up to %d hops)",
			target, source, opts.RemainingCap, opts.MaxDepth),
	}
}

func gapCutVerificationUnavailable() model.Gap {
	return model.Gap{
		Kind:    "missing-input",
		Subject: "cut-verification",
		Message: "cut verification and the bottleneck cover were not computed: this model carries no rebuild function, so no change can be evaluated in a hypothetical model (in the model and up to --max-depth)",
	}
}

func gapCoverIncomplete(pairs []Pair, kind string, opts Options) []model.Gap {
	message := fmt.Sprintf(
		"the verified cover is partial: this pair is still reachable in the model after applying the proposed changes, which is a heuristic and not a minimum set (in the model and up to %d hops)",
		opts.MaxDepth)
	out := make([]model.Gap, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, model.Gap{Kind: kind, Subject: subjectPair(pair), Message: message})
	}
	return out
}
