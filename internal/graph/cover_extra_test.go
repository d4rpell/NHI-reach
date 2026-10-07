package graph

import (
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// TestCoverJudgesCompletenessOnTheFinalModel covers the case a caller-supplied
// rebuild admits: removals that are not monotone, so a pair that had stopped
// being reachable comes back. Completeness is a claim about the final model over
// every pair that was reachable at the start, so this must not be reported as a
// complete cover.
func TestCoverJudgesCompletenessOnTheFinalModel(t *testing.T) {
	direct := granted("s1", "t", "rbac-cluster-admin",
		removal("binding-subject", "subject ServiceAccount app/s1", "ClusterRoleBinding", "", "b1"))
	other := granted("s2", "t", "rbac-cluster-admin",
		removal("binding-subject", "subject ServiceAccount app/s2", "ClusterRoleBinding", "", "b2"))
	edges := []model.Edge{direct, other}

	pairs := []string{"s1", "s2"}
	rebuild := func(removed []model.Grant) ([]model.Edge, error) {
		// Removing the first grant leaves the second route; removing both
		// re-opens the first one, which is what a non-monotone callback may do.
		switch len(removed) {
		case 0:
			return edges, nil
		case 1:
			if removed[0].Detail == "subject ServiceAccount app/s1" {
				return []model.Edge{other}, nil
			}
			return []model.Edge{direct}, nil
		default:
			return []model.Edge{direct}, nil
		}
	}

	result, err := Solve(Options{Sources: pairs, Targets: []string{"t"}, System: []string{}}, edges, rebuild)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(result.Pairs) != 2 || !result.Pairs[0].Reachable || !result.Pairs[1].Reachable {
		t.Fatalf("fixture is wrong: %+v", result.Pairs)
	}

	final, err := rebuild(grantList(result.Cover))
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if _, ok := Reach(final, "s1", "t", DefaultMaxDepth); !ok {
		t.Fatal("fixture is wrong: the non-monotone rebuild should have re-opened s1")
	}

	if result.Cover.Complete {
		t.Error("the cover claims completeness although a pair is reachable in the final model")
	}
	var declared bool
	for _, gap := range result.Gaps {
		if gap.Kind == "missing-input" && gap.Subject == "s1 -> t" {
			declared = true
		}
	}
	if !declared {
		t.Errorf("no Gap names the pair left reachable: %+v", result.Gaps)
	}
}

func grantList(cover Cover) []model.Grant {
	removed := make([]model.Grant, 0, len(cover.Steps))
	for _, step := range cover.Steps {
		removed = append(removed, step.Grant)
	}
	return removed
}
