package graph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/hops"
	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

const clusterAdminRule = `{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}`

const impersonatorRole = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"impersonator"},
	"rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"]}]}`

func addObject(t *testing.T, ix *snapshot.Index, raw string) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if err := ix.Add(obj); err != nil {
		t.Fatalf("index fixture: %v", err)
	}
}

func fixture(t *testing.T, raws ...string) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	for _, raw := range raws {
		addObject(t, ix, raw)
	}
	return ix
}

func analyzeFixture(t *testing.T, ix *snapshot.Index, opts Options) Result {
	t.Helper()
	model, err := FromSnapshot(ix)
	if err != nil {
		t.Fatalf("FromSnapshot: %v", err)
	}
	if len(model.Edges()) == 0 {
		t.Fatal("fixture produced no edges")
	}
	result, err := model.Analyze(opts)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return result
}

func clusterAdminTarget() []string { return []string{hops.TargetClusterAdmin} }

// viaSystemFixture gives app/deployer cluster-wide impersonation and makes a
// kube-system ServiceAccount cluster-admin, so the only route from the
// application identity goes through a system identity.
func viaSystemFixture(t *testing.T) *snapshot.Index {
	return fixture(t,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"unprivileged","namespace":"app"}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"node-sa","namespace":"kube-system"}}`,
		impersonatorRole,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"impersonator"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},
			"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRule+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"node-sa-admin"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
			"subjects":[{"kind":"ServiceAccount","name":"node-sa","namespace":"kube-system"}]}`,
	)
}

func TestSolveMarksRoutesThroughASystemIdentity(t *testing.T) {
	ix := viaSystemFixture(t)

	result := analyzeFixture(t, ix, Options{Sources: []string{"sa:app/deployer"}, Targets: clusterAdminTarget()})
	want := "sa:app/deployer>sa:kube-system/node-sa>target:cluster-admin"
	var throughSystem int
	for _, path := range result.Paths {
		if !path.ViaSystem {
			t.Errorf("route %q from an application identity through a system identity is not marked via_system", pathString(path.Path.Edges))
		}
		if got := pathString(path.Path.Edges); got == want {
			throughSystem++
		}
	}
	if throughSystem == 0 {
		t.Fatalf("no route goes through kube-system/node-sa: %v", result.Paths)
	}
	if len(result.Pairs) != 1 || result.Pairs[0].Distance != 2 {
		t.Errorf("pairs = %+v, want the target reachable at distance 2", result.Pairs)
	}

	// A route that is born at a system identity is not a via_system finding.
	fromSystem := analyzeFixture(t, ix, Options{Sources: []string{"sa:kube-system/node-sa"}, Targets: clusterAdminTarget()})
	if len(fromSystem.Paths) == 0 {
		t.Fatal("no route from the system identity")
	}
	for _, path := range fromSystem.Paths {
		if path.ViaSystem {
			t.Errorf("route %q born at a system identity is marked via_system", pathString(path.Path.Edges))
		}
	}
	if !fromSystem.Paths[0].Path.Cuts[0].Verified {
		t.Error("the direct cluster-admin route was not verified as cuttable by its own grant")
	}
}

func TestSolveVerifiesACutThatRemovesTheOnlyRoute(t *testing.T) {
	ix := fixture(t,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRule+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"deployer-admin"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
			"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`,
	)

	result := analyzeFixture(t, ix, Options{Sources: []string{"sa:app/deployer"}, Targets: clusterAdminTarget()})
	if len(result.Paths) == 0 {
		t.Fatal("no path reported for a direct cluster-admin binding")
	}
	// An identity that is already cluster-admin also satisfies the conditions of
	// NR-004 and NR-005 (D-024), so several parallel edges reach the target; the
	// candidates below are the ones the grants of every one of them carries.
	cuts := result.Paths[0].Path.Cuts
	if len(cuts) != 2 {
		t.Fatalf("got %d candidate cuts, want the binding subject and the role rule", len(cuts))
	}
	for _, routed := range result.Paths {
		for _, cut := range routed.Path.Cuts {
			if !cut.Verified {
				t.Errorf("cut %q is not verified although it removes the only route", cut.Change)
			}
			if cut.RemainingPaths != 0 {
				t.Errorf("verified cut %q reports %d remaining paths", cut.Change, cut.RemainingPaths)
			}
		}
	}
	// Verified cuts come first, and between two verified ones the more local unit
	// (a subject of a binding) is proposed before a rule of a role.
	if cuts[0].Grant.Kind != "binding-subject" || cuts[1].Grant.Kind != "role-rule" {
		t.Errorf("cuts are ordered %q, %q; want binding-subject before role-rule", cuts[0].Grant.Kind, cuts[1].Grant.Kind)
	}
	if want := "remove subject ServiceAccount app/deployer from ClusterRoleBinding deployer-admin"; cuts[0].Change != want {
		t.Errorf("cut change is %q, want %q", cuts[0].Change, want)
	}
}

// twoRouteFixture reaches cluster-admin by two independent routes that share no
// grant: a direct binding and impersonation of another cluster-admin. Two
// different ClusterRoles keep the two routes independent, so no single removal
// cuts the escalation.
func twoRouteFixture(t *testing.T) *snapshot.Index {
	return fixture(t,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops-admin","namespace":"app"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"admin-direct"},"rules":[`+clusterAdminRule+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"deployer-direct"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"admin-direct"},
			"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"admin-via"},"rules":[`+clusterAdminRule+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"ops-admin-admin"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"admin-via"},
			"subjects":[{"kind":"ServiceAccount","name":"ops-admin","namespace":"app"}]}`,
		impersonatorRole,
		`{"apiVersion":"rbac.authorization.k8s.io","kind":"ClusterRoleBinding","metadata":{"name":"impersonator"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},
			"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`,
	)
}

func TestSolveReportsACutThatIsNotEnough(t *testing.T) {
	ix := twoRouteFixture(t)
	// K is raised above the three parallel edges an already-cluster-admin
	// identity produces, so both independent routes stay in the enumeration.
	result := analyzeFixture(t, ix, Options{
		Sources:      []string{"sa:app/deployer"},
		Targets:      clusterAdminTarget(),
		PathsPerPair: 8,
	})

	if len(result.Paths) < 2 {
		t.Fatalf("got %d paths, want the two independent routes (and their parallel edges)", len(result.Paths))
	}
	sequences := map[string]bool{}
	for _, routed := range result.Paths {
		sequences[pathString(routed.Path.Edges)] = true
	}
	if len(sequences) < 2 {
		t.Fatalf("the fixture produced %d distinct routes, want two independent ones: %v", len(sequences), sequences)
	}
	for _, routed := range result.Paths {
		for _, cut := range routed.Path.Cuts {
			if cut.Verified {
				t.Errorf("cut %q claims to remove the escalation although another route survives", cut.Change)
			}
			if cut.RemainingPaths < 1 {
				t.Errorf("unverified cut %q reports %d remaining paths, want at least 1", cut.Change, cut.RemainingPaths)
			}
		}
	}

	// The cover reaches completeness, and every proposed removal is distinct:
	// the greedy never proposes a grant it already removed.
	if !result.Cover.Complete {
		t.Errorf("cover is not complete although every grant was removable: %+v", result.Cover)
	}
	if len(result.Cover.Steps) == 0 {
		t.Fatal("cover proposed no step")
	}
	seen := map[string]bool{}
	for _, step := range result.Cover.Steps {
		key := grantKey(step.Grant)
		if seen[key] {
			t.Errorf("cover proposed %q twice", step.Change)
		}
		seen[key] = true
	}

	// Applying the proposed set must leave the pair unreachable: the cover is
	// verified, not asserted.
	removed := make([]model.Grant, 0, len(result.Cover.Steps))
	for _, step := range result.Cover.Steps {
		removed = append(removed, step.Grant)
	}
	hypothetical, err := hops.Rebuild(ix, removed)
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if _, ok := Reach(hypothetical, "sa:app/deployer", hops.TargetClusterAdmin, DefaultMaxDepth); ok {
		t.Error("the verified cover left the target reachable")
	}
}

func TestSolveDeclaresAnIncompleteCover(t *testing.T) {
	ix := twoRouteFixture(t)
	result := analyzeFixture(t, ix, Options{
		Sources:       []string{"sa:app/deployer"},
		Targets:       clusterAdminTarget(),
		MaxCoverSteps: 1,
	})

	if result.Cover.Complete {
		t.Error("cover claims completeness with a single allowed step over two independent routes")
	}
	if len(result.Cover.Steps) != 1 {
		t.Fatalf("cover took %d steps with MaxCoverSteps 1", len(result.Cover.Steps))
	}
	var declared bool
	for _, gap := range result.Gaps {
		if gap.Kind == "truncated-enumeration" && strings.Contains(gap.Subject, "sa:app/deployer") {
			declared = true
		}
	}
	if !declared {
		t.Errorf("no Gap declared the incomplete cover: %+v", result.Gaps)
	}
}

func TestSolveProposesOneSubjectOfAMultiSubjectBinding(t *testing.T) {
	ix := fixture(t,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRule+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"shared-admin"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
			"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"},
			            {"kind":"Group","name":"system:authenticated"}]}`,
	)

	result := analyzeFixture(t, ix, Options{Sources: []string{"sa:app/deployer"}, Targets: clusterAdminTarget()})
	if len(result.Paths) == 0 {
		t.Fatal("no path reported")
	}
	cuts := result.Paths[0].Path.Cuts

	subjects := map[string]model.Cut{}
	for _, cut := range cuts {
		if cut.Grant.Kind == "binding-subject" {
			subjects[cut.Grant.Detail] = cut
		}
	}
	if len(subjects) != 2 {
		t.Fatalf("got %d subject candidates, want the ServiceAccount and the Group of the binding", len(subjects))
	}

	// Removing either subject on its own leaves the other granting cluster-admin,
	// so neither cut is verified and routes to the target remain: this is the
	// multi-subject case spec §5 asks for.
	for detail, cut := range subjects {
		if cut.Verified {
			t.Errorf("removing %q claims to cut the escalation although the other subject still confers it", detail)
		}
		if cut.RemainingPaths < 1 {
			t.Errorf("removing %q reports %d remaining paths, want at least 1", detail, cut.RemainingPaths)
		}
	}

	// Removing the rule does cut it, and only that proposal is verified.
	var verified int
	for _, cut := range cuts {
		if cut.Verified {
			verified++
			if cut.Grant.Kind != "role-rule" {
				t.Errorf("unexpected verified cut kind %q", cut.Grant.Kind)
			}
		}
	}
	if verified != 1 {
		t.Errorf("got %d verified cuts, want only the role rule", verified)
	}
}

// sharedAdminFixture reaches cluster-admin from two different origins through one
// shared identity, so a single removal cuts both pairs.
func sharedAdminFixture(t *testing.T) *snapshot.Index {
	return fixture(t,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer2","namespace":"app"}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"shared","namespace":"app"}}`,
		impersonatorRole,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"impersonator"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},
			"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"},
			            {"kind":"ServiceAccount","name":"deployer2","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRule+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"shared-admin"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
			"subjects":[{"kind":"ServiceAccount","name":"shared","namespace":"app"}]}`,
	)
}

func TestCoverPrefersTheGrantThatCutsTheMostPairs(t *testing.T) {
	ix := sharedAdminFixture(t)
	result := analyzeFixture(t, ix, Options{
		Sources: []string{"sa:app/deployer", "sa:app/deployer2"},
		Targets: clusterAdminTarget(),
	})

	if len(result.Pairs) != 2 {
		t.Fatalf("got %d pairs, want two", len(result.Pairs))
	}
	for _, pair := range result.Pairs {
		if !pair.Reachable || pair.Distance != 2 {
			t.Fatalf("pair %s->%s is %+v, want reachable at distance 2", pair.Pair.Source, pair.Pair.Target, pair)
		}
	}
	if !result.Cover.Complete {
		t.Error("cover is not complete")
	}
	if len(result.Cover.Steps) != 1 {
		t.Fatalf("cover took %d steps, want a single grant shared by both pairs", len(result.Cover.Steps))
	}
	// The property is coverage, not a particular grant: the chosen unit is one
	// that appears in both pairs, and removing it must cut both.
	step := result.Cover.Steps[0]
	if len(step.Eliminated) != 2 {
		t.Errorf("the chosen grant eliminated %d pairs, want both", len(step.Eliminated))
	}
	hypothetical, err := hops.Rebuild(ix, []model.Grant{step.Grant})
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	for _, pair := range result.Pairs {
		if _, ok := Reach(hypothetical, pair.Pair.Source, pair.Pair.Target, DefaultMaxDepth); ok {
			t.Errorf("the chosen grant did not cut %s->%s on its own", pair.Pair.Source, pair.Pair.Target)
		}
	}
}

func TestSolveDeclaresItsLimits(t *testing.T) {
	ix := twoRouteFixture(t)
	result := analyzeFixture(t, ix, Options{
		Sources:       []string{"sa:app/deployer"},
		Targets:       clusterAdminTarget(),
		Budget:        1,
		MaxCoverSteps: 1,
	})

	if len(result.Gaps) == 0 {
		t.Fatal("a truncated run produced no gaps")
	}
	for _, gap := range result.Gaps {
		// Every verification is "in the model and up to --max-depth": no message
		// may read as a statement about the real cluster.
		if !strings.Contains(gap.Message, "in the model") {
			t.Errorf("gap message %q does not declare the model limit", gap.Message)
		}
		if strings.Contains(gap.Message, "cluster is") {
			t.Errorf("gap message %q claims something about the cluster", gap.Message)
		}
	}
}
