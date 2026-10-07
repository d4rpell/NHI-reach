package hops

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/rbac"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

func add(t *testing.T, ix *snapshot.Index, raw string) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if err := ix.Add(obj); err != nil {
		t.Fatalf("index fixture: %v", err)
	}
}

func identity(t *testing.T, ix *snapshot.Index, namespace, name string) model.ObjectRef {
	t.Helper()
	ref, ok := ix.Get("ServiceAccount", namespace, name)
	if !ok {
		t.Fatalf("ServiceAccount %s/%s not indexed", namespace, name)
	}
	return ref
}

func permissions(t *testing.T, ix *snapshot.Index, sa model.ObjectRef) []rbac.Granted {
	t.Helper()
	granted, err := rbac.Effective(ix, rbac.ServiceAccount(sa))
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	return granted
}

func workloadFixture(t *testing.T) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops-admin","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"other","namespace":"other"}}`)
	return ix
}

func TestCatalogEntryCitesOfficialSource(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != 1 {
		t.Fatalf("light vertical exposes %d hops, want 1", len(catalog))
	}
	entry := catalog[0]
	if entry.ID != NR001.ID {
		t.Errorf("catalog holds %q, want %q", entry.ID, NR001.ID)
	}
	if !strings.HasPrefix(entry.Reference, "https://kubernetes.io/") || !strings.Contains(entry.Reference, "#") {
		t.Errorf("hop reference %q is not an anchored official Kubernetes URL", entry.Reference)
	}
	if entry.Status != "enabled" {
		t.Errorf("hop status is %q, want enabled", entry.Status)
	}
	if entry.Rationale == "" || entry.Remediation == "" {
		t.Error("hop lacks rationale or remediation")
	}
}

func TestWorkloadCreationEmitsEdgesToNamespacePeers(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"creator","namespace":"app"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"creator","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	edges := WorkloadCreation(ix, sa, permissions(t, ix, sa))

	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1 (the other namespace peer only)", len(edges))
	}
	edge := edges[0]
	if edge.From != "sa:app/deployer" || edge.To != "sa:app/ops-admin" {
		t.Errorf("edge is %s -> %s, want sa:app/deployer -> sa:app/ops-admin", edge.From, edge.To)
	}
	if edge.HopID != NR001.ID {
		t.Errorf("edge uses hop %q, want %q", edge.HopID, NR001.ID)
	}
	// Creating a workload proves only the RBAC rule; running it as the target
	// service account depends on admission, which the model does not cover.
	if edge.Confidence != "conditional" {
		t.Errorf("edge confidence is %q, want conditional", edge.Confidence)
	}
	if len(edge.Evidence) == 0 || len(edge.Grants) == 0 {
		t.Error("edge carries no evidence or no removable grant")
	}
}

func TestWorkloadCreationRequiresCreateOnPods(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"app"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"reader","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	if edges := WorkloadCreation(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("read-only permission produced %d edges, want 0", len(edges))
	}
}

func TestWorkloadCreationMatchesWildcardRule(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"admin-app","namespace":"app"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"admin-app","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"admin-app"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	if edges := WorkloadCreation(ix, sa, permissions(t, ix, sa)); len(edges) != 1 {
		t.Fatalf("wildcard rule produced %d edges, want 1", len(edges))
	}
}

func TestClusterAdminEdges(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
		"metadata":{"name":"ops-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "ops")
	edges := ClusterAdminEdges(sa, permissions(t, ix, sa))
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	if edges[0].From != "sa:app/ops" || edges[0].To != TargetClusterAdmin {
		t.Errorf("edge is %s -> %s, want sa:app/ops -> %s", edges[0].From, edges[0].To, TargetClusterAdmin)
	}
	if len(edges[0].Evidence) < 2 {
		t.Errorf("edge evidence holds %d objects, want the service account and the binding", len(edges[0].Evidence))
	}
}

func TestClusterAdminEdgesEmptyWithoutPermission(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	sa := identity(t, ix, "app", "ops")
	if edges := ClusterAdminEdges(sa, nil); len(edges) != 0 {
		t.Fatalf("unprivileged identity produced %d cluster-admin edges, want 0", len(edges))
	}
}

func TestWorkloadCreationUsesBindingNamespace(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"worker","namespace":"other"}}`)
	// The RoleBinding lives in "other" and names the "app" deployer: the grant
	// reaches the service accounts of "other", never those of "app".
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"creator","namespace":"other"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"creator","namespace":"other"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	edges := WorkloadCreation(ix, sa, permissions(t, ix, sa))
	want := []string{"sa:other/other", "sa:other/worker"}
	if got := edgeTargets(edges); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("binding in namespace other reached %v, want the service accounts of other %v", got, want)
	}
}

func TestWorkloadCreationClusterScopedReachesEveryNamespace(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"creator"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"creator"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	edges := WorkloadCreation(ix, sa, permissions(t, ix, sa))
	want := []string{"sa:app/ops-admin", "sa:other/other"}
	if got := edgeTargets(edges); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cluster-scoped create reached %v, want every other service account %v", got, want)
	}
}

func TestCollectGrantsDeduplicatesIdenticalUnits(t *testing.T) {
	role := model.ObjectRef{Kind: "ClusterRole", Name: "reader"}
	binding := model.ObjectRef{Kind: "ClusterRoleBinding", Name: "readers"}
	rule := model.Grant{Object: role, Kind: "role-rule", Detail: "rules[0]"}
	subjectA := model.Grant{Object: binding, Kind: "binding-subject", Detail: "subject Group system:authenticated"}
	subjectB := model.Grant{Object: binding, Kind: "binding-subject", Detail: "subject Group system:serviceaccounts"}

	got := collectGrants([]rbac.Granted{
		{Grants: []model.Grant{subjectA, rule}},
		{Grants: []model.Grant{subjectB, rule}},
	})
	if len(got) != 3 {
		t.Fatalf("collectGrants returned %d units, want the two subjects and one role-rule", len(got))
	}
	// Ordered by (object kind, namespace, name, unit kind, detail): the
	// ClusterRole sorts before the ClusterRoleBinding, and the two subjects are
	// kept distinct.
	if got[0].Detail != "rules[0]" || got[0].Kind != "role-rule" {
		t.Errorf("first unit is %v, want the role-rule", got[0])
	}
	if got[1].Detail != "subject Group system:authenticated" || got[2].Detail != "subject Group system:serviceaccounts" {
		t.Errorf("binding-subject units were not preserved: %v", got[1:])
	}
}

func edgeTargets(edges []model.Edge) []string {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.To)
	}
	return out
}

func evidenceKeys(refs []model.ObjectRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.Kind+"/"+ref.Namespace+"/"+ref.Name)
	}
	return out
}

func hasString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestWorkloadCreationAttributesGrantsToEachDestination(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"other"}}`)
	// A cluster-scoped grant covers every namespace; a namespaced grant covers
	// only its own. Each edge must carry the grants that reach its destination,
	// and the origin's homonym in another namespace must still be a destination.
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"creator"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"global-creator"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"creator","namespace":"other"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"other-creator","namespace":"other"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	edges := WorkloadCreation(ix, sa, permissions(t, ix, sa))

	want := "sa:app/ops-admin,sa:other/deployer,sa:other/other"
	if got := strings.Join(edgeTargets(edges), ","); got != want {
		t.Fatalf("edges reach %v, want %v (the origin app/deployer is never a destination)", got, want)
	}
	for _, edge := range edges {
		ev := evidenceKeys(edge.Evidence)
		global := hasString(ev, "ClusterRoleBinding//global-creator")
		scoped := hasString(ev, "RoleBinding/other/other-creator")
		if edge.To == "sa:app/ops-admin" {
			if !global || scoped {
				t.Errorf("edge to %s carries %v, want only the cluster-scoped grant", edge.To, ev)
			}
			if len(edge.Grants) != 2 {
				t.Errorf("edge to %s removes %d units, want the cluster-scoped binding-subject and role-rule", edge.To, len(edge.Grants))
			}
			continue
		}
		if !global || !scoped {
			t.Errorf("edge to %s carries %v, want both the cluster-scoped and the namespaced grant", edge.To, ev)
		}
		if len(edge.Grants) != 4 {
			t.Errorf("edge to %s removes %d units, want both grants' binding-subject and role-rule", edge.To, len(edge.Grants))
		}
	}
}
