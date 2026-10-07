package hops

import (
	"encoding/json"
	"reflect"
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
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(catalog) != 6 {
		t.Fatalf("catalog exposes %d hops, want 6", len(catalog))
	}
	for _, entry := range catalog {
		if !strings.HasPrefix(entry.Reference, "https://kubernetes.io/") || !strings.Contains(entry.Reference, "#") {
			t.Errorf("hop %s reference %q is not an anchored official Kubernetes URL", entry.ID, entry.Reference)
		}
		if entry.Status != "enabled" {
			t.Errorf("hop %s status is %q, want enabled", entry.ID, entry.Status)
		}
		if entry.Rationale == "" || entry.Remediation == "" {
			t.Errorf("hop %s lacks rationale or remediation", entry.ID)
		}
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
	if edge.HopID != hopWorkloadCreation {
		t.Errorf("edge uses hop %q, want %q", edge.HopID, hopWorkloadCreation)
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

func indexOf(t *testing.T, raws ...string) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	for _, raw := range raws {
		add(t, ix, raw)
	}
	return ix
}

// serviceAccountRaws are the identity fixture shared by the new-hop tests: one
// identity per namespace.
var serviceAccountRaws = []string{
	`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}`,
	`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"peer","namespace":"app"}}`,
	`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"far","namespace":"other"}}`,
}

func TestImpersonationReachesNamespacePeers(t *testing.T) {
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"impersonator","namespace":"app"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"impersonator","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"impersonator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	edges := Impersonation(ix, sa, permissions(t, ix, sa))
	if got := strings.Join(edgeTargets(edges), ","); got != "sa:app/peer" {
		t.Fatalf("impersonation reached %v, want only the namespace peer", got)
	}
	if edges[0].HopID != hopImpersonation || edges[0].Confidence != "definite" {
		t.Errorf("edge is %s/%s, want %s/definite", edges[0].HopID, edges[0].Confidence, hopImpersonation)
	}
}

func TestImpersonationRequiresImpersonateVerb(t *testing.T) {
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"app"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["get","list"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"reader","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if edges := Impersonation(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("read-only permission produced %d edges, want 0", len(edges))
	}
}

func TestImpersonationHonoursResourceNamesAndScope(t *testing.T) {
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"impersonator"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"],"resourceNames":["peer"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"impersonator"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	// resourceNames ["peer"] reaches app/peer only; the cluster scope reaches
	// other namespaces, but the name restriction still applies.
	if got := strings.Join(edgeTargets(Impersonation(ix, sa, permissions(t, ix, sa))), ","); got != "sa:app/peer" {
		t.Fatalf("resourceNames reached %v, want only sa:app/peer", got)
	}
}

func TestImpersonationResourceNamesExcludesOthers(t *testing.T) {
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"impersonator"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"],"resourceNames":["nobody"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"impersonator"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if edges := Impersonation(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("a rule restricting the name to a non-existent service account produced %d edges, want 0", len(edges))
	}
}

func TestTokenRequestUsesTheTokenSubresource(t *testing.T) {
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"minter"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts/token"],"verbs":["create"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"minter"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"minter"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if got := strings.Join(edgeTargets(TokenRequest(ix, sa, permissions(t, ix, sa))), ","); got != "sa:app/peer,sa:other/far" {
		t.Fatalf("token request reached %v, want every other service account", got)
	}
}

func TestTokenRequestDoesNotMatchBareServiceAccounts(t *testing.T) {
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"creator"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["create"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"creator"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"creator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if edges := TokenRequest(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("create on the serviceaccounts resource produced %d token edges, want 0", len(edges))
	}
}

// binderFixture grants ci the two cluster-scoped permissions NR-004 needs.
func binderFixture(t *testing.T, roleRules, bindingRules string) *snapshot.Index {
	t.Helper()
	return indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},"rules":[`+roleRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"binder"},"rules":[`+bindingRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"binder"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"binder"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)
}

const clusterAdminRules = `{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}`
const bindAndCreate = `{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"],"resourceNames":["target-role"]},
	{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}`

func TestBindClusterRoleEscalates(t *testing.T) {
	ix := binderFixture(t, clusterAdminRules, bindAndCreate)
	sa := identity(t, ix, "app", "ci")
	edges := BindClusterRole(ix, sa, permissions(t, ix, sa))
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	if edges[0].To != TargetClusterAdmin || edges[0].HopID != hopBindClusterRole || edges[0].Confidence != "definite" {
		t.Errorf("edge is %+v, want a definite %s edge to %s", edges[0], hopBindClusterRole, TargetClusterAdmin)
	}
}

func TestBindClusterRoleRequiresAClusterAdminTargetRole(t *testing.T) {
	ix := binderFixture(t, `{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}`, bindAndCreate)
	sa := identity(t, ix, "app", "ci")
	if edges := BindClusterRole(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("binding a non-admin role produced %d edges, want 0", len(edges))
	}
}

func TestBindClusterRoleRequiresClusterScopedPermissions(t *testing.T) {
	// bind is granted by a RoleBinding (namespaced); create on
	// clusterrolebindings is granted cluster-wide.
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},"rules":[`+clusterAdminRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"binder","namespace":"app"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"binder","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"binder"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"crb-creator"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"crb-creator"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"crb-creator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if edges := BindClusterRole(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("a namespaced bind produced %d edges, want 0", len(edges))
	}
}

func TestBindClusterRoleRequiresALinkPath(t *testing.T) {
	ix := binderFixture(t, clusterAdminRules,
		`{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"],"resourceNames":["target-role"]}`)
	sa := identity(t, ix, "app", "ci")
	if edges := BindClusterRole(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("bind without a cluster-scoped link path produced %d edges, want 0", len(edges))
	}
}

func TestBindClusterRoleViaExistingBindingUpdate(t *testing.T) {
	// No create on clusterrolebindings: the identity may repoint an existing
	// ClusterRoleBinding of the role it can bind.
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},"rules":[`+clusterAdminRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"existing-admins"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target-role"},
		 "subjects":[{"kind":"ServiceAccount","name":"peer","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"binder"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"],"resourceNames":["target-role"]},
		 {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["update"],"resourceNames":["existing-admins"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"binder"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"binder"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	edges := BindClusterRole(ix, sa, permissions(t, ix, sa))
	if len(edges) != 1 || edges[0].To != TargetClusterAdmin {
		t.Fatalf("update on an existing binding produced %v, want one edge to %s", edgeTargets(edges), TargetClusterAdmin)
	}
}

func widenerFixture(t *testing.T, targetRoleRaw, extraBinding string) *snapshot.Index {
	t.Helper()
	raws := append(serviceAccountRaws,
		targetRoleRaw,
		extraBinding,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"widener"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate"],"resourceNames":["target-role"]},
		 {"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["update"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"widener"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"widener"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)
	return indexOf(t, raws...)
}

const targetRoleWithRules = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},
	"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`

const targetRoleClusterBound = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"target-binding"},
	"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target-role"},
	"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`

func TestWidenClusterRoleEscalates(t *testing.T) {
	ix := widenerFixture(t, targetRoleWithRules, targetRoleClusterBound)
	sa := identity(t, ix, "app", "ci")
	edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
	if err != nil {
		t.Fatalf("WidenClusterRole: %v", err)
	}
	if len(edges) != 1 || edges[0].To != TargetClusterAdmin || edges[0].HopID != hopWidenClusterRole {
		t.Fatalf("got %v, want one %s edge to %s", edgeTargets(edges), hopWidenClusterRole, TargetClusterAdmin)
	}
}

func TestWidenClusterRoleNeedsAReachingClusterRoleBinding(t *testing.T) {
	// The target role reaches the identity only through a RoleBinding.
	roleBound := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"target-binding","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target-role"},
		"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`
	ix := widenerFixture(t, targetRoleWithRules, roleBound)
	sa := identity(t, ix, "app", "ci")
	edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
	if err != nil {
		t.Fatalf("WidenClusterRole: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("a RoleBinding link produced %d edges, want 0", len(edges))
	}
}

func TestWidenClusterRoleSeesARuleLessRole(t *testing.T) {
	// A ClusterRole with no rules produces no effective permission, but the
	// binding still reaches the identity; escalate + update can widen it.
	rulessRole := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"}}`
	ix := widenerFixture(t, rulessRole, targetRoleClusterBound)
	sa := identity(t, ix, "app", "ci")
	edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
	if err != nil {
		t.Fatalf("WidenClusterRole: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("a rule-less but bound ClusterRole produced %d edges, want 1", len(edges))
	}
}

func TestWidenClusterRoleRequiresUpdate(t *testing.T) {
	// escalate only, no update/patch on the role.
	ix := indexOf(t, append(serviceAccountRaws,
		targetRoleWithRules,
		targetRoleClusterBound,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"widener"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"widener"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"widener"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)
	sa := identity(t, ix, "app", "ci")
	edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
	if err != nil {
		t.Fatalf("WidenClusterRole: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("escalate without update produced %d edges, want 0", len(edges))
	}
}

func TestBindClusterRoleRejectsNamespacedLinkPath(t *testing.T) {
	// bind is cluster-scoped, but the only way to create a binding is a
	// RoleBinding, which cannot reach cluster scope.
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},"rules":[`+clusterAdminRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"binder"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"binder"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"binder"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"crb-creator","namespace":"app"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["create"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"crb-creator","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"crb-creator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if edges := BindClusterRole(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("a namespaced link path produced %d edges, want 0", len(edges))
	}
}

func TestWidenClusterRoleRejectsNamespacedPermissions(t *testing.T) {
	// escalate is cluster-scoped; update on the same role comes from a
	// RoleBinding, which cannot authorize a cluster-scoped resource.
	ix := indexOf(t, append(serviceAccountRaws,
		targetRoleWithRules,
		targetRoleClusterBound,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"escalator"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"escalator"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"escalator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"updater","namespace":"app"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["update"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"updater","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"updater"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
	if err != nil {
		t.Fatalf("WidenClusterRole: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("a namespaced update produced %d edges, want 0", len(edges))
	}
}

func TestBindClusterRoleRejectsNamespacedBindingUpdate(t *testing.T) {
	// bind is cluster-scoped; the update that would repoint the existing
	// ClusterRoleBinding comes from a RoleBinding (namespaced) and is discarded.
	ix := indexOf(t, append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},"rules":[`+clusterAdminRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"existing-admins"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target-role"},
		 "subjects":[{"kind":"ServiceAccount","name":"peer","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"binder"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["bind"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"binder"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"binder"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"crb-updater","namespace":"app"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterrolebindings"],"verbs":["update"],"resourceNames":["existing-admins"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"crb-updater","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"crb-updater"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	if edges := BindClusterRole(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("a namespaced binding update produced %d edges, want 0", len(edges))
	}
}

func TestWidenClusterRoleRejectsNamespacedEscalate(t *testing.T) {
	// escalate comes from a RoleBinding (namespaced); update on the role is
	// cluster-scoped.
	ix := indexOf(t, append(serviceAccountRaws,
		targetRoleWithRules,
		targetRoleClusterBound,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"updater"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["update"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"updater"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"updater"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"escalator","namespace":"app"},
		 "rules":[{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate"],"resourceNames":["target-role"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"escalator","namespace":"app"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"escalator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)...)

	sa := identity(t, ix, "app", "ci")
	edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
	if err != nil {
		t.Fatalf("WidenClusterRole: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("a namespaced escalate produced %d edges, want 0", len(edges))
	}
}

func csrFixture(t *testing.T, csrRules string, privilegedSubjectRaw string) (*snapshot.Index, model.ObjectRef) {
	t.Helper()
	raws := append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"csr-issuer"},"rules":[`+csrRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"csr-issuer"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"csr-issuer"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRules+`]}`,
		privilegedSubjectRaw)
	ix := indexOf(t, raws...)
	return ix, identity(t, ix, "app", "ci")
}

const fullCSRRules = `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},
	{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]},
	{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["kubernetes.io/kube-apiserver-client"]}`

const aliceAdminBinding = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"alice-admin"},
	"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
	"subjects":[{"kind":"User","name":"alice"}]}`

func csrEdges(t *testing.T, ix *snapshot.Index, sa model.ObjectRef) []model.Edge {
	t.Helper()
	privileged, err := rbac.PrivilegedSubjects(ix)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}
	return CSRClientCertificate(ix, sa, permissions(t, ix, sa), privileged)
}

func TestCSRClientCertificateEscalates(t *testing.T) {
	ix, sa := csrFixture(t, fullCSRRules, aliceAdminBinding)
	edges := csrEdges(t, ix, sa)
	if len(edges) != 1 || edges[0].To != TargetClusterAdmin || edges[0].HopID != hopCSRClientCertificate {
		t.Fatalf("got %v, want one %s edge to %s", edgeTargets(edges), hopCSRClientCertificate, TargetClusterAdmin)
	}
	if edges[0].Confidence != "conditional" {
		t.Errorf("edge confidence is %q, want conditional", edges[0].Confidence)
	}
}

func TestCSRClientCertificateNeedsEveryPermission(t *testing.T) {
	cases := map[string]string{
		"no create":   `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]},{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["kubernetes.io/kube-apiserver-client"]}`,
		"no approval": `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["kubernetes.io/kube-apiserver-client"]}`,
		"no approve":  `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]}`,
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			ix, sa := csrFixture(t, rules, aliceAdminBinding)
			if edges := csrEdges(t, ix, sa); len(edges) != 0 {
				t.Fatalf("%s produced %d edges, want 0", name, len(edges))
			}
		})
	}
}

func TestCSRClientCertificateRequiresLiteralSigner(t *testing.T) {
	cases := map[string]string{
		"no resourceNames": `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},
			{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]},
			{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"]}`,
		"wildcard name": `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},
			{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]},
			{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["*"]}`,
		"other signer": `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},
			{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]},
			{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["example.com/other"]}`,
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			ix, sa := csrFixture(t, rules, aliceAdminBinding)
			if edges := csrEdges(t, ix, sa); len(edges) != 0 {
				t.Fatalf("%s produced %d edges, want 0", name, len(edges))
			}
		})
	}
}

func TestCSRClientCertificateNeedsAPrivilegedSubject(t *testing.T) {
	mastersOnly := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"masters"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"Group","name":"system:masters"}]}`
	ix, sa := csrFixture(t, fullCSRRules, mastersOnly)
	if edges := csrEdges(t, ix, sa); len(edges) != 0 {
		t.Fatalf("only a system:masters subject produced %d edges, want 0", len(edges))
	}

	ix, sa = csrFixture(t, fullCSRRules, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"sa-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"someone","namespace":"app"}]}`)
	if edges := csrEdges(t, ix, sa); len(edges) != 0 {
		t.Fatalf("only a ServiceAccount subject produced %d edges, want 0", len(edges))
	}
}

func TestCSRClientCertificateAcceptsRestrictedApproval(t *testing.T) {
	// Approval restricted to a name the identity can choose: creating a CSR is
	// unrestricted, so the identity names the request it will approve. A bare
	// Allows check would miss this and be a false negative.
	rules := `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},
		{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"],"resourceNames":["chosen-csr"]},
		{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["kubernetes.io/kube-apiserver-client"]}`
	ix, sa := csrFixture(t, rules, aliceAdminBinding)
	if edges := csrEdges(t, ix, sa); len(edges) != 1 {
		t.Fatalf("a restricted approval produced %d edges, want 1", len(edges))
	}
}

func TestCSRClientCertificateRejectsNamespacedPermissions(t *testing.T) {
	// Exactly one participant is granted by a RoleBinding (namespaced); the
	// other two stay cluster-scoped. The hop must stay silent for each case.
	const createRule = `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]}`
	const approvalRule = `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]}`
	const approveRule = `{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["kubernetes.io/kube-apiserver-client"]}`

	cases := map[string]struct {
		scopedRules      string
		role, verb, item string
	}{
		"create":   {approvalRule + "," + approveRule, "csr-creator", "create", "certificatesigningrequests"},
		"approval": {createRule + "," + approveRule, "csr-approver", "update", "certificatesigningrequests/approval"},
		"approve":  {createRule + "," + approvalRule, "csr-signer", "approve", "signers"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ix := indexOf(t, append(serviceAccountRaws,
				`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"csr-issuer"},"rules":[`+tc.scopedRules+`]}`,
				`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"csr-issuer"},
				 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"csr-issuer"},
				 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
				`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"`+tc.role+`","namespace":"app"},
				 "rules":[{"apiGroups":["certificates.k8s.io"],"resources":["`+tc.item+`"],"verbs":["`+tc.verb+`"],"resourceNames":["kubernetes.io/kube-apiserver-client","chosen"]}]}`,
				`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"`+tc.role+`","namespace":"app"},
				 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"`+tc.role+`"},
				 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
				`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRules+`]}`,
				aliceAdminBinding)...)
			sa := identity(t, ix, "app", "ci")
			if edges := csrEdges(t, ix, sa); len(edges) != 0 {
				t.Fatalf("a namespaced %s produced %d edges, want 0", name, len(edges))
			}
		})
	}
}

func TestCSRClientCertificateRejectsUnusableApprovalNames(t *testing.T) {
	// "*" is a literal name, not a wildcard, and neither it nor "" is a name a
	// CSR could have; a mixed list with one valid name stays usable.
	cases := map[string]struct {
		names string
		want  int
	}{
		"wildcard":     {`["*"]`, 0},
		"empty":        {`[""]`, 0},
		"invalid":      {`["Bad_Name"]`, 0},
		"mixed":        {`["*","chosen-csr"]`, 1},
		"unrestricted": {``, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			approval := `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests/approval"],"verbs":["update"]`
			if tc.names != "" {
				approval += `,"resourceNames":` + tc.names
			}
			approval += `}`
			rules := `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create"]},` +
				approval + `,` +
				`{"apiGroups":["certificates.k8s.io"],"resources":["signers"],"verbs":["approve"],"resourceNames":["kubernetes.io/kube-apiserver-client"]}`
			ix, sa := csrFixture(t, rules, aliceAdminBinding)
			if edges := csrEdges(t, ix, sa); len(edges) != tc.want {
				t.Fatalf("approval resourceNames %s produced %d edges, want %d", tc.names, len(edges), tc.want)
			}
		})
	}
}

func TestNewHopsAreDeterministic(t *testing.T) {
	raws := append(serviceAccountRaws,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},"rules":[`+clusterAdminRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-role"},"rules":[`+clusterAdminRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"binder"},"rules":[`+bindAndCreate+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"binder"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"binder"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		aliceAdminBinding,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"target-binding"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target-role"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"impersonator"},
		 "rules":[{"apiGroups":[""],"resources":["serviceaccounts"],"verbs":["impersonate"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"impersonator"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"impersonator"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"csr-issuer"},
		 "rules":[`+fullCSRRules+`]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"csr-issuer"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"csr-issuer"},
		 "subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)

	first := indexOf(t, raws...)
	reversed := make([]string, len(raws))
	for i, raw := range raws {
		reversed[len(raws)-1-i] = raw
	}
	second := indexOf(t, reversed...)

	sa1 := identity(t, first, "app", "ci")
	sa2 := identity(t, second, "app", "ci")
	privileged1, err := rbac.PrivilegedSubjects(first)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}
	privileged2, err := rbac.PrivilegedSubjects(second)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}

	hops := map[string]func(*snapshot.Index, model.ObjectRef, []rbac.PrivilegedSubject) []model.Edge{
		"NR-002": func(ix *snapshot.Index, sa model.ObjectRef, _ []rbac.PrivilegedSubject) []model.Edge {
			return Impersonation(ix, sa, permissions(t, ix, sa))
		},
		"NR-003": func(ix *snapshot.Index, sa model.ObjectRef, _ []rbac.PrivilegedSubject) []model.Edge {
			return TokenRequest(ix, sa, permissions(t, ix, sa))
		},
		"NR-004": func(ix *snapshot.Index, sa model.ObjectRef, _ []rbac.PrivilegedSubject) []model.Edge {
			return BindClusterRole(ix, sa, permissions(t, ix, sa))
		},
		"NR-005": func(ix *snapshot.Index, sa model.ObjectRef, _ []rbac.PrivilegedSubject) []model.Edge {
			edges, err := WidenClusterRole(ix, sa, permissions(t, ix, sa))
			if err != nil {
				t.Fatalf("WidenClusterRole: %v", err)
			}
			return edges
		},
		"NR-006": func(ix *snapshot.Index, sa model.ObjectRef, privileged []rbac.PrivilegedSubject) []model.Edge {
			return CSRClientCertificate(ix, sa, permissions(t, ix, sa), privileged)
		},
	}
	for name, run := range hops {
		a := run(first, sa1, privileged1)
		b := run(second, sa2, privileged2)
		if len(a) == 0 {
			t.Fatalf("%s produced no edge, so the determinism check would be vacuous", name)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s depends on insert order", name)
		}
	}
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
