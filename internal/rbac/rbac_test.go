package rbac

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
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

func allowed(t *testing.T, ix *snapshot.Index, p Principal) []Granted {
	t.Helper()
	granted, err := Effective(ix, p)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	return granted
}

func fingerprint(granted []Granted) []string {
	out := make([]string, 0, len(granted))
	for _, g := range granted {
		out = append(out, strings.Join([]string{
			g.Source.Kind, g.Source.Namespace, g.Source.Name,
			g.Binding.Kind, g.Binding.Namespace, g.Binding.Name,
			g.Grants[0].Detail, g.Grants[1].Detail,
			fmt.Sprintf("%t", g.ClusterScoped),
		}, "|"))
	}
	return out
}

func TestRuleAllows(t *testing.T) {
	cases := []struct {
		name   string
		rule   Rule
		group  string
		object string
		verb   string
		want   bool
	}{
		{"exact", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}, "", "pods", "create", true},
		{"other verb", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, "", "pods", "create", false},
		{"wildcard everything", Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}, "apps", "deployments", "delete", true},
		{"wildcard verb", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}, "", "pods", "create", true},
		{"other group", Rule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}, "", "pods", "create", false},
		{"named resources restrict get", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web"}, Verbs: []string{"get"}}, "", "pods", "get", false},
		{"named resources restrict update", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web"}, Verbs: []string{"update"}}, "", "pods", "update", false},
		{"named resources restrict list", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web"}, Verbs: []string{"list"}}, "", "pods", "list", false},
		{"named resources restrict watch", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web"}, Verbs: []string{"watch"}}, "", "pods", "watch", false},
		{"named resources restrict create", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web"}, Verbs: []string{"create"}}, "", "pods", "create", false},
		{"named resources restrict deletecollection", Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"web"}, Verbs: []string{"deletecollection"}}, "", "secrets", "deletecollection", false},
		{"named subresource restricts create", Rule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, ResourceNames: []string{"web"}, Verbs: []string{"create"}}, "", "pods/exec", "create", false},
		{"unrestricted rule allows create", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}, "", "pods", "create", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Allows(tc.group, tc.object, tc.verb); got != tc.want {
				t.Errorf("Allows(%q, %q, %q) = %v, want %v", tc.group, tc.object, tc.verb, got, tc.want)
			}
		})
	}
}

func TestRuleAllowsName(t *testing.T) {
	restricted := Rule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"},
		ResourceNames: []string{"admin", "edit", "view"}, Verbs: []string{"bind", "escalate", "approve"}}
	open := Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}
	star := Rule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"*"}, Verbs: []string{"get"}}

	cases := []struct {
		name                       string
		rule                       Rule
		group, resource, obj, verb string
		want                       bool
	}{
		{"listed name", restricted, "rbac.authorization.k8s.io", "clusterroles", "admin", "bind", true},
		{"listed name for escalate", restricted, "rbac.authorization.k8s.io", "clusterroles", "edit", "escalate", true},
		{"listed name for approve", restricted, "rbac.authorization.k8s.io", "clusterroles", "view", "approve", true},
		{"other name", restricted, "rbac.authorization.k8s.io", "clusterroles", "other", "bind", false},
		{"empty name is not covered", restricted, "rbac.authorization.k8s.io", "clusterroles", "", "bind", false},
		{"other verb is not covered", restricted, "rbac.authorization.k8s.io", "clusterroles", "admin", "get", false},
		{"empty resourceNames covers the name", open, "", "pods", "anything", "get", true},
		{"empty resourceNames covers the empty name", open, "", "pods", "", "get", true},
		{"star is a literal name", star, "", "configmaps", "anything", "get", false},
		{"star is a literal name for itself", star, "", "configmaps", "*", "get", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.AllowsName(tc.group, tc.resource, tc.obj, tc.verb); got != tc.want {
				t.Errorf("AllowsName(%q, %q, %q, %q) = %v, want %v", tc.group, tc.resource, tc.obj, tc.verb, got, tc.want)
			}
		})
	}
}

func TestRuleMatchesSubresources(t *testing.T) {
	wildcard := Rule{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}
	named := Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}

	if !wildcard.Allows("", "pods/log", "get") {
		t.Error(`wildcard resource did not cover the subresource "pods/log"`)
	}
	if named.Allows("", "pods/log", "get") {
		t.Error(`"pods" covered the subresource "pods/log" without naming it`)
	}
	if !named.Allows("", "pods", "get") {
		t.Error(`"pods" did not cover the resource "pods"`)
	}
}

func TestPrincipalUsernameAndGroups(t *testing.T) {
	cases := []struct {
		principal Principal
		username  string
		groups    []string
	}{
		{Principal{Kind: "ServiceAccount", Namespace: "app", Name: "ci"}, "system:serviceaccount:app:ci",
			[]string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:app"}},
		{Principal{Kind: "User", Name: "alice"}, "alice", []string{"system:authenticated"}},
		{Principal{Kind: "Group", Name: "developers"}, "", []string{"developers"}},
	}
	for _, tc := range cases {
		if got := tc.principal.username(); got != tc.username {
			t.Errorf("%s username = %q, want %q", tc.principal.Kind, got, tc.username)
		}
		got := tc.principal.groups()
		if strings.Join(got, ",") != strings.Join(tc.groups, ",") {
			t.Errorf("%s groups = %v, want %v", tc.principal.Kind, got, tc.groups)
		}
		for i := 1; i < len(got); i++ {
			if got[i-1] > got[i] {
				t.Errorf("%s groups are not ascending: %v", tc.principal.Kind, got)
			}
		}
	}
}

func TestEffectiveClusterScopedBindingIsClusterAdmin(t *testing.T) {
	ix := clusterAdminIndex(t, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
		"metadata":{"name":"ops-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	granted := allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))
	if !IsClusterAdmin(granted) {
		t.Fatal("cluster-scoped binding to cluster-admin was not equivalent to cluster-admin")
	}
	admins := ClusterAdminGrants(granted)
	if len(admins) != 1 {
		t.Fatalf("got %d cluster-admin grants, want 1", len(admins))
	}
	if admins[0].Binding.Name != "ops-admin" {
		t.Errorf("grant attributed to binding %q, want ops-admin", admins[0].Binding.Name)
	}
	if len(admins[0].Grants) != 2 {
		t.Errorf("grant carries %d removal units, want binding-subject and role-rule", len(admins[0].Grants))
	}
	if admins[0].Grants[0].Detail != "subject ServiceAccount app/ops" {
		t.Errorf("removal unit is %q, want the canonical subject identity", admins[0].Grants[0].Detail)
	}
}

func clusterAdminIndex(t *testing.T, binding string) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	add(t, ix, binding)
	return ix
}

func TestEffectiveNamespaceBindingIsNotClusterAdmin(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"ops-admin","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	granted := allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))
	if IsClusterAdmin(granted) {
		t.Fatal("a namespace-scoped binding was treated as cluster-admin")
	}
}

func TestEffectiveIgnoresOtherSubjects(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"creator","namespace":"app"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"creator","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"someone-else","namespace":"app"}]}`)

	granted := allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))
	if len(granted) != 0 {
		t.Fatalf("got %d grants for a subject that is not bound, want 0", len(granted))
	}
}

func TestEffectiveReportsDanglingRoleRef(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"creator","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"missing"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	_, err := Effective(ix, ServiceAccount(identity(t, ix, "app", "ops")))
	if err == nil {
		t.Fatal("Effective accepted a binding whose role does not exist")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error does not name the missing role: %v", err)
	}
}

func namespaceGroupIndex(t *testing.T) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"other"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	return ix
}

func TestEffectiveMatchesNamespaceServiceAccountGroup(t *testing.T) {
	ix := namespaceGroupIndex(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"app-sa-admins"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"Group","name":"system:serviceaccounts:app","apiGroup":"rbac.authorization.k8s.io"}]}`)

	if !IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))) {
		t.Error("a service account of the bound namespace group was not granted")
	}
	if IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "other", "ops")))) {
		t.Error("a service account of another namespace group was granted")
	}
}

func TestEffectiveMatchesGlobalServiceAccountGroups(t *testing.T) {
	for _, group := range []string{"system:serviceaccounts", "system:authenticated"} {
		t.Run(group, func(t *testing.T) {
			ix := namespaceGroupIndex(t)
			add(t, ix, fmt.Sprintf(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"all"},
				"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
				"subjects":[{"kind":"Group","name":%q,"apiGroup":"rbac.authorization.k8s.io"}]}`, group))

			if !IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))) {
				t.Errorf("group %q did not grant the service account", group)
			}
			if !IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "other", "ops")))) {
				t.Errorf("group %q did not grant a service account of another namespace", group)
			}
		})
	}
}

func TestEffectiveMatchesUserSubject(t *testing.T) {
	ix := namespaceGroupIndex(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"user-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"User","name":"system:serviceaccount:app:ops","apiGroup":"rbac.authorization.k8s.io"}]}`)

	if !IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))) {
		t.Error("a binding naming the service account's user name did not grant it")
	}
	if IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "other", "ops")))) {
		t.Error("a binding naming another user name granted this service account")
	}
}

func TestEffectiveEvaluatesNonServiceAccountPrincipals(t *testing.T) {
	ix := namespaceGroupIndex(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"user-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"User","name":"privileged-user","apiGroup":"rbac.authorization.k8s.io"}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"group-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"Group","name":"privileged-group","apiGroup":"rbac.authorization.k8s.io"}]}`)

	if !IsClusterAdmin(allowed(t, ix, Principal{Kind: "User", Name: "privileged-user"})) {
		t.Error("a User principal bound to cluster-admin was not equivalent to cluster-admin")
	}
	if !IsClusterAdmin(allowed(t, ix, Principal{Kind: "Group", Name: "privileged-group"})) {
		t.Error("a Group principal bound to cluster-admin was not equivalent to cluster-admin")
	}
	if IsClusterAdmin(allowed(t, ix, Principal{Kind: "User", Name: "someone-else"})) {
		t.Error("an unbound User principal was treated as cluster-admin")
	}
}

func TestEffectiveEnumeratesEveryNamespace(t *testing.T) {
	ix := namespaceGroupIndex(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"pod-creator","namespace":"b"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"pod-creator","namespace":"b"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"pod-creator"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	granted := allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))
	if len(granted) != 1 {
		t.Fatalf("got %d grants, want the RoleBinding of the other namespace", len(granted))
	}
	if granted[0].ClusterScoped {
		t.Error("a RoleBinding grant was reported as cluster scoped")
	}
	if granted[0].Binding.Namespace != "b" {
		t.Errorf("grant scope is namespace %q, want the binding namespace b", granted[0].Binding.Namespace)
	}
}

func TestEffectiveKeepsEveryMatchingSubject(t *testing.T) {
	build := func(subjects string) *snapshot.Index {
		ix := namespaceGroupIndex(t)
		add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"reader"},
			"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`)
		add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"readers"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"reader"},
			"subjects":[`+subjects+`]}`)
		return ix
	}

	both := build(`{"kind":"Group","name":"system:authenticated","apiGroup":"rbac.authorization.k8s.io"},
		{"kind":"Group","name":"system:serviceaccounts","apiGroup":"rbac.authorization.k8s.io"}`)
	granted := allowed(t, both, ServiceAccount(identity(t, both, "app", "ops")))
	if len(granted) != 2 {
		t.Fatalf("got %d grants for a binding with two matching subjects, want 2", len(granted))
	}
	details := []string{granted[0].Grants[0].Detail, granted[1].Grants[0].Detail}
	if details[0] == details[1] {
		t.Errorf("both grants name the same removal unit %q", details[0])
	}
	if !strings.Contains(strings.Join(details, " "), "subject Group system:authenticated") ||
		!strings.Contains(strings.Join(details, " "), "subject Group system:serviceaccounts") {
		t.Errorf("removal units do not name both subjects: %v", details)
	}

	one := build(`{"kind":"Group","name":"system:authenticated","apiGroup":"rbac.authorization.k8s.io"}`)
	if got := allowed(t, one, ServiceAccount(identity(t, one, "app", "ops"))); len(got) != 1 {
		t.Fatalf("after dropping one of the two subjects the rule is granted %d times, want 1", len(got))
	}
}

func TestEffectiveDistinguishesServiceAccountHomonyms(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"b"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"reader"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"readers"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"reader"},
		"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"},{"kind":"ServiceAccount","name":"ci","namespace":"b"}]}`)

	app := allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ci")))
	other := allowed(t, ix, ServiceAccount(identity(t, ix, "b", "ci")))
	if len(app) != 1 || len(other) != 1 {
		t.Fatalf("got %d and %d grants, want one each", len(app), len(other))
	}
	if app[0].Grants[0].Detail != "subject ServiceAccount app/ci" {
		t.Errorf("app homonym removal unit is %q", app[0].Grants[0].Detail)
	}
	if other[0].Grants[0].Detail != "subject ServiceAccount b/ci" {
		t.Errorf("b homonym removal unit is %q", other[0].Grants[0].Detail)
	}
}

func TestClusterAdminRequiresUnrestrictedRule(t *testing.T) {
	ix := namespaceGroupIndex(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"restricted-admin"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"],"resourceNames":["only-this"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"restricted"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"restricted-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	if IsClusterAdmin(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))) {
		t.Error("a */*/* rule restricted with resourceNames was treated as cluster-admin")
	}
}

func TestAggregatedClusterRoleUsesMaterializedRules(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	// The aggregationRule selects nothing that carries rules: only the rules the
	// control plane materialized into the object may grant anything.
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"monitoring"},
		"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"rbac.example.com/aggregate-to-monitoring":"true"}}]},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"empty-aggregate"},
		"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"rbac.example.com/aggregate-to-empty":"true"}}]}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"monitoring"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"monitoring"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"empty-aggregate"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"empty-aggregate"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	granted := allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))
	if len(granted) != 1 {
		t.Fatalf("got %d grants, want only the materialized rule of the aggregated role", len(granted))
	}
	if !granted[0].Rule.Allows("", "pods", "get") {
		t.Error("the materialized rule of the aggregated ClusterRole was not evaluated")
	}
}

// TestEffectiveIgnoresSecrets is supporting evidence only: the invariant that no
// permission path reads a Secret is accredited by reviewing the code paths, not
// by observing results. A Secret whose name matches a subject must not change
// the outcome.
func TestEffectiveIgnoresSecrets(t *testing.T) {
	ix := namespaceGroupIndex(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"app-sa-admins"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"Group","name":"system:serviceaccounts:app","apiGroup":"rbac.authorization.k8s.io"}]}`)

	before := fingerprint(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops"))))

	add(t, ix, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"ops","namespace":"app"},
		"type":"Opaque","data":{"password":"c2VjcmV0"}}`)

	after := fingerprint(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops"))))
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("adding a Secret changed the effective permissions:\n%v\n%v", before, after)
	}
}

func TestEffectiveIsDeterministicAcrossBindingOrder(t *testing.T) {
	objects := []string{
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"creator","namespace":"app"},
			"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"creator","namespace":"app"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
			"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"reader"},
			"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"reader"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"reader"},
			"subjects":[{"kind":"Group","name":"system:serviceaccounts","apiGroup":"rbac.authorization.k8s.io"}]}`,
	}

	build := func(order []int) *snapshot.Index {
		ix := snapshot.New()
		for _, i := range order {
			add(t, ix, objects[i])
		}
		return ix
	}

	forward := build([]int{0, 1, 2, 3, 4})
	backward := build([]int{4, 3, 2, 1, 0})
	shuffled := build([]int{2, 0, 4, 1, 3})

	want := strings.Join(fingerprint(allowed(t, forward, ServiceAccount(identity(t, forward, "app", "ops")))), "\n")
	for name, ix := range map[string]*snapshot.Index{"backward": backward, "shuffled": shuffled} {
		got := strings.Join(fingerprint(allowed(t, ix, ServiceAccount(identity(t, ix, "app", "ops")))), "\n")
		if got != want {
			t.Errorf("%s order produced a different result:\n%s\nwant:\n%s", name, got, want)
		}
	}
}

func TestEffectiveOrderHandlesNameCollisions(t *testing.T) {
	// A Role and a ClusterRole share a name, and a RoleBinding and a
	// ClusterRoleBinding share another one: the order must not depend on which
	// object was indexed first.
	shared := []string{
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"admin","namespace":"app"},
			"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"admin"},
			"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["list"]}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"binding","namespace":"app"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"admin"},
			"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"binding"},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"admin"},
			"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`,
	}

	build := func(order []int) *snapshot.Index {
		ix := snapshot.New()
		for _, i := range order {
			add(t, ix, shared[i])
		}
		return ix
	}

	forward := build([]int{0, 1, 2, 3, 4})
	backward := build([]int{4, 3, 2, 1, 0})
	want := strings.Join(fingerprint(allowed(t, forward, ServiceAccount(identity(t, forward, "app", "ops")))), "\n")
	got := strings.Join(fingerprint(allowed(t, backward, ServiceAccount(identity(t, backward, "app", "ops")))), "\n")
	if got != want {
		t.Errorf("reverse indexing produced a different order:\n%s\nwant:\n%s", got, want)
	}
}
