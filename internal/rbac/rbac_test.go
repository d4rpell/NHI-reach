package rbac

import (
	"encoding/json"
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
		{"named resources never match", Rule{APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web"}, Verbs: []string{"create"}}, "", "pods", "create", false},
		{"other group", Rule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}, "", "pods", "create", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Allows(tc.group, tc.object, tc.verb); got != tc.want {
				t.Errorf("Allows(%q, %q, %q) = %v, want %v", tc.group, tc.object, tc.verb, got, tc.want)
			}
		})
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

func TestEffectiveClusterScopedBindingIsClusterAdmin(t *testing.T) {
	ix := clusterAdminIndex(t, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
		"metadata":{"name":"ops-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	granted, err := Effective(ix, identity(t, ix, "app", "ops"))
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
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

	granted, err := Effective(ix, identity(t, ix, "app", "ops"))
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
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

	granted, err := Effective(ix, identity(t, ix, "app", "ops"))
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
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

	_, err := Effective(ix, identity(t, ix, "app", "ops"))
	if err == nil {
		t.Fatal("Effective accepted a binding whose role does not exist")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error does not name the missing role: %v", err)
	}
}
