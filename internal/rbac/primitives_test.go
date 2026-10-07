package rbac

import (
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

func TestRuleMatchesIgnoresResourceNames(t *testing.T) {
	restricted := Rule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}, ResourceNames: []string{"chosen"}}
	if !restricted.Matches("certificates.k8s.io", "certificatesigningrequests/approval", "update") {
		t.Error("Matches rejected a rule that covers the triple but carries resourceNames")
	}
	if restricted.Allows("certificates.k8s.io", "certificatesigningrequests/approval", "update") {
		t.Error("Allows accepted a rule restricted by resourceNames")
	}
	if restricted.Matches("certificates.k8s.io", "signers", "update") {
		t.Error("Matches accepted a rule for a different resource")
	}
}

func TestParseRulesExtractsRules(t *testing.T) {
	role := map[string]any{"rules": []any{
		map[string]any{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"}},
	}}
	rules := ParseRules(role)
	if len(rules) != 1 || !rules[0].Allows("*", "*", "*") {
		t.Fatalf("ParseRules returned %+v, want the single wildcard rule", rules)
	}
	if got := ParseRules(map[string]any{}); len(got) != 0 {
		t.Fatalf("ParseRules returned %d rules for a role without rules", len(got))
	}
}

func TestRulesAreClusterAdmin(t *testing.T) {
	cases := map[string]bool{
		"wildcard":            true,
		"restricted names":    false,
		"specific resources":  false,
		"missing verbs":       false,
		"empty rule list":     false,
		"wildcard with names": false,
	}
	inputs := map[string][]Rule{
		"wildcard":            {{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		"restricted names":    {{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}, ResourceNames: []string{"x"}}},
		"specific resources":  {{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
		"missing verbs":       {{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get"}}},
		"empty rule list":     {},
		"wildcard with names": {{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}, ResourceNames: []string{"*"}}},
	}
	for name, want := range cases {
		if got := RulesAreClusterAdmin(inputs[name]); got != want {
			t.Errorf("%s: RulesAreClusterAdmin = %t, want %t", name, got, want)
		}
	}
}

func TestBindingsReturnsReferencedRole(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"reader","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
		"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"admin"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)

	p := ServiceAccount(identity(t, ix, "app", "ci"))
	bindings, err := Bindings(ix, p)
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("Bindings returned %d, want 2", len(bindings))
	}
	// Ordered by (kind, namespace, name): ClusterRoleBinding before RoleBinding.
	if bindings[0].Object.Kind != "ClusterRoleBinding" || bindings[0].Role.Name != "admin" {
		t.Errorf("first binding is %+v, want the ClusterRoleBinding to admin", bindings[0])
	}
	if bindings[1].Object.Kind != "RoleBinding" || bindings[1].Role.Namespace != "app" || bindings[1].Role.Name != "reader" {
		t.Errorf("second binding is %+v, want the namespaced RoleBinding to app/reader", bindings[1])
	}
}

func TestBindingsSeesRuleLessRole(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"empty"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"empty"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"empty"},
		"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)

	p := ServiceAccount(identity(t, ix, "app", "ci"))
	bindings, err := Bindings(ix, p)
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if len(bindings) != 1 || bindings[0].Role.Name != "empty" {
		t.Fatalf("Bindings returned %+v, want the rule-less ClusterRole link", bindings)
	}
}

func TestBindingsReportsDanglingRoleRef(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"dangling"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"missing"},
		"subjects":[{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)

	p := ServiceAccount(identity(t, ix, "app", "ci"))
	if _, err := Bindings(ix, p); err == nil {
		t.Fatal("Bindings accepted a dangling roleRef")
	}
}

func privilegedFixture(t *testing.T, clusterRoleRules string, bindings ...string) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target"}`+
		clusterRoleRules+`}`)
	for _, binding := range bindings {
		add(t, ix, binding)
	}
	return ix
}

func TestPrivilegedSubjectsFindsUserAndGroup(t *testing.T) {
	ix := privilegedFixture(t, `,"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"users"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target"},
		 "subjects":[{"kind":"User","name":"alice"},{"kind":"Group","name":"developers"}]}`)

	subjects, err := PrivilegedSubjects(ix)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}
	if len(subjects) != 2 {
		t.Fatalf("PrivilegedSubjects returned %d, want 2", len(subjects))
	}
	// Ordered by (Kind, Name): Group before User.
	if subjects[0].Principal.Kind != "Group" || subjects[0].Principal.Name != "developers" {
		t.Errorf("first subject is %+v, want Group developers", subjects[0].Principal)
	}
	if subjects[1].Principal.Kind != "User" || subjects[1].Principal.Name != "alice" {
		t.Errorf("second subject is %+v, want User alice", subjects[1].Principal)
	}
	for _, subject := range subjects {
		if len(subject.Evidence) != 2 {
			t.Errorf("subject %+v carries %d evidence objects, want the binding and the role", subject.Principal, len(subject.Evidence))
		}
	}
}

func TestPrivilegedSubjectsExcludesSystemMastersAndServiceAccounts(t *testing.T) {
	ix := privilegedFixture(t, `,"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"masters"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target"},
		 "subjects":[{"kind":"Group","name":"system:masters"},{"kind":"ServiceAccount","name":"ci","namespace":"app"}]}`)

	subjects, err := PrivilegedSubjects(ix)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}
	if len(subjects) != 0 {
		t.Fatalf("PrivilegedSubjects returned %+v, want none (system:masters and ServiceAccounts are excluded)", subjects)
	}
}

func TestPrivilegedSubjectsRequiresClusterAdminRole(t *testing.T) {
	ix := privilegedFixture(t, `,"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"users"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target"},
		 "subjects":[{"kind":"User","name":"alice"}]}`)

	subjects, err := PrivilegedSubjects(ix)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}
	if len(subjects) != 0 {
		t.Fatalf("PrivilegedSubjects returned %+v, want none for a non-admin role", subjects)
	}
}

func TestPrivilegedSubjectsAggregatesEvidencePerSubject(t *testing.T) {
	binding := func(name string) string {
		return `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"` + name + `"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"target"},
		 "subjects":[{"kind":"User","name":"alice"}]}`
	}
	ix := privilegedFixture(t, `,"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]`,
		binding("one"), binding("two"))

	subjects, err := PrivilegedSubjects(ix)
	if err != nil {
		t.Fatalf("PrivilegedSubjects: %v", err)
	}
	if len(subjects) != 1 {
		t.Fatalf("PrivilegedSubjects returned %d subjects, want 1 (deduplicated)", len(subjects))
	}
	// Two bindings plus the single ClusterRole, deduplicated.
	if len(subjects[0].Evidence) != 3 {
		t.Fatalf("evidence holds %d objects, want two bindings and one role", len(subjects[0].Evidence))
	}
	var names []string
	for _, ref := range subjects[0].Evidence {
		names = append(names, ref.Kind+"/"+ref.Name)
	}
	if strings.Join(names, ",") != "ClusterRole/target,ClusterRoleBinding/one,ClusterRoleBinding/two" {
		t.Errorf("evidence order is %v, want the role first then the bindings", names)
	}
}
