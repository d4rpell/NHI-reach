package rbac

import (
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// The cases below are the removals the read-only contract must reject: a unit
// that changes nothing would let an untouched model be reported as a verified
// cut.
func TestWithoutRejectsRemovalsThatWouldChangeNothing(t *testing.T) {
	ix := multiSubjectBinding(t)
	binding, _, _ := ix.Entry("ClusterRoleBinding", "", "admin")

	for _, tc := range []struct {
		name  string
		units []model.Grant
	}{
		{"subject the binding does not name", []model.Grant{
			unit("binding-subject", "subject ServiceAccount app/absent", binding),
		}},
		{"one of two subjects is absent", []model.Grant{
			unit("binding-subject", "subject ServiceAccount app/deployer", binding),
			unit("binding-subject", "subject ServiceAccount app/absent", binding),
		}},
		{"unsupported subject kind", []model.Grant{
			unit("binding-subject", "subject Robot r2d2", binding),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Without(ix, tc.units)
			if err == nil {
				t.Fatal("Without accepted a removal that changes nothing")
			}
			if result != nil {
				t.Error("Without returned an index along with the error")
			}
		})
	}
}

func TestWithoutCollapsesEquivalentUnits(t *testing.T) {
	ix := multiSubjectBinding(t)
	sa := ServiceAccount(identity(t, ix, "app", "deployer"))
	binding, _, _ := ix.Entry("ClusterRoleBinding", "", "admin")

	// Asking twice for one removal is the same request, not a contradiction: it
	// must succeed and remove the subject once.
	edited, err := Without(ix, []model.Grant{
		unit("binding-subject", "subject ServiceAccount app/deployer", binding),
		unit("binding-subject", "subject ServiceAccount app/deployer", binding),
	})
	if err != nil {
		t.Fatalf("Without: %v", err)
	}
	_, obj, _ := edited.Entry("ClusterRoleBinding", "", "admin")
	subjects, _ := obj["subjects"].([]any)
	if len(subjects) != 1 {
		t.Fatalf("binding holds %d subjects, want only the group one", len(subjects))
	}
	if !IsClusterAdmin(allowed(t, edited, sa)) {
		t.Error("the group subject should still grant cluster-admin")
	}

	// The same for a rule index asked twice.
	ix = snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"mixed"},"rules":[
		{"apiGroups":[""],"resources":["pods"],"verbs":["get"]},
		{"apiGroups":[""],"resources":["pods"],"verbs":["list"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"mixed"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"mixed"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)
	role, _, _ := ix.Entry("ClusterRole", "", "mixed")
	edited, err = Without(ix, []model.Grant{
		unit("role-rule", "rules[0]", role),
		unit("role-rule", "rules[0]", role),
	})
	if err != nil {
		t.Fatalf("Without: %v", err)
	}
	_, obj, _ = edited.Entry("ClusterRole", "", "mixed")
	rules, _ := obj["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("role holds %d rules, want the second one only", len(rules))
	}
	verbs := rules[0].(map[string]any)["verbs"].([]any)
	if len(verbs) != 1 || verbs[0] != "list" {
		t.Errorf("surviving rule is %v, want the one at index 1", verbs)
	}
}

// TestWithoutMatchesADuplicateSubjectEntryBoundByEffective binds a User subject
// that also carries a namespace: Effective matches a User by name alone (the
// canonical detail omits the namespace), so the removal must resolve it the same
// way instead of reporting that the binding does not name it.
func TestWithoutMatchesADuplicateSubjectEntryBoundByEffective(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"reader"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"reader"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"reader"},
		"subjects":[{"kind":"User","name":"alice","namespace":"somewhere"}]}`)
	principal := Principal{Kind: "User", Name: "alice"}
	binding, _, _ := ix.Entry("ClusterRoleBinding", "", "reader")

	granted := allowed(t, ix, principal)
	if len(granted) == 0 {
		t.Fatal("fixture is wrong: Effective did not match the namespaced User subject by name")
	}

	edited, err := Without(ix, []model.Grant{unit("binding-subject", "subject User alice", binding)})
	if err != nil {
		t.Fatalf("Without rejected a subject Effective matched: %v", err)
	}
	if got := allowed(t, edited, principal); len(got) != 0 {
		t.Errorf("the User grant survived the removal: %d grants", len(got))
	}
}
