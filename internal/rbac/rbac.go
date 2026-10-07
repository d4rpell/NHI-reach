// Package rbac computes the effective RBAC permissions of a ServiceAccount
// from the objects of a snapshot.
//
// The light vertical implements direct subjects only: implicit ServiceAccount
// groups, wildcards on resources beyond the basic form, aggregation and
// OpenShift additions belong to T1-02.
package rbac

import (
	"fmt"
	"sort"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// Rule is one policy rule of a Role or ClusterRole.
type Rule struct {
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	Verbs           []string
	NonResourceURLs []string
}

// Allows reports whether the rule grants verb on resource of apiGroup, honouring
// the "*" wildcard. A rule restricted with resourceNames never matches here:
// the light vertical does not model named-resource grants.
func (r Rule) Allows(apiGroup, resource, verb string) bool {
	if len(r.ResourceNames) > 0 {
		return false
	}
	return has(r.APIGroups, apiGroup) && has(r.Resources, resource) && has(r.Verbs, verb)
}

func has(values []string, want string) bool {
	for _, v := range values {
		if v == want || v == "*" {
			return true
		}
	}
	return false
}

// Granted is one effective rule together with the objects that produce it and
// the minimal grants whose removal eliminates it.
type Granted struct {
	Rule    Rule
	Source  model.ObjectRef // the Role or ClusterRole holding the rule
	Binding model.ObjectRef // the binding that applies it to the subject
	// ClusterScoped is true when the rule reaches the whole cluster, that is,
	// when it comes from a ClusterRoleBinding.
	ClusterScoped bool
	Grants        []model.Grant
}

// Effective returns every rule that applies to sa through a RoleBinding of its
// namespace or a ClusterRoleBinding, ordered by (source, binding, rule).
//
// It fails when a binding references a role the snapshot does not hold: a
// dangling roleRef is an input defect, not a silent skip.
func Effective(ix *snapshot.Index, sa model.ObjectRef) ([]Granted, error) {
	bindings := ix.List("RoleBinding", sa.Namespace)
	bindings = append(bindings, ix.List("ClusterRoleBinding", "")...)

	var out []Granted
	for _, binding := range bindings {
		_, obj, ok := ix.Entry(binding.Kind, binding.Namespace, binding.Name)
		if !ok {
			continue
		}
		subjects, _ := obj["subjects"].([]any)
		if !hasSubject(subjects, sa) {
			continue
		}
		roleRef, _ := obj["roleRef"].(map[string]any)
		roleKind, _ := roleRef["kind"].(string)
		roleName, _ := roleRef["name"].(string)
		roleNamespace := ""
		if roleKind == "Role" {
			roleNamespace = binding.Namespace
		}
		roleObj, role, ok := ix.Entry(roleKind, roleNamespace, roleName)
		if !ok {
			return nil, fmt.Errorf("binding %s %s/%s references missing %s %s/%s",
				binding.Kind, binding.Namespace, binding.Name, roleKind, roleNamespace, roleName)
		}

		rules, _ := role["rules"].([]any)
		subjectDetail := fmt.Sprintf("subject ServiceAccount %s/%s", sa.Namespace, sa.Name)
		for i, raw := range rules {
			rule, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, Granted{
				Rule:          parseRule(rule),
				Source:        roleObj,
				Binding:       binding,
				ClusterScoped: binding.Kind == "ClusterRoleBinding",
				Grants: []model.Grant{
					{Object: binding, Kind: "binding-subject", Detail: subjectDetail},
					{Object: roleObj, Kind: "role-rule", Detail: fmt.Sprintf("rules[%d]", i)},
				},
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Source.Namespace != b.Source.Namespace {
			return a.Source.Namespace < b.Source.Namespace
		}
		if a.Source.Name != b.Source.Name {
			return a.Source.Name < b.Source.Name
		}
		if a.Binding.Namespace != b.Binding.Namespace {
			return a.Binding.Namespace < b.Binding.Namespace
		}
		if a.Binding.Name != b.Binding.Name {
			return a.Binding.Name < b.Binding.Name
		}
		return a.Grants[1].Detail < b.Grants[1].Detail
	})
	return out, nil
}

// IsClusterAdmin reports whether the effective permissions are equivalent to
// "*/*/*" at cluster scope (spec §2.5).
func IsClusterAdmin(granted []Granted) bool {
	return len(ClusterAdminGrants(granted)) > 0
}

// ClusterAdminGrants returns the cluster-scoped rules equivalent to "*/*/*".
func ClusterAdminGrants(granted []Granted) []Granted {
	var out []Granted
	for _, g := range granted {
		if g.ClusterScoped && g.Rule.Allows("*", "*", "*") {
			out = append(out, g)
		}
	}
	return out
}

func hasSubject(subjects []any, sa model.ObjectRef) bool {
	for _, raw := range subjects {
		subject, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := subject["kind"].(string)
		name, _ := subject["name"].(string)
		namespace, _ := subject["namespace"].(string)
		if kind == "ServiceAccount" && name == sa.Name && namespace == sa.Namespace {
			return true
		}
	}
	return false
}

func parseRule(rule map[string]any) Rule {
	return Rule{
		APIGroups:       stringSlice(rule["apiGroups"]),
		Resources:       stringSlice(rule["resources"]),
		ResourceNames:   stringSlice(rule["resourceNames"]),
		Verbs:           stringSlice(rule["verbs"]),
		NonResourceURLs: stringSlice(rule["nonResourceURLs"]),
	}
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
