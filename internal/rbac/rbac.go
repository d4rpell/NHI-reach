// Package rbac computes the effective permissions of an identity from the
// objects of a snapshot.
//
// Permissions follow the Kubernetes authorization model: a binding grants its
// role within its own scope, subjects are matched by ServiceAccount, user name
// or implicit group membership, and a rule restricted with resourceNames is
// honoured. Role aggregation is not recomputed: the rules materialized into the
// ClusterRole by the control plane are the ones evaluated.
package rbac

import (
	"fmt"
	"sort"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// Principal is a subject that authorization rules can be bound to.
type Principal struct {
	Kind      string // "ServiceAccount", "User" or "Group"
	Namespace string // ServiceAccount only
	Name      string
}

// ServiceAccount returns the principal of a ServiceAccount reference.
func ServiceAccount(ref model.ObjectRef) Principal {
	return Principal{Kind: "ServiceAccount", Namespace: ref.Namespace, Name: ref.Name}
}

// username is the authenticated user name of the principal, empty when the
// principal has none.
func (p Principal) username() string {
	switch p.Kind {
	case "ServiceAccount":
		return "system:serviceaccount:" + p.Namespace + ":" + p.Name
	case "User":
		return p.Name
	default:
		return ""
	}
}

// groups lists, in ascending order, the implicit group memberships used to
// match Group subjects. A ServiceAccount belongs to every service account, to
// the service accounts of its namespace and to every authenticated user; a
// User is an authenticated user; a Group is only a member of itself. The
// snapshot holds no user directory, so nothing else is assumed.
func (p Principal) groups() []string {
	switch p.Kind {
	case "ServiceAccount":
		return []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + p.Namespace}
	case "User":
		return []string{"system:authenticated"}
	case "Group":
		return []string{p.Name}
	default:
		return nil
	}
}

// Rule is one policy rule of a Role or ClusterRole.
type Rule struct {
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	Verbs           []string
	NonResourceURLs []string
}

// Allows reports whether the rule grants verb on resource of apiGroup for a
// request whose resource name is unrestricted. A rule carrying resourceNames
// restricts every request it authorizes to the listed instances, so Allows is
// false whenever resourceNames is not empty.
func (r Rule) Allows(apiGroup, resource, verb string) bool {
	return len(r.ResourceNames) == 0 && r.matches(apiGroup, resource, verb)
}

// AllowsName reports whether the rule grants verb on the resource instance
// named name. An empty resourceNames covers every name; otherwise name must be
// non-empty and listed literally. For list and watch, name stands for the
// metadata.name field selector such a request must carry; this query does not
// attest that the real request carries it.
func (r Rule) AllowsName(apiGroup, resource, name, verb string) bool {
	if !r.matches(apiGroup, resource, verb) {
		return false
	}
	if len(r.ResourceNames) == 0 {
		return true
	}
	return name != "" && contains(r.ResourceNames, name)
}

// matches reports whether the rule covers the (apiGroup, resource, verb)
// triple, ignoring resourceNames. This implementation supports exact matches
// and the "*" wildcard; a subresource such as "pods/log" is named explicitly,
// so a rule listing "pods" does not cover it.
func (r Rule) matches(apiGroup, resource, verb string) bool {
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

// contains reports exact membership; unlike has it does not treat "*" as a
// wildcard, because resourceNames is a list of names.
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// Granted is one effective rule together with the objects that produce it and
// the minimal grants whose removal eliminates it. One Granted is emitted per
// matching subject of the binding, because each subject is removable on its
// own.
type Granted struct {
	Rule    Rule
	Source  model.ObjectRef // the Role or ClusterRole holding the rule
	Binding model.ObjectRef // the binding that applies it to the subject
	// ClusterScoped is true when the rule reaches the whole cluster, that is,
	// when it comes from a ClusterRoleBinding.
	ClusterScoped bool
	Grants        []model.Grant
}

// Effective returns every rule that applies to p, ordered by (source, binding,
// rule, subject).
//
// Every RoleBinding of the snapshot is considered, in every namespace: a
// RoleBinding grants its role inside its own namespace and may name a subject
// from any namespace, so the namespace of p does not select the bindings. Every
// ClusterRoleBinding is considered too.
//
// It fails when a matched binding references a role the snapshot does not hold:
// a dangling roleRef is an input defect, not a silent skip.
func Effective(ix *snapshot.Index, p Principal) ([]Granted, error) {
	bindings := ix.List("RoleBinding", "")
	bindings = append(bindings, ix.List("ClusterRoleBinding", "")...)

	var out []Granted
	for _, binding := range bindings {
		_, obj, ok := ix.Entry(binding.Kind, binding.Namespace, binding.Name)
		if !ok {
			continue
		}
		subjects, _ := obj["subjects"].([]any)
		matched := matchedSubjects(subjects, p)
		if len(matched) == 0 {
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
		for _, detail := range matched {
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
						{Object: binding, Kind: "binding-subject", Detail: detail},
						{Object: roleObj, Kind: "role-rule", Detail: fmt.Sprintf("rules[%d]", i)},
					},
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Source.Kind != b.Source.Kind {
			return a.Source.Kind < b.Source.Kind
		}
		if a.Source.Namespace != b.Source.Namespace {
			return a.Source.Namespace < b.Source.Namespace
		}
		if a.Source.Name != b.Source.Name {
			return a.Source.Name < b.Source.Name
		}
		if a.Binding.Kind != b.Binding.Kind {
			return a.Binding.Kind < b.Binding.Kind
		}
		if a.Binding.Namespace != b.Binding.Namespace {
			return a.Binding.Namespace < b.Binding.Namespace
		}
		if a.Binding.Name != b.Binding.Name {
			return a.Binding.Name < b.Binding.Name
		}
		if a.Grants[1].Detail != b.Grants[1].Detail {
			return a.Grants[1].Detail < b.Grants[1].Detail
		}
		return a.Grants[0].Detail < b.Grants[0].Detail
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

// matchedSubjects returns the canonical detail of every subject of the binding
// that matches p, without duplicates.
func matchedSubjects(subjects []any, p Principal) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range subjects {
		subject, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		kind, _ := subject["kind"].(string)
		name, _ := subject["name"].(string)
		namespace, _ := subject["namespace"].(string)
		if !matchesSubject(p, kind, namespace, name) {
			continue
		}
		detail := subjectDetail(kind, namespace, name)
		if seen[detail] {
			continue
		}
		seen[detail] = true
		out = append(out, detail)
	}
	return out
}

func matchesSubject(p Principal, kind, namespace, name string) bool {
	switch kind {
	case "ServiceAccount":
		return p.Kind == "ServiceAccount" && name == p.Name && namespace == p.Namespace
	case "User":
		username := p.username()
		return username != "" && name == username
	case "Group":
		return contains(p.groups(), name)
	}
	return false
}

// subjectDetail renders the canonical identity of a subject. A ServiceAccount
// keeps its namespace, so homonyms in different namespaces stay distinct.
func subjectDetail(kind, namespace, name string) string {
	if kind == "ServiceAccount" {
		return "subject ServiceAccount " + namespace + "/" + name
	}
	return "subject " + kind + " " + name
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
