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
	"strconv"
	"strings"

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
	return len(r.ResourceNames) == 0 && r.Matches(apiGroup, resource, verb)
}

// AllowsName reports whether the rule grants verb on the resource instance
// named name. An empty resourceNames covers every name; otherwise name must be
// non-empty and listed literally. For list and watch, name stands for the
// metadata.name field selector such a request must carry; this query does not
// attest that the real request carries it.
func (r Rule) AllowsName(apiGroup, resource, name, verb string) bool {
	if !r.Matches(apiGroup, resource, verb) {
		return false
	}
	if len(r.ResourceNames) == 0 {
		return true
	}
	return name != "" && contains(r.ResourceNames, name)
}

// Matches reports whether the rule covers the (apiGroup, resource, verb)
// triple, ignoring resourceNames. A caller that knows the request may target
// whichever name it chooses — for instance a CSR it creates itself — uses this
// to recognise that a rule restricted to some names is still usable, which
// Allows cannot express.
//
// This implementation supports exact matches and the "*" wildcard; a
// subresource such as "pods/log" is named explicitly, so a rule listing "pods"
// does not cover it.
func (r Rule) Matches(apiGroup, resource, verb string) bool {
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
		roleObj, role, err := roleRefOf(ix, binding, obj)
		if err != nil {
			return nil, err
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

// BindingRef is a binding that names a principal, together with the role it
// references. The roleRef is resolved the same way Effective resolves it, so a
// dangling reference is reported here too instead of being skipped.
type BindingRef struct {
	Object model.ObjectRef // the RoleBinding or ClusterRoleBinding
	Role   model.ObjectRef // the Role or ClusterRole it applies
}

// Without returns a copy of the snapshot index in which the given removal units
// have been applied: a "binding-subject" unit drops every subject entry of its
// binding that names that subject, and a "role-rule" unit drops the rule at the
// index it names. It is the inverse of the units Effective produces, and the
// substrate of cut verification (spec §3 step 6): the hypothetical model in
// which a grant is no longer granted.
//
// Neither the receiver nor the caller's index is modified. A unit the index
// cannot apply — an unsupported kind, an object the snapshot does not hold, a
// rule index out of range, a malformed detail — is an error, never a silent
// no-op: a removal that did nothing would let a cut be reported as verified
// against an untouched model.
func Without(ix *snapshot.Index, units []model.Grant) (*snapshot.Index, error) {
	type group struct {
		object model.ObjectRef
		units  []model.Grant
	}
	var order []string
	groups := map[string]*group{}
	for _, unit := range units {
		key := objectKey(unit.Object)
		g := groups[key]
		if g == nil {
			g = &group{object: unit.Object}
			groups[key] = g
			order = append(order, key)
		}
		g.units = append(g.units, unit)
	}

	out := ix
	for _, key := range order {
		g := groups[key]
		plan, err := removalPlanFor(g.units)
		if err != nil {
			return nil, fmt.Errorf("remove from %s: %w", describeObject(g.object), err)
		}
		next, err := out.Edited(g.object.Kind, g.object.Namespace, g.object.Name, plan)
		if err != nil {
			return nil, err
		}
		out = next
	}
	return out, nil
}

// removalPlanFor turns the removal units of one object into the edit that
// applies them together. Equivalent units are collapsed, so asking twice for the
// same removal is not an error; every other unit is validated against the
// object's own fields, so an unsupported kind, a rule index out of range, a
// malformed detail or a subject the object does not name fails here instead of
// being dropped silently.
func removalPlanFor(units []model.Grant) (func(map[string]any) error, error) {
	var subjects []Principal
	var rules []int
	seenSubjects := map[Principal]bool{}
	seenRules := map[int]bool{}
	for _, unit := range units {
		switch unit.Kind {
		case "binding-subject":
			subject, err := parseSubjectDetail(unit.Detail)
			if err != nil {
				return nil, err
			}
			if seenSubjects[subject] {
				continue
			}
			seenSubjects[subject] = true
			subjects = append(subjects, subject)
		case "role-rule":
			index, err := parseRuleDetail(unit.Detail)
			if err != nil {
				return nil, err
			}
			if seenRules[index] {
				continue
			}
			seenRules[index] = true
			rules = append(rules, index)
		default:
			return nil, fmt.Errorf("unsupported removal unit kind %q", unit.Kind)
		}
	}

	return func(obj map[string]any) error {
		if len(subjects) > 0 {
			kept, err := dropSubjects(obj["subjects"], subjects)
			if err != nil {
				return err
			}
			obj["subjects"] = kept
		}
		if len(rules) > 0 {
			kept, err := dropRules(obj["rules"], rules)
			if err != nil {
				return err
			}
			obj["rules"] = kept
		}
		return nil
	}, nil
}

// dropSubjects removes every entry that names one of the subjects. Removing a
// single entry would leave the grant alive through a duplicated one, and a
// subject the object does not name is an error: a removal that changed nothing
// would let an untouched model be reported as a verified cut.
func dropSubjects(raw any, drop []Principal) ([]any, error) {
	subjects, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("object carries no subjects")
	}
	matched := make([]bool, len(drop))
	kept := make([]any, 0, len(subjects))
	for _, item := range subjects {
		if subject, ok := item.(map[string]any); ok {
			if at := indexOfSubject(subject, drop); at >= 0 {
				matched[at] = true
				continue
			}
		}
		kept = append(kept, item)
	}
	for at, found := range matched {
		if !found {
			return nil, fmt.Errorf("the object does not name subject %s", describePrincipal(drop[at]))
		}
	}
	return kept, nil
}

// indexOfSubject reports which of the dropped identities the subject entry is,
// or -1. It compares the entry as written, so dropping a subject never depends
// on re-deriving group membership. A ServiceAccount keeps its namespace, while
// the canonical detail of a User or a Group carries none: matchedSubjects
// ignores that namespace too, so a namespaced User or Group entry is matched by
// name alone, exactly as it was granted.
func indexOfSubject(subject map[string]any, drop []Principal) int {
	kind, _ := subject["kind"].(string)
	name, _ := subject["name"].(string)
	namespace, _ := subject["namespace"].(string)
	for at, p := range drop {
		if kind != p.Kind || name != p.Name {
			continue
		}
		if kind == "ServiceAccount" && namespace != p.Namespace {
			continue
		}
		return at
	}
	return -1
}

func describePrincipal(p Principal) string {
	if p.Namespace == "" {
		return p.Kind + " " + p.Name
	}
	return p.Kind + " " + p.Namespace + "/" + p.Name
}

// dropRules removes the rules at the given indices, validated against the
// object's own rule list.
func dropRules(raw any, drop []int) ([]any, error) {
	rules, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("object carries no rules")
	}
	dropping := map[int]bool{}
	for _, index := range drop {
		if index < 0 || index >= len(rules) {
			return nil, fmt.Errorf("rule index %d is out of range: the object has %d rules", index, len(rules))
		}
		dropping[index] = true
	}
	kept := make([]any, 0, len(rules)-len(dropping))
	for index, rule := range rules {
		if dropping[index] {
			continue
		}
		kept = append(kept, rule)
	}
	return kept, nil
}

// objectKey is the index key of the object a removal unit belongs to.
func objectKey(ref model.ObjectRef) string {
	return ref.Kind + "\x00" + ref.Namespace + "\x00" + ref.Name
}

func describeObject(ref model.ObjectRef) string {
	if ref.Namespace == "" {
		return ref.Kind + " " + ref.Name
	}
	return ref.Kind + " " + ref.Namespace + "/" + ref.Name
}

// Bindings returns the bindings that name p as a subject, ordered by (kind,
// namespace, name). It reuses the subject matching of Effective, so a binding
// that matches through several subjects is returned once. Unlike Effective it
// does not depend on the referenced role having rules: a rule-less ClusterRole
// bound to p is still reported, which lets a caller see that the role already
// reaches the principal.
func Bindings(ix *snapshot.Index, p Principal) ([]BindingRef, error) {
	bindings := ix.List("RoleBinding", "")
	bindings = append(bindings, ix.List("ClusterRoleBinding", "")...)

	var out []BindingRef
	for _, binding := range bindings {
		_, obj, ok := ix.Entry(binding.Kind, binding.Namespace, binding.Name)
		if !ok {
			continue
		}
		subjects, _ := obj["subjects"].([]any)
		if len(matchedSubjects(subjects, p)) == 0 {
			continue
		}
		role, _, err := roleRefOf(ix, binding, obj)
		if err != nil {
			return nil, err
		}
		out = append(out, BindingRef{Object: binding, Role: role})
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Object, out[j].Object
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return out, nil
}

// PrivilegedSubject is a User or Group bound by a ClusterRoleBinding to a
// ClusterRole whose rules are equivalent to "*/*/*". Evidence lists the
// ClusterRoleBinding and the ClusterRole that justify it.
type PrivilegedSubject struct {
	Principal Principal
	Evidence  []model.ObjectRef
}

// PrivilegedSubjects returns the User and Group subjects, other than
// system:masters, that a ClusterRoleBinding binds to a cluster-admin equivalent
// ClusterRole. system:masters is excluded because the CertificateSubject
// Restriction admission plugin restricts it by default, so a client certificate
// for it is not an admissible escalation.
//
// It is the primitive NR-006's condition consumes (D-023). Results are ordered
// by (Kind, Name); a subject named by several bindings is returned once with
// every justifying object, ordered by (kind, namespace, name).
func PrivilegedSubjects(ix *snapshot.Index) ([]PrivilegedSubject, error) {
	var out []PrivilegedSubject
	index := map[Principal]int{}

	for _, binding := range ix.List("ClusterRoleBinding", "") {
		_, obj, ok := ix.Entry("ClusterRoleBinding", "", binding.Name)
		if !ok {
			continue
		}
		role, roleObj, err := roleRefOf(ix, binding, obj)
		if err != nil {
			return nil, err
		}
		if role.Kind != "ClusterRole" {
			continue
		}
		if !RulesAreClusterAdmin(ParseRules(roleObj)) {
			continue
		}

		subjects, _ := obj["subjects"].([]any)
		for _, raw := range subjects {
			subject, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			kind, _ := subject["kind"].(string)
			name, _ := subject["name"].(string)
			if (kind != "User" && kind != "Group") || name == "" || name == "system:masters" {
				continue
			}
			p := Principal{Kind: kind, Name: name}
			evidence := []model.ObjectRef{binding, role}
			if at, seen := index[p]; seen {
				out[at].Evidence = append(out[at].Evidence, evidence...)
				continue
			}
			index[p] = len(out)
			out = append(out, PrivilegedSubject{Principal: p, Evidence: evidence})
		}
	}

	for i := range out {
		out[i].Evidence = dedupeRefs(out[i].Evidence)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Principal.Kind != out[j].Principal.Kind {
			return out[i].Principal.Kind < out[j].Principal.Kind
		}
		return out[i].Principal.Name < out[j].Principal.Name
	})
	return out, nil
}

// roleRefOf resolves the role a binding references, returning both its
// reference and its object. A Role is resolved inside the binding's namespace;
// a dangling reference is an input defect, not a silent skip.
func roleRefOf(ix *snapshot.Index, binding model.ObjectRef, obj map[string]any) (model.ObjectRef, map[string]any, error) {
	roleRef, _ := obj["roleRef"].(map[string]any)
	roleKind, _ := roleRef["kind"].(string)
	roleName, _ := roleRef["name"].(string)
	roleNamespace := ""
	if roleKind == "Role" {
		roleNamespace = binding.Namespace
	}
	roleObj, role, ok := ix.Entry(roleKind, roleNamespace, roleName)
	if !ok {
		return model.ObjectRef{}, nil, fmt.Errorf("binding %s %s/%s references missing %s %s/%s",
			binding.Kind, binding.Namespace, binding.Name, roleKind, roleNamespace, roleName)
	}
	return roleObj, role, nil
}

// ParseRules extracts the rules of a Role or ClusterRole object. It reuses the
// rule parser of Effective, so a caller that must judge a role object directly
// does not re-implement it.
func ParseRules(role map[string]any) []Rule {
	raw, _ := role["rules"].([]any)
	rules := make([]Rule, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			rules = append(rules, parseRule(m))
		}
	}
	return rules
}

// RulesAreClusterAdmin reports whether any rule grants an unrestricted
// "*/*/*", which is the equivalence ClusterAdminGrants applies to a granted
// rule.
func RulesAreClusterAdmin(rules []Rule) bool {
	for _, r := range rules {
		if r.Allows("*", "*", "*") {
			return true
		}
	}
	return false
}

func dedupeRefs(refs []model.ObjectRef) []model.ObjectRef {
	seen := map[string]bool{}
	out := make([]model.ObjectRef, 0, len(refs))
	for _, ref := range refs {
		key := ref.Kind + "\x00" + ref.Namespace + "\x00" + ref.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return out
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

// parseSubjectDetail reads the canonical detail subjectDetail writes:
// "subject <Kind> <identity>", where a ServiceAccount identity is
// "<namespace>/<name>" and a User or Group identity is its name as it appears in
// the binding, spaces included. The three kinds are the ones subjectDetail can
// produce, so any other kind is a detail this index never wrote.
func parseSubjectDetail(detail string) (Principal, error) {
	rest, ok := strings.CutPrefix(detail, "subject ")
	if !ok {
		return Principal{}, fmt.Errorf("unrecognised subject detail %q", detail)
	}
	kind, identity, ok := strings.Cut(rest, " ")
	if !ok || kind == "" || identity == "" {
		return Principal{}, fmt.Errorf("unrecognised subject detail %q", detail)
	}
	switch kind {
	case "ServiceAccount":
		namespace, name, ok := strings.Cut(identity, "/")
		if !ok || namespace == "" || name == "" {
			return Principal{}, fmt.Errorf("subject detail %q does not hold a namespace/name", detail)
		}
		return Principal{Kind: kind, Namespace: namespace, Name: name}, nil
	case "User", "Group":
		return Principal{Kind: kind, Name: identity}, nil
	default:
		return Principal{}, fmt.Errorf("subject detail %q names an unsupported subject kind %q", detail, kind)
	}
}

// parseRuleDetail reads the canonical detail Effective writes for a rule:
// "rules[i]".
func parseRuleDetail(detail string) (int, error) {
	inner, ok := strings.CutPrefix(detail, "rules[")
	if !ok {
		return 0, fmt.Errorf("unrecognised rule detail %q", detail)
	}
	inner, ok = strings.CutSuffix(inner, "]")
	if !ok {
		return 0, fmt.Errorf("unrecognised rule detail %q", detail)
	}
	index, err := strconv.Atoi(inner)
	if err != nil || index < 0 {
		return 0, fmt.Errorf("unrecognised rule detail %q", detail)
	}
	return index, nil
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
