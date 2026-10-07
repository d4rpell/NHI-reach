// Package hops turns effective permissions into graph edges.
//
// Every catalog hop is a pure function over the snapshot and the effective
// permissions of one identity, and every entry cites the official documentation
// that justifies it (spec §2.4). The catalog itself is the embedded
// catalog.yaml; this file implements the six entries it approves. The direct
// binding to cluster-admin is not a catalog hop: spec §2.6 treats it as a
// single-edge finding.
package hops

import (
	"regexp"
	"sort"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/rbac"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// TargetClusterAdmin is the node id of the cluster-admin goal.
const TargetClusterAdmin = "target:cluster-admin"

// Hop ids. They mirror the ids of the embedded catalog; a guard test keeps the
// two sets equal in both directions.
const (
	hopWorkloadCreation     = "NR-001"
	hopImpersonation        = "NR-002"
	hopTokenRequest         = "NR-003"
	hopBindClusterRole      = "NR-004"
	hopWidenClusterRole     = "NR-005"
	hopCSRClientCertificate = "NR-006"
)

// IdentityID is the stable node id of a non-human identity.
func IdentityID(ref model.ObjectRef) string {
	return "sa:" + ref.Namespace + "/" + ref.Name
}

// Context carries the inputs every hop shares for one identity.
type Context struct {
	Index      *snapshot.Index
	Identity   model.ObjectRef
	Granted    []rbac.Granted
	Privileged []rbac.PrivilegedSubject // NR-006's admissible privileged subjects
}

type builder struct {
	id   string
	emit func(Context) ([]model.Edge, error)
}

// builders wires one function per catalog entry. It is the single place that
// maps an approved hop id to its implementation; a guard test keeps it in step
// with the embedded catalog.
var builders = []builder{
	{hopWorkloadCreation, func(ctx Context) ([]model.Edge, error) {
		return WorkloadCreation(ctx.Index, ctx.Identity, ctx.Granted), nil
	}},
	{hopImpersonation, func(ctx Context) ([]model.Edge, error) {
		return Impersonation(ctx.Index, ctx.Identity, ctx.Granted), nil
	}},
	{hopTokenRequest, func(ctx Context) ([]model.Edge, error) {
		return TokenRequest(ctx.Index, ctx.Identity, ctx.Granted), nil
	}},
	{hopBindClusterRole, func(ctx Context) ([]model.Edge, error) {
		return BindClusterRole(ctx.Index, ctx.Identity, ctx.Granted), nil
	}},
	{hopWidenClusterRole, func(ctx Context) ([]model.Edge, error) {
		return WidenClusterRole(ctx.Index, ctx.Identity, ctx.Granted)
	}},
	{hopCSRClientCertificate, func(ctx Context) ([]model.Edge, error) {
		return CSRClientCertificate(ctx.Index, ctx.Identity, ctx.Granted, ctx.Privileged), nil
	}},
}

// CatalogEdges runs every enabled hop for one identity and concatenates their
// edges. One edge is emitted per (origin, destination) hop, so the caller can
// order them by (From, To, HopID) without ties.
func CatalogEdges(ctx Context) ([]model.Edge, error) {
	var edges []model.Edge
	for _, b := range builders {
		hopEdges, err := b.emit(ctx)
		if err != nil {
			return nil, err
		}
		edges = append(edges, hopEdges...)
	}
	return edges, nil
}

// Edges derives every edge of a snapshot's graph: the direct cluster-admin edge
// of each ServiceAccount plus every catalog hop. It is the single derivation of
// the graph — `analyze` and the hypothetical models that cut verification
// rebuilds both use it — and its result is ordered by (From, To, HopID).
//
// It fails when the snapshot is defective in a way a hop cannot evaluate (a
// dangling roleRef), so an input defect is never silently left out of the graph.
func Edges(ix *snapshot.Index) ([]model.Edge, error) {
	privileged, err := rbac.PrivilegedSubjects(ix)
	if err != nil {
		return nil, err
	}

	var edges []model.Edge
	for _, sa := range ix.List("ServiceAccount", "") {
		granted, err := rbac.Effective(ix, rbac.ServiceAccount(sa))
		if err != nil {
			return nil, err
		}
		edges = append(edges, ClusterAdminEdges(sa, granted)...)
		catalogEdges, err := CatalogEdges(Context{
			Index:      ix,
			Identity:   sa,
			Granted:    granted,
			Privileged: privileged,
		})
		if err != nil {
			return nil, err
		}
		edges = append(edges, catalogEdges...)
	}

	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.HopID < b.HopID
	})
	return edges, nil
}

// Rebuild derives the edges of the hypothetical model in which the given
// removal units are no longer granted: the substrate of cut verification (spec
// §3 step 6). It starts from the snapshot it is given and applies the whole set
// at once, and never modifies that snapshot — a failed removal is returned as an
// error, not as an unremoved grant.
func Rebuild(ix *snapshot.Index, removed []model.Grant) ([]model.Edge, error) {
	hypothetical, err := rbac.Without(ix, removed)
	if err != nil {
		return nil, err
	}
	return Edges(hypothetical)
}

// ClusterAdminEdges emits the direct edge from an identity whose effective
// permissions are cluster-admin-equivalent to the cluster-admin target.
//
// This edge is not a catalog hop: spec §2.6 treats a direct binding to
// cluster-admin as a single-edge finding, not a special case.
func ClusterAdminEdges(sa model.ObjectRef, granted []rbac.Granted) []model.Edge {
	admins := rbac.ClusterAdminGrants(granted)
	if len(admins) == 0 {
		return nil
	}
	refs := []model.ObjectRef{sa}
	for _, g := range admins {
		refs = append(refs, g.Source, g.Binding)
	}
	return []model.Edge{{
		From:       IdentityID(sa),
		To:         TargetClusterAdmin,
		HopID:      "rbac-cluster-admin",
		Evidence:   dedupeRefs(refs),
		Grants:     collectGrants(admins),
		Confidence: "definite",
	}}
}

// WorkloadCreation emits one edge from sa to every other ServiceAccount that
// sa may run inside a workload, when sa may create Pods there (hop NR-001).
//
// The reach of the permission is the scope of its grant: a RoleBinding grants
// it inside the binding's namespace, a ClusterRoleBinding in every namespace.
// The edges are "conditional", not "definite": the RBAC rule is what the model
// proves, but the escalation itself needs the created workload to be admitted
// and run as the target service account, and admission is a step the model does
// not cover (spec §2.4).
func WorkloadCreation(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted) []model.Edge {
	byTarget := map[model.ObjectRef][]rbac.Granted{}
	for _, g := range granted {
		if !g.Rule.Allows("", "pods", "create") {
			continue
		}
		for _, target := range namedTargets(ix, g, sa, "pods", "create") {
			byTarget[target] = append(byTarget[target], g)
		}
	}
	return identityEdges(sa, hopWorkloadCreation, "conditional", byTarget)
}

// Impersonation emits an edge from sa to every ServiceAccount it may impersonate
// (hop NR-002). The impersonate verb lets the identity issue API requests as
// the target subject and inherit its rights.
func Impersonation(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted) []model.Edge {
	return serviceAccountReach(ix, sa, granted, "serviceaccounts", "impersonate", hopImpersonation)
}

// TokenRequest emits an edge from sa to every ServiceAccount it may mint a token
// for (hop NR-003). Create on serviceaccounts/token is the exact rule the API
// server checks to authorize a TokenRequest.
func TokenRequest(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted) []model.Edge {
	return serviceAccountReach(ix, sa, granted, "serviceaccounts/token", "create", hopTokenRequest)
}

// BindClusterRole emits the escalation edge from sa to cluster-admin when sa may
// bind a cluster-admin equivalent ClusterRole and may also bind it at cluster
// scope (hop NR-004). The bind verb bypasses the protection that stops a binding
// from conferring permissions its author does not hold; roleRef is immutable and
// a RoleBinding only reaches its own namespace, so both a bind permission on the
// role and a cluster-scoped way to create or repoint a ClusterRoleBinding are
// required.
func BindClusterRole(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted) []model.Edge {
	var refs []model.ObjectRef
	var units []rbac.Granted

	for _, cr := range ix.List("ClusterRole", "") {
		_, role, ok := ix.Entry("ClusterRole", "", cr.Name)
		if !ok || !rbac.RulesAreClusterAdmin(rbac.ParseRules(role)) {
			continue
		}
		binds := clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterroles", "bind", cr.Name)
		if len(binds) == 0 {
			continue
		}
		via := clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterrolebindings", "create", "")
		via = append(via, clusterRoleBindingWrites(ix, granted, cr.Name)...)
		if len(via) == 0 {
			continue
		}
		refs = append(refs, cr)
		units = append(units, binds...)
		units = append(units, via...)
	}

	if len(units) == 0 {
		return nil
	}
	return []model.Edge{targetEdge(sa, hopBindClusterRole, "definite", refs, units)}
}

// WidenClusterRole emits the escalation edge from sa to cluster-admin when sa
// may widen a ClusterRole that already reaches it through a ClusterRoleBinding
// (hop NR-005). Escalate is what lets a subject add permissions it does not
// hold; update or patch on the same role is what applies the widening, and the
// existing binding propagates it cluster-wide.
func WidenClusterRole(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted) ([]model.Edge, error) {
	bindings, err := rbac.Bindings(ix, rbac.ServiceAccount(sa))
	if err != nil {
		return nil, err
	}

	var refs []model.ObjectRef
	var units []rbac.Granted

	for _, cr := range ix.List("ClusterRole", "") {
		escalates := clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterroles", "escalate", cr.Name)
		if len(escalates) == 0 {
			continue
		}
		writes := clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterroles", "update", cr.Name)
		writes = append(writes, clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterroles", "patch", cr.Name)...)
		if len(writes) == 0 {
			continue
		}
		var reaching []model.ObjectRef
		for _, binding := range bindings {
			if binding.Object.Kind == "ClusterRoleBinding" && binding.Role.Kind == "ClusterRole" && binding.Role.Name == cr.Name {
				reaching = append(reaching, binding.Object)
			}
		}
		if len(reaching) == 0 {
			continue
		}
		refs = append(refs, cr)
		refs = append(refs, reaching...)
		units = append(units, escalates...)
		units = append(units, writes...)
	}

	if len(units) == 0 {
		return nil, nil
	}
	return []model.Edge{targetEdge(sa, hopWidenClusterRole, "definite", refs, units)}, nil
}

// CSRClientCertificate emits the escalation edge from sa to cluster-admin when
// sa may issue a client certificate for a privileged subject (hop NR-006). The
// three permissions are those the CSR API checks; the privileged subject is
// proven by the snapshot, never assumed, so the hop stays silent when no
// admissible subject exists. The edges are "conditional": the model does not
// cover the act of signing or the CertificateSubjectRestriction admission step.
func CSRClientCertificate(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted, privileged []rbac.PrivilegedSubject) []model.Edge {
	if len(privileged) == 0 {
		return nil
	}
	creates := clusterScopedGrants(granted, "certificates.k8s.io", "certificatesigningrequests", "create", "")
	if len(creates) == 0 {
		return nil
	}
	// Update on certificatesigningrequests/approval may be restricted to a set
	// of names. Creating a CSR is unrestricted here, so the identity names the
	// request it will approve: an approval rule is usable when it is
	// unrestricted or names at least one valid object name. A rule restricted to
	// names that could never exist — the empty string, or "*", which RBAC treats
	// as a literal name, not a wildcard — grants no usable approval, so Allows
	// would miss the usable case and a bare triple match would invent the
	// unusable one.
	approvals := usableApprovals(granted)
	if len(approvals) == 0 {
		return nil
	}
	approves := signerApprovals(granted, "kubernetes.io/kube-apiserver-client")
	if len(approves) == 0 {
		return nil
	}

	units := make([]rbac.Granted, 0, len(creates)+len(approvals)+len(approves))
	units = append(units, creates...)
	units = append(units, approvals...)
	units = append(units, approves...)

	var refs []model.ObjectRef
	for _, subject := range privileged {
		refs = append(refs, subject.Evidence...)
	}
	return []model.Edge{targetEdge(sa, hopCSRClientCertificate, "conditional", refs, units)}
}

// serviceAccountReach is the shared body of NR-002 and NR-003: a rule naming a
// service account resource with a verb reaches the service accounts of the
// grant's scope, honoured by resourceNames.
func serviceAccountReach(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted, resource, verb, hopID string) []model.Edge {
	byTarget := map[model.ObjectRef][]rbac.Granted{}
	for _, g := range granted {
		for _, target := range namedTargets(ix, g, sa, resource, verb) {
			byTarget[target] = append(byTarget[target], g)
		}
	}
	return identityEdges(sa, hopID, "definite", byTarget)
}

// namedTargets returns the ServiceAccounts a granted rule that names resource
// with verb reaches. The scope is the grant's: a RoleBinding reaches the service
// accounts of its namespace, a ClusterRoleBinding reaches every namespace. The
// rule's resourceNames is honoured per name through AllowsName, and the origin
// is never its own destination.
func namedTargets(ix *snapshot.Index, g rbac.Granted, origin model.ObjectRef, resource, verb string) []model.ObjectRef {
	var targets []model.ObjectRef
	for _, sa := range ix.List("ServiceAccount", "") {
		if !g.ClusterScoped && sa.Namespace != g.Binding.Namespace {
			continue
		}
		if sa.Namespace == origin.Namespace && sa.Name == origin.Name {
			continue
		}
		if !g.Rule.AllowsName("", resource, sa.Name, verb) {
			continue
		}
		targets = append(targets, sa)
	}
	return targets
}

// clusterScopedGrants returns the cluster-scoped grants whose rule allows
// (apiGroup, resource, verb). The resources of NR-004, NR-005 and NR-006 are
// cluster-scoped, so a grant that only reaches one namespace cannot authorize
// them; such a grant is discarded here. An empty name asks for the unrestricted
// form; a non-empty name is honoured literally through AllowsName.
func clusterScopedGrants(granted []rbac.Granted, apiGroup, resource, verb, name string) []rbac.Granted {
	var out []rbac.Granted
	for _, g := range granted {
		if !g.ClusterScoped {
			continue
		}
		if name == "" {
			if g.Rule.Allows(apiGroup, resource, verb) {
				out = append(out, g)
			}
			continue
		}
		if g.Rule.AllowsName(apiGroup, resource, name, verb) {
			out = append(out, g)
		}
	}
	return out
}

// usableApprovals returns the cluster-scoped grants that may approve a CSR the
// identity creates: the rule covers certificatesigningrequests/approval with
// update and either carries no resourceNames or lists at least one name a CSR
// could actually have.
func usableApprovals(granted []rbac.Granted) []rbac.Granted {
	var out []rbac.Granted
	for _, g := range granted {
		if !g.ClusterScoped || !g.Rule.Matches("certificates.k8s.io", "certificatesigningrequests/approval", "update") {
			continue
		}
		if len(g.Rule.ResourceNames) == 0 {
			out = append(out, g)
			continue
		}
		for _, name := range g.Rule.ResourceNames {
			if validObjectName(name) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// objectName is the DNS-1123 subdomain form every Kubernetes object name must
// have, so a CSR could carry it.
var objectName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// validObjectName reports whether name is a name a CSR could have.
func validObjectName(name string) bool {
	return len(name) <= 253 && objectName.MatchString(name)
}

// signerApprovals returns the cluster-scoped grants that approve CSRs for the
// given signer. Unlike a bare AllowsName it requires the signer to be named
// literally in resourceNames: a rule with no resourceNames would approve every
// signer, which the hop's condition does not authorize.
func signerApprovals(granted []rbac.Granted, signer string) []rbac.Granted {
	var out []rbac.Granted
	for _, g := range granted {
		if !g.ClusterScoped {
			continue
		}
		if !g.Rule.AllowsName("certificates.k8s.io", "signers", signer, "approve") {
			continue
		}
		if !containsString(g.Rule.ResourceNames, signer) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// clusterRoleBindingWrites returns the cluster-scoped grants that may repoint
// the subjects of a ClusterRoleBinding whose roleRef already is the named
// ClusterRole. Because roleRef is immutable, such an update is how the identity
// adds itself to an existing binding of the role it may bind.
func clusterRoleBindingWrites(ix *snapshot.Index, granted []rbac.Granted, clusterRole string) []rbac.Granted {
	var out []rbac.Granted
	for _, binding := range ix.List("ClusterRoleBinding", "") {
		_, obj, ok := ix.Entry("ClusterRoleBinding", "", binding.Name)
		if !ok {
			continue
		}
		roleRef, _ := obj["roleRef"].(map[string]any)
		if kind, _ := roleRef["kind"].(string); kind != "ClusterRole" {
			continue
		}
		if name, _ := roleRef["name"].(string); name != clusterRole {
			continue
		}
		out = append(out, clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterrolebindings", "update", binding.Name)...)
		out = append(out, clusterScopedGrants(granted, "rbac.authorization.k8s.io", "clusterrolebindings", "patch", binding.Name)...)
	}
	return out
}

// identityEdges renders one edge per reached ServiceAccount, ordered by the
// destination id so the result does not depend on map iteration order.
func identityEdges(origin model.ObjectRef, hopID, confidence string, byTarget map[model.ObjectRef][]rbac.Granted) []model.Edge {
	targets := make([]model.ObjectRef, 0, len(byTarget))
	for target := range byTarget {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return IdentityID(targets[i]) < IdentityID(targets[j]) })

	edges := make([]model.Edge, 0, len(targets))
	for _, target := range targets {
		grants := byTarget[target]
		refs := []model.ObjectRef{origin, target}
		for _, g := range grants {
			refs = append(refs, g.Source, g.Binding)
		}
		edges = append(edges, model.Edge{
			From:       IdentityID(origin),
			To:         IdentityID(target),
			HopID:      hopID,
			Evidence:   dedupeRefs(refs),
			Grants:     collectGrants(grants),
			Confidence: confidence,
		})
	}
	return edges
}

// targetEdge renders the single edge from an identity to the cluster-admin
// target, combining the extra evidence with the sources of the granting rules.
func targetEdge(origin model.ObjectRef, hopID, confidence string, extra []model.ObjectRef, grants []rbac.Granted) model.Edge {
	refs := append([]model.ObjectRef{origin}, extra...)
	for _, g := range grants {
		refs = append(refs, g.Source, g.Binding)
	}
	return model.Edge{
		From:       IdentityID(origin),
		To:         TargetClusterAdmin,
		HopID:      hopID,
		Evidence:   dedupeRefs(refs),
		Grants:     collectGrants(grants),
		Confidence: confidence,
	}
}

// collectGrants flattens the removal units of the given grants, drops exact
// duplicates (the same unit can be produced once per matching subject) and
// orders them deterministically.
func collectGrants(granted []rbac.Granted) []model.Grant {
	var out []model.Grant
	seen := map[model.Grant]bool{}
	for _, g := range granted {
		for _, unit := range g.Grants {
			if seen[unit] {
				continue
			}
			seen[unit] = true
			out = append(out, unit)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Object, out[j].Object
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Detail < out[j].Detail
	})
	return out
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
