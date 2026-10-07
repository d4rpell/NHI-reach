// Package model holds the shared types of the analysis pipeline: the
// normalized resource reference, the read-only snapshot index, graph nodes and
// edges, grants, cuts, paths and gaps.
//
// It carries no analysis logic. These types are the shared contract between
// the snapshot, rbac, hops, graph and report packages, so changing any of them
// is a design decision that must be settled before the change, not during it.
package model

// ObjectRef points at one normalized object of a snapshot and carries the hash
// of its canonical JSON. Secrets are referenced by metadata only; their
// data/stringData never reach this type.
type ObjectRef struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	SHA256     string
}

// NodeKind classifies a node of the reachability graph.
type NodeKind string

const (
	// NodeIdentity is a non-human identity, such as a ServiceAccount.
	NodeIdentity NodeKind = "Identity"
	// NodeWorkload is a workload whose pod spec is relevant to a hop.
	NodeWorkload NodeKind = "Workload"
	// NodeTarget is an analysis target, such as cluster-admin.
	NodeTarget NodeKind = "Target"
	// NodeGroup is a group, including the implicit groups of a ServiceAccount.
	NodeGroup NodeKind = "Group"
)

// Node is a vertex of the reachability graph.
type Node struct {
	ID     string // stable: "sa:ns/name", "target:cluster-admin", ...
	Kind   NodeKind
	System bool // system identity: namespace on the configurable system list; not an origin unless requested, but a valid intermediate hop
}

// Edge is one hop of the graph. Evidence lists the objects that enable the
// hop; Grants lists the concrete grants whose removal eliminates the edge.
type Edge struct {
	From, To string
	HopID    string
	Evidence []ObjectRef
	Grants   []Grant
	// Confidence is "definite" or "conditional"; conditional means the hop
	// depends on a Gap or on an admission step the model does not cover.
	Confidence string
}

// Grant is the minimal removable unit, not the whole object: one subject
// inside a binding, or one rule inside a Role.
type Grant struct {
	Object ObjectRef
	// Kind is "binding-subject", "role-rule", "scc-user" or "scc-group".
	Kind string
	// Detail identifies the unit within the object, e.g.
	// "subject ServiceAccount app/ci" or "rules[2]".
	Detail string
}

// Cut proposes removing one grant and records whether that removal was
// verified in the model.
type Cut struct {
	Grant Grant
	// Change is the proposal text, e.g.
	// "remove subject app/ci from RoleBinding app/deployer".
	Change string
	// Verified is true when, after removing the grant in memory, the target is
	// no longer reachable from the source.
	Verified bool
	// RemainingPaths counts the paths that still exist up to --max-depth when
	// the single removal is not enough.
	RemainingPaths int
}

// Path is one escalation route from a source to a target, with its candidate
// cuts ordered verified first and then by smallest scope.
type Path struct {
	ID     string // hash of the edge sequence
	Source string
	Target string
	Edges  []Edge
	Cuts   []Cut
}

// Snapshot is a read-only index over the normalized resources of a snapshot.
// It holds no analysis logic; the rbac and hops packages consume it.
type Snapshot interface {
	Get(kind, namespace, name string) (ObjectRef, bool)
	// List returns every object of kind; an empty namespace means every
	// namespace, not the empty namespace.
	List(kind, namespace string) []ObjectRef
	Gaps() []Gap
}

// Gap records a missing input or a truncated analysis. It is never replaced by
// a silent assumption: an unevaluated hop is reported as a gap.
type Gap struct {
	// Kind is "missing-input" or "truncated-enumeration".
	Kind string
	// Subject is the absent resource (e.g. "scc") or the (origin, target) pair.
	Subject string
	// Message is the human-readable text included in the report.
	Message string
}
