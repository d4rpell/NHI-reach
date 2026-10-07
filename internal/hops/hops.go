// Package hops turns effective permissions into graph edges.
//
// Every catalog hop is a pure function over the snapshot and the effective
// permissions of one identity, and every entry cites the official documentation
// that justifies it (spec §2.4). The light vertical ships a single hop, NR-001;
// the remaining catalog is selected and approved in T1-03 and implemented in
// T1-04.
package hops

import (
	"sort"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/rbac"
	"github.com/d4rpell/nhi-reach/internal/snapshot"
)

// TargetClusterAdmin is the node id of the cluster-admin goal.
const TargetClusterAdmin = "target:cluster-admin"

// IdentityID is the stable node id of a non-human identity.
func IdentityID(ref model.ObjectRef) string {
	return "sa:" + ref.Namespace + "/" + ref.Name
}

// CatalogEntry is one hop of the catalog. Its fields mirror the YAML format of
// spec §2.4, so the embedded catalog can replace this literal in T1-04 without
// changing consumers.
type CatalogEntry struct {
	ID           string
	Title        string
	Reference    string
	TargetEffect string
	Status       string
	Rationale    string
	Remediation  string
}

// NR001 is the single hop of the light vertical. Source: Kubernetes
// documentation, "RBAC Good Practices", section "Workload creation":
// "since Pods can run as any ServiceAccount, granting permission to create
// workloads also implicitly grants the API access levels of any service
// account in that namespace."
var NR001 = CatalogEntry{
	ID:           "NR-001",
	Title:        "Workload creation grants any service account of the namespace",
	Reference:    "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation",
	TargetEffect: "identity",
	Status:       "enabled",
	Rationale:    "Creating a workload in a namespace lets an identity run a Pod as any ServiceAccount of that namespace, so the identity inherits that service account's API access level. Namespace boundaries are weak separation, not a privilege boundary.",
	Remediation:  "Remove the create permission on workloads from identities that do not need it and enforce the Baseline or Restricted Pod Security Standard.",
}

// Catalog returns the hops enabled in this version, ordered by ID.
func Catalog() []CatalogEntry {
	return []CatalogEntry{NR001}
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

// WorkloadCreation emits one edge from sa to every other ServiceAccount of its
// namespace when sa may create Pods there (hop NR-001).
//
// The edges are "conditional", not "definite": the RBAC rule is what the model
// proves, but the escalation itself needs the created workload to be admitted
// and run as the target service account, and admission is a step the model does
// not cover (spec §2.4).
func WorkloadCreation(ix *snapshot.Index, sa model.ObjectRef, granted []rbac.Granted) []model.Edge {
	var granting []rbac.Granted
	for _, g := range granted {
		if g.Rule.Allows("", "pods", "create") {
			granting = append(granting, g)
		}
	}
	if len(granting) == 0 {
		return nil
	}

	targets := ix.List("ServiceAccount", sa.Namespace)
	edges := make([]model.Edge, 0, len(targets))
	for _, target := range targets {
		if target.Name == sa.Name {
			continue
		}
		refs := append([]model.ObjectRef{sa}, target)
		for _, g := range granting {
			refs = append(refs, g.Source, g.Binding)
		}
		edges = append(edges, model.Edge{
			From:       IdentityID(sa),
			To:         IdentityID(target),
			HopID:      NR001.ID,
			Evidence:   dedupeRefs(refs),
			Grants:     collectGrants(granting),
			Confidence: "conditional",
		})
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].To < edges[j].To })
	return edges
}

func collectGrants(granted []rbac.Granted) []model.Grant {
	var out []model.Grant
	for _, g := range granted {
		out = append(out, g.Grants...)
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
