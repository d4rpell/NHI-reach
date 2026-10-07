package hops

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
	"github.com/d4rpell/nhi-reach/internal/rbac"
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

func permissions(t *testing.T, ix *snapshot.Index, sa model.ObjectRef) []rbac.Granted {
	t.Helper()
	granted, err := rbac.Effective(ix, sa)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	return granted
}

func workloadFixture(t *testing.T) *snapshot.Index {
	t.Helper()
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops-admin","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"other","namespace":"other"}}`)
	return ix
}

func TestCatalogEntryCitesOfficialSource(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != 1 {
		t.Fatalf("light vertical exposes %d hops, want 1", len(catalog))
	}
	entry := catalog[0]
	if entry.ID != NR001.ID {
		t.Errorf("catalog holds %q, want %q", entry.ID, NR001.ID)
	}
	if !strings.HasPrefix(entry.Reference, "https://kubernetes.io/") || !strings.Contains(entry.Reference, "#") {
		t.Errorf("hop reference %q is not an anchored official Kubernetes URL", entry.Reference)
	}
	if entry.Status != "enabled" {
		t.Errorf("hop status is %q, want enabled", entry.Status)
	}
	if entry.Rationale == "" || entry.Remediation == "" {
		t.Error("hop lacks rationale or remediation")
	}
}

func TestWorkloadCreationEmitsEdgesToNamespacePeers(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"creator","namespace":"app"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["create"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"creator","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	edges := WorkloadCreation(ix, sa, permissions(t, ix, sa))

	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1 (the other namespace peer only)", len(edges))
	}
	edge := edges[0]
	if edge.From != "sa:app/deployer" || edge.To != "sa:app/ops-admin" {
		t.Errorf("edge is %s -> %s, want sa:app/deployer -> sa:app/ops-admin", edge.From, edge.To)
	}
	if edge.HopID != NR001.ID {
		t.Errorf("edge uses hop %q, want %q", edge.HopID, NR001.ID)
	}
	// Creating a workload proves only the RBAC rule; running it as the target
	// service account depends on admission, which the model does not cover.
	if edge.Confidence != "conditional" {
		t.Errorf("edge confidence is %q, want conditional", edge.Confidence)
	}
	if len(edge.Evidence) == 0 || len(edge.Grants) == 0 {
		t.Error("edge carries no evidence or no removable grant")
	}
}

func TestWorkloadCreationRequiresCreateOnPods(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"app"},
		"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"reader","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	if edges := WorkloadCreation(ix, sa, permissions(t, ix, sa)); len(edges) != 0 {
		t.Fatalf("read-only permission produced %d edges, want 0", len(edges))
	}
}

func TestWorkloadCreationMatchesWildcardRule(t *testing.T) {
	ix := workloadFixture(t)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"admin-app","namespace":"app"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
		"metadata":{"name":"admin-app","namespace":"app"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"admin-app"},
		"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "deployer")
	if edges := WorkloadCreation(ix, sa, permissions(t, ix, sa)); len(edges) != 1 {
		t.Fatalf("wildcard rule produced %d edges, want 1", len(edges))
	}
}

func TestClusterAdminEdges(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"cluster-admin"},
		"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
	add(t, ix, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding",
		"metadata":{"name":"ops-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"ops","namespace":"app"}]}`)

	sa := identity(t, ix, "app", "ops")
	edges := ClusterAdminEdges(sa, permissions(t, ix, sa))
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	if edges[0].From != "sa:app/ops" || edges[0].To != TargetClusterAdmin {
		t.Errorf("edge is %s -> %s, want sa:app/ops -> %s", edges[0].From, edges[0].To, TargetClusterAdmin)
	}
	if len(edges[0].Evidence) < 2 {
		t.Errorf("edge evidence holds %d objects, want the service account and the binding", len(edges[0].Evidence))
	}
}

func TestClusterAdminEdgesEmptyWithoutPermission(t *testing.T) {
	ix := snapshot.New()
	add(t, ix, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ops","namespace":"app"}}`)
	sa := identity(t, ix, "app", "ops")
	if edges := ClusterAdminEdges(sa, nil); len(edges) != 0 {
		t.Fatalf("unprivileged identity produced %d cluster-admin edges, want 0", len(edges))
	}
}
