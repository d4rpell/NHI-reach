package graph

import (
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
)

func TestSystemNamespacesMatchesLiterallyAndByPrefix(t *testing.T) {
	system := DefaultSystemNamespaces()
	for _, namespace := range []string{"kube-system", "kube-public", "kube-node-lease", "openshift", "openshift-monitoring", "openshift-apiserver"} {
		if !system.Matches(namespace) {
			t.Errorf("%s is not treated as a system namespace", namespace)
		}
	}
	for _, namespace := range []string{"app", "openshifts", "kube-systems", "default"} {
		if system.Matches(namespace) {
			t.Errorf("%s is treated as a system namespace", namespace)
		}
	}
	if (SystemNamespaces{}).Matches("kube-system") {
		t.Error("an empty list matched a system namespace")
	}
}

func TestIdentityNamespaceParsesOnlyIdentityNodes(t *testing.T) {
	for _, tc := range []struct {
		node      string
		namespace string
		ok        bool
	}{
		{"sa:app/deployer", "app", true},
		{"sa:kube-system/node-sa", "kube-system", true},
		{"target:cluster-admin", "", false},
		{"sa:", "", false},
		{"sa:app", "", false},
		{"sa:/deployer", "", false},
		{"sa:app/", "", false},
		{"", "", false},
	} {
		t.Run(tc.node, func(t *testing.T) {
			namespace, ok := IdentityNamespace(tc.node)
			if ok != tc.ok || namespace != tc.namespace {
				t.Errorf("IdentityNamespace(%q) = (%q, %v), want (%q, %v)", tc.node, namespace, ok, tc.namespace, tc.ok)
			}
		})
	}
}

func TestViaSystemNeedsAnApplicationOrigin(t *testing.T) {
	system := DefaultSystemNamespaces()
	edge := func(from, to string) model.Edge { return model.Edge{From: from, To: to, HopID: "NR-002"} }

	for _, tc := range []struct {
		name  string
		path  model.Path
		viaSy bool
	}{
		{
			name:  "application to system",
			path:  model.Path{Source: "sa:app/deployer", Edges: []model.Edge{edge("sa:app/deployer", "sa:kube-system/node-sa")}},
			viaSy: true,
		},
		{
			name: "application through system to the target",
			path: model.Path{Source: "sa:app/deployer", Edges: []model.Edge{
				edge("sa:app/deployer", "sa:kube-system/node-sa"),
				edge("sa:kube-system/node-sa", "target:cluster-admin"),
			}},
			viaSy: true,
		},
		{
			name: "application without a system identity",
			path: model.Path{Source: "sa:app/deployer", Edges: []model.Edge{
				edge("sa:app/deployer", "sa:app/ops-admin"),
				edge("sa:app/ops-admin", "target:cluster-admin"),
			}},
			viaSy: false,
		},
		{
			// A route born at a system identity is not a via_system finding, even
			// when it later passes through another system identity.
			name: "system origin through another system identity",
			path: model.Path{Source: "sa:kube-system/node-sa", Edges: []model.Edge{
				edge("sa:kube-system/node-sa", "sa:openshift-monitoring/other"),
				edge("sa:openshift-monitoring/other", "target:cluster-admin"),
			}},
			viaSy: false,
		},
		{
			name:  "zero-hop route",
			path:  model.Path{Source: "sa:app/deployer"},
			viaSy: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ViaSystem(tc.path, system); got != tc.viaSy {
				t.Errorf("ViaSystem = %v, want %v", got, tc.viaSy)
			}
		})
	}
}
