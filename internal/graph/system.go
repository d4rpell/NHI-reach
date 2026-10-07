package graph

import (
	"strings"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// SystemNamespaces is the system-identity list of spec §2.6 (D-009): the
// namespaces whose ServiceAccounts are system identities. An entry matches its
// namespace literally, or by prefix when it ends in "*".
type SystemNamespaces []string

// DefaultSystemNamespaces is the default list of spec §2.6.
func DefaultSystemNamespaces() SystemNamespaces {
	return SystemNamespaces{"kube-system", "kube-public", "kube-node-lease", "openshift", "openshift-*"}
}

// Matches reports whether namespace is a system namespace.
func (s SystemNamespaces) Matches(namespace string) bool {
	for _, entry := range s {
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			if strings.HasPrefix(namespace, prefix) {
				return true
			}
			continue
		}
		if namespace == entry {
			return true
		}
	}
	return false
}

// IdentityNamespace returns the namespace of an identity node id of the form
// "sa:<namespace>/<name>". The second result is false for every other node — a
// target, or a node kind this version does not build — so no caller has to
// guess whether a node is an identity.
func IdentityNamespace(nodeID string) (string, bool) {
	rest, ok := strings.CutPrefix(nodeID, "sa:")
	if !ok {
		return "", false
	}
	namespace, name, ok := strings.Cut(rest, "/")
	if !ok || namespace == "" || name == "" {
		return "", false
	}
	return namespace, true
}

// ViaSystem reports whether path is an escalation that starts at an application
// identity and goes through a system identity, which spec §2.6 marks as the most
// relevant finding. The origin must be a ServiceAccount outside the system
// namespaces, and at least one later node must be a ServiceAccount inside them:
// a route that already starts at a system identity is not a via_system finding,
// because §2.6 marks the routes that are born at an application identity.
//
// The origin selection of D-009 (--include-system, --from-identity) belongs to
// the caller; this only derives the flag from the route.
func ViaSystem(path model.Path, system SystemNamespaces) bool {
	originNamespace, ok := IdentityNamespace(path.Source)
	if !ok || system.Matches(originNamespace) {
		return false
	}
	for _, edge := range path.Edges {
		if namespace, ok := IdentityNamespace(edge.To); ok && system.Matches(namespace) {
			return true
		}
	}
	return false
}
