# Permissions needed by the live mode

`nhi-reach snapshot` and `nhi-reach analyze --live` read a cluster through the
Kubernetes API. They are read-only by construction: the client installs a
transport that refuses every request that is not a plain read (only `GET`, only
the discovery and collection paths the tool uses, and no watch parameters)
before the request reaches the network. No verb outside `get`/`list` is ever
issued, and nothing is created, modified or executed in the cluster.

## Minimal ClusterRole

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nhi-reach-readonly
rules:
  - apiGroups: [""]
    resources: [namespaces, serviceaccounts, pods, secrets]
    verbs: [get, list]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, rolebindings, clusterroles, clusterrolebindings]
    verbs: [get, list]
  # Only when auditing OpenShift: the tool attempts it when the API exposes it
  # and reports a gap when it does not.
  - apiGroups: [security.openshift.io]
    resources: [securitycontextconstraints]
    verbs: [get, list]
```

Bind it with a ClusterRoleBinding to the identity that runs the tool:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nhi-reach-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nhi-reach-readonly
subjects:
  - kind: ServiceAccount
    name: nhi-reach
    namespace: audit
```

## What is read, and what is not

- **Collections only.** The tool lists collections (`list`). It never fetches an
  individual object, a subresource (`exec`, `proxy`, `portforward`, `logs`, …)
  or a stream (`watch`), and it never issues `create`, `update`, `patch` or
  `delete`. This is enforced in the HTTP transport, not just documented.
- **Secrets: metadata and key names only.** Listing `secrets` returns their
  content to the client, but the tool rebuilds every Secret immediately from an
  explicit field list (`apiVersion`, `kind`, `metadata.name`, `metadata.namespace`,
  `type` and the names of the keys of `data`/`stringData`) and discards
  everything else — values included — before anything is indexed, hashed,
  written or reported. A written snapshot stores the key names under `data` with
  empty values; no secret value ever reaches disk. See `docs/evidence.md`.
- **Discovery and version.** The client reads `/version`, `/api`, `/api/v1`,
  `/apis` and `/apis/<group>/<version>` to learn which types the server exposes.
  These are `GET` requests already covered by the `get`/`list` rules above.
- **Pagination.** Large collections are paginated (`limit` + `continue`) with a
  bounded number of pages; exceeding the bound is an error, never a silently
  partial result.

## Cluster-admin is not required

`cluster-admin` is enough but not necessary: the ClusterRole above is what the
tool actually needs. A permission that is missing from it turns the affected
resource type into an explicit gap in the report (or an error when the type is
one of the mandatory ones), never into a silent assumption.
