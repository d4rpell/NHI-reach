# nhi-reach lab

A disposable Kubernetes cluster with **intentionally misconfigured** RBAC. Its
only purpose is to exercise `nhi-reach` end to end against a real apiserver and
to check that the findings match the expected result. Everything here is
synthetic: no object, name or value comes from a client or employer cluster.

The lab never runs against a cluster you do not own. It is not part of CI.

![nhi-reach analyzing the lab cluster](demo.gif)

The GIF is generated from `demo.tape`, which replays the bounded analysis of the
captured snapshot; the command that reproduces it is in the tape header.

## What the lab demonstrates

Each manifest in `manifests/` plants one escalation that a catalog hop of
`internal/hops/catalog.yaml` is documented to recognise. The comments in the
manifests name the hop (NR-001…NR-006) and cite the official Kubernetes
documentation that justifies it.

| Object | Hop / finding | Why it is an escalation |
| --- | --- | --- |
| Role `lab-pod-creator` (lab-app) | NR-001 | `create` on pods lets the holder run a workload as any ServiceAccount of the namespace |
| ClusterRole `lab-system-sa-impersonator` | NR-002 | `impersonate` on a ServiceAccount lets the holder act as it |
| Role `lab-token-minter` (lab-app) | NR-003 | `create` on `serviceaccounts/token` mints a token for an existing ServiceAccount |
| ClusterRole `lab-binding-controller` | NR-004 | `bind` on ClusterRoles plus `create` on ClusterRoleBindings grants any cluster role |
| ClusterRole `lab-escalator` | NR-005 | `escalate` + `update` on a ClusterRole that already reaches the holder widens it |
| ClusterRole `lab-csr-issuer` | NR-006 | create/approve a CSR lets the holder obtain a client certificate for a privileged subject |
| ClusterRole `lab-secret-reader` | secrets goal (§2.5) | cluster-wide `get`/`list` on Secrets reaches the sensitive namespaces |

Two accounts are deliberate controls:

- `lab-dev/idle` holds a Role that only reads ConfigMaps. No catalog hop applies,
  so it must produce **no** path. It proves the tool does not manufacture
  findings out of unrelated access.
- `kube-system/lab-system-ops` is a system identity, privileged by design. It is
  never an origin by default (D-009); it only appears as an **intermediate hop**,
  reached through the impersonation grant. Any path that crosses it is flagged
  `via_system`.

## The SCC part is a synthetic offline snapshot

`kind` has no SecurityContextConstraints API, so a kind cluster cannot exercise
that type. Rather than stand up an OpenShift arm64 cluster (a large,
`[NO VERIFIED]` dependency), the SCC part of the lab is a **synthetic offline
snapshot** that carries a `securitycontextconstraints` list. It demonstrates that
the loader accepts the type and that the `SecurityContextConstraints` gap
disappears, without claiming any SCC escalation — NR-007 (OpenShift SCC) is
deferred from v1 (D-022).

## Running the lab

The cluster runs on the owner's Oracle VPS (arm64, podman rootless, D-013). The
apiserver is published only on `127.0.0.1:16444` and reached over an SSH tunnel;
no port is opened in firewalld or the OCI security list.

On the VPS (over SSH):

```sh
cd ~/nhi-reach-lab
export KIND_EXPERIMENTAL_PROVIDER=podman
bin/kind create cluster --name nhi-reach-lab --config config/kind-config.yaml
bin/kubectl --kubeconfig state/kubeconfig apply -f manifests/
```

Build the tool for arm64 from a dev box and copy it to the VPS, then capture and
analyse:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/nhi-reach-linux-arm64 ./cmd/nhi-reach
scp bin/nhi-reach-linux-arm64 oracle:~/nhi-reach-lab/bin/nhi-reach

# on the VPS
cd ~/nhi-reach-lab
export KUBECONFIG=$PWD/state/kubeconfig
bin/nhi-reach snapshot -o out/snapshot
bin/nhi-reach analyze --from out/snapshot -o table
```

`analyze --live` reads the same cluster directly (read-only, `get`/`list` only).
The offline snapshot is written to `out/`, which is not committed.

`run-lab.sh` runs the whole check in one shot: it captures a snapshot, analyses
it offline and live, asserts the two are byte-identical, and compares the bounded
table against `expected/lab-table.txt`. `MEASUREMENTS.md` records the observed
cluster cost and the D-009 system-identity noise.

The captured table is compared byte for byte against `expected/lab-table.txt`.

## Files

| Path | Purpose |
| --- | --- |
| `kind-config.yaml` | single-node kind cluster, API on `127.0.0.1:16444` |
| `manifests/` | the intentionally misconfigured objects, one file per concern |
| `scc-demo/` | synthetic offline snapshot carrying a `securitycontextconstraints` list |
| `run-lab.sh` | reproducible driver: snapshot, offline==live, expected-table check |
| `expected/lab-table.txt` | the byte-exact bounded table the lab must reproduce |
| `demo.tape` / `demo.gif` | the README demo recording script and the GIF it produces |
| `MEASUREMENTS.md` | observed RAM/disk and the D-009 noise measurement |

