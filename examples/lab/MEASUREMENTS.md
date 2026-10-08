# Lab measurements

Measured on the owner's Oracle VPS (Ampere A1, arm64, Oracle Linux 9.7, podman
rootless 5.8.2) on 2026-10-08, with `kind` v0.33.0 and node image
`kindest/node:v1.37.0@sha256:a1ed56cf…`. These are observed values, not
estimates.

## Cluster cost

| Cluster | RAM (container, podman stats) | Host disk (`du`) |
| --- | --- | --- |
| `nhi-reach-lab` | 658.9 MB | 46 MB |
| `ariadne-lab` (sibling, still running) | 774.3 MB | — |

The podman image store is shared and holds ~3.3 GB in total for both clusters.
The VPS had 19 GiB available; the two clusters fit at once, so `ariadne-lab` was
left untouched (D-013: never delete it without the owner's explicit go).

## End-to-end result

- `snapshot -o out/snapshot` wrote 259 objects; `snapshot_sha256 5d57ca4f…`.
- The **offline** analysis (`analyze --from out/snapshot`) and the **live**
  analysis (`analyze --live`) of the same cluster state are **byte-identical**:
  `cmp` reported no difference. This is the T2-04 parity claim checked against a
  real apiserver, not only the local test server.
- The bounded table (`--from-identity lab-app/deployer`, `--max-depth 2`,
  `--paths-per-pair 8`, targets `cluster-admin` and `secrets`) matches
  `expected/lab-table.txt` byte for byte. It exercises every edge type the
  catalog can emit: NR-001, NR-002, NR-003, NR-004, NR-005, NR-006, the direct
  `rbac-cluster-admin` edge and the `rbac-secret-read` edge.
- The default RBAC that `kind` installs (the whole `kube-system` operator set)
  produces 45 ServiceAccounts in `kube-system`; with the default targets the
  analysis reports `system identities` noise the way D-009 predicts (see below).

## D-009 — system-identity noise (measured)

The tool does not treat system namespaces as origins by default. The measured
effect on this cluster. All rows below use the same `--max-depth 4`; the
`--paths-per-pair` (ppp) value is stated per row:

| Invocation (target `cluster-admin`) | Distinct origins | System origins | Paths reported | Paths via a system identity |
| --- | --- | --- | --- | --- |
| Default origins, ppp 3 (default) | 2 (both `lab-app`) | 0 | 6 | 0 |
| Default origins, ppp 25 | 2 (both `lab-app`) | 0 | 50 | 29 |
| `--include-system`, ppp 3 | 3 (all `kube-system`) | 3 | 7 | 0 |
| `--include-system`, ppp 25 | 3 (all `kube-system`) | 3 | 51 | 0 |
| Single origin `--from-identity lab-app/deployer`, ppp 25 | 1 | 0 | 25 | 16 |
| Single origin `--from-identity lab-app/deployer`, ppp 25, `--include-system` | 1 | 0 | 25 | 16 |

Reading these numbers:

- The clean indicator of D-009 is the **System origins** column: it is 0 by
  default (no system identity is an origin) and 3 with `--include-system`. This
  is the decision D-009 encodes and it is stable across ppp values.
- `--paths-per-pair` bounds how many paths are *shown* per origin/target pair,
  not which paths exist. With the default ppp 3 only the three shortest paths
  show and none of them happens to cross a system identity; at ppp 25, 29 of the
  50 reported paths cross `kube-system`. The intermediate system identity is
  never hidden by default — it is simply not among the shortest paths.
- The `--include-system, ppp 25` row shows 0 `via_system` despite adding system
  origins. This is **not** a contradiction: adding 3 system origins (plus the
  default RBAC noise) makes the enumeration budget the binding constraint, so the
  report fills the budget with each origin's own paths and flags the exhaustion
  as a gap (11 gaps, 10 of them budget-related, vs 4/3 without
  `--include-system`). The `via_system` count is therefore not comparable across
  those two runs; the System-origins count is, and it is what the table reports.
- The single-origin row is invariant to `--include-system` (16 of 25 paths
  `via_system` either way), which confirms that `via_system` marks a property of
  the path, not of the origin filter.

The bounded run used for `expected/lab-table.txt` reports two `via_system` paths,
both crossing `kube-system/lab-system-ops` through NR-002 and reaching
`cluster-admin` and `secrets`. They are flagged (`via_system: true`) and
highlight the intermediate system identity rather than burying it, which is the
behaviour D-009 requires.

Note on cost: the default `cluster-admin` analysis over the full default RBAC
already hits the enumeration budget and reports it as a gap (`RemainingPaths is
a lower bound`, `exploration budget … exhausted`). That is the tool correctly
declaring the limit of its own search, not a failure; it is also the reason the
committed expected table uses a bounded invocation that does not depend on the
default cluster RBAC that kind happens to install.
