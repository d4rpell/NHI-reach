# nhi-reach

> How far can this non-human identity get?

`nhi-reach` is a defensive, read-only CLI tool that audits non-human identities (NHI) in Kubernetes/OpenShift. It analyzes ServiceAccounts, their tokens and their RBAC/SCC bindings, and computes which **privilege escalation paths** exist from each identity toward three critical targets:

1. Privileges equivalent to `cluster-admin`.
2. Control of a node (privileged workloads, `hostPath`, permissive SCCs).
3. Read access to Secrets in sensitive namespaces.

Of these, `cluster-admin` and `secrets` are evaluated today; `node` is accepted and reported as a gap until the workload-effect representation exists.

**Status (2026-10-07): the analysis engine and the output surface are complete; the light version runs end to end.** `nhi-reach analyze --from DIR -o table|json|html` reads an offline snapshot, resolves the effective permissions of every ServiceAccount (implicit groups, `resourceNames`, materialized aggregated ClusterRoles) and enumerates the escalation paths to the `cluster-admin` and `secrets` targets, chaining the direct binding and the six hops of the approved catalog (NR-001…NR-006). The table report, the versioned JSON schema v1 (`schema_version: 1`) and a **self-contained HTML report** (a single file, no network requests, with the graph embedded) are written with `--out`; per-path cuts are verified in the model and bottlenecks are proposed as a verified cover. There is **no** live mode yet (T2-04), and the `node` target is not evaluated: it is accepted and reported as a `gap` until the workload-effect representation exists.

## Positioning

| Tool | What it does | Difference with nhi-reach |
|---|---|---|
| [nhi-watch](https://github.com/Zyrakk/nhi-watch) | NHI inventory, per-identity scoring, CIS, drift, inactivity, minimum RBAC by use | Evaluates each identity in isolation and does not chain permissions. **Complementary**: nhi-reach could consume its JSON later |
| [KubeHound](https://github.com/DataDog/KubeHound) (Datadog) | Attack-path graph in K8s | Its README lists Docker and Docker Compose V2 as requirements and documents Gremlin queries (TinkerPop); it also offers a service mode (KHaaS). nhi-reach is a single offline binary, NHI-focused, with cuts verified in the model. Its [homepage](https://kubehound.io/) and [attacks index](https://kubehound.io/reference/attacks/), checked 2026-10-07, show no mentions of OpenShift SCCs |
| KubiScan / rbac-tool | Risky permissions / RBAC visualization | They do not compute escalation chains |

Status of these tools checked 2026-10-07 through the GitHub API: [KubeHound](https://github.com/DataDog/KubeHound), last push 2026-09-30; [rbac-police](https://github.com/PaloAltoNetworks/rbac-police), archived; [KubiScan](https://github.com/cyberark/KubiScan) and [rbac-tool](https://github.com/alcideio/rbac-tool), no pushes since 2025; [nhi-watch](https://github.com/Zyrakk/nhi-watch), last push 2026-03-16.

## Principles

- **Read-only**, always: it never creates, modifies or executes anything in the cluster.
- **Offline first**: it analyzes exported snapshots; the planned live mode will use only `get`/`list`.
- **Deterministic**: same snapshot → same output, byte for byte (table, JSON and HTML, with golden files compared byte for byte).
- **Evidence-first**: every edge carries references to the objects that enable it, with their SHA-256 hash ([evidence rules](docs/evidence.md)).
- **Never stores Secret values**: only metadata, `type` and the key names of `data`/`stringData` ([evidence rules](docs/evidence.md)).

## Usage

```bash
go run ./cmd/nhi-reach analyze --from testdata/light/hit
go run ./cmd/nhi-reach analyze --from testdata/light/hit -o json --out report.json
go run ./cmd/nhi-reach analyze --from testdata/light/hit -o html --out report.html
```

The table prints one row per path (origin, target, hop count, confidence, whether the route crosses a system identity, and the best cut with its verification state), grouped by target, with routes born at system identities in a separate block, followed by the analysis `gaps`. The JSON is the versioned v1 schema (`schema_version: 1`). The HTML is a single self-contained file: it opens with no network (the graph library is embedded, no CDN, no requests), draws the route graph with system identities, application identities and targets styled apart, and shows per path the hops, the evidence, the link to the official catalog reference, the cuts with their verification state and the bottlenecks; the content is rendered in Go and stays readable without JavaScript (only the graph is missing).

The repository fixtures are synthetic: `testdata/light/hit` has expected paths, `testdata/light/miss` has none, and `testdata/light/secrets` exercises the `secrets` target. The input format is the JSON of `kubectl get <resource> -o json`, a list, or a single object per file.

Every analysis flag is wired: `--from`, `-o table|json|html`, `--out`, `--max-depth`, `--paths-per-pair`, `--from-identity`, `--target cluster-admin|node|secrets` (repeatable; defaults to all three), `--sensitive-ns` (extends the default list), `--system-ns`, `--include-system` and `--fail-on none|any`. What is not implemented yet (`--live`, `snapshot`) exits with code 3 instead of being silently ignored; `--target node` is accepted and reported as a `gap`. Exit codes: 0 complete analysis, 1 unclassified error (including `--out` I/O), 2 `--fail-on any` with findings, 3 input error. With `go run`, `go` reports the code as `exit status N` and returns 1, while the binary returns the real code.

Every hop of the catalog cites the official Kubernetes/OpenShift documentation that justifies it (`nhi-reach rules` prints the catalog with its references).

## Building

Go 1.23 is the minimum declared in `go.mod`; the `toolchain go1.25.13` directive pins the build toolchain to a release whose standard library has the `html/template` fixes the HTML report needs (those advisories have no 1.23/1.24 backport). `make build` produces `bin/nhi-reach`; `make test`, `make vet`, `make lint` and `make vuln` run the checks CI runs.

## Documentation

- [Evidence rules](docs/evidence.md): what the tool keeps from each resource and why Secret values can never reach a report.
- [Third-party notices](THIRD_PARTY_NOTICES.md): the embedded graph library (cytoscape.js, MIT), its version, source and pinned digest.
- Design decisions, the backlog and the design spec are kept in the project's private documentation and are not linked from here.

## Roadmap

- Live mode via client-go, enforcing read-only `get`/`list` verbs in code (T2-04).
- The `node` target, once the workload-effect representation is decided (needed also for the OpenShift SCC hop, NR-007).
- v0.1 release: GoReleaser, distroless Docker image, install docs.

## License

[Apache-2.0](LICENSE).
