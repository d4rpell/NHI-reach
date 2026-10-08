# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-08

First public release. `nhi-reach` is a defensive, read-only tool that traces
privilege escalation paths from non-human identities (Kubernetes ServiceAccounts)
toward privileged targets, in Kubernetes and OpenShift.

### Added

- **Analysis engine**: effective permissions of any principal (ServiceAccount,
  `User` or `Group`), including implicit ServiceAccount groups, literal
  `resourceNames` matching and the materialized rules of aggregated
  ClusterRoles. It enumerates simple paths to the targets, verifies each path's
  cuts in a hypothetical model, and proposes a greedy, verified bottleneck
  cover.
- **Hop catalog**: six documented escalation hops (NR-001…NR-006), each citing
  the official Kubernetes/OpenShift page that justifies it. `nhi-reach rules`
  prints the catalog with its references.
- **Targets**: `cluster-admin` (privileges equivalent to cluster-admin) and
  `secrets` (read access to Secrets in sensitive namespaces) are evaluated;
  `node` is accepted and reported as a `gap` until the workload-effect
  representation exists.
- **Reports**: a `table`, the versioned JSON schema v1 (`schema_version: 1`) and
  a fully self-contained HTML report (a single file, no network requests, the
  graph library embedded in the page).
- **Live mode**: `nhi-reach snapshot -o DIR` captures a cluster and
  `nhi-reach analyze --live` analyzes it directly. Read-only is enforced in the
  HTTP transport (only `get`/`list`), not only in the documentation. Secret
  values are never written to disk or to a report.
- **Offline first**: `nhi-reach analyze --from DIR` analyzes exported snapshots
  with the same engine as the live mode.
- **Determinism**: the same snapshot produces byte-identical output in all
  three formats; the repository compares golden files byte for byte.

### Notes

- Cut verification runs by default and holds **in the model and up to
  `--max-depth` only**; it is not a guarantee about a real cluster. A benchmark
  of the engine (task T3-02) measured the cost of the verified-cut step and
  recommended a `--verify-cuts` opt-in flag; that flag is **not implemented in
  this release**, so verification stays enabled by default.
- Installing with `go install` does not inject the build metadata (version,
  commit, date, catalog hash); `nhi-reach version` reports the defaults in that
  case. Use a precompiled release binary or the container image for the values
  to be populated.
- Exit codes: `0` complete analysis, `1` unclassified error, `2` `--fail-on any`
  with findings, `3` input error.

[Unreleased]: https://github.com/d4rpell/NHI-reach/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/d4rpell/NHI-reach/releases/tag/v0.1.0
