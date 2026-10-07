# Evidence and hashes

This document specifies how `nhi-reach` normalizes the objects of a snapshot,
how canonical hashes are computed, and the format of `manifest.json`. These
rules exist so that two loads of the same configuration state produce the same
hashes under the normalization defined here — an equality of normalized
representations, not full semantic equality of live cluster state.

## Input and sanitization

A snapshot directory holds one `.json` file per resource type, each containing
either a Kubernetes `List` or a single object. The required types are
`ServiceAccount`, `Role`, `RoleBinding`, `ClusterRole`, `ClusterRoleBinding`
and `Namespace`; a load that is missing one of them fails. `Pod`, `Secret` and
`SecurityContextConstraints` are optional, and their absence is reported as a
`missing-input` gap, never assumed away.

As soon as a decoded object is identified as a `Secret` — and before any other
processing — the loader replaces it by a reconstruction that copies only:
`apiVersion`, `kind`, `metadata.name`, `metadata.namespace`, `type`, and
`dataKeys` (see below). No other field of the original object reaches the
index, the hashes or the report. This is stronger than deleting
`data`/`stringData`: a field added by a future Kubernetes version, or a
serialized copy of the object such as the conventional
`kubectl.kubernetes.io/last-applied-configuration` annotation, cannot survive
the rebuild. Secret values take part in the initial JSON decode, like every
other byte of the file, but are never used to build the index, the hashes or
the report; only key names survive.

`dataKeys` is the sorted (Go string order), de-duplicated list of the key names
of `data` and `stringData`. It is always recomputed from those two fields; a
`dataKeys` field supplied in the input is ignored, whatever its JSON type. When
there are no keys, the field is omitted: absence means zero keys. Key names are
kept because the snapshot format defines Secrets as "metadata, type and key
names"; a name that is itself sensitive stays in the snapshot by design.

## Normalization

For every other object, the loader removes before hashing:

- `metadata.managedFields`
- `metadata.resourceVersion`
- `metadata.uid`
- `metadata.generation`
- `metadata.creationTimestamp`
- the whole top-level `status`

The equivalence this buys is scoped to exactly this list. A field kept by the
normalization — notably `last-applied-configuration` on non-Secret objects —
still affects the hash when it differs between two exports of the same state.

## Canonicalization and hashing

The hash of an object is the SHA-256 of its canonical JSON: Go's
`encoding/json` serialization of the normalized object — keys sorted by the
map marshaller, compact (no whitespace) — encoded as lowercase hexadecimal.

`manifest.json` is the inventory of a snapshot:

```json
{
  "schema": "nhi-reach/snapshot-manifest/v1",
  "objects": [
    {
      "apiVersion": "v1",
      "kind": "Namespace",
      "namespace": "",
      "name": "app",
      "sha256": "<hex>"
    }
  ],
  "snapshot_sha256": "<hex>"
}
```

Contract:

- `objects` is ordered by `(kind, namespace, name)` with Go string comparison.
  Field names and order inside each entry are fixed: `apiVersion`, `kind`,
  `namespace`, `name`, `sha256`. `namespace` is always present, even when
  empty. An inventory with no objects serializes `objects` as `[]`, never as
  `null`.
- `snapshot_sha256` is the SHA-256 of the **preimage**: the compact JSON of
  `{"objects":[...]}` with the entry encoding above (fixed field order,
  `namespace` always present, Go escapes `<`, `>` and `&` in strings), with no
  trailing newline. The preimage excludes `schema` and `snapshot_sha256`
  itself; a verifier must check `schema` before interpreting the hash.
- The file is written with two-space indentation, the field order shown above
  and a trailing newline. The writer refuses to publish a manifest with a
  foreign `schema` or whose `snapshot_sha256` does not match its own objects.
- The snapshot hash identifies only the set of normalized objects. It does not
  attest coverage of the resource types, the absence of gaps, or the
  byte-level integrity of the directory: an optional type that is absent and
  the same type present as an empty list produce the same inventory.

`nhi-reach analyze` ignores `manifest.json` when reading a directory. Verifying
a directory against its manifest is the live `snapshot` command's job
(forthcoming release).
