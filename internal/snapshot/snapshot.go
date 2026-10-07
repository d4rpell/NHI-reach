// Package snapshot loads an offline snapshot directory into a read-only,
// deterministic index of the input resources of spec §2.1.
//
// Secret content never survives the load: as soon as a decoded object is
// identified as a Secret, the loader replaces it by the reconstruction of
// sanitizeSecret, and only that representation is validated, indexed, hashed or
// reported. The normalization of spec §2.2 (volatile metadata and status) is
// applied before hashing, so two snapshots of the same configuration state
// produce the same hashes.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// SecretContentKeys are the fields that carry Secret values. The loader never
// copies them: a Secret is rebuilt from an explicit field list (minimalSecret),
// so neither these keys nor any field outside that list can appear in the
// index, the hash or the report.
var SecretContentKeys = []string{"data", "stringData"}

// namespacedKinds are the input types that must carry a namespace. Without one
// a namespace-scoped lookup would silently widen to every namespace.
var namespacedKinds = map[string]bool{
	"Pod":            true,
	"Role":           true,
	"RoleBinding":    true,
	"Secret":         true,
	"ServiceAccount": true,
}

// RequiredKinds are the resource types a snapshot must provide (spec §2.1).
// When one is missing the load fails and the command exits 3.
var RequiredKinds = []string{
	"ClusterRole",
	"ClusterRoleBinding",
	"Namespace",
	"Role",
	"RoleBinding",
	"ServiceAccount",
}

// optionalKinds are the resource types whose absence is reported as a Gap
// instead of failing the load (spec §2.1).
var optionalKinds = []string{"Pod", "Secret", "SecurityContextConstraints"}

// pluralToKind maps the conventional file name of a list to the kind of its
// items. It lets an empty list declare which type it represents.
var pluralToKind = map[string]string{
	"clusterrolebindings":        "ClusterRoleBinding",
	"clusterroles":               "ClusterRole",
	"namespaces":                 "Namespace",
	"pods":                       "Pod",
	"rolebindings":               "RoleBinding",
	"roles":                      "Role",
	"secrets":                    "Secret",
	"securitycontextconstraints": "SecurityContextConstraints",
	"serviceaccounts":            "ServiceAccount",
}

type object struct {
	ref model.ObjectRef
	raw map[string]any
}

// Index is a read-only, deterministic index over the normalized objects of a
// snapshot. It implements model.Snapshot.
type Index struct {
	byKind  map[string]map[string]*object
	present map[string]bool
	gaps    []model.Gap
}

// New returns an empty index. Objects are added with Add; Load builds one from
// a directory.
func New() *Index {
	return &Index{byKind: map[string]map[string]*object{}, present: map[string]bool{}}
}

// Add indexes one decoded object under (kind, namespace, name) after reducing
// it to the representation that is allowed to be indexed: a Secret becomes the
// reconstruction of sanitizeSecret, any other object loses the volatile fields
// listed by spec §2.2. The hash is always that of the reduced representation.
// The caller's map is never mutated.
func (ix *Index) Add(raw map[string]any) error {
	kind, _ := raw["kind"].(string)
	if kind == "Secret" {
		raw = sanitizeSecret(raw)
	} else {
		raw = normalized(raw)
	}
	return ix.index(raw)
}

// index validates one already-reduced object and stores it under (kind,
// namespace, name) with the hash of its canonical JSON. It is the single write
// path of the index: Add and Load both reach it only after reducing the object
// — Secrets rebuilt from an explicit field list, everything else stripped of
// volatile fields — so no code path can index a representation that was not
// reduced first.
func (ix *Index) index(raw map[string]any) error {
	kind, _ := raw["kind"].(string)
	if kind == "" {
		return fmt.Errorf("object without kind")
	}
	meta, _ := raw["metadata"].(map[string]any)
	if meta == nil {
		return fmt.Errorf("%s object without metadata", kind)
	}
	name, _ := meta["name"].(string)
	if name == "" {
		return fmt.Errorf("%s object without metadata.name", kind)
	}
	namespace, _ := meta["namespace"].(string)
	if namespacedKinds[kind] && namespace == "" {
		return fmt.Errorf("%s %s is missing metadata.namespace", kind, name)
	}
	apiVersion, _ := raw["apiVersion"].(string)

	canonical, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal %s %s/%s: %w", kind, namespace, name, err)
	}
	sum := sha256.Sum256(canonical)

	if ix.byKind[kind] == nil {
		ix.byKind[kind] = map[string]*object{}
	}
	key := namespace + "/" + name
	if _, dup := ix.byKind[kind][key]; dup {
		return fmt.Errorf("duplicate object %s %s", kind, key)
	}
	ix.byKind[kind][key] = &object{
		ref: model.ObjectRef{
			APIVersion: apiVersion,
			Kind:       kind,
			Namespace:  namespace,
			Name:       name,
			SHA256:     hex.EncodeToString(sum[:]),
		},
		raw: raw,
	}
	ix.present[kind] = true
	return nil
}

// sanitizeSecret rebuilds a decoded Secret from scratch: only the fields of
// minimalSecret survive, so no other field of the original — neither a value
// nor a serialized copy of the object — can reach the index or the hash. It
// never trusts the input, not even a dataKeys field: the list is always
// recomputed from data/stringData.
func sanitizeSecret(raw map[string]any) map[string]any {
	meta, _ := raw["metadata"].(map[string]any)
	var name, namespace string
	if meta != nil {
		name, _ = meta["name"].(string)
		namespace, _ = meta["namespace"].(string)
	}
	apiVersion, _ := raw["apiVersion"].(string)
	return minimalSecret(apiVersion, name, namespace, raw)
}

// minimalSecret builds the whole representation a Secret is allowed to have
// here: only the fields below, copied explicitly by name. Every other field of
// the original object is discarded, so neither a value nor a serialized copy of
// the object — for instance the conventional annotation
// kubectl.kubernetes.io/last-applied-configuration — can reach the index or the
// hash.
//
// The names of the keys of data/stringData are kept (spec §2.1: "solo
// metadatos, tipo y nombres de clave") as dataKeys, sorted ascending with Go
// string comparison and free of duplicates; the values behind them are never
// used to build the index, the hashes or the report. When there are no keys the
// field is omitted: absence means zero keys.
//
// dataKeys is always recomputed from data/stringData and a dataKeys field coming
// from the input is ignored, whatever its JSON type: key names are the only
// trace a written snapshot keeps of a Secret, so the writer materializes them
// under data with empty values (see secretForDisk) and this reader rebuilds them,
// which makes the reduced form round-trip without ever trusting a supplied list.
func minimalSecret(apiVersion, name, namespace string, raw map[string]any) map[string]any {
	reduced := map[string]any{
		"kind":     "Secret",
		"metadata": map[string]any{"name": name, "namespace": namespace},
	}
	if apiVersion != "" {
		reduced["apiVersion"] = apiVersion
	}
	if secretType, ok := raw["type"].(string); ok {
		reduced["type"] = secretType
	}
	if keys := dataKeyNames(raw); len(keys) > 0 {
		reduced["dataKeys"] = keys
	}
	return reduced
}

// dataKeyNames returns the sorted, de-duplicated names of the keys of
// data/stringData. It reads key names only, never values.
func dataKeyNames(raw map[string]any) []string {
	seen := map[string]bool{}
	var names []string
	for _, field := range SecretContentKeys {
		entries, ok := raw[field].(map[string]any)
		if !ok {
			continue
		}
		for name := range entries {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// strippedMetadataKeys are the metadata fields spec §2.2 removes before
// hashing: they differ between two reads of the same configuration state.
var strippedMetadataKeys = []string{
	"creationTimestamp",
	"generation",
	"managedFields",
	"resourceVersion",
	"uid",
}

// normalized returns a shallow copy of raw without the volatile fields of spec
// §2.2 (metadata.managedFields, resourceVersion, uid, generation,
// creationTimestamp and the whole status). The equivalence it buys is scoped to
// this list: a field kept here — notably the last-applied-configuration
// annotation — still affects the hash when it differs between two exports.
func normalized(raw map[string]any) map[string]any {
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		if k == "status" {
			continue
		}
		out[k] = v
	}
	if meta, ok := raw["metadata"].(map[string]any); ok {
		metaCopy := make(map[string]any, len(meta))
		for k, v := range meta {
			metaCopy[k] = v
		}
		for _, k := range strippedMetadataKeys {
			delete(metaCopy, k)
		}
		out["metadata"] = metaCopy
	}
	return out
}

// Entry returns the reference and the normalized object of one object. Secret
// objects never carry their data/stringData fields.
func (ix *Index) Entry(kind, namespace, name string) (model.ObjectRef, map[string]any, bool) {
	o, ok := ix.byKind[kind][namespace+"/"+name]
	if !ok {
		return model.ObjectRef{}, nil, false
	}
	return o.ref, o.raw, true
}

// Get returns the reference of one object.
func (ix *Index) Get(kind, namespace, name string) (model.ObjectRef, bool) {
	ref, _, ok := ix.Entry(kind, namespace, name)
	return ref, ok
}

// List returns the references of kind, ordered by (namespace, name). An empty
// namespace means every namespace (spec §2.3).
func (ix *Index) List(kind, namespace string) []model.ObjectRef {
	objects := ix.byKind[kind]
	out := make([]model.ObjectRef, 0, len(objects))
	for _, o := range objects {
		if namespace != "" && o.ref.Namespace != namespace {
			continue
		}
		out = append(out, o.ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Gaps returns the gaps recorded while loading, ordered by subject.
func (ix *Index) Gaps() []model.Gap {
	return append([]model.Gap(nil), ix.gaps...)
}

// HasKind reports whether the snapshot provided a resource type, either through
// its items or through a conventionally named empty list file.
func (ix *Index) HasKind(kind string) bool { return ix.present[kind] }

// Edited returns a copy of the index in which the object at (kind, namespace,
// name) is replaced by edit applied to a copy of its fields, re-validated and
// re-hashed.
//
// The receiver is never modified, so the index stays a read-only view of the
// input snapshot; the result is the hypothetical model that cut verification
// works on (spec §3 step 6). It is a purely in-memory operation: no cluster is
// contacted and nothing is written.
//
// The callback receives a deep copy of the object and its result is copied
// again before it is stored, so neither mutating a nested field nor keeping a
// reference to the map can reach the receiver or the returned index. It may
// fail, and validation runs against a scratch index before the copy is
// published, so an error leaves both indexes untouched.
func (ix *Index) Edited(kind, namespace, name string, edit func(map[string]any) error) (*Index, error) {
	key := namespace + "/" + name
	o, ok := ix.byKind[kind][key]
	if !ok {
		return nil, fmt.Errorf("cannot edit missing object %s %s", kind, key)
	}

	edited := deepCopy(o.raw).(map[string]any)
	if err := edit(edited); err != nil {
		return nil, err
	}
	// The identity is part of the index key, so it is checked before any
	// reduction: a reduction could otherwise rebuild the object under the name it
	// expects and hide the change.
	if err := checkIdentity(kind, namespace, name, edited); err != nil {
		return nil, err
	}

	published, err := canonical(kind, edited, o.raw)
	if err != nil {
		return nil, err
	}

	scratch := New()
	if err := scratch.index(published); err != nil {
		return nil, err
	}
	replacement, ok := scratch.byKind[kind][key]
	if !ok {
		return nil, fmt.Errorf("edit changed the identity of %s %s", kind, key)
	}

	clone := ix.copy()
	clone.byKind[kind][key] = replacement
	return clone, nil
}

// canonical turns a freshly edited object into the representation the index
// stores: the canonical decoding of its own JSON. The decoding shares nothing
// with the caller — a callback may build Go values, not only decoded JSON, and
// may keep references to them — and it rejects any value the index cannot hold,
// so a func, a channel or a cycle is an error instead of a silently shared
// reference the hash would not cover.
//
// A Secret is reduced exactly as Add reduces it, with one exception: when the
// edit left the content fields untouched it keeps the key names the object
// already carried, because they are the only trace the reduction allows and the
// fields they were derived from are no longer there.
func canonical(kind string, edited, original map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(edited)
	if err != nil {
		return nil, fmt.Errorf("edited %s is not representable as JSON: %w", kind, err)
	}
	published := map[string]any{}
	if err := json.Unmarshal(encoded, &published); err != nil {
		return nil, fmt.Errorf("edited %s is not representable as JSON: %w", kind, err)
	}

	if kind != "Secret" {
		return published, nil
	}
	reduced := sanitizeSecret(published)
	if !carriesContentFields(edited) {
		// The edit did not decide the content fields, so the key names the object
		// already carried — the only trace of them the reduction keeps — are
		// preserved. Writing them empty is a decision, and then they are
		// recomputed from what the callback wrote.
		if keys, ok := original["dataKeys"]; ok {
			reduced["dataKeys"] = deepCopy(keys)
		}
	}
	return reduced, nil
}

// carriesContentFields reports whether the object carries the fields Secret
// values live in, even when they hold nothing.
func carriesContentFields(raw map[string]any) bool {
	for _, field := range SecretContentKeys {
		if _, ok := raw[field]; ok {
			return true
		}
	}
	return false
}

// checkIdentity rejects an edit that changes the kind, the name or the namespace
// of the object: those are the index key, so accepting the change would publish
// the object under an identity no caller asked for.
func checkIdentity(kind, namespace, name string, edited map[string]any) error {
	meta, _ := edited["metadata"].(map[string]any)
	editedKind, _ := edited["kind"].(string)
	editedName, _ := meta["name"].(string)
	editedNamespace, _ := meta["namespace"].(string)
	if editedKind == kind && editedName == name && editedNamespace == namespace {
		return nil
	}
	return fmt.Errorf("edit changed the identity of %s %s/%s", kind, namespace, name)
}

// deepCopy returns an independent copy of a decoded JSON value: maps and slices
// are rebuilt recursively, scalars are shared because they are immutable.
func deepCopy(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = deepCopy(v)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = deepCopy(v)
		}
		return out
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}

// copy returns an independent copy of the index. The kind and object maps are
// new; the objects themselves are shared, because they are never mutated in
// place — Edited replaces the whole entry.
func (ix *Index) copy() *Index {
	out := &Index{
		byKind:  make(map[string]map[string]*object, len(ix.byKind)),
		present: make(map[string]bool, len(ix.present)),
		gaps:    append([]model.Gap(nil), ix.gaps...),
	}
	for kind, byKey := range ix.byKind {
		copied := make(map[string]*object, len(byKey))
		for key, o := range byKey {
			copied[key] = o
		}
		out.byKind[kind] = copied
	}
	for kind, present := range ix.present {
		out.present[kind] = present
	}
	return out
}

// ManifestSchema identifies the manifest.json format of WriteFile.
const ManifestSchema = "nhi-reach/snapshot-manifest/v1"

// SnapshotObject is one entry of Manifest.Objects. Its JSON encoding is part of
// the manifest contract: field names and order are fixed and namespace is
// always present, even when empty.
type SnapshotObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
}

// Manifest is the inventory of a snapshot: every normalized object with its
// canonical hash, plus the hash of that inventory. The snapshot hash identifies
// only the set of normalized objects: it does not attest coverage of the
// resource types, the absence of Gaps or the byte-level integrity of the
// directory.
type Manifest struct {
	Schema  string           `json:"schema"`
	Objects []SnapshotObject `json:"objects"`
	SHA256  string           `json:"snapshot_sha256"`
}

// preimage returns the exact bytes the snapshot hash is computed over: the
// compact JSON of {"objects":[...]} with no trailing newline, excluding schema
// and snapshot_sha256. Field order is fixed by the struct definitions; Go
// escapes <, > and & in strings.
func (m Manifest) preimage() ([]byte, error) {
	return json.Marshal(struct {
		Objects []SnapshotObject `json:"objects"`
	}{Objects: m.Objects})
}

func (m Manifest) digest() string {
	pre, err := m.preimage()
	if err != nil {
		// Unreachable: preimage marshals plain strings and a struct slice.
		panic(fmt.Sprintf("marshal manifest preimage: %v", err))
	}
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:])
}

// Manifest builds the manifest of the index. Objects are ordered by (kind,
// namespace, name) with Go string comparison; Objects is never nil.
func (ix *Index) Manifest() Manifest {
	objects := make([]SnapshotObject, 0)
	for _, byKey := range ix.byKind {
		for _, o := range byKey {
			r := o.ref
			objects = append(objects, SnapshotObject{
				APIVersion: r.APIVersion,
				Kind:       r.Kind,
				Namespace:  r.Namespace,
				Name:       r.Name,
				SHA256:     r.SHA256,
			})
		}
	}
	sort.Slice(objects, func(i, j int) bool {
		a, b := objects[i], objects[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	m := Manifest{Schema: ManifestSchema, Objects: objects}
	m.SHA256 = m.digest()
	return m
}

// WriteFile writes manifest.json into dir with two-space indentation and a
// trailing newline. It refuses to write a manifest with a foreign schema or one
// whose snapshot hash does not match its own objects, so a stale or tampered
// object list cannot be published. Load ignores the file; verifying a directory
// against its manifest is the live mode's job (T2-04).
func (m Manifest) WriteFile(dir string) error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("unsupported manifest schema %q, want %q", m.Schema, ManifestSchema)
	}
	if m.SHA256 != m.digest() {
		return fmt.Errorf("manifest snapshot hash %s does not match its objects", m.SHA256)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), append(data, '\n'), 0o644)
}

// Load reads every *.json file of dir (except manifest.json, which is an output
// artifact of Manifest.WriteFile), indexes the objects it holds and records a
// Gap for each missing optional resource type. It fails when a required type of
// spec §2.1 is absent. Every object is reduced to its allowed representation
// (Secrets rebuilt, everything else stripped of volatile fields) before any
// validation looks at it, so no check runs on unsanitized content.
func Load(dir string) (*Index, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read snapshot directory: %w", err)
	}
	names := make([]string, 0, len(dirEntries))
	for _, e := range dirEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// manifest.json and metadata.json are output artifacts of WriteSnapshot,
		// not input data; ignoring them lets a directory this tool wrote be read
		// back.
		if e.Name() == "manifest.json" || e.Name() == "metadata.json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("snapshot directory %q holds no .json files", dir)
	}

	ix := New()
	for _, name := range names {
		base := strings.ToLower(strings.TrimSuffix(name, ".json"))
		declared, declaredByFile := pluralToKind[base]
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		items, err := decodeItems(name, data)
		if err != nil {
			return nil, err
		}
		for i, item := range items {
			if kind, _ := item["kind"].(string); kind == "Secret" {
				items[i] = sanitizeSecret(item)
			} else {
				items[i] = normalized(item)
			}
		}
		if declaredByFile {
			for _, item := range items {
				if kind, _ := item["kind"].(string); kind != declared {
					return nil, fmt.Errorf("%s: the file declares %s but holds a %s object", name, declared, kind)
				}
			}
			ix.present[declared] = true
		}
		for _, item := range items {
			if err := ix.index(item); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}

	var missing []string
	for _, kind := range RequiredKinds {
		if !ix.present[kind] {
			missing = append(missing, kind)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("snapshot is missing required resource types: %s", strings.Join(missing, ", "))
	}

	if err := ix.finalize(); err != nil {
		return nil, err
	}
	return ix, nil
}

// finalize records one missing-input gap per absent optional type and orders
// the gaps. Load and LoadLive share it, so an offline and a live load of the
// same state report the same gaps with the same shape.
func (ix *Index) finalize() error {
	for _, kind := range optionalKinds {
		if ix.present[kind] {
			continue
		}
		ix.gaps = append(ix.gaps, model.Gap{
			Kind:    "missing-input",
			Subject: kind,
			Message: fmt.Sprintf("snapshot has no %s; hops that depend on them are not evaluated", pluralOf(kind)),
		})
	}
	sort.Slice(ix.gaps, func(i, j int) bool { return ix.gaps[i].Subject < ix.gaps[j].Subject })
	return nil
}

func pluralOf(kind string) string {
	for plural, k := range pluralToKind {
		if k == kind {
			return plural
		}
	}
	return strings.ToLower(kind)
}

// decodeItems accepts either a Kubernetes list ("items") or a single object.
func decodeItems(file string, data []byte) ([]map[string]any, error) {
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", file, err)
	}
	rawItems, ok := top["items"]
	if !ok {
		return []map[string]any{top}, nil
	}
	items, ok := rawItems.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: \"items\" is not a list", file)
	}
	out := make([]map[string]any, 0, len(items))
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: items[%d] is not an object", file, i)
		}
		out = append(out, m)
	}
	return out, nil
}
