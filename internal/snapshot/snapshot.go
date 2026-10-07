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
		if e.IsDir() || e.Name() == "manifest.json" || !strings.HasSuffix(e.Name(), ".json") {
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
	return ix, nil
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
