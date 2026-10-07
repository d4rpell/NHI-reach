// Package snapshot loads an offline snapshot directory into a read-only,
// deterministic index of the input resources of spec §2.1.
//
// The loader strips Secret content (data/stringData) from every object as soon
// as it is decoded, before the object is indexed, hashed or reported.
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

// Add indexes one decoded object under (kind, namespace, name) after computing
// the hash of its canonical JSON.
//
// A Secret is replaced by the reduced representation of minimalSecret: only its
// identity, apiVersion and type survive, so no other field of the original can
// reach the index, the hash or the report. Any other object is indexed as
// decoded and the caller's map is left untouched.
func (ix *Index) Add(raw map[string]any) error {
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

	if kind == "Secret" {
		raw = minimalSecret(apiVersion, name, namespace, raw)
	}

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

// minimalSecret builds the whole representation a Secret is allowed to have
// here: only the fields below, copied explicitly by name. Every other field of
// the original object is discarded, so neither a value nor a serialized copy of
// the object — for instance the conventional annotation
// kubectl.kubernetes.io/last-applied-configuration — can reach the index or the
// hash.
//
// The data-key names of spec §2.1 are not retained yet; they belong to the
// snapshot normalization of T1-01, which the secrets target of T1-02 consumes.
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
	return reduced
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

// Load reads every *.json file of dir (except manifest.json), indexes the
// objects it holds and records a Gap for each missing optional resource type.
// It fails when a required type of spec §2.1 is absent.
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
		if declaredByFile {
			for _, item := range items {
				if kind, _ := item["kind"].(string); kind != declared {
					return nil, fmt.Errorf("%s: the file declares %s but holds a %s object", name, declared, kind)
				}
			}
			ix.present[declared] = true
		}
		for _, item := range items {
			if err := ix.Add(item); err != nil {
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
