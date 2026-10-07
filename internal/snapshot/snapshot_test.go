package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// minimalSnapshot writes the six required types as empty lists, except for one
// namespace.
func minimalSnapshot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "namespaces.json",
		`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}]}`)
	for _, name := range []string{"serviceaccounts", "roles", "clusterroles", "rolebindings", "clusterrolebindings"} {
		writeFile(t, dir, name+".json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[]}`)
	}
	return dir
}

func TestLoadRejectsMissingRequiredKind(t *testing.T) {
	dir := minimalSnapshot(t)
	if err := os.Remove(filepath.Join(dir, "clusterroles.json")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted a snapshot without ClusterRole")
	}
	if !strings.Contains(err.Error(), "ClusterRole") {
		t.Errorf("error does not name the missing type: %v", err)
	}
}

func TestLoadRejectsEmptyDirectory(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("Load accepted a directory without JSON files")
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	dir := minimalSnapshot(t)
	writeFile(t, dir, "pods.json", `{"kind":`)
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted invalid JSON")
	}
}

func TestLoadReducesSecretToItsMinimalRepresentation(t *testing.T) {
	dir := minimalSnapshot(t)
	writeFile(t, dir, "secrets.json", `{"apiVersion":"v1","kind":"List","items":[{
		"apiVersion":"v1","kind":"Secret","metadata":{"name":"registry","namespace":"app",
			"labels":{"copy":"LABEL-COPY"},
			"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"data\":{\"token\":\"ANNOTATION-COPY\"}}","owner":"platform"}},
		"type":"kubernetes.io/dockerconfigjson",
		"data":{".dockerconfigjson":"c3VwZXItc2VjcmV0"},
		"stringData":{"backup-token":"PLAINTEXT-TOKEN"}}]}`)

	ix, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ref, obj, ok := ix.Entry("Secret", "app", "registry")
	if !ok {
		t.Fatal("secret not indexed")
	}

	want := `{"apiVersion":"v1","dataKeys":[".dockerconfigjson","backup-token"],"kind":"Secret","metadata":{"name":"registry","namespace":"app"},"type":"kubernetes.io/dockerconfigjson"}`
	encoded, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != want {
		t.Errorf("indexed secret is %s, want only %s", encoded, want)
	}
	for _, key := range SecretContentKeys {
		if _, present := obj[key]; present {
			t.Errorf("secret object still carries %q", key)
		}
	}
	for _, leak := range []string{"c3VwZXItc2VjcmV0", "PLAINTEXT-TOKEN", "ANNOTATION-COPY", "LABEL-COPY"} {
		if strings.Contains(string(encoded), leak) {
			t.Errorf("reduced secret leaks %q", leak)
		}
	}
	// The hash must be that of the reduced representation, not of the original
	// object: hashing before reduction would leave content in the reference.
	sum := sha256.Sum256([]byte(want))
	if ref.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("secret hash is %s, want the hash of %s", ref.SHA256, want)
	}
	if ref.Name != "registry" || ref.Namespace != "app" || ref.Kind != "Secret" {
		t.Errorf("secret reference lost its identity: %+v", ref)
	}
}

func TestSecretHashIgnoresValuesButNotKeyNames(t *testing.T) {
	ix := New()
	var values map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Secret",
		"metadata":{"name":"s","namespace":"app"},"type":"Opaque",
		"data":{"token":"c3RhdGUtMQ=="}}`), &values); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(values); err != nil {
		t.Fatal(err)
	}
	other := New()
	var renamed map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Secret",
		"metadata":{"name":"s","namespace":"app"},"type":"Opaque",
		"data":{"other-token":"c3RhdGUtMQ=="}}`), &renamed); err != nil {
		t.Fatal(err)
	}
	if err := other.Add(renamed); err != nil {
		t.Fatal(err)
	}
	first, _ := ix.Get("Secret", "app", "s")
	second, _ := other.Get("Secret", "app", "s")
	if first.SHA256 == second.SHA256 {
		t.Fatal("secrets differing only in data-key names share a hash")
	}

	sameValues := New()
	var rotated map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Secret",
		"metadata":{"name":"s","namespace":"app"},"type":"Opaque",
		"data":{"token":"c3RhdGUtMg=="}}`), &rotated); err != nil {
		t.Fatal(err)
	}
	if err := sameValues.Add(rotated); err != nil {
		t.Fatal(err)
	}
	third, _ := sameValues.Get("Secret", "app", "s")
	if third.SHA256 != first.SHA256 {
		t.Error("rotating a secret value changed its hash, which must only cover key names")
	}
}

func TestAddIgnoresSuppliedDataKeys(t *testing.T) {
	ix := New()
	var obj map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Secret",
		"metadata":{"name":"s","namespace":"app"},"type":"Opaque",
		"dataKeys":["forged"]}`), &obj); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(obj); err != nil {
		t.Fatal(err)
	}
	_, reduced, ok := ix.Entry("Secret", "app", "s")
	if !ok {
		t.Fatal("secret not indexed")
	}
	if _, present := reduced["dataKeys"]; present {
		t.Error("a file-supplied dataKeys list survived sanitization")
	}
}

func TestAddRebuildsSecretEvenWithTypedList(t *testing.T) {
	ix := New()
	// Built in memory, not decoded from JSON: dataKeys is a genuine []string,
	// and the annotation carries a serialized copy with a synthetic value. A
	// type-based trust would index this map as received.
	raw := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      "s",
			"namespace": "app",
			"annotations": map[string]any{
				"kubectl.kubernetes.io/last-applied-configuration": `{"data":{"token":"SYNTHETIC-VALUE"}}`,
			},
		},
		"dataKeys": []string{"token"},
	}
	if err := ix.Add(raw); err != nil {
		t.Fatal(err)
	}
	_, reduced, ok := ix.Entry("Secret", "app", "s")
	if !ok {
		t.Fatal("secret not indexed")
	}
	encoded, err := json.Marshal(reduced)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SYNTHETIC-VALUE", "annotations", "last-applied-configuration"} {
		if strings.Contains(string(encoded), leak) {
			t.Errorf("typedList bypass leaked %q: %s", leak, encoded)
		}
	}
	if string(encoded) != `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"app"}}` {
		t.Errorf("secret was not rebuilt from the allowed fields: %s", encoded)
	}
}

func TestSecretDataKeysAreSortedDeduplicatedOrOmitted(t *testing.T) {
	load := func(t *testing.T, raw string) map[string]any {
		t.Helper()
		dir := minimalSnapshot(t)
		writeFile(t, dir, "secrets.json", raw)
		ix, err := Load(dir)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		_, obj, ok := ix.Entry("Secret", "app", "s")
		if !ok {
			t.Fatal("secret not indexed")
		}
		return obj
	}
	obj := load(t, `{"apiVersion":"v1","kind":"List","items":[
		{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"app"},"type":"Opaque",
		"data":{"b":"VAxB","a":"VAxB"},"stringData":{"c":"VAxB","a":"VAxB"}}]}`)
	if keys, ok := obj["dataKeys"].([]string); !ok || len(keys) != 3 ||
		keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Errorf("dataKeys is %v, want [a b c] sorted and deduplicated", obj["dataKeys"])
	}
	obj = load(t, `{"apiVersion":"v1","kind":"List","items":[
		{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"app"},"type":"Opaque"}]}`)
	if _, present := obj["dataKeys"]; present {
		t.Error("a secret without keys carries an empty dataKeys list; absence must mean zero keys")
	}
}

func TestHashIgnoresVolatileFields(t *testing.T) {
	addOne := func(t *testing.T, raw string) model.ObjectRef {
		ix := New()
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			t.Fatal(err)
		}
		if err := ix.Add(obj); err != nil {
			t.Fatal(err)
		}
		ref, ok := ix.Get("Namespace", "", "app")
		if !ok {
			t.Fatal("namespace not indexed")
		}
		return ref
	}
	volatile := addOne(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app",
			"uid":"11111111-1111-1111-1111-111111111111","resourceVersion":"100",
			"generation":1,"creationTimestamp":"2026-01-01T00:00:00Z",
			"managedFields":[{"manager":"kubectl"}]}}`)
	withStatus := addOne(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app",
			"uid":"22222222-2222-2222-2222-222222222222","resourceVersion":"999",
			"generation":7,"creationTimestamp":"2020-05-05T05:05:05Z"},
			"status":{"phase":"Active"}}`)
	if volatile.SHA256 != withStatus.SHA256 {
		t.Errorf("objects differing only in volatile fields hash differently: %s vs %s", volatile.SHA256, withStatus.SHA256)
	}
}

func TestManifestIsDeterministicAcrossItemOrder(t *testing.T) {
	objects := `[
		{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"b"}},
		{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"a"}}]`
	first := minimalSnapshot(t)
	writeFile(t, first, "namespaces.json", `{"apiVersion":"v1","kind":"List","items":`+objects+`}`)
	second := minimalSnapshot(t)
	writeFile(t, second, "namespaces.json", `{"apiVersion":"v1","kind":"List","items":[
		{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"a"}},
		{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"b"}}]}`)

	firstIndex, err := Load(first)
	if err != nil {
		t.Fatal(err)
	}
	secondIndex, err := Load(second)
	if err != nil {
		t.Fatal(err)
	}
	a, b := firstIndex.Manifest(), secondIndex.Manifest()
	if a.SHA256 != b.SHA256 || len(a.Objects) != len(b.Objects) {
		t.Fatalf("manifests differ across item order: %s vs %s", a.SHA256, b.SHA256)
	}
	for i := range a.Objects {
		if a.Objects[i] != b.Objects[i] {
			t.Errorf("object %d differs: %+v vs %+v", i, a.Objects[i], b.Objects[i])
		}
	}
}

func TestManifestBytesAndDigestMatchTheContract(t *testing.T) {
	ix := New()
	var obj map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}`), &obj); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(obj); err != nil {
		t.Fatal(err)
	}
	m := ix.Manifest()

	objectHash := sha256.Sum256([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}`))
	objectSHA := hex.EncodeToString(objectHash[:])
	preimage := `{"objects":[{"apiVersion":"v1","kind":"Namespace","namespace":"","name":"app","sha256":"` + objectSHA + `"}]}`
	digest := sha256.Sum256([]byte(preimage))
	if m.SHA256 != hex.EncodeToString(digest[:]) {
		t.Errorf("snapshot hash is %s, want the hash of the preimage %s", m.SHA256, preimage)
	}
	if len(m.Objects) != 1 || m.Objects[0].SHA256 != objectSHA || m.Objects[0].Namespace != "" {
		t.Errorf("unexpected objects: %+v", m.Objects)
	}

	dir := t.TempDir()
	if err := m.WriteFile(dir); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "schema": "nhi-reach/snapshot-manifest/v1",
  "objects": [
    {
      "apiVersion": "v1",
      "kind": "Namespace",
      "namespace": "",
      "name": "app",
      "sha256": "` + objectSHA + `"
    }
  ],
  "snapshot_sha256": "` + m.SHA256 + `"
}
`
	if string(written) != want {
		t.Errorf("manifest.json is %q, want %q", written, want)
	}
}

func TestWriteFileRejectsTamperedDigest(t *testing.T) {
	ix := New()
	var obj map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}`), &obj); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(obj); err != nil {
		t.Fatal(err)
	}
	m := ix.Manifest()
	m.Objects = append(m.Objects, SnapshotObject{Kind: "Namespace", Name: "forged"})
	if err := m.WriteFile(t.TempDir()); err == nil {
		t.Fatal("WriteFile published a manifest whose objects do not match its hash")
	}
}

func TestWriteFileRejectsForeignSchema(t *testing.T) {
	ix := New()
	var obj map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}`), &obj); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(obj); err != nil {
		t.Fatal(err)
	}
	m := ix.Manifest()
	m.Schema = "unsupported"
	if err := m.WriteFile(t.TempDir()); err == nil {
		t.Fatal("WriteFile published a manifest with a foreign schema")
	}
}

func TestLoadRejectsFileHoldingAnotherKind(t *testing.T) {
	dir := minimalSnapshot(t)
	writeFile(t, dir, "serviceaccounts.json",
		`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}]}`)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted a serviceaccounts.json holding a Namespace")
	}
	if !strings.Contains(err.Error(), "ServiceAccount") {
		t.Errorf("error does not name the declared kind: %v", err)
	}
}

func TestAddRejectsNamespacedObjectWithoutNamespace(t *testing.T) {
	ix := New()
	var obj map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"orphan"}}`), &obj); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(obj); err == nil {
		t.Fatal("Add accepted a ServiceAccount without metadata.namespace")
	}
}

func TestLoadReportsMissingOptionalKinds(t *testing.T) {
	ix, err := Load(minimalSnapshot(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	subjects := map[string]bool{}
	for _, gap := range ix.Gaps() {
		if gap.Kind != "missing-input" {
			t.Errorf("gap %q has kind %q, want missing-input", gap.Subject, gap.Kind)
		}
		subjects[gap.Subject] = true
	}
	for _, kind := range optionalKinds {
		if !subjects[kind] {
			t.Errorf("no gap reported for missing %s", kind)
		}
	}
}

func TestLoadIsDeterministicAcrossItemOrder(t *testing.T) {
	objects := `[
		{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"b","namespace":"ns2"}},
		{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"a","namespace":"ns1"}}]`

	first := minimalSnapshot(t)
	writeFile(t, first, "serviceaccounts.json", `{"apiVersion":"v1","kind":"List","items":`+objects+`}`)
	second := minimalSnapshot(t)
	writeFile(t, second, "serviceaccounts.json",
		`{"apiVersion":"v1","kind":"List","items":[
		{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"a","namespace":"ns1"}},
		{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"b","namespace":"ns2"}}]}`)

	firstIndex, err := Load(first)
	if err != nil {
		t.Fatal(err)
	}
	secondIndex, err := Load(second)
	if err != nil {
		t.Fatal(err)
	}
	firstList := firstIndex.List("ServiceAccount", "")
	secondList := secondIndex.List("ServiceAccount", "")
	if len(firstList) != 2 {
		t.Fatalf("indexed %d service accounts, want 2", len(firstList))
	}
	for i := range firstList {
		if firstList[i] != secondList[i] {
			t.Errorf("item %d differs between orders: %+v vs %+v", i, firstList[i], secondList[i])
		}
	}
	if firstList[0].Namespace != "ns1" || firstList[1].Namespace != "ns2" {
		t.Errorf("list is not ordered by (namespace, name): %+v", firstList)
	}
}

func TestAddRejectsDuplicateObject(t *testing.T) {
	ix := New()
	raw := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}`
	for i := 0; i < 2; i++ {
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			t.Fatal(err)
		}
		err := ix.Add(obj)
		if i == 0 && err != nil {
			t.Fatalf("first Add: %v", err)
		}
		if i == 1 && err == nil {
			t.Fatal("Add accepted a duplicate object")
		}
	}
}

func TestListNamespaceFilter(t *testing.T) {
	ix := New()
	for _, raw := range []string{
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"a","namespace":"ns1"}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"b","namespace":"ns2"}}`,
	} {
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			t.Fatal(err)
		}
		if err := ix.Add(obj); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(ix.List("ServiceAccount", "")); got != 2 {
		t.Errorf("empty namespace returned %d objects, want every namespace (2)", got)
	}
	if got := len(ix.List("ServiceAccount", "ns1")); got != 1 {
		t.Errorf("namespace filter returned %d objects, want 1", got)
	}
}
