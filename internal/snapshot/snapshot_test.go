package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	want := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"registry","namespace":"app"},"type":"kubernetes.io/dockerconfigjson"}`
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
