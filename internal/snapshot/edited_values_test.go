package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func sha256Of(t *testing.T, obj map[string]any) string {
	t.Helper()
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func nan() float64 { return math.NaN() }

// TestEditedRejectsOrDetachesValuesBuiltByTheCallback covers the representation
// a callback may introduce that is not decoded JSON: a Go map, a Go struct or a
// value JSON cannot carry. None of them may end up shared with the published
// object, which the index hashes.
func TestEditedRejectsOrDetachesValuesBuiltByTheCallback(t *testing.T) {
	ix := New()
	addRaw(t, ix, nestedObjectFixture)

	// A Go map handed to the callback and mutated afterwards must not reach the
	// published object: the published representation is the canonical decoding of
	// its own JSON, not the map the callback kept.
	labels := map[string]string{"review": "before"}
	edited, err := ix.Edited("RoleBinding", "app", "creator", func(obj map[string]any) error {
		meta, _ := obj["metadata"].(map[string]any)
		meta["labels"] = labels
		return nil
	})
	if err != nil {
		t.Fatalf("Edited: %v", err)
	}
	labels["review"] = "after"

	ref, obj, _ := edited.Entry("RoleBinding", "app", "creator")
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(canonical); got != `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"labels":{"review":"before"},"name":"creator","namespace":"app"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}` {
		t.Errorf("published object is %s, want the state at edit time", got)
	}

	// The hash covers exactly what the index stores, so mutating the callback's
	// value cannot leave it stale.
	sum := sha256Of(t, obj)
	if ref.SHA256 != sum {
		t.Errorf("stored hash %s does not match the published object %s", ref.SHA256, sum)
	}

	// A value JSON cannot carry is an error, never a silently shared reference.
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"func", func() {}},
		{"channel", make(chan int)},
		{"nan", nan()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ix.Edited("RoleBinding", "app", "creator", func(obj map[string]any) error {
				meta, _ := obj["metadata"].(map[string]any)
				meta["value"] = tc.value
				return nil
			})
			if err == nil {
				t.Fatal("Edited published an object JSON cannot represent")
			}
			if result != nil {
				t.Error("Edited returned an index along with the error")
			}
		})
	}
}

// TestEditedIsNeutralOnAnUnchangedSecret keeps the key names a reduced Secret
// already carries: the fields they were derived from are no longer in the index,
// so re-deriving them from nothing would lose information the object had.
func TestEditedIsNeutralOnAnUnchangedSecret(t *testing.T) {
	ix := New()
	addRaw(t, ix, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"token","namespace":"app"},
		"type":"Opaque","data":{"ca.crt":"c2VjcmV0","token":"c2VjcmV0"}}`)

	before, _, _ := ix.Entry("Secret", "app", "token")

	edited, err := ix.Edited("Secret", "app", "token", func(map[string]any) error { return nil })
	if err != nil {
		t.Fatalf("Edited: %v", err)
	}
	after, obj, _ := edited.Entry("Secret", "app", "token")
	if after.SHA256 != before.SHA256 {
		t.Errorf("a no-op edit changed the hash: %s -> %s", before.SHA256, after.SHA256)
	}
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		DataKeys []string `json:"dataKeys"`
	}
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.DataKeys) != 2 || decoded.DataKeys[0] != "ca.crt" || decoded.DataKeys[1] != "token" {
		t.Errorf("dataKeys = %v, want the key names the Secret already carried", decoded.DataKeys)
	}
}

// TestEditedReplacesSecretKeyNamesWithTheEditedOnes is the other half: a
// callback that does write content fields must have them re-derived, never
// merged with the previous names.
func TestEditedReplacesSecretKeyNamesWithTheEditedOnes(t *testing.T) {
	ix := New()
	addRaw(t, ix, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"token","namespace":"app"},
		"type":"Opaque","data":{"ca.crt":"c2VjcmV0"}}`)

	edited, err := ix.Edited("Secret", "app", "token", func(obj map[string]any) error {
		obj["data"] = map[string]any{"replacement": "c2VjcmV0"}
		return nil
	})
	if err != nil {
		t.Fatalf("Edited: %v", err)
	}
	_, obj, _ := edited.Entry("Secret", "app", "token")
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		DataKeys []string `json:"dataKeys"`
	}
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.DataKeys) != 1 || decoded.DataKeys[0] != "replacement" {
		t.Errorf("dataKeys = %v, want only the edited key names", decoded.DataKeys)
	}
}

// TestEditedDecidesSecretKeysOnWhatTheCallbackWrote distinguishes an edit that
// left the content fields alone from one that wrote them empty: only the first
// keeps the key names the object already carried.
func TestEditedDecidesSecretKeysOnWhatTheCallbackWrote(t *testing.T) {
	ix := New()
	addRaw(t, ix, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"token","namespace":"app"},
		"type":"Opaque","data":{"ca.crt":"c2VjcmV0"}}`)

	edited, err := ix.Edited("Secret", "app", "token", func(obj map[string]any) error {
		obj["data"] = map[string]any{}
		return nil
	})
	if err != nil {
		t.Fatalf("Edited: %v", err)
	}
	_, obj, _ := edited.Entry("Secret", "app", "token")
	canonical, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), "dataKeys") {
		t.Errorf("writing the content fields empty kept the old key names: %s", canonical)
	}
}

func TestEditedRejectsASecretTurnedIntoAnotherKind(t *testing.T) {
	ix := New()
	addRaw(t, ix, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"token","namespace":"app"},
		"type":"Opaque","data":{"ca.crt":"c2VjcmV0"}}`)

	result, err := ix.Edited("Secret", "app", "token", func(obj map[string]any) error {
		obj["kind"] = "ConfigMap"
		return nil
	})
	if err == nil {
		t.Fatal("Edited accepted an edit that changed the kind of the object")
	}
	if result != nil {
		t.Error("Edited returned an index along with the error")
	}
	_, obj, _ := ix.Entry("Secret", "app", "token")
	if kind, _ := obj["kind"].(string); kind != "Secret" {
		t.Errorf("the receiver changed kind to %q", kind)
	}
}
