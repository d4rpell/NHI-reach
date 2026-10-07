package snapshot

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// nestedObjectFixture indexes one object with a nested list, the shape a
// callback must not be able to mutate behind the index's back.
const nestedObjectFixture = `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding",
	"metadata":{"name":"creator","namespace":"app"},
	"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"creator"},
	"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"app"}]}`

func TestEditedIsolatesTheCallbackFromNestedFields(t *testing.T) {
	ix := New()
	addRaw(t, ix, nestedObjectFixture)
	_, before, _ := ix.Entry("RoleBinding", "app", "creator")
	beforeCopy, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}

	// A callback that mutates a nested map and then fails must not leave a
	// trace: the copy handed to it is deep, so the receiver's nested maps are
	// not the ones the callback writes to.
	if _, err := ix.Edited("RoleBinding", "app", "creator", func(obj map[string]any) error {
		meta, _ := obj["metadata"].(map[string]any)
		meta["name"] = "changed"
		subjects, _ := obj["subjects"].([]any)
		if len(subjects) > 0 {
			subject, _ := subjects[0].(map[string]any)
			subject["name"] = "changed"
		}
		return errors.New("fixture edit failure")
	}); err == nil {
		t.Fatal("Edited accepted a failing edit")
	}

	_, after, _ := ix.Entry("RoleBinding", "app", "creator")
	afterCopy, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterCopy) != string(beforeCopy) {
		t.Errorf("a failing edit reached the receiver:\n before %s\n  after %s", beforeCopy, afterCopy)
	}
}

func TestEditedDoesNotPublishThroughTheCallbackReference(t *testing.T) {
	ix := New()
	addRaw(t, ix, nestedObjectFixture)

	var retained map[string]any
	edited, err := ix.Edited("RoleBinding", "app", "creator", func(obj map[string]any) error {
		retained = obj
		obj["subjects"] = []any{}
		return nil
	})
	if err != nil {
		t.Fatalf("Edited: %v", err)
	}

	// Writing through the reference the callback kept must not reach the
	// published index.
	retained["subjects"] = []any{map[string]any{"kind": "ServiceAccount", "name": "injected", "namespace": "app"}}

	_, obj, _ := edited.Entry("RoleBinding", "app", "creator")
	subjects, _ := obj["subjects"].([]any)
	if len(subjects) != 0 {
		t.Errorf("the callback reference changed the published index: %v", subjects)
	}
	_, original, _ := ix.Entry("RoleBinding", "app", "creator")
	originalSubjects, _ := original["subjects"].([]any)
	if len(originalSubjects) != 1 {
		t.Errorf("the receiver holds %d subjects, want the fixture's one", len(originalSubjects))
	}
}

func TestEditedNeverPublishesSecretContent(t *testing.T) {
	ix := New()
	addRaw(t, ix, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"token","namespace":"app"},
		"type":"Opaque","data":{"ca.crt":"c2VjcmV0"}}`)

	edited, err := ix.Edited("Secret", "app", "token", func(obj map[string]any) error {
		// A callback that tries to write content must not be able to put it in
		// the index, exactly as Add cannot.
		obj["data"] = map[string]any{"injected": "c2VjcmV0"}
		obj["stringData"] = map[string]any{"also-injected": "PLAINTEXT"}
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
	// Values never survive: the reconstruction keeps key names only.
	for _, secret := range []string{"c2VjcmV0", "PLAINTEXT"} {
		if strings.Contains(string(canonical), secret) {
			t.Errorf("the edited Secret carries the value %q: %s", secret, canonical)
		}
	}
	for _, field := range SecretContentKeys {
		if _, present := obj[field]; present {
			t.Errorf("the edited Secret kept a %s field: %s", field, canonical)
		}
	}
	var decoded struct {
		DataKeys []string `json:"dataKeys"`
	}
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.DataKeys) != 2 || decoded.DataKeys[0] != "also-injected" || decoded.DataKeys[1] != "injected" {
		t.Errorf("dataKeys = %v, want the sorted names of the edited keys and nothing else", decoded.DataKeys)
	}
}
