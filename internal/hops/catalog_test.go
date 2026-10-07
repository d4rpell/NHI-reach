package hops

import (
	"sort"
	"strings"
	"testing"
)

// validEntry is a complete, valid catalog entry; tests mutate one field at a
// time to check the validation rules.
const validEntry = `
- id: NR-900
  title: "Title"
  reference: "https://kubernetes.io/docs/x/#anchor"
  target_effect: identity
  status: enabled
  rationale: "why"
  remediation: "how"
`

func TestParseCatalogAcceptsValidEntry(t *testing.T) {
	entries, err := parseCatalog([]byte(validEntry))
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "NR-900" {
		t.Fatalf("parsed %+v, want the single NR-900 entry", entries)
	}
}

func TestParseCatalogRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"unknown key", strings.Replace(validEntry, "  remediation:", "  notes: \"x\"\n  remediation:", 1)},
		{"duplicate key", strings.Replace(validEntry, `  title: "Title"`, "  title: \"One\"\n  title: \"Two\"", 1)},
		{"empty field", strings.Replace(validEntry, `  title: "Title"`, `  title: ""`, 1)},
		{"missing field", strings.Replace(validEntry, `  remediation: "how"`, "", 1)},
		{"bad status", strings.Replace(validEntry, "status: enabled", "status: maybe", 1)},
		{"bad effect", strings.Replace(validEntry, "target_effect: identity", "target_effect: admin", 1)},
		{"reference not https", strings.Replace(validEntry, `"https://kubernetes.io/docs/x/#anchor"`, `"http://k8s.io/#a"`, 1)},
		{"reference without fragment", strings.Replace(validEntry, `"https://kubernetes.io/docs/x/#anchor"`, `"https://kubernetes.io/docs/x/"`, 1)},
		{"reference with empty fragment", strings.Replace(validEntry, `"https://kubernetes.io/docs/x/#anchor"`, `"https://kubernetes.io/docs/x/#"`, 1)},
		{"duplicate id", validEntry + strings.Replace(validEntry, "NR-900", "NR-900", 1)},
		{"second document", validEntry + "\n---\n" + strings.Replace(validEntry, "NR-900", "NR-901", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCatalog([]byte(tc.data)); err == nil {
				t.Fatal("parseCatalog accepted malformed input")
			}
		})
	}
}

func TestCatalogHoldsTheApprovedEntries(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	want := []string{"NR-001", "NR-002", "NR-003", "NR-004", "NR-005", "NR-006"}
	var got []string
	for _, entry := range catalog {
		got = append(got, entry.ID)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog ids are %v, want %v", got, want)
	}
}

// TestEnabledHopsMatchBuilders is the guard T1-03 anticipated: the enabled
// catalog entries and the implemented hop builders must be the same set, in
// both directions.
func TestEnabledHopsMatchBuilders(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	var fromCatalog []string
	for _, entry := range catalog {
		if entry.Status == "enabled" {
			fromCatalog = append(fromCatalog, entry.ID)
		}
	}
	var fromBuilders []string
	for _, b := range builders {
		fromBuilders = append(fromBuilders, b.id)
	}
	sort.Strings(fromCatalog)
	sort.Strings(fromBuilders)
	if strings.Join(fromCatalog, ",") != strings.Join(fromBuilders, ",") {
		t.Fatalf("enabled hops %v do not match builders %v", fromCatalog, fromBuilders)
	}
}
