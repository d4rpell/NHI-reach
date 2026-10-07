package hops

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogYAML []byte

// CatalogEntry is one hop of the catalog. Its fields mirror the YAML format of
// spec §2.4 exactly: an entry carrying any other key is rejected when the
// catalog is parsed.
type CatalogEntry struct {
	ID           string `yaml:"id"`
	Title        string `yaml:"title"`
	Reference    string `yaml:"reference"`
	TargetEffect string `yaml:"target_effect"`
	Status       string `yaml:"status"`
	Rationale    string `yaml:"rationale"`
	Remediation  string `yaml:"remediation"`
}

// catalogEffects and catalogStatuses are the values spec §2.4 admits.
var (
	catalogEffects  = []string{"identity", "workload", "target"}
	catalogStatuses = []string{"enabled", "experimental"}
)

// Catalog returns the embedded hop catalog, ordered by id. The file is data of
// the binary; an entry that does not satisfy spec §2.4 is an error, never a
// silent skip.
func Catalog() ([]CatalogEntry, error) {
	return parseCatalog(catalogYAML)
}

// CatalogSHA256 is the hex SHA-256 of the embedded catalog bytes. It identifies
// the exact catalog a report was produced from and, unlike the link-time
// version.CatalogHash, it is computed from the same bytes the binary runs, so it
// is never "unknown" and never depends on how the binary was built.
func CatalogSHA256() string {
	sum := sha256.Sum256(catalogYAML)
	return hex.EncodeToString(sum[:])
}

// parseCatalog decodes and validates a catalog document. It is separate from
// Catalog so the rules can be tested against crafted bytes.
func parseCatalog(data []byte) ([]CatalogEntry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var entries []CatalogEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("parse hop catalog: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("hop catalog holds more than one YAML document")
		}
		return nil, fmt.Errorf("parse hop catalog: %w", err)
	}

	seen := map[string]bool{}
	for _, entry := range entries {
		if err := entry.validate(); err != nil {
			return nil, err
		}
		if seen[entry.ID] {
			return nil, fmt.Errorf("hop catalog has duplicate id %q", entry.ID)
		}
		seen[entry.ID] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

func (e CatalogEntry) validate() error {
	fields := []struct{ name, value string }{
		{"id", e.ID},
		{"title", e.Title},
		{"reference", e.Reference},
		{"target_effect", e.TargetEffect},
		{"status", e.Status},
		{"rationale", e.Rationale},
		{"remediation", e.Remediation},
	}
	for _, field := range fields {
		if field.value == "" {
			return fmt.Errorf("hop catalog entry %q has an empty %s", e.ID, field.name)
		}
	}
	if !containsValue(catalogEffects, e.TargetEffect) {
		return fmt.Errorf("hop %s has target_effect %q, want one of %v", e.ID, e.TargetEffect, catalogEffects)
	}
	if !containsValue(catalogStatuses, e.Status) {
		return fmt.Errorf("hop %s has status %q, want one of %v", e.ID, e.Status, catalogStatuses)
	}
	if !strings.HasPrefix(e.Reference, "https://") || strings.HasSuffix(e.Reference, "#") {
		return fmt.Errorf("hop %s reference %q is not an anchored https URL", e.ID, e.Reference)
	}
	if _, fragment, ok := strings.Cut(e.Reference, "#"); !ok || fragment == "" {
		return fmt.Errorf("hop %s reference %q has no fragment", e.ID, e.Reference)
	}
	return nil
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
