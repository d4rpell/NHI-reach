package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/d4rpell/nhi-reach/internal/version"
)

// MetadataSchema identifies the metadata.json format written next to a snapshot.
const MetadataSchema = "nhi-reach/snapshot-metadata/v1"

// Metadata is the provenance of a written snapshot: what the tool wrote, when,
// against which context and server, and the hash of every data file it wrote.
// It is additive to the frozen manifest contract of T1-01 (Manifest, unchanged).
type Metadata struct {
	Schema         string         `json:"schema"`
	ToolVersion    string         `json:"tool_version"`
	ToolCommit     string         `json:"tool_commit"`
	Date           string         `json:"date"`
	Context        string         `json:"context"`
	ServerVersion  string         `json:"server_version"`
	ManifestSHA256 string         `json:"input_manifest_sha256"`
	Files          []MetadataFile `json:"files"`
}

// MetadataFile is the hash of the bytes of one written data file.
type MetadataFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// WriteSnapshot writes the reduced objects of the index into dir as one JSON
// list file per kind, plus manifest.json and metadata.json, and then verifies
// what it wrote.
//
// The caller must pass a directory that does not exist or is empty: a snapshot
// never overwrites or merges into an existing one, so a file of a previous
// capture cannot survive into a new one. Nothing of the index is written
// verbatim: only the reduced representation reaches disk, so no Secret value and
// no volatile field is ever persisted. The hashes of metadata.json cover the
// bytes actually written, so they do not incorporate anything discarded.
func WriteSnapshot(dir string, ix *Index, meta Metadata) error {
	if err := ensureEmptyDir(dir); err != nil {
		return err
	}

	kinds := ix.kinds()
	written := make([]MetadataFile, 0, len(kinds))
	for _, kind := range kinds {
		name := pluralOf(kind) + ".json"
		items := ix.objectsOf(kind)
		if kind == "Secret" {
			for i := range items {
				items[i] = secretForDisk(items[i])
			}
		}
		payload := struct {
			APIVersion string           `json:"apiVersion"`
			Kind       string           `json:"kind"`
			Items      []map[string]any `json:"items"`
		}{
			APIVersion: ListAPIVersion(kind),
			Kind:       "List",
			Items:      items,
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("encode %s: %w", name, err)
		}
		data = append(data, '\n')
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		written = append(written, MetadataFile{Name: name, SHA256: hex.EncodeToString(sum[:])})
	}

	manifest := ix.Manifest()
	if err := manifest.WriteFile(dir); err != nil {
		return err
	}
	sort.Slice(written, func(i, j int) bool { return written[i].Name < written[j].Name })

	meta.Schema = MetadataSchema
	if meta.ToolVersion == "" {
		meta.ToolVersion = version.Version
	}
	if meta.ToolCommit == "" {
		meta.ToolCommit = version.Commit
	}
	if meta.Date == "" {
		meta.Date = time.Now().UTC().Format(time.RFC3339)
	}
	meta.ManifestSHA256 = manifest.SHA256
	meta.Files = written
	if err := writeMetadata(dir, meta); err != nil {
		return err
	}

	return VerifySnapshot(dir)
}

// ValidateOutputDir checks that dir can receive a snapshot: it must not exist or
// be empty. It is the input check the command runs before contacting the API, so
// a bad destination fails as an input error (exit 3) and never leaves a cluster
// query half-done. WriteSnapshot repeats it as a guard.
func ValidateOutputDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("read output directory: %w", err)
	case len(entries) > 0:
		return fmt.Errorf("output directory %q is not empty; refusing to mix snapshots", dir)
	}
	return nil
}

// ensureEmptyDir creates dir when absent and rejects it when it already holds
// anything, so a capture is never mixed with a previous one.
func ensureEmptyDir(dir string) error {
	if err := ValidateOutputDir(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o755)
}

func writeMetadata(dir string, meta Metadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode metadata.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write metadata.json: %w", err)
	}
	return nil
}

// secretForDisk turns the index representation of a Secret (which keeps key
// names in dataKeys, not in data) into the shape a snapshot file uses, so that
// reading it back rebuilds the same key names and the same hash.
//
// The reduced representation keeps key names in dataKeys; the file format,
// however, is a Kubernetes list, and the loader always recomputes key names from
// data/stringData and ignores a supplied dataKeys (the accepted rule: never trust
// a list coming from the input). So the writer materializes each key name under
// data with an empty value. That is metadata, not content: the names were already
// part of the reduced form and no secret value is written, only an empty
// placeholder per name. A Secret without keys writes an empty data map.
func secretForDisk(item map[string]any) map[string]any {
	keys, _ := item["dataKeys"].([]string)
	out := make(map[string]any, len(item)+1)
	for k, v := range item {
		if k == "dataKeys" {
			continue
		}
		out[k] = v
	}
	if len(keys) > 0 {
		data := make(map[string]any, len(keys))
		for _, key := range keys {
			data[key] = ""
		}
		out["data"] = data
	}
	return out
}

// VerifySnapshot re-reads a directory this tool wrote and checks it against its
// own artifacts.
//
// It compares the manifest persisted on disk with the one rebuilt from the data
// files, checks the file inventory and the hash of every data file declared in
// metadata.json, and requires that no other file is present. Re-reading with
// Load alone would not catch a tampered manifest.json, because Load ignores it;
// the explicit comparison against the file on disk is what closes that hole.
func VerifySnapshot(dir string) error {
	ix, err := Load(dir)
	if err != nil {
		return fmt.Errorf("verify snapshot: %w", err)
	}
	rebuilt := ix.Manifest()

	stored, err := readManifest(dir)
	if err != nil {
		return fmt.Errorf("verify snapshot: %w", err)
	}
	if stored.Schema != ManifestSchema {
		return fmt.Errorf("verify snapshot: manifest schema is %q, want %q", stored.Schema, ManifestSchema)
	}
	if stored.SHA256 != rebuilt.SHA256 || !sameObjects(stored.Objects, rebuilt.Objects) {
		return fmt.Errorf("verify snapshot: manifest.json does not match the data files")
	}

	meta, err := readMetadata(dir)
	if err != nil {
		return fmt.Errorf("verify snapshot: %w", err)
	}
	if meta.ManifestSHA256 != rebuilt.SHA256 {
		return fmt.Errorf("verify snapshot: metadata.json names manifest %s, want %s", meta.ManifestSHA256, rebuilt.SHA256)
	}

	onDisk, err := dataFiles(dir)
	if err != nil {
		return fmt.Errorf("verify snapshot: %w", err)
	}
	if len(onDisk) != len(meta.Files) {
		return fmt.Errorf("verify snapshot: found %d data files, metadata.json declares %d", len(onDisk), len(meta.Files))
	}
	for i, file := range meta.Files {
		if onDisk[i] != file.Name {
			return fmt.Errorf("verify snapshot: data file %q is not the declared %q", onDisk[i], file.Name)
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name))
		if err != nil {
			return fmt.Errorf("verify snapshot: read %s: %w", file.Name, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != file.SHA256 {
			return fmt.Errorf("verify snapshot: %s hashes to %s, metadata.json declares %s", file.Name, got, file.SHA256)
		}
	}
	return nil
}

func readManifest(dir string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return manifest, fmt.Errorf("read manifest.json: %w", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("decode manifest.json: %w", err)
	}
	return manifest, nil
}

func readMetadata(dir string) (Metadata, error) {
	var meta Metadata
	data, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return meta, fmt.Errorf("read metadata.json: %w", err)
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, fmt.Errorf("decode metadata.json: %w", err)
	}
	if meta.Schema != MetadataSchema {
		return meta, fmt.Errorf("metadata.json schema is %q, want %q", meta.Schema, MetadataSchema)
	}
	return meta, nil
}

// dataFiles returns the sorted names of the snapshot's data files: every .json
// that is not manifest.json or metadata.json.
func dataFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" || name == "manifest.json" || name == "metadata.json" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func sameObjects(a, b []SnapshotObject) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// kinds returns the kinds the snapshot provided, ordered by name. It is driven
// by presence, not by the objects held: a type listed as an empty collection is
// still part of the snapshot and must be written, or re-reading it would report
// the type as missing.
func (ix *Index) kinds() []string {
	out := make([]string, 0, len(ix.present))
	for kind := range ix.present {
		out = append(out, kind)
	}
	sort.Strings(out)
	return out
}

// objectsOf returns the reduced objects of one kind, ordered by (namespace,
// name): the deterministic order WriteSnapshot writes and the one the index
// lists.
func (ix *Index) objectsOf(kind string) []map[string]any {
	refs := ix.List(kind, "")
	out := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		if _, raw, ok := ix.Entry(kind, ref.Namespace, ref.Name); ok {
			out = append(out, raw)
		}
	}
	return out
}
