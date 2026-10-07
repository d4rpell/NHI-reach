package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestRulesGolden pins the `rules` output byte for byte; the catalog is static,
// so the same build always renders the same table.
func TestRulesGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := runRules(&buf); err != nil {
		t.Fatalf("rules: %v", err)
	}
	path := filepath.Join("testdata", "golden", "rules.txt")
	if os.Getenv(goldenEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with: %s=1 go test ./cmd/nhi-reach)", path, err, goldenEnv)
	}
	if buf.String() != string(want) {
		t.Errorf("rules output differs from golden\n--- got ---\n%s\n--- want ---\n%s", buf.String(), want)
	}
}

// TestRulesListsEveryEnabledHop keeps the command honest: each catalog entry
// appears with its id, and the table is not empty.
func TestRulesListsEveryEnabledHop(t *testing.T) {
	var buf bytes.Buffer
	if err := runRules(&buf); err != nil {
		t.Fatalf("rules: %v", err)
	}
	out := buf.String()
	for _, id := range []string{"NR-001", "NR-002", "NR-003", "NR-004", "NR-005", "NR-006"} {
		if !bytes.Contains([]byte(out), []byte(id)) {
			t.Errorf("rules output does not list %s:\n%s", id, out)
		}
	}
	if !bytes.Contains([]byte(out), []byte("REFERENCE")) {
		t.Errorf("rules output has no header:\n%s", out)
	}
}
