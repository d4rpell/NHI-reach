package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenEnv regenerates the golden files instead of comparing them. It is an
// environment variable, not a flag, so that `go test ./...` never has to know it.
const goldenEnv = "NHI_REACH_UPDATE_GOLDEN"

const fixtureRoot = "../../testdata/light"

func baseOptions() analyzeOptions {
	return analyzeOptions{
		output:       "table",
		maxDepth:     4,
		pathsPerPair: 3,
		targets:      []string{evaluatedTarget},
		failOn:       "none",
	}
}

func run(t *testing.T, opts analyzeOptions) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := runAnalyze(&buf, opts)
	return buf.String(), err
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if os.Getenv(goldenEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with: %s=1 go test ./cmd/nhi-reach)", path, err, goldenEnv)
	}
	if got != string(want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestAnalyzeFixtureWithPaths(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	checkGolden(t, "hit.txt", got)

	for _, secret := range []string{
		"c3VwZXItc2VjcmV0LWRvY2tlcmNvbmZpZw==",
		"PLAINTEXT-BACKUP-TOKEN",
		".dockerconfigjson",
		"backup-token",
	} {
		if strings.Contains(got, secret) {
			t.Errorf("report leaks secret material %q:\n%s", secret, got)
		}
	}
	for _, want := range []string{"app/deployer", "app/ops-admin", "NR-001", "rbac-cluster-admin"} {
		if !strings.Contains(got, want) {
			t.Errorf("report does not mention %q:\n%s", want, got)
		}
	}
}

func TestAnalyzeSingleOriginHasOnePath(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.fromIdentity = "app/deployer"

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	checkGolden(t, "from-identity.txt", got)

	rows := 0
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "app/deployer") {
			rows++
		}
	}
	if rows != 1 {
		t.Errorf("got %d paths for a single origin, want 1:\n%s", rows, got)
	}
}

func TestAnalyzeFixtureWithoutPaths(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "miss")

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	checkGolden(t, "miss.txt", got)
	if !strings.Contains(got, "no escalation paths found") {
		t.Errorf("empty result is not stated:\n%s", got)
	}
}

func TestAnalyzeIsDeterministicAcrossItemOrder(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	shuffledCopy(t, filepath.Join(fixtureRoot, "hit"), first, false)
	shuffledCopy(t, filepath.Join(fixtureRoot, "hit"), second, true)

	opts := baseOptions()
	opts.fromDir = first
	firstOut, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze first: %v", err)
	}
	opts.fromDir = second
	secondOut, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze second: %v", err)
	}
	if firstOut != secondOut {
		t.Errorf("output depends on input order\n--- first ---\n%s\n--- second ---\n%s", firstOut, secondOut)
	}
}

// shuffledCopy copies every JSON file of src into dst, reversing the items of
// each list when reverse is true.
func shuffledCopy(t *testing.T, src, dst string, reverse bool) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(src, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]any
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatal(err)
		}
		if items, ok := top["items"].([]any); ok && reverse {
			for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
				items[i], items[j] = items[j], items[i]
			}
		}
		out, err := json.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, entry.Name()), out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalyzeInputErrorsExitWith3(t *testing.T) {
	hit := filepath.Join(fixtureRoot, "hit")

	cases := []struct {
		name   string
		modify func(*analyzeOptions)
	}{
		{"live", func(o *analyzeOptions) { o.live = true; o.fromDir = hit }},
		{"no --from", func(o *analyzeOptions) {}},
		{"json output", func(o *analyzeOptions) { o.fromDir = hit; o.output = "json" }},
		{"--out", func(o *analyzeOptions) { o.fromDir = hit; o.outFile = "report.txt" }},
		{"--paths-per-pair", func(o *analyzeOptions) { o.fromDir = hit; o.pathsPerPair = 1 }},
		{"--sensitive-ns", func(o *analyzeOptions) { o.fromDir = hit; o.sensitiveNS = "kube-system" }},
		{"--fail-on any", func(o *analyzeOptions) { o.fromDir = hit; o.failOn = "any" }},
		{"--max-depth 0", func(o *analyzeOptions) { o.fromDir = hit; o.maxDepth = 0 }},
		{"unknown target", func(o *analyzeOptions) { o.fromDir = hit; o.targets = []string{"bogus"} }},
		{"target node", func(o *analyzeOptions) { o.fromDir = hit; o.targets = []string{"node"} }},
		{"target secrets", func(o *analyzeOptions) { o.fromDir = hit; o.targets = []string{"secrets"} }},
		{"target node and cluster-admin", func(o *analyzeOptions) { o.fromDir = hit; o.targets = []string{"cluster-admin", "node"} }},
		{"empty target list", func(o *analyzeOptions) { o.fromDir = hit; o.targets = []string{} }},
		{"--from-identity without namespace", func(o *analyzeOptions) { o.fromDir = hit; o.fromIdentity = "deployer" }},
		{"--from-identity missing", func(o *analyzeOptions) { o.fromDir = hit; o.fromIdentity = "app/nobody" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := baseOptions()
			tc.modify(&opts)
			if _, err := run(t, opts); err == nil {
				t.Fatal("analyze accepted unsupported input")
			} else if code := exitCode(err); code != 3 {
				t.Errorf("exit code %d, want 3: %v", code, err)
			}
		})
	}
}

func TestAnalyzeMissingRequiredTypeExitsWith3(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "namespaces.json"),
		[]byte(`{"apiVersion":"v1","kind":"List","items":[]}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	opts := baseOptions()
	opts.fromDir = dir
	_, err = run(t, opts)
	if err == nil {
		t.Fatal("analyze accepted a snapshot without required types")
	}
	if code := exitCode(err); code != 3 {
		t.Errorf("exit code %d, want 3: %v", code, err)
	}
	if !strings.Contains(err.Error(), "ServiceAccount") {
		t.Errorf("error does not list the missing types: %v", err)
	}
}

func TestAnalyzeSystemOriginsExcludedUnlessRequested(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	shuffledCopy(t, filepath.Join(fixtureRoot, "hit"), dir, false)
	writeFixture(t, dir, "serviceaccounts.json", `{"apiVersion":"v1","kind":"List","items":[
		{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"system-admin","namespace":"kube-system"}}]}`)
	writeFixture(t, dir, "clusterrolebindings.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[
		{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"system-admin"},
		"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
		"subjects":[{"kind":"ServiceAccount","name":"system-admin","namespace":"kube-system"}]}]}`)
	writeFixture(t, dir, "roles.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[]}`)
	writeFixture(t, dir, "rolebindings.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[]}`)

	opts := baseOptions()
	opts.fromDir = dir
	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if strings.Contains(got, "kube-system/system-admin") {
		t.Errorf("a system identity was used as origin by default:\n%s", got)
	}

	opts.includeSystem = true
	got, err = run(t, opts)
	if err != nil {
		t.Fatalf("analyze --include-system: %v", err)
	}
	if !strings.Contains(got, "kube-system/system-admin") {
		t.Errorf("--include-system did not add the system origin:\n%s", got)
	}
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
