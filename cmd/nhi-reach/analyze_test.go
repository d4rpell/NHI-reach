package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/graph"
)

// goldenEnv regenerates the golden files instead of comparing them. It is an
// environment variable, not a flag, so that `go test ./...` never has to know it.
const goldenEnv = "NHI_REACH_UPDATE_GOLDEN"

const fixtureRoot = "../../testdata/light"

func baseOptions() analyzeOptions {
	return analyzeOptions{
		output:       "table",
		maxDepth:     graph.DefaultMaxDepth,
		pathsPerPair: graph.DefaultPathsPerPair,
		targets:      []string{targetClusterAdmin},
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

func TestAnalyzeJSONGolden(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.output = "json"

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	checkGolden(t, "hit.json", got)

	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if version, _ := decoded["schema_version"].(float64); int(version) != 1 {
		t.Errorf("schema_version is %v, want 1", decoded["schema_version"])
	}
	for _, leak := range []string{"c3VwZXItc2VjcmV0LWRvY2tlcmNvbmZpZw==", "PLAINTEXT-BACKUP-TOKEN"} {
		if strings.Contains(got, leak) {
			t.Errorf("JSON report leaks secret material %q", leak)
		}
	}
}

func TestAnalyzeSingleOriginHasOnlyThatOrigin(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.fromIdentity = "app/deployer"

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	checkGolden(t, "from-identity.txt", got)

	// --from-identity restricts the origin: every row is that identity, and no
	// other ServiceAccount of the snapshot appears as an origin. It may still
	// list several paths, because the enumeration keeps up to --paths-per-pair.
	for _, line := range strings.Split(got, "\n") {
		if line == "" || strings.HasPrefix(line, "target:") || strings.HasPrefix(line, "SOURCE") {
			continue
		}
		if strings.HasPrefix(line, "gaps:") {
			break
		}
		if !strings.HasPrefix(line, "app/deployer") {
			t.Errorf("a row has an origin other than the requested one:\n%s", line)
		}
	}
	if !strings.Contains(got, "app/deployer") {
		t.Errorf("the requested origin produced no path:\n%s", got)
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

func TestAnalyzeSecretsTarget(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "secrets")
	opts.targets = []string{targetSecrets}

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	checkGolden(t, "secrets.txt", got)

	// reader: get/list secrets cluster-scoped, no resourceNames -> edge.
	if !strings.Contains(got, "app/reader") {
		t.Errorf("an unrestricted read of a sensitive namespace did not reach secrets:\n%s", got)
	}
	// named-cluster: resourceNames restricted, the Secret exists in kube-system -> edge.
	if !strings.Contains(got, "app/named-cluster") {
		t.Errorf("a resourceNames read backed by an existing sensitive Secret did not reach secrets:\n%s", got)
	}
	// named-app: resourceNames restricted in namespace app, the Secret only
	// exists in kube-system -> no edge (name, namespace and scope must coincide).
	if strings.Contains(got, "app/named-app") {
		t.Errorf("a resourceNames read whose Secret is in another namespace reached secrets:\n%s", got)
	}
	if strings.Contains(got, "UExBSU5URVhULVNFQ1JFVA==") {
		t.Errorf("the secrets report leaks secret content:\n%s", got)
	}
}

func TestAnalyzeSecretsTargetUnrestrictedWithoutSecrets(t *testing.T) {
	// A snapshot with no Secrets still shows an unrestricted read capability:
	// the absence of observed objects does not remove a permission.
	dir := filepath.Join(t.TempDir(), "snap")
	shuffledCopy(t, filepath.Join(fixtureRoot, "miss"), dir, false)
	writeFixture(t, dir, "clusterroles.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[
		{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"secret-reader"},
		 "rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}]}`)
	writeFixture(t, dir, "clusterrolebindings.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[
		{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"reader"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"secret-reader"},
		 "subjects":[{"kind":"ServiceAccount","name":"ops-admin","namespace":"app"}]}]}`)

	opts := baseOptions()
	opts.fromDir = dir
	opts.targets = []string{targetSecrets}
	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !strings.Contains(got, "app/ops-admin") {
		t.Errorf("an unrestricted read was dropped because the snapshot holds no Secrets:\n%s", got)
	}
}

func TestAnalyzeNodeTargetIsAGap(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.targets = []string{targetNode}

	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !strings.Contains(got, "target:node") || !strings.Contains(got, "not evaluated") {
		t.Errorf("the node target is not reported as a gap:\n%s", got)
	}
	if strings.Contains(got, "cluster-admin") {
		t.Errorf("a node-only run reported cluster-admin paths:\n%s", got)
	}
}

func TestAnalyzeFailOnAnyExitsWith2(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.failOn = "any"

	got, err := run(t, opts)
	if err == nil {
		t.Fatal("--fail-on any did not fail on a snapshot with paths")
	}
	if code := exitCode(err); code != 2 {
		t.Errorf("exit code %d, want 2: %v", code, err)
	}
	if !strings.Contains(got, "app/deployer") {
		t.Errorf("the report was not written before failing:\n%s", got)
	}
}

func TestAnalyzeFailOnAnyWithoutPathsExitsWith0(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "miss")
	opts.failOn = "any"

	if _, err := run(t, opts); err != nil {
		t.Fatalf("--fail-on any failed without paths: %v", err)
	}
}

func TestAnalyzeOutWritesFile(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.output = "json"
	opts.outFile = filepath.Join(t.TempDir(), "report.json")

	var buf bytes.Buffer
	if err := runAnalyze(&buf, opts); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("--out also wrote to stdout: %q", buf.String())
	}
	data, err := os.ReadFile(opts.outFile)
	if err != nil {
		t.Fatalf("read --out file: %v", err)
	}
	if !strings.Contains(string(data), `"schema_version": 1`) {
		t.Errorf("--out file is not the JSON report:\n%s", data)
	}
}

func TestAnalyzeOutWriteFailureExitsWith1(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.outFile = filepath.Join(t.TempDir(), "missing", "report.txt")

	_, err := run(t, opts)
	if err == nil {
		t.Fatal("analyze accepted an unwritable --out path")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code %d, want 1: %v", code, err)
	}
}

func TestAnalyzeIsDeterministicAcrossItemOrder(t *testing.T) {
	for _, output := range []string{"table", "json"} {
		t.Run(output, func(t *testing.T) {
			first := filepath.Join(t.TempDir(), "first")
			second := filepath.Join(t.TempDir(), "second")
			shuffledCopy(t, filepath.Join(fixtureRoot, "hit"), first, false)
			shuffledCopy(t, filepath.Join(fixtureRoot, "hit"), second, true)

			opts := baseOptions()
			opts.output = output
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
				t.Errorf("%s output depends on input order\n--- first ---\n%s\n--- second ---\n%s", output, firstOut, secondOut)
			}
		})
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
		{"unknown output", func(o *analyzeOptions) { o.fromDir = hit; o.output = "yaml" }},
		{"html output", func(o *analyzeOptions) { o.fromDir = hit; o.output = "html" }},
		{"--max-depth 0", func(o *analyzeOptions) { o.fromDir = hit; o.maxDepth = 0 }},
		{"--paths-per-pair 0", func(o *analyzeOptions) { o.fromDir = hit; o.pathsPerPair = 0 }},
		{"--fail-on bogus", func(o *analyzeOptions) { o.fromDir = hit; o.failOn = "maybe" }},
		{"unknown target", func(o *analyzeOptions) { o.fromDir = hit; o.targets = []string{"bogus"} }},
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

func TestAnalyzeSensitiveNamespaceExtendsDefaults(t *testing.T) {
	// A namespaced read in a namespace added with --sensitive-ns reaches the
	// secrets goal, and the default sensitive list is still in effect.
	dir := filepath.Join(t.TempDir(), "snap")
	shuffledCopy(t, filepath.Join(fixtureRoot, "miss"), dir, false)
	writeFixture(t, dir, "roles.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[
		{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"reader","namespace":"vault"},
		 "rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}]}`)
	writeFixture(t, dir, "rolebindings.json", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"List","items":[
		{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"reader","namespace":"vault"},
		 "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},
		 "subjects":[{"kind":"ServiceAccount","name":"ops-admin","namespace":"app"}]}]}`)

	opts := baseOptions()
	opts.fromDir = dir
	opts.targets = []string{targetSecrets}
	got, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if strings.Contains(got, "app/ops-admin") {
		t.Errorf("a read in a non-sensitive namespace reached secrets:\n%s", got)
	}

	opts.sensitiveNS = "vault"
	got, err = run(t, opts)
	if err != nil {
		t.Fatalf("analyze --sensitive-ns: %v", err)
	}
	if !strings.Contains(got, "app/ops-admin") {
		t.Errorf("--sensitive-ns did not extend the sensitive list:\n%s", got)
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
	if !strings.Contains(got, "system origins:") {
		t.Errorf("--include-system did not group the system origin apart:\n%s", got)
	}
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// failingWriter fails on its first write, so a render error can be observed.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

var errWriteFailed = errors.New("write failed")

func TestAnalyzeRenderFailureExitsWith1EvenWithFailOnAny(t *testing.T) {
	// The report could not be emitted, so the run is an unclassified failure
	// (exit 1), not the finding exit code (2): there is no report to be
	// non-zero about.
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.failOn = "any"

	err := runAnalyze(failingWriter{}, opts)
	if err == nil {
		t.Fatal("a render failure returned no error")
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exit code %d, want 1: %v", code, err)
	}
}
