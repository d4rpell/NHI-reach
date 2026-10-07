package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSnapshotWritesAndVerifies drives the snapshot command against a fake API
// served by a local test server, using a synthetic kubeconfig, and asserts the
// directory it wrote verifies and carries no secret value.
func TestSnapshotWritesAndVerifies(t *testing.T) {
	const decoy = "SNAPSHOT-SECRET-DECOY"
	server := newLiveAPIServer(t, decoy)
	ts := newTestServer(t, server)
	defer ts.Close()

	kubeconfig := writeKubeconfig(t, ts.URL)
	outDir := filepath.Join(t.TempDir(), "capture")

	var buf bytes.Buffer
	if err := runSnapshot(context.Background(), &buf, outDir, kubeconfig, ""); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !strings.Contains(buf.String(), "snapshot_sha256:") {
		t.Errorf("snapshot did not print the snapshot hash: %q", buf.String())
	}
	for _, name := range []string{"manifest.json", "metadata.json", "serviceaccounts.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
	leaks := grepDir(t, outDir, decoy)
	if len(leaks) != 0 {
		t.Errorf("a secret value reached disk in %v", leaks)
	}
}

func TestSnapshotRejectsNonEmptyOutput(t *testing.T) {
	server := newLiveAPIServer(t, "value")
	ts := newTestServer(t, server)
	defer ts.Close()
	kubeconfig := writeKubeconfig(t, ts.URL)

	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "old.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runSnapshot(context.Background(), &bytes.Buffer{}, outDir, kubeconfig, "")
	if err == nil {
		t.Fatal("snapshot wrote into a non-empty directory")
	}
	if code := exitCode(err); code != 3 {
		t.Errorf("exit code %d, want 3: %v", code, err)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "old.json")); statErr != nil {
		t.Error("the previous content was not left intact")
	}
}

func TestSnapshotBadKubeconfigExitsWith3(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "capture")
	err := runSnapshot(context.Background(), &bytes.Buffer{}, outDir, filepath.Join(t.TempDir(), "absent"), "")
	if err == nil {
		t.Fatal("snapshot accepted an absent kubeconfig")
	}
	if code := exitCode(err); code != 3 {
		t.Errorf("exit code %d, want 3: %v", code, err)
	}
}

func TestAnalyzeLiveRunsEndToEnd(t *testing.T) {
	server := newLiveAPIServer(t, "value")
	ts := newTestServer(t, server)
	defer ts.Close()
	kubeconfig := writeKubeconfig(t, ts.URL)

	opts := baseOptions()
	opts.live = true
	opts.kubeconfig = kubeconfig
	out, err := run(t, opts)
	if err != nil {
		t.Fatalf("analyze --live: %v", err)
	}
	if strings.Contains(out, "not supported") {
		t.Fatalf("--live still reports not supported: %s", out)
	}
	if bad := server.sawNonRead(); len(bad) != 0 {
		t.Fatalf("the live client issued non-read methods: %v", bad)
	}
}

func TestAnalyzeLiveAndFromAreMutuallyExclusive(t *testing.T) {
	opts := baseOptions()
	opts.live = true
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	if _, err := run(t, opts); err == nil {
		t.Fatal("analyze accepted --live together with --from")
	} else if code := exitCode(err); code != 3 {
		t.Errorf("exit code %d, want 3: %v", code, err)
	}
}

func TestAnalyzeWithoutAnySourceExitsWith3(t *testing.T) {
	opts := baseOptions()
	if _, err := run(t, opts); err == nil {
		t.Fatal("analyze accepted neither --from nor --live")
	} else if code := exitCode(err); code != 3 {
		t.Errorf("exit code %d, want 3: %v", code, err)
	}
}

func TestAnalyzeKubeconfigFlagsOnlyApplyToLive(t *testing.T) {
	opts := baseOptions()
	opts.fromDir = filepath.Join(fixtureRoot, "hit")
	opts.kubeconfig = "somewhere"
	if _, err := run(t, opts); err == nil {
		t.Fatal("analyze accepted --kubeconfig without --live")
	} else if code := exitCode(err); code != 3 {
		t.Errorf("exit code %d, want 3: %v", code, err)
	}
}

// --- helpers --------------------------------------------------------------

// apiRecorder is a test API server that records the methods it receives, so a
// test can assert the client only issued reads.
type apiRecorder struct {
	inner   http.Handler
	methods []string
}

func (s *apiRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.methods = append(s.methods, r.Method)
	s.inner.ServeHTTP(w, r)
}

func (s *apiRecorder) sawNonRead() []string {
	var bad []string
	for _, method := range s.methods {
		if method != http.MethodGet {
			bad = append(bad, method)
		}
	}
	return bad
}

// newLiveAPIServer serves the discovery and list endpoints of the required types
// (plus Pods and a Secret) so the live path runs end to end. secretValue overrides
// the Secret payload to a decoy a test can look for on disk.
func newLiveAPIServer(t *testing.T, secretValue string) *apiRecorder {
	t.Helper()
	return &apiRecorder{inner: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case path == "/version":
			writeBody(w, `{"gitVersion":"v1.32.0"}`)
		case path == "/api/v1":
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[
				{"name":"namespaces","namespaced":false,"kind":"Namespace","verbs":["get","list"]},
				{"name":"serviceaccounts","namespaced":true,"kind":"ServiceAccount","verbs":["get","list"]},
				{"name":"pods","namespaced":true,"kind":"Pod","verbs":["get","list"]},
				{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["get","list"]}]}`)
		case path == "/apis/rbac.authorization.k8s.io/v1":
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"rbac.authorization.k8s.io/v1","resources":[
				{"name":"roles","namespaced":true,"kind":"Role","verbs":["get","list"]},
				{"name":"rolebindings","namespaced":true,"kind":"RoleBinding","verbs":["get","list"]},
				{"name":"clusterroles","namespaced":false,"kind":"ClusterRole","verbs":["get","list"]},
				{"name":"clusterrolebindings","namespaced":false,"kind":"ClusterRoleBinding","verbs":["get","list"]}]}`)
		case strings.HasSuffix(path, "/namespaces"):
			writeBody(w, `{"apiVersion":"v1","kind":"NamespaceList","items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}}]}`)
		case strings.HasSuffix(path, "/serviceaccounts"):
			writeBody(w, `{"apiVersion":"v1","kind":"ServiceAccountList","items":[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}]}`)
		case strings.HasSuffix(path, "/secrets"):
			writeBody(w, `{"apiVersion":"v1","kind":"SecretList","items":[{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"app"},"type":"Opaque","data":{"token":"%s"}}]}`, secretValue)
		case strings.HasSuffix(path, "/pods"):
			writeBody(w, `{"apiVersion":"v1","kind":"PodList","items":[]}`)
		case strings.HasSuffix(path, "/roles"):
			writeBody(w, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleList","items":[]}`)
		case strings.HasSuffix(path, "/rolebindings"):
			writeBody(w, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","items":[]}`)
		case strings.HasSuffix(path, "/clusterroles"):
			writeBody(w, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleList","items":[]}`)
		case strings.HasSuffix(path, "/clusterrolebindings"):
			writeBody(w, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBindingList","items":[]}`)
		default:
			http.NotFound(w, r)
		}
	})}
}

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// writeKubeconfig writes a synthetic kubeconfig pointing at the test server.
func writeKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster: {server: \"" + serverURL + "\"}\n" +
		"contexts:\n- name: ctx\n  context: {cluster: c, user: u}\ncurrent-context: ctx\n" +
		"users:\n- name: u\n  user: {token: \"synthetic\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// grepDir returns the files under dir that contain needle.
func grepDir(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), needle) {
			hits = append(hits, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// writeBody writes a test API response body. Tests ignore write errors to a
// ResponseWriter the httptest server owns; there is nothing to recover there.
func writeBody(w http.ResponseWriter, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
