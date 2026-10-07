package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// recordingServer is a fake API server that records every method and path it
// receives, so a test can assert exactly what went on the wire.
type recordingServer struct {
	mu      sync.Mutex
	methods []string
	paths   []string
	handler func(w http.ResponseWriter, r *http.Request)
}

func (s *recordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.methods = append(s.methods, r.Method)
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()
	if s.handler != nil {
		s.handler(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *recordingServer) sawNonRead() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var bad []string
	for _, method := range s.methods {
		if method != http.MethodGet {
			bad = append(bad, method)
		}
	}
	return bad
}

// apiServerConfig returns a rest.Config pointing at a test server, with only the
// read-only policy to be installed by NewLiveClient. It mirrors RESTConfig's
// contract: no transport and no wrapper.
func apiServerConfig(t *testing.T, server *httptest.Server) *rest.Config {
	t.Helper()
	return &rest.Config{Host: server.URL, ContentConfig: rest.ContentConfig{}}
}

func TestReadOnlyTransportRejectsNonGet(t *testing.T) {
	var called bool
	inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})
	transport := ReadOnlyTransport(inner)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		req, err := http.NewRequest(method, "https://cluster.example/api/v1/namespaces", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err == nil {
			t.Errorf("%s was not rejected", method)
		}
	}
	if called {
		t.Fatal("the inner transport was called for a non-read method")
	}
}

func TestReadOnlyTransportRejectsForbiddenPaths(t *testing.T) {
	var called bool
	inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})
	transport := ReadOnlyTransport(inner)

	for _, path := range []string{
		"/api/v1/namespaces/app/pods/x/exec",
		"/api/v1/namespaces/app/pods/x/proxy",
		"/api/v1/namespaces/app/pods/x/portforward",
		"/api/v1/namespaces/app/secrets/registry", // an individual object
		"/apis/rbac.authorization.k8s.io/v1/roles/app/ci",
		"/api/v1/components",          // not a type this tool lists
		"/apis/apps/v1/deployments",   // a type outside the table
		"/api/v1/namespaces/app/pods", // namespaced collection is allowed, see below
	} {
		req, err := http.NewRequest(http.MethodGet, "https://cluster.example"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = transport.RoundTrip(req)
		wantAllowed := path == "/api/v1/namespaces/app/pods"
		if wantAllowed && err != nil {
			t.Errorf("a namespaced collection read was rejected: %v", err)
		}
		if !wantAllowed && err == nil {
			t.Errorf("GET %s was allowed and should not be", path)
		}
	}
	// Every request that was rejected left the inner transport untouched; the
	// only allowed one may reach it.
	if !called {
		t.Fatal("a permitted collection read never reached the inner transport")
	}
}

func TestReadOnlyTransportRejectsWatchParameters(t *testing.T) {
	var called bool
	inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})
	transport := ReadOnlyTransport(inner)

	for _, query := range []string{"watch=true", "watch=false", "sendInitialEvents=true", "fieldSelector=a", "labelSelector=b"} {
		req, err := http.NewRequest(http.MethodGet, "https://cluster.example/api/v1/namespaces?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err == nil {
			t.Errorf("query %q was allowed", query)
		}
	}
	for _, query := range []string{"limit=500", "continue=abc", "resourceVersion=1", "timeout=30s"} {
		req, err := http.NewRequest(http.MethodGet, "https://cluster.example/api/v1/namespaces?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err != nil {
			t.Errorf("query %q was rejected: %v", query, err)
		}
	}
	if !called {
		t.Fatal("no permitted query reached the inner transport")
	}
}

func TestReadOnlyTransportAllowsDiscoveryAndCollections(t *testing.T) {
	inner := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	transport := ReadOnlyTransport(inner)
	for _, path := range []string{
		"/version",
		"/api",
		"/api/v1",
		"/apis",
		"/apis/rbac.authorization.k8s.io",
		"/apis/rbac.authorization.k8s.io/v1",
		"/api/v1/namespaces",
		"/api/v1/serviceaccounts",
		"/apis/rbac.authorization.k8s.io/v1/clusterroles",
		"/apis/security.openshift.io/v1/securitycontextconstraints",
		"/api/v1/namespaces/app/secrets",
	} {
		req, err := http.NewRequest(http.MethodGet, "https://cluster.example"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err != nil {
			t.Errorf("GET %s was rejected: %v", path, err)
		}
	}
}

func TestLiveClientRefusesCustomTransport(t *testing.T) {
	cfg := &rest.Config{Host: "https://cluster.example", WrapTransport: func(rt http.RoundTripper) http.RoundTripper { return rt }}
	if _, err := NewLiveClient(cfg); err == nil {
		t.Fatal("NewLiveClient accepted a config that already carries a custom transport")
	}
}

func TestLiveClientRejectsCreateAttemptAtTheWire(t *testing.T) {
	server := &recordingServer{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"apiVersion":"v1","kind":"ServiceAccountList","items":[]}`)
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()

	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	// Reach for a write on purpose: the transport must stop it before the wire.
	_, _ = client.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}).
		Namespace("app").Create(context.Background(), mustUnstructured(t), metav1.CreateOptions{})

	if bad := server.sawNonRead(); len(bad) != 0 {
		t.Fatalf("the server saw non-read methods: %v", bad)
	}
}

func TestLiveClientListAndDiscoverOnlyIssueGet(t *testing.T) {
	server := &recordingServer{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1":
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"serviceaccounts","namespaced":true,"kind":"ServiceAccount","verbs":["get","list"]}]}`)
		case r.URL.Path == "/apis/rbac.authorization.k8s.io/v1":
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"rbac.authorization.k8s.io/v1","resources":[{"name":"roles","namespaced":true,"kind":"Role","verbs":["get","list"]}]}`)
		case strings.HasSuffix(r.URL.Path, "/serviceaccounts"):
			writeBody(w, `{"apiVersion":"v1","kind":"ServiceAccountList","items":[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()

	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	list, err := client.List(context.Background(), schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}, metav1.NamespaceAll)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("List returned %d items, want 1", len(list.Items))
	}
	if bad := server.sawNonRead(); len(bad) != 0 {
		t.Fatalf("the server saw non-read methods: %v", bad)
	}
}

func TestLiveClientFollowsRedirectToForbiddenPath(t *testing.T) {
	server := &recordingServer{handler: func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/v1/namespaces/app/pods/x/exec", http.StatusFound)
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()

	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(context.Background(), schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, metav1.NamespaceAll); err == nil {
		t.Fatal("a redirect to a forbidden path was followed without error")
	}
	if bad := server.sawNonRead(); len(bad) != 0 {
		t.Fatalf("the server saw non-read methods: %v", bad)
	}
}

func TestRESTConfigWithoutKubeconfigFailsAndDoesNotContactAPI(t *testing.T) {
	// Point every standard location at an empty directory so no kubeconfig is
	// found, and set the in-cluster variables so the deferred builder would have
	// fallen back to them.
	empty := t.TempDir()
	t.Setenv("KUBECONFIG", filepath.Join(empty, "none"))
	t.Setenv("HOME", empty)
	t.Setenv("USERPROFILE", empty)
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	cfg, _, err := RESTConfig(filepath.Join(empty, "absent"), "")
	if err == nil && cfg != nil && cfg.Host != "" {
		t.Skip("a real kubeconfig was found; cannot assert absence here")
	}
	if err == nil {
		t.Fatal("RESTConfig produced a config with no kubeconfig available")
	}
	if !strings.Contains(err.Error(), "kubeconfig") {
		t.Errorf("error does not name the kubeconfig: %v", err)
	}
}

func TestRESTConfigDoesNotInstallAWrapper(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "config")
	writeFile(t, dir, "config", `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: "https://cluster.example"}
contexts:
- name: ctx
  context: {cluster: c, user: u}
current-context: ctx
users:
- name: u
  user: {token: "x"}
`)
	cfg, contextName, err := RESTConfig(kubeconfig, "")
	if err != nil {
		t.Fatalf("RESTConfig: %v", err)
	}
	if cfg.WrapTransport != nil || cfg.Transport != nil {
		t.Fatal("RESTConfig installed a transport; NewLiveClient must be the only place that does")
	}
	if contextName != "ctx" {
		t.Errorf("effective context is %q, want ctx", contextName)
	}
	if _, err := NewLiveClient(cfg); err != nil {
		t.Fatalf("the normal RESTConfig -> NewLiveClient path failed: %v", err)
	}
}

func TestLoadLiveMatchesLoad(t *testing.T) {
	server := newFullAPIServer(t)
	ts := httptest.NewServer(server)
	defer ts.Close()

	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	live, err := LoadLive(context.Background(), client)
	if err != nil {
		t.Fatalf("LoadLive: %v", err)
	}

	dir := t.TempDir()
	if err := WriteSnapshot(dir, live, Metadata{}); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	offline, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if live.Manifest().SHA256 != offline.Manifest().SHA256 {
		t.Errorf("live and offline manifests differ: %s vs %s", live.Manifest().SHA256, offline.Manifest().SHA256)
	}
	if fmt.Sprint(live.Gaps()) != fmt.Sprint(offline.Gaps()) {
		t.Errorf("live and offline gaps differ: %v vs %v", live.Gaps(), offline.Gaps())
	}
}

func TestSnapshotNeverWritesSecretContent(t *testing.T) {
	const decoy = "SUPER-SECRET-DECOY-VALUE"
	server := newFullAPIServerWithSecret(t, decoy)
	ts := httptest.NewServer(server)
	defer ts.Close()

	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := LoadLive(context.Background(), client)
	if err != nil {
		t.Fatalf("LoadLive: %v", err)
	}
	dir := t.TempDir()
	if err := WriteSnapshot(dir, ix, Metadata{}); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := readFileString(entry)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(data, decoy) {
			t.Errorf("%s leaks the secret value", filepath.Base(entry))
		}
	}
}

func TestSnapshotRejectsNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "stale.json", `{"apiVersion":"v1","kind":"List","items":[]}`)
	ix, err := Load(minimalSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(dir, ix, Metadata{}); err == nil {
		t.Fatal("WriteSnapshot wrote into a non-empty directory")
	}
}

func TestVerifySnapshotDetectsTampering(t *testing.T) {
	ix, err := Load(minimalSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := WriteSnapshot(dir, ix, Metadata{}); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	if err := VerifySnapshot(dir); err != nil {
		t.Fatalf("a freshly written snapshot did not verify: %v", err)
	}

	tampered := t.TempDir()
	if err := WriteSnapshot(tampered, ix, Metadata{}); err != nil {
		t.Fatal(err)
	}
	manifest, err := readManifest(tampered)
	if err != nil {
		t.Fatal(err)
	}
	manifest.SHA256 = strings.Repeat("0", 64)
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileErr(tampered, "manifest.json", string(data)); err != nil {
		t.Fatal(err)
	}
	if err := VerifySnapshot(tampered); err == nil {
		t.Fatal("a tampered manifest.json verified")
	}

	extra := t.TempDir()
	if err := WriteSnapshot(extra, ix, Metadata{}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, extra, "extra.json", `{"apiVersion":"v1","kind":"List","items":[]}`)
	if err := VerifySnapshot(extra); err == nil {
		t.Fatal("an extra data file verified")
	}
}

func TestLoadIgnoresMetadataJSON(t *testing.T) {
	dir := minimalSnapshot(t)
	writeFile(t, dir, "metadata.json", `{"schema":"nhi-reach/snapshot-metadata/v1","files":[]}`)
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load choked on metadata.json: %v", err)
	}
}

func TestWrittenSecretRoundTripsToTheSameKeyNamesAndHash(t *testing.T) {
	// A live Secret carries values; the reduced form keeps key names and a hash.
	// The surrounding snapshot is the minimal one, so the directory is complete.
	ix, err := Load(minimalSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	var live map[string]any
	if err := json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Secret",
		"metadata":{"name":"s","namespace":"app"},"type":"Opaque",
		"data":{"token":"c3RhdGUtMQ==","ca":"Y2VydA=="}}`), &live); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(live); err != nil {
		t.Fatal(err)
	}
	liveRef, _ := ix.Get("Secret", "app", "s")

	dir := t.TempDir()
	if err := WriteSnapshot(dir, ix, Metadata{}); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	// The written file must not carry a secret value, only empty placeholders.
	data, err := os.ReadFile(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "c3RhdGUtMQ") || strings.Contains(string(data), "Y2VydA") {
		t.Fatalf("the written secret file carries a value: %s", data)
	}
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	offlineRef, ok := reloaded.Get("Secret", "app", "s")
	if !ok {
		t.Fatal("the secret did not survive the round-trip")
	}
	if offlineRef.SHA256 != liveRef.SHA256 {
		t.Errorf("the secret hash changed across the round-trip: %s vs %s", liveRef.SHA256, offlineRef.SHA256)
	}
	keyListBefore := secretDataKeys(t, ix)
	keyListAfter := secretDataKeys(t, reloaded)
	if fmt.Sprint(keyListBefore) != fmt.Sprint(keyListAfter) {
		t.Errorf("the key names changed across the round-trip: %v vs %v", keyListBefore, keyListAfter)
	}
}

func secretDataKeys(t *testing.T, ix *Index) []string {
	t.Helper()
	_, raw, ok := ix.Entry("Secret", "app", "s")
	if !ok {
		t.Fatal("secret not indexed")
	}
	keys, _ := raw["dataKeys"].([]string)
	return keys
}

func TestLoadLiveReportsExposedEmptyTypeAsPresent(t *testing.T) {
	// Every required type is exposed; Pods is exposed too but empty. Pods must be
	// present (no gap), and the optional Secret and SCC must be absent (gaps).
	server := newFullAPIServer(t)
	ts := httptest.NewServer(server)
	defer ts.Close()
	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := LoadLive(context.Background(), client)
	if err != nil {
		t.Fatalf("LoadLive: %v", err)
	}
	present := map[string]bool{}
	for _, gap := range ix.Gaps() {
		present[gap.Subject] = true
	}
	if present["Pod"] {
		t.Error("Pods is exposed (empty) but was reported as missing")
	}
	if !present["SecurityContextConstraints"] {
		t.Error("the OpenShift API is absent but no gap was reported for SCC")
	}
}

func TestDiscoverFailureIsNotReportedAsAbsence(t *testing.T) {
	server := &recordingServer{handler: func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()
	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadLive(context.Background(), client)
	if err == nil {
		t.Fatal("a discovery failure was accepted as a missing type")
	}
	if strings.Contains(err.Error(), "gap") {
		t.Errorf("a discovery failure produced a gap instead of an error: %v", err)
	}
}

// --- helpers --------------------------------------------------------------

func mustUnstructured(t *testing.T) *unstructured.Unstructured {
	t.Helper()
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ServiceAccount",
		"metadata": map[string]any{"name": "forbidden", "namespace": "app"},
	}}
}

// newFullAPIServer serves the discovery and list endpoints for the six required
// types plus a Pod and a Secret, so LoadLive succeeds end to end. Values for the
// Secret are fixed; newFullAPIServerWithSecret overrides them to a decoy.
func newFullAPIServer(t *testing.T) *recordingServer {
	t.Helper()
	return fullAPIServer(t, "c3VwZXItc2VjcmV0")
}

func newFullAPIServerWithSecret(t *testing.T, decoy string) *recordingServer {
	t.Helper()
	return fullAPIServer(t, decoy)
}

func fullAPIServer(t *testing.T, secretValue string) *recordingServer {
	t.Helper()
	return &recordingServer{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case path == "/version":
			writeBody(w, `{"major":"1","minor":"32","gitVersion":"v1.32.0"}`)
		case path == "/apis":
			writeBody(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"rbac.authorization.k8s.io","versions":[{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}}]}`)
		case path == "/api/v1":
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[
				{"name":"namespaces","namespaced":false,"kind":"Namespace","verbs":["get","list"]},
				{"name":"serviceaccounts","namespaced":true,"kind":"ServiceAccount","verbs":["get","list"]},
				{"name":"pods","namespaced":true,"kind":"Pod","verbs":["get","list"]},
				{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["get","list"]},
				{"name":"pods/exec","namespaced":true,"kind":"PodExecOptions","verbs":["get","create"]}]}`)
		case path == "/apis/rbac.authorization.k8s.io/v1":
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"rbac.authorization.k8s.io/v1","resources":[
				{"name":"roles","namespaced":true,"kind":"Role","verbs":["get","list"]},
				{"name":"rolebindings","namespaced":true,"kind":"RoleBinding","verbs":["get","list"]},
				{"name":"clusterroles","namespaced":false,"kind":"ClusterRole","verbs":["get","list"]},
				{"name":"clusterrolebindings","namespaced":false,"kind":"ClusterRoleBinding","verbs":["get","list"]}]}`)
		case path == "/apis/security.openshift.io/v1":
			http.NotFound(w, r)
		case strings.HasSuffix(path, "/namespaces"):
			writeBody(w, `{"apiVersion":"v1","kind":"NamespaceList","items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"app"}},{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system"}}]}`)
		case strings.HasSuffix(path, "/serviceaccounts"):
			writeBody(w, `{"apiVersion":"v1","kind":"ServiceAccountList","items":[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"ci","namespace":"app"}, "uid":"x","resourceVersion":"9"}]}`)
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
	}}
}

func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func writeFileErr(dir, name, content string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
}

// writeBody writes a test API response body. Tests ignore write errors to a
// ResponseWriter the httptest server owns; there is nothing to recover there.
func writeBody(w http.ResponseWriter, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func TestLiveErrorsNeverCarryServerMessage(t *testing.T) {
	const (
		decoy       = "STATUS-MESSAGE-SECRET-DECOY"
		decoyReason = "STATUS-REASON-SECRET-DECOY"
	)
	server := &recordingServer{handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1":
			// A discovery listing that names the type, so List is attempted next.
			writeBody(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["get","list"]}]}`)
		case "/apis/rbac.authorization.k8s.io/v1":
			// A discovery failure whose reason is itself the payload: a known reason
			// string and an unknown one, both server-provided.
			w.WriteHeader(http.StatusForbidden)
			writeBody(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"%s","code":403,"message":"redacted"}`, decoyReason)
		default:
			// A Kubernetes StatusError whose message repeats a secret-looking value.
			w.WriteHeader(http.StatusForbidden)
			writeBody(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403,"message":"secrets is forbidden: %s"}`, decoy)
		}
	}}
	ts := httptest.NewServer(server)
	defer ts.Close()

	client, err := NewLiveClient(apiServerConfig(t, ts))
	if err != nil {
		t.Fatal(err)
	}

	// List: the message field carries the decoy, the reason is a known one.
	_, err = client.List(context.Background(), schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, metav1.NamespaceAll)
	if err == nil {
		t.Fatal("a failing list returned no error")
	}
	if strings.Contains(err.Error(), decoy) {
		t.Errorf("the error carries the server-provided message: %v", err)
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("the error lost the known reason label: %v", err)
	}

	// Discovery: an unknown reason string must not be echoed either.
	_, err = LoadLive(context.Background(), client)
	if err == nil {
		t.Fatal("LoadLive accepted a discovery failure")
	}
	if strings.Contains(err.Error(), decoyReason) {
		t.Errorf("the error carries the server-provided reason: %v", err)
	}
}
