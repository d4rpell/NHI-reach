// Live access to a cluster's API, restricted in code to read-only requests.
//
// The whole live path of the product goes through LiveClient, and LiveClient
// installs a transport that rejects any request that is not a plain read: the
// HTTP method must be GET, the path must be one of the discovery or collection
// paths this tool actually uses, and the query string may not carry watch-like
// parameters. The check runs before the request reaches the network, so a
// non-read verb cannot be issued even by a future caller.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/d4rpell/nhi-reach/internal/version"
)

// liveResource is one input type of spec §2.1 as it exists in the API.
type liveResource struct {
	gvr        schema.GroupVersionResource
	kind       string
	namespaced bool
}

// liveResources is the closed set of resource types the tool lists. It is the
// authority both for what is fetched and for what ReadOnlyTransport allows on
// the wire: anything outside this table is not a read this tool performs.
var liveResources = []liveResource{
	{gvr: schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, kind: "Namespace"},
	{gvr: schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}, kind: "ServiceAccount", namespaced: true},
	{gvr: schema.GroupVersionResource{Version: "v1", Resource: "pods"}, kind: "Pod", namespaced: true},
	{gvr: schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, kind: "Secret", namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, kind: "Role", namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, kind: "RoleBinding", namespaced: true},
	{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}, kind: "ClusterRole"},
	{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}, kind: "ClusterRoleBinding"},
	// OpenShift only: attempted when the API exposes it, reported as a Gap when
	// it does not (spec §2.1).
	{gvr: schema.GroupVersionResource{Group: "security.openshift.io", Version: "v1", Resource: "securitycontextconstraints"}, kind: "SecurityContextConstraints"},
}

// maxListPages bounds the pagination of one collection. Beyond it the list is
// reported as an error rather than accepted as complete.
const maxListPages = 100

// listPageLimit is the page size of a paginated list.
const listPageLimit = 500

// allowedQuery are the query parameters a read this tool performs may carry.
// timeout is added by client-go itself; limit/continue paginate; resourceVersion
// pins the list to one snapshot. watch and sendInitialEvents are deliberately
// absent: they turn a list into a stream.
var allowedQuery = map[string]bool{
	"timeout":         true,
	"limit":           true,
	"continue":        true,
	"resourceVersion": true,
}

// requiredKinds is the set of types a snapshot must provide (spec §2.1). A live
// load that cannot obtain one of them fails instead of reporting an incomplete
// analysis.
var requiredKinds = func() map[string]bool {
	out := make(map[string]bool, len(RequiredKinds))
	for _, kind := range RequiredKinds {
		out[kind] = true
	}
	return out
}()

// safeAPIError turns an error from the API client into a diagnostic built only
// from information this tool controls: the operation, the resource and, when the
// server answered, a label derived from its status reason and its status code. It
// never carries the raw error text nor any server-provided string, because a
// Kubernetes StatusError quotes the server-provided message and reason verbatim
// and either can repeat the content of an object, a Secret value included. A
// malformed body or a transport failure is reported as a plain request failure.
func safeAPIError(op, resource string, err error) error {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		s := status.Status()
		if label, known := reasonLabels[s.Reason]; known {
			return fmt.Errorf("%s %s: the server answered %s (code %d)", op, resource, label, s.Code)
		}
		return fmt.Errorf("%s %s: the server refused the request (code %d)", op, resource, s.Code)
	}
	return fmt.Errorf("%s %s: the request failed", op, resource)
}

// reasonLabels maps the Kubernetes status reasons this tool recognises to a
// constant of its own. A reason outside the list — the field is server-provided
// and its type guarantees nothing — produces a generic, constant label instead
// of echoing whatever the server sent.
var reasonLabels = map[metav1.StatusReason]string{
	metav1.StatusReasonBadRequest:           "BadRequest",
	metav1.StatusReasonUnauthorized:         "Unauthorized",
	metav1.StatusReasonForbidden:            "Forbidden",
	metav1.StatusReasonNotFound:             "NotFound",
	metav1.StatusReasonConflict:             "Conflict",
	metav1.StatusReasonGone:                 "Gone",
	metav1.StatusReasonInvalid:              "Invalid",
	metav1.StatusReasonTooManyRequests:      "TooManyRequests",
	metav1.StatusReasonInternalError:        "InternalError",
	metav1.StatusReasonServiceUnavailable:   "ServiceUnavailable",
	metav1.StatusReasonTimeout:              "Timeout",
	metav1.StatusReasonExpired:              "Expired",
	metav1.StatusReasonMethodNotAllowed:     "MethodNotAllowed",
	metav1.StatusReasonNotAcceptable:        "NotAcceptable",
	metav1.StatusReasonUnsupportedMediaType: "UnsupportedMediaType",
}

// ReadOnlyTransport wraps a transport and refuses every request that is not a
// plain read: only GET, only a discovery or collection path of liveResources,
// and only the query parameters of allowedQuery. The rejection happens before
// the inner transport is called, so the request never reaches the network. The
// error it returns is an ordinary error, never a panic, so callers see it as a
// failed operation.
func ReadOnlyTransport(inner http.RoundTripper) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := checkReadOnly(req); err != nil {
			return nil, err
		}
		return inner.RoundTrip(req)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// checkReadOnly is the read-only policy: method, path shape and query string.
// It names the method and the path of a rejected request but never a body.
func checkReadOnly(req *http.Request) error {
	if req.Method != http.MethodGet {
		return fmt.Errorf("read-only client: refusing %s %s: only GET is allowed", req.Method, req.URL.Path)
	}
	if !allowedPath(req.URL.Path) {
		return fmt.Errorf("read-only client: refusing GET %s: it is not a discovery or collection read of a supported type", req.URL.Path)
	}
	for key := range req.URL.Query() {
		if !allowedQuery[key] {
			return fmt.Errorf("read-only client: refusing query parameter %q on %s", key, req.URL.Path)
		}
	}
	return nil
}

// allowedPath reports whether path is a discovery path or the collection path of
// one of the types of liveResources. Subresources and individual objects are
// rejected: this tool lists collections, it never fetches an object.
func allowedPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(segments) == 1 && segments[0] == "version":
		return true
	case segments[0] == "api":
		// /api is discovery; the core API group has no group segment, so the
		// version is the first segment after "api".
		if len(segments) == 1 {
			return true
		}
		return versionedPath("", segments[1], segments[2:])
	case segments[0] == "apis":
		if len(segments) == 1 {
			return true
		}
		if len(segments) == 2 { // /apis/<group> is discovery
			return true
		}
		return versionedPath(segments[1], segments[2], segments[3:])
	}
	return false
}

// versionedPath matches the tail of a versioned API path: a discovery path, a
// collection path, or the collection path scoped to one namespace.
func versionedPath(group, version string, rest []string) bool {
	if !isKnownGroupVersion(group, version) {
		return false
	}
	switch len(rest) {
	case 0: // /apis/<group>/<version> or /api/v1 is discovery
		return true
	case 1:
		return isListResource(group, version, rest[0])
	case 3:
		return rest[0] == "namespaces" && isNamespacedListResource(group, version, rest[2])
	}
	return false
}

func isKnownGroupVersion(group, version string) bool {
	for _, res := range liveResources {
		if res.gvr.Group == group && res.gvr.Version == version {
			return true
		}
	}
	return false
}

func isListResource(group, version, resource string) bool {
	for _, res := range liveResources {
		if res.gvr.Group == group && res.gvr.Version == version && res.gvr.Resource == resource {
			return true
		}
	}
	return false
}

func isNamespacedListResource(group, version, resource string) bool {
	for _, res := range liveResources {
		if res.namespaced && res.gvr.Group == group && res.gvr.Version == version && res.gvr.Resource == resource {
			return true
		}
	}
	return false
}

// RESTConfig builds a rest.Config from an explicit kubeconfig file and context.
//
// It loads explicitly and never uses the deferred builder, whose ClientConfig
// falls back to the in-cluster configuration when the merged kubeconfig is empty
// or the default one and an in-cluster environment is detected: an audit run
// must never pick up ambient credentials the operator did not point it at.
//
// It does not touch Transport or WrapTransport: installing the read-only policy
// is NewLiveClient's job, so there is a single place responsible for it.
func RESTConfig(kubeconfigPath, contextName string) (*rest.Config, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	raw, err := rules.Load()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	cfg, err := clientcmd.NewNonInteractiveClientConfig(*raw, contextName, overrides, nil).ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("build rest config: %w", err)
	}
	effective := contextName
	if effective == "" {
		effective = raw.CurrentContext
	}
	cfg.UserAgent = "nhi-reach/" + version.Version
	return cfg, effective, nil
}

// LiveClient is the read-only client of the live path: a dynamic client for the
// list calls and a discovery client for the type inventory, both built from a
// config that carries ReadOnlyTransport.
type LiveClient struct {
	dynamic   dynamic.Interface
	discovery discovery.DiscoveryInterface
}

// NewLiveClient builds the client. The read-only policy is installed here, on a
// copy of the given config, so a caller cannot obtain a protected-looking client
// without the policy: an unprotected config gains it, and a config that already
// carries its own Transport or WrapTransport is rejected instead of composed
// with an unknown transport. The guarantee covers the live paths of this
// product; it cannot stop future code from building an unrelated HTTP client.
func NewLiveClient(cfg *rest.Config) (*LiveClient, error) {
	if cfg == nil {
		return nil, errors.New("live client: nil rest config")
	}
	if cfg.Transport != nil || cfg.WrapTransport != nil {
		return nil, errors.New("live client: refusing a rest config that already carries a custom transport")
	}
	protected := rest.CopyConfig(cfg)
	protected.WrapTransport = ReadOnlyTransport
	dynamicClient, err := dynamic.NewForConfig(protected)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(protected)
	if err != nil {
		return nil, fmt.Errorf("build discovery client: %w", err)
	}
	return &LiveClient{dynamic: dynamicClient, discovery: discoveryClient}, nil
}

// Discover returns the resource types of liveResources the API exposes.
//
// A group/version the server answers as not found is a confirmed absence and is
// left out of the result; any other discovery failure — transport, credentials,
// authorization — is an error, because a failure does not prove absence and must
// never be reported as one.
func (c *LiveClient) Discover(ctx context.Context) (map[schema.GroupVersionResource]bool, error) {
	listed := map[string]map[string]bool{}
	present := map[schema.GroupVersionResource]bool{}
	for _, res := range liveResources {
		groupVersion := res.gvr.GroupVersion().String()
		resources, seen := listed[groupVersion]
		if !seen {
			found, err := c.discovery.ServerResourcesForGroupVersion(groupVersion)
			if err != nil {
				if apierrors.IsNotFound(err) {
					listed[groupVersion] = map[string]bool{}
					continue
				}
				return nil, safeAPIError("live discovery of", groupVersion, err)
			}
			resources = map[string]bool{}
			for _, apiResource := range found.APIResources {
				if strings.Contains(apiResource.Name, "/") {
					continue // a subresource, never a collection this tool lists
				}
				resources[apiResource.Name] = true
			}
			listed[groupVersion] = resources
		}
		if resources[res.gvr.Resource] {
			present[res.gvr] = true
		}
	}
	return present, nil
}

// List returns every object of one resource type.
//
// A cluster-wide list is asked without a namespace, so each item keeps the
// namespace the API reported. The list is paginated: with a page size set, a
// server that answers a continue token is followed until it is exhausted, and
// exceeding maxListPages is an error instead of a silently partial collection.
func (c *LiveClient) List(ctx context.Context, gvr schema.GroupVersionResource, namespace string) (*unstructured.UnstructuredList, error) {
	resource := c.dynamic.Resource(gvr)
	var namespaced dynamic.ResourceInterface = resource
	if namespace != "" {
		namespaced = resource.Namespace(namespace)
	}
	out := &unstructured.UnstructuredList{}
	opts := metav1.ListOptions{Limit: listPageLimit}
	for page := 0; ; page++ {
		if page >= maxListPages {
			return nil, fmt.Errorf("live list of %s: more than %d pages, the collection is incomplete", gvr.Resource, maxListPages)
		}
		list, err := namespaced.List(ctx, opts)
		if err != nil {
			return nil, safeAPIError("live list of", gvr.Resource, err)
		}
		out.Items = append(out.Items, list.Items...)
		if list.GetContinue() == "" {
			out.SetAPIVersion(list.GetAPIVersion())
			out.SetKind(list.GetKind())
			return out, nil
		}
		opts.Continue = list.GetContinue()
	}
}

// ServerVersion returns the server version, best effort: a failure is not a
// reason to abort a capture.
func (c *LiveClient) ServerVersion(ctx context.Context) string {
	info, err := c.discovery.ServerVersion()
	if err != nil {
		return "unknown"
	}
	return info.GitVersion
}

// LoadLive builds an index from the API through the read-only client.
//
// It reuses the offline load path exactly: every listed object goes through
// Index.Add, which reduces it (a Secret rebuilt from its allowed fields, any
// other object without the volatile fields of spec §2.2) and validates it before
// indexing, so a hash never depends on where the object came from. A required
// type that discovery does not expose is an error; an optional one is a gap, and
// both are computed by the same finalize step the offline loader runs, so the two
// sources report the same missing types with the same shape.
func LoadLive(ctx context.Context, c *LiveClient) (*Index, error) {
	present, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, res := range liveResources {
		if present[res.gvr] || !requiredKinds[res.kind] {
			continue
		}
		missing = append(missing, res.kind)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("live cluster is missing required resource types: %s", strings.Join(missing, ", "))
	}

	ix := New()
	for _, res := range liveResources {
		if !present[res.gvr] {
			continue
		}
		items, err := c.List(ctx, res.gvr, metav1.NamespaceAll)
		if err != nil {
			return nil, err
		}
		for i := range items.Items {
			raw := items.Items[i].Object
			if kind, _ := raw["kind"].(string); kind != res.kind {
				return nil, fmt.Errorf("live %s: got a %s object, want %s", res.gvr.Resource, kind, res.kind)
			}
			if err := ix.Add(raw); err != nil {
				return nil, fmt.Errorf("live %s: %w", res.gvr.Resource, err)
			}
		}
		ix.present[res.kind] = true
	}
	if err := ix.finalize(); err != nil {
		return nil, err
	}
	return ix, nil
}

// ListAPIVersion returns the apiVersion written on the JSON list file of a kind.
func ListAPIVersion(kind string) string {
	for _, res := range liveResources {
		if res.kind != kind {
			continue
		}
		if res.gvr.Group == "" {
			return res.gvr.Version
		}
		return res.gvr.GroupVersion().String()
	}
	return ""
}
