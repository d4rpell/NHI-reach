package report

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"sort"
	"strings"
)

//go:embed assets/report.html.tmpl
var reportTemplate string

//go:embed assets/cytoscape.min.js
var cytoscapeJS []byte

// cytoscapeSHA256 is the pinned digest of the embedded graph library. It is
// checked by TestEmbeddedAssetIntegrity: replacing the asset must be a
// deliberate change that also updates THIRD_PARTY_NOTICES.md.
const cytoscapeSHA256 = "83e8c54a6bec655bfd81df07df605649c268af69aeca67a5ea2da54ea42dac81"

// ToolInfo is the build metadata of the binary that produced the report. It is
// passed in, never read from the environment or the clock, so the output
// depends only on its arguments.
type ToolInfo struct {
	Version       string
	Commit        string
	Date          string
	CatalogSHA256 string
}

// HopReference is the official reference of one catalog hop.
type HopReference struct {
	ID        string
	Reference string
}

// HTMLOptions carries what the HTML renderer needs beyond the report: the build
// metadata for the footer and the official reference of each catalog hop.
type HTMLOptions struct {
	Tool       ToolInfo
	References []HopReference
}

type graphNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	System bool   `json:"system"`
}

type graphEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	HopID      string `json:"hop_id"`
	Confidence string `json:"confidence"`
}

type graphPayload struct {
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
}

type cardData struct {
	Path PathView
	Cuts []CutView
	// Refs is read by the pathCard template as $.Refs: inside that nested
	// template the $ is the card, not the page root.
	Refs map[string]string
}

type groupData struct {
	Target string
	App    []cardData
	System []cardData
}

type pageData struct {
	Report Report
	Tool   ToolInfo
	Groups []groupData
	Graph  template.JS
	Asset  template.JS
	Refs   map[string]string
}

// HTML writes the report as a single self-contained HTML document (spec §4).
// The document makes no network request: the graph library is embedded inline
// and every resource is part of the file. The substantive content is rendered
// in Go; JavaScript only draws the graph, so the report stays readable without
// it.
//
// The output depends only on (r, opts) and never mutates them: the report is
// deep-copied before it is normalized, because Normalize reorders cuts and
// rewrites elements of the slices the caller owns. The embedded payload is
// escaped so that no literal "<" reaches it, which closes the script-termination
// vector for untrusted object names.
func HTML(w io.Writer, r Report, opts HTMLOptions) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"label": nodeLabel,
		"short": shortHash,
		"yesno": yesNo,
	}).Parse(reportTemplate)
	if err != nil {
		return err
	}

	rep := copyReport(r).Normalize()
	refs := referenceMap(opts.References)

	payload, err := marshalGraph(payloadFor(rep))
	if err != nil {
		return err
	}

	page := pageData{
		Report: rep,
		Tool:   opts.Tool,
		Groups: groupsFor(rep, refs),
		Graph:  template.JS(payload),
		Asset:  template.JS(cytoscapeJS),
		Refs:   refs,
	}
	return tmpl.Execute(w, page)
}

// copyReport deep-copies the slices Normalize touches, so HTML never mutates
// the caller's report. The frozen struct fields are values, so copying the
// slices is enough.
func copyReport(r Report) Report {
	r.Params.Targets = append([]string(nil), r.Params.Targets...)
	r.Params.SystemNamespaces = append([]string(nil), r.Params.SystemNamespaces...)
	r.Params.SensitiveNamespaces = append([]string(nil), r.Params.SensitiveNamespaces...)
	r.Paths = append([]PathView(nil), r.Paths...)
	for i := range r.Paths {
		r.Paths[i].Route = append([]StepView(nil), r.Paths[i].Route...)
		for j := range r.Paths[i].Route {
			r.Paths[i].Route[j].Evidence = append([]RefView(nil), r.Paths[i].Route[j].Evidence...)
		}
	}
	r.Cuts = append([]CutView(nil), r.Cuts...)
	r.Bottlenecks = append([]Bottleneck(nil), r.Bottlenecks...)
	for i := range r.Bottlenecks {
		r.Bottlenecks[i].Eliminated = append([]PairView(nil), r.Bottlenecks[i].Eliminated...)
	}
	r.Gaps = append([]GapView(nil), r.Gaps...)
	return r
}

// referenceMap maps hop id to official reference, ordered and de-duplicated by
// hop id (the first appearance wins), so the output does not depend on the
// order the caller passed.
func referenceMap(refs []HopReference) map[string]string {
	sorted := append([]HopReference(nil), refs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	out := map[string]string{}
	for _, ref := range sorted {
		if _, ok := out[ref.ID]; ok {
			continue
		}
		out[ref.ID] = ref.Reference
	}
	return out
}

// groupsFor groups the paths by target, splitting system origins into a
// separate block, exactly as the table does. The paths arrive already
// normalized, so the order is deterministic.
func groupsFor(r Report, refs map[string]string) []groupData {
	var groups []groupData
	for _, target := range orderedTargets(r.Paths) {
		group := groupData{Target: target}
		for _, path := range r.Paths {
			if path.Target != target {
				continue
			}
			card := cardData{Path: path, Cuts: CutsOf(r.Cuts, path.ID), Refs: refs}
			if path.SystemOrigin {
				group.System = append(group.System, card)
			} else {
				group.App = append(group.App, card)
			}
		}
		groups = append(groups, group)
	}
	return groups
}

// payloadFor derives the graph nodes and edges from the routes in Go. Nodes are
// ordered by id; edges are unique by (from, to, hop_id) and ordered by that
// triple. An edge shared by two routes with different confidence keeps the
// conditional one, so a hop that is conditional in any route is never drawn as
// definite.
func payloadFor(r Report) graphPayload {
	nodes := map[string]graphNode{}
	edges := map[string]graphEdge{}
	for _, path := range r.Paths {
		nodes[path.Source] = nodeFor(path.Source, r.Params.SystemNamespaces)
		nodes[path.Target] = nodeFor(path.Target, r.Params.SystemNamespaces)
		for _, step := range path.Route {
			nodes[step.From] = nodeFor(step.From, r.Params.SystemNamespaces)
			nodes[step.To] = nodeFor(step.To, r.Params.SystemNamespaces)
			key := step.From + "\x00" + step.To + "\x00" + step.HopID
			edge := graphEdge{From: step.From, To: step.To, HopID: step.HopID, Confidence: step.Confidence}
			if prev, ok := edges[key]; ok {
				edge.Confidence = weakerConfidence(prev.Confidence, step.Confidence)
			}
			edges[key] = edge
		}
	}

	payload := graphPayload{Nodes: make([]graphNode, 0, len(nodes)), Edges: make([]graphEdge, 0, len(edges))}
	for _, node := range nodes {
		payload.Nodes = append(payload.Nodes, node)
	}
	sort.Slice(payload.Nodes, func(i, j int) bool { return payload.Nodes[i].ID < payload.Nodes[j].ID })
	for _, edge := range edges {
		payload.Edges = append(payload.Edges, edge)
	}
	sort.Slice(payload.Edges, func(i, j int) bool {
		if payload.Edges[i].From != payload.Edges[j].From {
			return payload.Edges[i].From < payload.Edges[j].From
		}
		if payload.Edges[i].To != payload.Edges[j].To {
			return payload.Edges[i].To < payload.Edges[j].To
		}
		return payload.Edges[i].HopID < payload.Edges[j].HopID
	})
	return payload
}

// weakerConfidence returns "conditional" unless both inputs are "definite".
func weakerConfidence(a, b string) string {
	if a == "definite" && b == "definite" {
		return "definite"
	}
	return "conditional"
}

// nodeFor classifies a node id. Only the kinds the report can actually carry
// are produced: an identity (system or application) or a target. workload and
// group are part of the payload vocabulary but are not derivable from Report
// today, so they are never invented.
func nodeFor(id string, system []string) graphNode {
	node := graphNode{ID: id, Label: nodeLabel(id)}
	switch {
	case strings.HasPrefix(id, "sa:"):
		namespace, _ := splitIdentity(id)
		node.System = matchesSystemNamespace(namespace, system)
		if node.System {
			node.Kind = "system"
		} else {
			node.Kind = "identity"
		}
	case strings.HasPrefix(id, "target:"):
		node.Kind = "target"
	default:
		node.Kind = "identity"
	}
	return node
}

func splitIdentity(id string) (namespace, name string) {
	rest := strings.TrimPrefix(id, "sa:")
	namespace, name, _ = strings.Cut(rest, "/")
	return namespace, name
}

// matchesSystemNamespace applies the literal-or-prefix rule of spec §2.6 to a
// namespace list taken from the report parameters.
func matchesSystemNamespace(namespace string, system []string) bool {
	for _, entry := range system {
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			if strings.HasPrefix(namespace, prefix) {
				return true
			}
			continue
		}
		if namespace == entry {
			return true
		}
	}
	return false
}

// marshalGraph serializes the payload and escapes it so that no literal "<"
// survives. A JSON payload inside a <script> element is only safe when it
// cannot contain "</script>" (in any case or spacing), "<!--" or a CDATA
// section; removing every "<" removes all of them. The escapes are valid JSON,
// so the payload still parses.
func marshalGraph(payload graphPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	replacer := strings.NewReplacer(
		"<", `\u003c`,
		">", `\u003e`,
		"&", `\u0026`,
		"\u2028", `\u2028`,
		"\u2029", `\u2029`,
	)
	return replacer.Replace(string(data)), nil
}

// shortHash abbreviates a SHA-256 for display; the full hash stays in the JSON
// output.
func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

// assetSHA256 is used by tests to verify the embedded asset against the pinned
// digest.
func assetSHA256() string {
	sum := sha256.Sum256(cytoscapeJS)
	return hex.EncodeToString(sum[:])
}
