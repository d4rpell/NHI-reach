package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const graphPayloadPattern = `<script id="nhi-reach-graph" type="application/json">([^<]*)</script>`

func renderHTML(t *testing.T, r Report, opts HTMLOptions) string {
	t.Helper()
	var buf bytes.Buffer
	if err := HTML(&buf, r, opts); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	return buf.String()
}

func graphPayloadOf(t *testing.T, html string) graphPayload {
	t.Helper()
	match := regexp.MustCompile(graphPayloadPattern).FindStringSubmatch(html)
	if match == nil {
		t.Fatalf("the report has no embedded graph payload:\n%s", html[:min(len(html), 2000)])
	}
	var payload graphPayload
	if err := json.Unmarshal([]byte(match[1]), &payload); err != nil {
		t.Fatalf("the embedded payload is not valid JSON: %v\npayload:\n%s", err, match[1])
	}
	return payload
}

func TestEmbeddedAssetIntegrity(t *testing.T) {
	if got := assetSHA256(); got != cytoscapeSHA256 {
		t.Errorf("embedded asset digest is %s, want %s: replacing the asset must be deliberate and update THIRD_PARTY_NOTICES.md", got, cytoscapeSHA256)
	}
}

func TestHTMLNoExternalResources(t *testing.T) {
	html := renderHTML(t, sampleReport(), HTMLOptions{})
	for _, marker := range []string{"<script src", "<link", "@import", "url(http", "<iframe", "<img"} {
		if strings.Contains(html, marker) {
			t.Errorf("the report references an external resource through %q", marker)
		}
	}
}

func TestHTMLAssetInlined(t *testing.T) {
	html := renderHTML(t, sampleReport(), HTMLOptions{})
	// The whole asset must be inline, not just a version banner: the document
	// has to contain its bytes.
	asset := string(cytoscapeJS)
	if !strings.Contains(html, asset) {
		t.Errorf("the embedded asset is not present in full in the report")
	}
	if !strings.Contains(html, "3.30.2") {
		t.Errorf("the report does not carry the library version banner")
	}
}

func TestHTMLPayloadEscaping(t *testing.T) {
	hostile := []string{
		`</script><script>alert(1)</script>`,
		`</ScRiPt >`,
		`<!-- comment -->`,
		`a"b\c`,
		"line\u2028sep\u2029par",
	}
	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			r := Report{
				SchemaVersion: SchemaVersion,
				Paths: []PathView{{
					ID:     "p1",
					Source: "sa:app/" + name,
					Target: "target:cluster-admin",
					Hops:   1,
					Route: []StepView{{
						From: "sa:app/" + name, To: "target:cluster-admin",
						HopID: "NR-001", Confidence: "definite",
					}},
				}},
			}
			html := renderHTML(t, r, HTMLOptions{})

			match := regexp.MustCompile(graphPayloadPattern).FindStringSubmatch(html)
			if match == nil {
				t.Fatalf("no payload found")
			}
			payload := match[1]
			if strings.Contains(payload, "<") {
				t.Errorf("the payload still holds a literal '<':\n%s", payload)
			}
			if strings.Contains(html, "</script><script") {
				t.Errorf("an untrusted name closed the script element")
			}
			// The payload must still parse and round-trip the original text.
			var decoded graphPayload
			if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
				t.Fatalf("the escaped payload no longer parses: %v", err)
			}
			found := false
			for _, node := range decoded.Nodes {
				if node.ID == "sa:app/"+name {
					found = true
				}
			}
			if !found {
				t.Errorf("the payload did not round-trip the hostile name %q: %+v", name, decoded.Nodes)
			}
			if got := strings.Count(html, "<script"); got != 3 {
				t.Errorf("the document has %d <script> elements, want 3 (payload, asset, draw)", got)
			}
		})
	}
}

func TestHTMLEscapesUntrustedText(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		Paths: []PathView{{
			ID: "p1", Source: "sa:app/<b>bold</b>", Target: "target:cluster-admin", Hops: 1,
			Route: []StepView{{From: "sa:app/<b>bold</b>", To: "target:cluster-admin", HopID: "NR-001", Confidence: "definite"}},
		}},
	}
	html := renderHTML(t, r, HTMLOptions{})
	if strings.Contains(html, "<b>bold</b>") {
		t.Errorf("untrusted text was not escaped in the HTML body")
	}
	if !strings.Contains(html, "&lt;b&gt;") {
		t.Errorf("the escaped form of the untrusted text is missing")
	}
}

func TestHTMLRendersSecretReferenceWithoutContent(t *testing.T) {
	// RefView carries metadata only, by contract; the renderer must show the
	// reference and nothing else. The leak check against real decoy values runs
	// at the command level, where the fixture holds them.
	r := sampleReport()
	r.Paths[0].Route[0].Evidence = []RefView{{
		APIVersion: "v1", Kind: "Secret", Namespace: "app", Name: "registry", SHA256: "deadbeefcafe",
	}}
	html := renderHTML(t, r, HTMLOptions{})
	if !strings.Contains(html, "app/registry") {
		t.Errorf("the report dropped the Secret reference it is allowed to show")
	}
	if !strings.Contains(html, "deadbeefcafe") {
		t.Errorf("the report dropped the Secret metadata hash")
	}
}

func TestHTMLDoesNotMutateInput(t *testing.T) {
	r := sampleReport()
	// Deliberately unsorted, so Normalize would reorder the caller's slices.
	r.Paths = []PathView{r.Paths[1], r.Paths[0]}
	r.Cuts = []CutView{{PathID: "p2"}, {PathID: "p1"}}
	before := deepCopyReport(r)
	refs := []HopReference{{ID: "NR-002", Reference: "https://example.test/b"}, {ID: "NR-001", Reference: "https://example.test/a"}}
	refsBefore := append([]HopReference(nil), refs...)

	_ = renderHTML(t, r, HTMLOptions{References: refs})

	if !reflect.DeepEqual(r, before) {
		t.Errorf("HTML mutated its report argument\n got: %+v\nwant: %+v", r, before)
	}
	if !reflect.DeepEqual(refs, refsBefore) {
		t.Errorf("HTML mutated its references argument\n got: %+v\nwant: %+v", refs, refsBefore)
	}
}

func deepCopyReport(r Report) Report {
	clone := r
	clone.Params.Targets = append([]string(nil), r.Params.Targets...)
	clone.Params.SystemNamespaces = append([]string(nil), r.Params.SystemNamespaces...)
	clone.Params.SensitiveNamespaces = append([]string(nil), r.Params.SensitiveNamespaces...)
	clone.Paths = append([]PathView(nil), r.Paths...)
	for i := range clone.Paths {
		clone.Paths[i].Route = append([]StepView(nil), r.Paths[i].Route...)
		for j := range clone.Paths[i].Route {
			clone.Paths[i].Route[j].Evidence = append([]RefView(nil), r.Paths[i].Route[j].Evidence...)
		}
	}
	clone.Cuts = append([]CutView(nil), r.Cuts...)
	clone.Bottlenecks = append([]Bottleneck(nil), r.Bottlenecks...)
	for i := range clone.Bottlenecks {
		clone.Bottlenecks[i].Eliminated = append([]PairView(nil), r.Bottlenecks[i].Eliminated...)
	}
	clone.Gaps = append([]GapView(nil), r.Gaps...)
	return clone
}

func TestHTMLDeterministicAndOrderIndependent(t *testing.T) {
	first := sampleReport()
	second := sampleReport()
	// Only the order changes; the data is identical, so the bytes must match.
	second.Paths = []PathView{second.Paths[1], second.Paths[0]}

	refs := []HopReference{{ID: "NR-001", Reference: "https://example.test/a"}}
	firstHTML := renderHTML(t, first, HTMLOptions{References: refs})
	secondHTML := renderHTML(t, second, HTMLOptions{References: refs})
	if firstHTML != secondHTML {
		t.Errorf("the HTML output depends on the order of the input paths")
	}

	// The order of the references must not change the output either.
	ordered := []HopReference{{ID: "NR-001", Reference: "https://example.test/a"}, {ID: "NR-002", Reference: "https://example.test/b"}}
	reversed := []HopReference{ordered[1], ordered[0]}
	if renderHTML(t, first, HTMLOptions{References: ordered}) != renderHTML(t, first, HTMLOptions{References: reversed}) {
		t.Errorf("the HTML output depends on the order of the references")
	}
}

func TestHTMLSharedEdgeKeepsConditionalConfidence(t *testing.T) {
	// The same (from,to,hop_id) edge appears as definite in one route and
	// conditional in another: the deduplicated edge must stay conditional, and
	// the result must not depend on the order.
	build := func(definiteFirst bool) Report {
		steps := []StepView{
			{From: "sa:app/a", To: "sa:app/b", HopID: "NR-001", Confidence: "definite"},
			{From: "sa:app/a", To: "sa:app/b", HopID: "NR-001", Confidence: "conditional"},
		}
		if !definiteFirst {
			steps[0], steps[1] = steps[1], steps[0]
		}
		return Report{
			SchemaVersion: SchemaVersion,
			Paths: []PathView{
				{ID: "p1", Source: "sa:app/a", Target: "target:cluster-admin", Hops: 1, Route: []StepView{steps[0]}},
				{ID: "p2", Source: "sa:app/a", Target: "target:cluster-admin", Hops: 1, Route: []StepView{steps[1]}},
			},
		}
	}
	for _, order := range []bool{true, false} {
		payload := graphPayloadOf(t, renderHTML(t, build(order), HTMLOptions{}))
		if len(payload.Edges) != 1 {
			t.Fatalf("expected one deduplicated edge, got %d", len(payload.Edges))
		}
		if payload.Edges[0].Confidence != "conditional" {
			t.Errorf("a shared edge drawn as %q, want conditional (definiteFirst=%v)", payload.Edges[0].Confidence, order)
		}
	}
}

func TestHTMLGraphOrderIsTotal(t *testing.T) {
	r := sampleReport()
	payload := graphPayloadOf(t, renderHTML(t, r, HTMLOptions{}))
	for i := 1; i < len(payload.Nodes); i++ {
		if payload.Nodes[i-1].ID > payload.Nodes[i].ID {
			t.Errorf("nodes are not ordered by id: %s before %s", payload.Nodes[i-1].ID, payload.Nodes[i].ID)
		}
	}
	for i := 1; i < len(payload.Edges); i++ {
		a, b := payload.Edges[i-1], payload.Edges[i]
		if a.From > b.From || (a.From == b.From && a.To > b.To) || (a.From == b.From && a.To == b.To && a.HopID > b.HopID) {
			t.Errorf("edges are not ordered by (from,to,hop_id): %+v before %+v", a, b)
		}
	}
}

func TestHTMLEmptyResult(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		Params:        Params{MaxDepth: 4, PathsPerPair: 3, Targets: []string{"cluster-admin"}},
		Gaps:          []GapView{{Kind: "missing-input", Subject: "target:node", Message: "not evaluated"}},
	}
	html := renderHTML(t, r, HTMLOptions{})
	if !strings.Contains(html, "no escalation paths found") {
		t.Errorf("the empty result is not stated")
	}
	if !strings.Contains(html, "target:node") {
		t.Errorf("the gap is not rendered")
	}
	if strings.Contains(html, `<div id="graph">`) {
		t.Errorf("an empty result still renders a graph container")
	}
	payload := graphPayloadOf(t, html)
	if len(payload.Nodes) != 0 || len(payload.Edges) != 0 {
		t.Errorf("the empty result carries a graph payload: %+v", payload)
	}
}

func TestHTMLReferenceLinks(t *testing.T) {
	r := sampleReport()
	r.Paths[0].Route[0].HopID = "NR-004"
	opts := HTMLOptions{References: []HopReference{
		{ID: "NR-004", Reference: "https://kubernetes.io/docs/x#bind-verb"},
	}}
	html := renderHTML(t, r, opts)
	if !strings.Contains(html, `href="https://kubernetes.io/docs/x#bind-verb"`) {
		t.Errorf("the catalog reference is not linked")
	}
	// A hop with no catalog entry (an engine edge) is rendered without a link
	// and is not an error.
	engineEdge := renderHTML(t, sampleReport(), HTMLOptions{})
	if strings.Contains(engineEdge, "rbac-cluster-admin</a>") {
		t.Errorf("an engine edge without a catalog entry got a reference link")
	}
	if !strings.Contains(engineEdge, "rbac-cluster-admin") {
		t.Errorf("the engine edge hop id is not rendered at all")
	}
}

func TestHTMLWritesGapsAndFooter(t *testing.T) {
	r := sampleReport()
	r.Gaps = []GapView{{Kind: "missing-input", Subject: "SecurityContextConstraints", Message: "absent"}}
	opts := HTMLOptions{Tool: ToolInfo{Version: "v0.1", Commit: "abc", Date: "2026-10-07", CatalogSHA256: "cat"}}
	html := renderHTML(t, r, opts)
	for _, want := range []string{"SecurityContextConstraints", "v0.1", "2026-10-07", "cat", "in the model and up to"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report does not contain %q", want)
		}
	}
}
