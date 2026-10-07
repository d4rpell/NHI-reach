package report

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func ref(kind, namespace, name string) RefView {
	return RefView{APIVersion: "v1", Kind: kind, Namespace: namespace, Name: name, SHA256: "sha-" + name}
}

func step(from, to, hopID, confidence string) StepView {
	return StepView{From: from, To: to, HopID: hopID, Confidence: confidence, Evidence: []RefView{ref("RoleBinding", "app", "b")}}
}

func path(id, source, target string, systemOrigin bool, steps ...StepView) PathView {
	return PathView{
		ID:           id,
		Source:       source,
		Target:       target,
		Hops:         len(steps),
		Confidence:   "definite",
		SystemOrigin: systemOrigin,
		Route:        steps,
	}
}

func sampleReport() Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Params:        Params{MaxDepth: 4, PathsPerPair: 3, Targets: []string{"cluster-admin"}},
		Paths: []PathView{
			path("p1", "sa:app/deployer", "target:cluster-admin", false,
				step("sa:app/deployer", "sa:app/ops-admin", "NR-001", "conditional"),
				step("sa:app/ops-admin", "target:cluster-admin", "rbac-cluster-admin", "definite"),
			),
			path("p2", "sa:app/ops-admin", "target:cluster-admin", false,
				step("sa:app/ops-admin", "target:cluster-admin", "rbac-cluster-admin", "definite"),
			),
		},
		Cuts: []CutView{{
			PathID:   "p1",
			Grant:    GrantView{Object: ref("RoleBinding", "app", "b"), Kind: "binding-subject", Detail: "subject ServiceAccount app/deployer"},
			Change:   "remove subject ServiceAccount app/deployer from RoleBinding app/b",
			Verified: true,
		}},
		Bottlenecks:         []Bottleneck{{Change: "remove x", Eliminated: []PairView{{Source: "sa:app/deployer", Target: "target:cluster-admin"}}}},
		CoverComplete:       true,
		Gaps:                []GapView{{Kind: "missing-input", Subject: "Pod", Message: "snapshot has no pods"}},
		InputManifestSHA256: "manifest-sha",
		RulesCatalogSHA256:  "catalog-sha",
	}
}

func TestTableRendersGroupedRows(t *testing.T) {
	var buf strings.Builder
	if err := Table(&buf, sampleReport()); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"SOURCE", "TARGET", "HOPS", "CONFIDENCE", "VIA-SYSTEM", "BEST-CUT", "target: cluster-admin", "[NR-001]", "[rbac-cluster-admin]"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sa:app/deployer") {
		t.Errorf("table shows the internal node id instead of a label:\n%s", out)
	}
	if !strings.Contains(out, "verified") {
		t.Errorf("best cut does not show its verification state:\n%s", out)
	}
}

func TestTableSeparatesSystemOrigins(t *testing.T) {
	rep := sampleReport()
	rep.Paths = append(rep.Paths, path("p3", "sa:kube-system/root", "target:cluster-admin", true,
		step("sa:kube-system/root", "target:cluster-admin", "rbac-cluster-admin", "definite")))

	var buf strings.Builder
	if err := Table(&buf, rep); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "system origins:") {
		t.Fatalf("system origins are not in a separate block:\n%s", out)
	}
	systemAt := strings.Index(out, "system origins:")
	if !strings.Contains(out[systemAt:], "kube-system/root") {
		t.Errorf("the system origin is not in the system block:\n%s", out)
	}
	if strings.Contains(out[:systemAt], "kube-system/root") {
		t.Errorf("the system origin appears in the application block:\n%s", out)
	}
}

func TestTableReportsNoPathsAndGaps(t *testing.T) {
	rep := Report{SchemaVersion: SchemaVersion, Gaps: []GapView{{Kind: "missing-input", Subject: "Pod", Message: "snapshot has no pods"}}}
	var buf strings.Builder
	if err := Table(&buf, rep); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no escalation paths found") {
		t.Errorf("empty result is not stated:\n%s", out)
	}
	if !strings.Contains(out, "gaps:") || !strings.Contains(out, "snapshot has no pods") {
		t.Errorf("gaps are not reported:\n%s", out)
	}
}

func TestJSONIsDeterministicAndSnakeCase(t *testing.T) {
	var first, second strings.Builder
	if err := JSON(&first, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	// Shuffle the path order: the rendered output must not change.
	rep := sampleReport()
	rep.Paths[0], rep.Paths[1] = rep.Paths[1], rep.Paths[0]
	if err := JSON(&second, rep); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if first.String() != second.String() {
		t.Errorf("JSON depends on path order\n--- first ---\n%s\n--- second ---\n%s", first.String(), second.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(first.String()), &decoded); err != nil {
		t.Fatalf("JSON is not valid: %v\n%s", err, first.String())
	}
	for _, key := range []string{"schema_version", "params", "paths", "cuts", "bottlenecks", "cover_complete", "gaps", "input_manifest_sha256", "rules_catalog_sha256"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON lacks the top-level key %q:\n%s", key, first.String())
		}
	}
	if strings.Contains(first.String(), "apiVersion") {
		t.Errorf("JSON is not snake_case (found apiVersion):\n%s", first.String())
	}
	if !strings.HasSuffix(first.String(), "}\n") {
		t.Errorf("JSON does not end with a newline:\n%q", first.String())
	}
}

func TestJSONRendersEmptyCollectionsAsArrays(t *testing.T) {
	rep := Report{SchemaVersion: SchemaVersion}
	var buf strings.Builder
	if err := JSON(&buf, rep); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "null") {
		t.Errorf("empty collections render as null:\n%s", out)
	}
	for _, want := range []string{`"paths": []`, `"cuts": []`, `"gaps": []`, `"bottlenecks": []`, `"targets": []`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON lacks %q:\n%s", want, out)
		}
	}
}

func TestJSONCarriesCutsWithPathID(t *testing.T) {
	var buf strings.Builder
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"path_id": "p1"`) {
		t.Errorf("a cut is not tied to its path:\n%s", buf.String())
	}
}

// failAtWriter fails exactly on the nth write and accepts every other one. It
// reproduces a writer whose failure lands on a single call (for instance the
// flush of a block) and whose later writes succeed, so a renderer that drops
// that one error returns nil even though it emitted an incomplete report.
type failAtWriter struct {
	failAt int
	writes int
}

func (w *failAtWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errors.New("write failed")
	}
	return len(p), nil
}

func TestTablePropagatesWriteErrors(t *testing.T) {
	// Count the writes a successful render performs, then fail on each one in
	// turn: every failure must surface as an error.
	counting := &failAtWriter{failAt: -1}
	if err := Table(counting, sampleReport()); err != nil {
		t.Fatalf("baseline render failed: %v", err)
	}
	if counting.writes < 3 {
		t.Fatalf("the baseline render made %d writes; the test cannot distinguish calls", counting.writes)
	}
	for at := 1; at <= counting.writes; at++ {
		w := &failAtWriter{failAt: at}
		if err := Table(w, sampleReport()); err == nil {
			t.Errorf("Table returned nil after write %d of %d failed", at, counting.writes)
		}
	}
}
