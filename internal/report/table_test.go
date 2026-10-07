package report

import (
	"strings"
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
)

func path(source string, edges ...model.Edge) model.Path {
	return model.Path{ID: source, Source: source, Target: "target:cluster-admin", Edges: edges}
}

func TestTableRendersPathsInOrder(t *testing.T) {
	paths := []model.Path{
		path("sa:app/deployer",
			model.Edge{From: "sa:app/deployer", To: "sa:app/ops-admin", HopID: "NR-001", Confidence: "definite"},
			model.Edge{From: "sa:app/ops-admin", To: "target:cluster-admin", HopID: "rbac-cluster-admin", Confidence: "definite"},
		),
		path("sa:app/ops-admin",
			model.Edge{From: "sa:app/ops-admin", To: "target:cluster-admin", HopID: "rbac-cluster-admin", Confidence: "definite"},
		),
	}

	var buf strings.Builder
	if err := Table(&buf, paths, nil); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "SOURCE") || !strings.Contains(out, "CONFIDENCE") {
		t.Errorf("table lacks a header: %q", out)
	}
	if !strings.Contains(out, "[NR-001]") || !strings.Contains(out, "[rbac-cluster-admin]") {
		t.Errorf("route does not show the hop ids:\n%s", out)
	}
	if strings.Contains(out, "target:cluster-admin") {
		t.Errorf("target column still shows the internal node id:\n%s", out)
	}

	// Assert the source column of each data row: searching for the identity
	// anywhere in the output would also match it inside another row's route.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := [][3]string{
		{"app/deployer", "cluster-admin", "2"},
		{"app/ops-admin", "cluster-admin", "1"},
	}
	if len(lines) != len(want)+1 {
		t.Fatalf("table has %d lines, want a header and %d rows:\n%s", len(lines), len(want), out)
	}
	for i, expected := range want {
		fields := strings.Fields(lines[i+1])
		if len(fields) < 3 {
			t.Fatalf("row %d has %d columns:\n%s", i, len(fields), out)
		}
		if fields[0] != expected[0] || fields[1] != expected[1] || fields[2] != expected[2] {
			t.Errorf("row %d is %v, want %v", i, fields[:3], expected)
		}
	}
}

func TestTableReportsConditionalConfidence(t *testing.T) {
	paths := []model.Path{path("sa:app/ci",
		model.Edge{From: "sa:app/ci", To: "target:cluster-admin", HopID: "NR-001", Confidence: "conditional"},
	)}
	var buf strings.Builder
	if err := Table(&buf, paths, nil); err != nil {
		t.Fatalf("Table: %v", err)
	}
	if !strings.Contains(buf.String(), "conditional") {
		t.Errorf("conditional edge rendered as definite:\n%s", buf.String())
	}
}

func TestTableReportsNoPathsAndGaps(t *testing.T) {
	var buf strings.Builder
	gaps := []model.Gap{{Kind: "missing-input", Subject: "Pod", Message: "snapshot has no pods"}}
	if err := Table(&buf, nil, gaps); err != nil {
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
