package graph

import (
	"testing"

	"github.com/d4rpell/nhi-reach/internal/model"
)

func edge(from, to, hop string) model.Edge {
	return model.Edge{From: from, To: to, HopID: hop}
}

func TestShortestPathPrefersFewestHops(t *testing.T) {
	edges := []model.Edge{
		edge("a", "b", "NR-001"),
		edge("b", "d", "rbac-cluster-admin"),
		edge("a", "c", "NR-002"),
		edge("c", "b", "NR-002"),
		edge("a", "d", "rbac-cluster-admin"),
	}
	path, ok := ShortestPath(edges, "a", "d", 4)
	if !ok {
		t.Fatal("target reported unreachable")
	}
	if len(path) != 1 {
		t.Fatalf("path has %d hops, want the direct 1-hop path", len(path))
	}
	if path[0].HopID != "rbac-cluster-admin" {
		t.Errorf("path uses hop %q, want rbac-cluster-admin", path[0].HopID)
	}
}

func TestShortestPathRespectsMaxDepth(t *testing.T) {
	edges := []model.Edge{
		edge("a", "b", "NR-001"),
		edge("b", "c", "rbac-cluster-admin"),
	}
	if _, ok := ShortestPath(edges, "a", "c", 1); ok {
		t.Error("2-hop target reported reachable with --max-depth 1")
	}
	path, ok := ShortestPath(edges, "a", "c", 2)
	if !ok || len(path) != 2 {
		t.Fatalf("target with --max-depth 2: ok=%v hops=%d, want true/2", ok, len(path))
	}
}

func TestShortestPathUnreachable(t *testing.T) {
	edges := []model.Edge{edge("a", "b", "NR-001")}
	if path, ok := ShortestPath(edges, "a", "c", 4); ok || path != nil {
		t.Errorf("unreachable target returned path %v, ok=%v", path, ok)
	}
}

func TestShortestPathIsDeterministicAcrossEdgeOrder(t *testing.T) {
	edges := []model.Edge{
		edge("b", "d", "NR-009"),
		edge("a", "c", "NR-002"),
		edge("a", "b", "NR-001"),
		edge("c", "d", "NR-003"),
	}
	reversed := make([]model.Edge, len(edges))
	for i, e := range edges {
		reversed[len(edges)-1-i] = e
	}
	first, ok := ShortestPath(edges, "a", "d", 4)
	if !ok {
		t.Fatal("target unreachable")
	}
	second, ok := ShortestPath(reversed, "a", "d", 4)
	if !ok {
		t.Fatal("target unreachable with reversed edge order")
	}
	if len(first) != len(second) {
		t.Fatalf("path lengths differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].From != second[i].From || first[i].To != second[i].To || first[i].HopID != second[i].HopID {
			t.Errorf("hop %d differs between edge orders: %+v vs %+v", i, first[i], second[i])
		}
	}
}
