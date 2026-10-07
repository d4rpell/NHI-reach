// Package graph holds the reachability algorithms of the analysis.
//
// The light vertical implements only the shortest path between one origin and
// one target. Full path enumeration, cut verification and bottleneck coverage
// belong to T1-05.
package graph

import (
	"sort"
	"strconv"
	"strings"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// ShortestPath returns the fewest-edge path from source to target, and whether
// the target is reachable within maxDepth hops at all. Reachability is claimed
// only "in the model and up to maxDepth"; it is never a claim about the real
// cluster.
//
// Ties are broken deterministically: at each node the outgoing edges are
// explored in ascending order of their total key, so the result does not depend
// on the order in which the edges were produced.
func ShortestPath(edges []model.Edge, source, target string, maxDepth int) ([]model.Edge, bool) {
	if source == target {
		return nil, true
	}
	if maxDepth < 1 {
		return nil, false
	}

	adjacency := map[string][]model.Edge{}
	for _, edge := range edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge)
	}
	for from := range adjacency {
		neighbours := adjacency[from]
		sortEdges(neighbours)
		adjacency[from] = neighbours
	}

	type step struct {
		node  string
		path  []model.Edge
		depth int
	}
	queue := []step{{node: source}}
	visited := map[string]bool{source: true}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= maxDepth {
			continue
		}
		for _, edge := range adjacency[current.node] {
			path := make([]model.Edge, len(current.path)+1)
			copy(path, current.path)
			path[len(current.path)] = edge
			if edge.To == target {
				return path, true
			}
			if visited[edge.To] {
				continue
			}
			visited[edge.To] = true
			queue = append(queue, step{node: edge.To, path: path, depth: current.depth + 1})
		}
	}
	return nil, false
}

// sortEdges orders edges by the total key of edgeKey. Two edges with the same
// key agree on every field the model carries, so swapping them is not
// observable: the order is deterministic for any input order.
func sortEdges(edges []model.Edge) {
	keys := make([]string, len(edges))
	for i, edge := range edges {
		keys[i] = edgeKey(edge)
	}
	sort.Sort(&edgeSorter{edges: edges, keys: keys})
}

type edgeSorter struct {
	edges []model.Edge
	keys  []string
}

func (s *edgeSorter) Len() int           { return len(s.edges) }
func (s *edgeSorter) Less(i, j int) bool { return s.keys[i] < s.keys[j] }
func (s *edgeSorter) Swap(i, j int) {
	s.edges[i], s.edges[j] = s.edges[j], s.edges[i]
	s.keys[i], s.keys[j] = s.keys[j], s.keys[i]
}

// edgeKey is a total and injective ordering key over every field of an edge.
// Each field is written length-prefixed, so two different edges can never
// produce the same key — not even if a value contains the separator itself.
func edgeKey(edge model.Edge) string {
	var b strings.Builder
	writeField(&b, edge.From)
	writeField(&b, edge.To)
	writeField(&b, edge.HopID)
	writeField(&b, edge.Confidence)
	for _, ref := range edge.Evidence {
		b.WriteByte('E')
		writeField(&b, ref.APIVersion)
		writeField(&b, ref.Kind)
		writeField(&b, ref.Namespace)
		writeField(&b, ref.Name)
		writeField(&b, ref.SHA256)
	}
	for _, grant := range edge.Grants {
		b.WriteByte('G')
		writeField(&b, grant.Kind)
		writeField(&b, grant.Detail)
		writeField(&b, grant.Object.APIVersion)
		writeField(&b, grant.Object.Kind)
		writeField(&b, grant.Object.Namespace)
		writeField(&b, grant.Object.Name)
		writeField(&b, grant.Object.SHA256)
	}
	return b.String()
}

func writeField(b *strings.Builder, value string) {
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteByte(':')
	b.WriteString(value)
}
