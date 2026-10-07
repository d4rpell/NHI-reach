package graph

import (
	"sort"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// Reach returns whether target is reachable from source in at most maxDepth hops
// and, when it is, the smallest number of hops that reaches it. A source that is
// its own target is reachable at distance 0.
//
// The result holds in the model and up to maxDepth only (spec §3 step 8, D-011);
// it is never a claim about the real cluster. Reachability does not depend on
// any enumeration budget (spec §3 step 5): it is the bounded enumeration that a
// budget may truncate, not this.
func Reach(edges []model.Edge, source, target string, maxDepth int) (int, bool) {
	if source == target {
		return 0, true
	}
	if maxDepth < 1 {
		return 0, false
	}

	adj := adjacency(edges)

	type step struct {
		node  string
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
		for _, edge := range adj[current.node] {
			if edge.To == target {
				return current.depth + 1, true
			}
			if visited[edge.To] {
				continue
			}
			visited[edge.To] = true
			queue = append(queue, step{node: edge.To, depth: current.depth + 1})
		}
	}
	return 0, false
}

// SimplePaths enumerates the simple paths from source to target — no node
// repeated — with at most maxDepth edges, and returns them ordered by (length,
// PathID) as spec §3 step 5 requires.
//
// budget caps the path extensions explored, an extension being one edge followed
// from a partial path. The search stops as soon as the budget is used up:
// explored is what it consumed and truncated reports whether it stopped early. A
// truncated enumeration is a partial list and never a complete one, so it is the
// caller's job to report it as a Gap. Reachability is not subject to this
// budget; use Reach for that.
//
// A source that is its own target yields no path: a path is a non-empty sequence
// of hops, so the zero-hop case has an empty edge sequence, not an empty path.
// Every claim holds in the model and up to maxDepth only.
func SimplePaths(edges []model.Edge, source, target string, maxDepth, budget int) (paths [][]model.Edge, explored int, truncated bool) {
	if source == target || maxDepth < 1 {
		return nil, 0, false
	}
	if budget < 1 {
		return nil, 0, true
	}

	adj := adjacency(edges)
	onPath := map[string]bool{source: true}
	var found [][]model.Edge

	var walk func(node string, depth int, path []model.Edge)
	walk = func(node string, depth int, path []model.Edge) {
		if truncated || depth >= maxDepth {
			return
		}
		for _, edge := range adj[node] {
			if truncated {
				return
			}
			if explored >= budget {
				truncated = true
				return
			}
			explored++

			next := make([]model.Edge, len(path)+1)
			copy(next, path)
			next[len(path)] = edge

			// A path stops at the target: a route that went through the target
			// and continued is not a route to it.
			if edge.To == target {
				found = append(found, next)
				continue
			}
			if onPath[edge.To] {
				continue
			}
			onPath[edge.To] = true
			walk(edge.To, depth+1, next)
			delete(onPath, edge.To)
		}
	}
	walk(source, 0, nil)

	sort.Slice(found, func(i, j int) bool {
		if len(found[i]) != len(found[j]) {
			return len(found[i]) < len(found[j])
		}
		return PathID(found[i]) < PathID(found[j])
	})
	return found, explored, truncated
}
