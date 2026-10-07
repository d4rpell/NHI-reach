package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table writes the report as an aligned text table (spec §4). One row per path
// shows the origin, the target, the hop count, the confidence, whether the route
// goes through a system identity and the best cut with its verification state.
// Rows are grouped by target, and the routes that start at a system identity are
// printed in a separate block. The gaps are printed last.
//
// The output depends only on the report, never on map iteration order, so equal
// analyses render equal bytes.
func Table(w io.Writer, r Report) error {
	r = r.Normalize()

	if len(r.Paths) == 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if err := writeHeader(tw); err != nil {
			return err
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "no escalation paths found"); err != nil {
			return err
		}
		return writeGaps(w, r.Gaps)
	}

	for _, target := range orderedTargets(r.Paths) {
		rows := pathsForTarget(r.Paths, target, false)
		systemRows := pathsForTarget(r.Paths, target, true)
		if len(rows) == 0 && len(systemRows) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "target: %s\n", nodeLabel(target)); err != nil {
			return err
		}
		if err := writeBlock(w, rows, r.Cuts); err != nil {
			return err
		}
		if len(systemRows) == 0 {
			continue
		}
		if _, err := fmt.Fprintln(w, "  system origins:"); err != nil {
			return err
		}
		if err := writeBlock(w, systemRows, r.Cuts); err != nil {
			return err
		}
	}
	return writeGaps(w, r.Gaps)
}

// writeBlock writes the header and the rows of one block through a tabwriter,
// propagating the write error of every row and of the final flush.
func writeBlock(w io.Writer, paths []PathView, cuts []CutView) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if err := writeHeader(tw); err != nil {
		return err
	}
	for _, path := range paths {
		if err := writeRow(tw, path, cuts); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeHeader(w io.Writer) error {
	_, err := fmt.Fprintln(w, "SOURCE\tTARGET\tHOPS\tCONFIDENCE\tVIA-SYSTEM\tBEST-CUT\tROUTE")
	return err
}

func writeRow(w io.Writer, path PathView, cuts []CutView) error {
	_, err := fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
		nodeLabel(path.Source), nodeLabel(path.Target), path.Hops, path.Confidence,
		yesNo(path.ViaSystem), bestCut(CutsOf(cuts, path.ID)), route(path))
	return err
}

func writeGaps(w io.Writer, gaps []GapView) error {
	if len(gaps) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\ngaps:"); err != nil {
		return err
	}
	for _, gap := range gaps {
		if _, err := fmt.Fprintf(w, "  %s: %s\n", gap.Subject, gap.Message); err != nil {
			return err
		}
	}
	return nil
}

// orderedTargets lists the distinct targets in ascending order.
func orderedTargets(paths []PathView) []string {
	var targets []string
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path.Target] {
			continue
		}
		seen[path.Target] = true
		targets = append(targets, path.Target)
	}
	return targets
}

// pathsForTarget returns the paths of one target, split by whether their origin
// is a system identity.
func pathsForTarget(paths []PathView, target string, system bool) []PathView {
	var out []PathView
	for _, path := range paths {
		if path.Target == target && path.SystemOrigin == system {
			out = append(out, path)
		}
	}
	return out
}

func bestCut(cuts []CutView) string {
	if len(cuts) == 0 {
		return "-"
	}
	cut := cuts[0]
	if cut.Verified {
		return cut.Change + " (verified)"
	}
	return cut.Change + " (unverified)"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "-"
}

func route(path PathView) string {
	out := nodeLabel(path.Source)
	for _, step := range path.Route {
		out += " -[" + step.HopID + "]-> " + nodeLabel(step.To)
	}
	return out
}

func nodeLabel(id string) string {
	for _, prefix := range []string{"sa:", "target:"} {
		if strings.HasPrefix(id, prefix) {
			return strings.TrimPrefix(id, prefix)
		}
	}
	return id
}
