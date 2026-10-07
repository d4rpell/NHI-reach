// Package report renders the analysis result.
//
// The light vertical ships the table renderer only; JSON and the self-contained
// HTML report belong to T2-01 and T2-03.
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/d4rpell/nhi-reach/internal/model"
)

// Table writes the found paths and the gaps of the analysis as an aligned text
// table. The output depends only on its arguments, never on map iteration
// order, so equal analyses render equal bytes.
func Table(w io.Writer, paths []model.Path, gaps []model.Gap) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SOURCE\tTARGET\tHOPS\tCONFIDENCE\tROUTE"); err != nil {
		return err
	}
	for _, path := range paths {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
			nodeLabel(path.Source), nodeLabel(path.Target), len(path.Edges), confidence(path), route(path)); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(paths) == 0 {
		if _, err := fmt.Fprintln(w, "no escalation paths found"); err != nil {
			return err
		}
	}
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

func confidence(path model.Path) string {
	for _, edge := range path.Edges {
		if edge.Confidence != "definite" {
			return "conditional"
		}
	}
	return "definite"
}

func route(path model.Path) string {
	out := nodeLabel(path.Source)
	for _, edge := range path.Edges {
		out += " -[" + edge.HopID + "]-> " + nodeLabel(edge.To)
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
