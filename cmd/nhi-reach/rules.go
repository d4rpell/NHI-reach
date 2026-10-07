package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/d4rpell/nhi-reach/internal/hops"
	"github.com/spf13/cobra"
)

func newRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List the hop catalog (id, effect, status, title, reference)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRules(cmd.OutOrStdout())
		},
	}
}

// runRules writes the embedded hop catalog as an aligned table. The output
// depends only on the embedded file, so equal catalogs render equal bytes.
func runRules(w io.Writer) error {
	catalog, err := hops.Catalog()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tEFFECT\tSTATUS\tTITLE\tREFERENCE"); err != nil {
		return err
	}
	for _, entry := range catalog {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			entry.ID, entry.TargetEffect, entry.Status, entry.Title, entry.Reference); err != nil {
			return err
		}
	}
	return tw.Flush()
}
