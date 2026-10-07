package main

import (
	"github.com/d4rpell/nhi-reach/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit and rules catalog hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Printf("nhi-reach version %s\n", version.Version)
			cmd.Printf("commit:        %s\n", version.Commit)
			cmd.Printf("build date:    %s\n", version.Date)
			cmd.Printf("rules catalog: %s\n", version.CatalogHash)
			return nil
		},
	}
}
