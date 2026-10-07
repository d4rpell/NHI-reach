package main

import "github.com/spf13/cobra"

func newRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List the hop catalog (id, title, reference, status)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented
		},
	}
}
