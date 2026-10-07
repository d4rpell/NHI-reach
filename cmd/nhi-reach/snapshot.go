package main

import "github.com/spf13/cobra"

func newSnapshotCmd() *cobra.Command {
	var outDir string

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Dump the resource types of the MVP to a directory (read-only: get/list only)",
		Long: "Write the required Kubernetes/OpenShift resource types to DIR as JSON lists,\n" +
			"plus a manifest.json with the tool version, date, context and per-file hash.\n" +
			"Secret data/stringData are excluded before anything is written to disk.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented
		},
	}

	cmd.Flags().StringVarP(&outDir, "output", "o", "", "directory to write the snapshot to (required)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}
