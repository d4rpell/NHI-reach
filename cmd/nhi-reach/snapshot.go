package main

import (
	"context"
	"fmt"
	"io"

	"github.com/d4rpell/nhi-reach/internal/snapshot"
	"github.com/spf13/cobra"
)

func newSnapshotCmd() *cobra.Command {
	var (
		outDir   string
		kubeconf string
		context  string
	)

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Dump the resource types of the MVP to a directory (read-only: get/list only)",
		Long: "Write the required Kubernetes/OpenShift resource types to DIR as JSON lists,\n" +
			"plus a manifest.json with the per-object canonical hashes and a metadata.json\n" +
			"with the tool version, date, context and per-file hashes. Only get/list are\n" +
			"issued, enforced in code, and Secret data/stringData are excluded before\n" +
			"anything is written to disk. The result is verified by re-reading the\n" +
			"directory it wrote.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSnapshot(cmd.Context(), cmd.OutOrStdout(), outDir, kubeconf, context)
		},
	}

	cmd.Flags().StringVarP(&outDir, "output", "o", "", "directory to write the snapshot to (required, must not exist or be empty)")
	cmd.Flags().StringVar(&kubeconf, "kubeconfig", "", "path to the kubeconfig file (defaults to the standard locations)")
	cmd.Flags().StringVar(&context, "context", "", "kubeconfig context to use (defaults to the current one)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

// runSnapshot captures a live cluster into dir and verifies what it wrote.
func runSnapshot(ctx context.Context, w io.Writer, outDir, kubeconfig, contextName string) error {
	// A destination that cannot receive a snapshot is an input error (exit 3),
	// checked before the cluster is contacted.
	if err := snapshot.ValidateOutputDir(outDir); err != nil {
		return exitf(3, "%v", err)
	}
	cfg, effectiveContext, err := snapshot.RESTConfig(kubeconfig, contextName)
	if err != nil {
		return exitf(3, "%v", err)
	}
	client, err := snapshot.NewLiveClient(cfg)
	if err != nil {
		return exitf(3, "%v", err)
	}
	ix, err := snapshot.LoadLive(ctx, client)
	if err != nil {
		return exitf(3, "%v", err)
	}

	meta := snapshot.Metadata{
		Context:       effectiveContext,
		ServerVersion: client.ServerVersion(ctx),
	}
	if err := snapshot.WriteSnapshot(outDir, ix, meta); err != nil {
		// A capture that cannot be written or verified is an unclassified runtime
		// failure (exit 1), not an input error.
		return exitf(1, "%v", err)
	}

	manifest := ix.Manifest()
	if _, err := fmt.Fprintf(w, "wrote %d objects to %s\nsnapshot_sha256: %s\n", len(manifest.Objects), outDir, manifest.SHA256); err != nil {
		return err
	}
	return nil
}
