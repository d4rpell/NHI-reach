package main

import (
	"errors"

	"github.com/spf13/cobra"
)

var errNotImplemented = errors.New("not implemented yet")

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "nhi-reach",
		Short: "Audit escalation paths from non-human identities in Kubernetes and OpenShift",
		Long: "nhi-reach is a read-only, offline-first tool that traces escalation paths\n" +
			"from non-human identities (service accounts) to privileged targets.\n" +
			"It never creates, modifies or executes anything in a cluster.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newSnapshotCmd(),
		newAnalyzeCmd(),
		newRulesCmd(),
		newVersionCmd(),
	)
	return root
}
