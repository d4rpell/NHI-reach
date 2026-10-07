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
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// An unknown subcommand is an input error (spec §4, exit 3),
			// not the unclassified error cobra's default would produce.
			// With no arguments at all the root still just prints help.
			if len(args) == 0 {
				return cmd.Help()
			}
			return exitf(3, "unknown command %q", args[0])
		},
	}
	root.AddCommand(
		newSnapshotCmd(),
		newAnalyzeCmd(),
		newRulesCmd(),
		newVersionCmd(),
	)
	// A bad flag value or an unknown flag is an input error (spec §4, exit 3),
	// not the unclassified internal error that anything else maps to.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return exitf(3, "%v", err)
	})
	return root
}
