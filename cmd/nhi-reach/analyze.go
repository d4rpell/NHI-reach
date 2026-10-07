package main

import "github.com/spf13/cobra"

func newAnalyzeCmd() *cobra.Command {
	var (
		fromDir       string
		live          bool
		output        string
		outFile       string
		maxDepth      int
		pathsPerPair  int
		fromIdentity  string
		targets       []string
		sensitiveNS   string
		systemNS      string
		includeSystem bool
		failOn        string
	)

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Trace escalation paths from non-human identities to privileged targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented
		},
	}

	f := cmd.Flags()
	f.StringVar(&fromDir, "from", "", "directory holding a snapshot written by `nhi-reach snapshot`")
	f.BoolVar(&live, "live", false, "analyze a live cluster (read-only: get/list only)")
	f.StringVarP(&output, "output", "o", "table", "output format: table|json|html")
	f.StringVar(&outFile, "out", "", "write the report to FILE instead of stdout")
	f.IntVar(&maxDepth, "max-depth", 4, "maximum hop depth")
	f.IntVar(&pathsPerPair, "paths-per-pair", 3, "maximum number of paths reported per origin/target pair")
	f.StringVar(&fromIdentity, "from-identity", "", "restrict the origin to a single ns/sa")
	f.StringArrayVar(&targets, "target", []string{"cluster-admin", "node", "secrets"}, "target: cluster-admin|node|secrets (repeatable)")
	f.StringVar(&sensitiveNS, "sensitive-ns", "", "comma-separated namespaces treated as sensitive")
	f.StringVar(&systemNS, "system-ns", "", "comma-separated namespaces treated as system")
	f.BoolVar(&includeSystem, "include-system", false, "include system identities as origins")
	f.StringVar(&failOn, "fail-on", "none", "exit non-zero on findings: none|any")
	return cmd
}
