// Package version holds build metadata injected at link time with -ldflags.
package version

var (
	Version     = "dev"
	Commit      = "none"
	Date        = "unknown"
	CatalogHash = "unknown"
)
