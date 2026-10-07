package version

import "testing"

func TestDefaultsAreNonEmpty(t *testing.T) {
	for name, got := range map[string]string{
		"Version":     Version,
		"Commit":      Commit,
		"Date":        Date,
		"CatalogHash": CatalogHash,
	} {
		if got == "" {
			t.Errorf("%s default is empty", name)
		}
	}
}
