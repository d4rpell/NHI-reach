package report

import (
	"encoding/json"
	"io"
)

// JSON writes the report as the versioned JSON schema of spec §4. The encoding
// is deterministic: the field order is the struct order, every collection is a
// slice in a fixed order (never a map) and every empty collection is [], never
// null. The output ends with a newline.
func JSON(w io.Writer, r Report) error {
	data, err := json.MarshalIndent(r.Normalize(), "", "  ")
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}
