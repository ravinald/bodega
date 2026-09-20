package audit

import (
	"strings"

	"github.com/ravinald/jsondiff"
)

// FormatDiff computes a JSON diff between before and after states and returns
// a human-readable string suitable for storing in an audit event's Details field.
//
// Special cases:
//   - before == nil (create): returns the full "after" JSON
//   - after == nil (delete): returns "deleted: " + the full "before" JSON
//   - no changes: returns "no changes"
func FormatDiff(before, after []byte) string {
	if before == nil && after == nil {
		return ""
	}
	if before == nil {
		// Create: show the full new state.
		return "created:\n" + string(after)
	}
	if after == nil {
		// Delete: show what was removed.
		return "deleted:\n" + string(before)
	}

	opts := jsondiff.DiffOptions{
		ContextLines: 2,
		SortJSON:     true,
	}

	diffs, err := jsondiff.Diff(before, after, opts)
	if err != nil {
		// Fallback: just show after state.
		return "after:\n" + string(after)
	}

	// Check if there are any actual changes.
	hasChanges := false
	for _, d := range diffs {
		if d.Type != jsondiff.DiffTypeEqual {
			hasChanges = true
			break
		}
	}
	if !hasChanges {
		return "no changes"
	}

	// Format as a plain-text unified diff (no ANSI colors for storage).
	var sb strings.Builder
	for _, d := range diffs {
		switch d.Type {
		case jsondiff.DiffTypeAdded:
			sb.WriteString("+ ")
			sb.WriteString(d.Content)
			sb.WriteByte('\n')
		case jsondiff.DiffTypeRemoved:
			sb.WriteString("- ")
			sb.WriteString(d.Content)
			sb.WriteByte('\n')
		case jsondiff.DiffTypeEqual:
			sb.WriteString("  ")
			sb.WriteString(d.Content)
			sb.WriteByte('\n')
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}
