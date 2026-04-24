package tui

// splitArgs tokenises a shell-like line, respecting quoted strings.
// Ported from internal/shell so the tui package has no dependency on shell.
func splitArgs(line string) []string {
	var args []string
	var current []rune
	inQuote := false
	quoteChar := rune(0)

	for _, r := range line {
		switch {
		case inQuote && r == quoteChar:
			inQuote = false
		case !inQuote && (r == '"' || r == '\''):
			inQuote = true
			quoteChar = r
		case !inQuote && (r == ' ' || r == '\t'):
			if len(current) > 0 {
				args = append(args, string(current))
				current = current[:0]
			}
		default:
			current = append(current, r)
		}
	}
	if len(current) > 0 {
		args = append(args, string(current))
	}
	return args
}

// extractFlag scans args for "--flag value", removes the pair, and returns
// the value and the remaining args. Returns empty string if absent.
func extractFlag(args []string, flag string) (string, []string) {
	var value string
	var remaining []string
	i := 0
	for i < len(args) {
		if args[i] == flag && i+1 < len(args) {
			value = args[i+1]
			i += 2
		} else {
			remaining = append(remaining, args[i])
			i++
		}
	}
	return value, remaining
}
