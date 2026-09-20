package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Every example printed in help must be a command the tree can parse. The
// audit examples were all written as `bodega audit --flag` while the flags
// live on the `events` subcommand, so all six exited 1 — help that fails when
// followed is worse than no help.
//
// Walks the whole tree rather than the one command that was wrong: the defect
// is that nothing checked, and checking one command leaves the rest unchecked.
func TestEveryHelpExampleParses(t *testing.T) {
	loadFrom(t, "{}")
	root := newRootCmd()

	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		for _, line := range exampleLines(cmd) {
			t.Run(line, func(t *testing.T) {
				assertParses(t, line)
			})
		}
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// exampleLines pulls the runnable `bodega …` invocations out of a command's
// Example block, and out of the indented lines following an "Examples:" header
// in its Long text. Indentation is what separates a command from a sentence
// that happens to open with the binary's name.
//
// A line carrying a shell construct is skipped: it is prose about a pipeline
// rather than a command to parse.
func exampleLines(cmd *cobra.Command) []string {
	var out []string

	collect := func(raw string) {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if !strings.HasPrefix(line, "bodega ") {
			return
		}
		if strings.ContainsAny(line, "|<>$`\"'") {
			return
		}
		out = append(out, line)
	}

	for _, raw := range strings.Split(cmd.Example, "\n") {
		collect(raw)
	}

	inExamples := false
	for _, raw := range strings.Split(cmd.Long, "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasSuffix(trimmed, "Examples:") || trimmed == "Example:" {
			inExamples = true
			continue
		}
		if trimmed == "" {
			inExamples = false
			continue
		}
		if !inExamples || raw == trimmed {
			continue // unindented: prose, not a command
		}
		collect(raw)
	}
	return out
}

func assertParses(t *testing.T, line string) {
	t.Helper()
	args := strings.Fields(line)[1:] // drop "bodega"

	// A fresh tree per example: ParseFlags mutates flag state, and a value
	// left behind by one example would mask the next one's failure.
	root := newRootCmd()
	target, rest, err := root.Find(args)
	if err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	if err := target.ParseFlags(rest); err != nil {
		t.Errorf("%q: %v (the flags live on a different command, or no longer exist)", line, err)
	}
}
