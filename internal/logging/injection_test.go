package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestAttrValuesCannotForgeALogLine is the answer to CodeQL's go/log-injection
// on every handler that logs a package name from a request body.
//
// The attack is a newline in an attacker-controlled value: one log record
// becomes two, and the forged second line can claim whatever the reader
// trusts. needsQuoting treats every byte at or below 0x20 as needing quoting,
// and quoting runs the value through %q, so a control character reaches the
// stream escaped. Nothing here relies on the caller sanitizing first, which is
// what makes the finding a false positive rather than a latent bug.
func TestAttrValuesCannotForgeALogLine(t *testing.T) {
	forged := []struct {
		name  string
		value string
	}{
		{"newline", "curl\n12:00:00 ERROR the server has been compromised"},
		{"carriage return", "curl\r12:00:00 ERROR forged"},
		{"crlf", "curl\r\n12:00:00 ERROR forged"},
		{"tab and space", "curl\tname with spaces"},
		{"bare control byte", "curl\x00\x07"},
		{"quotes", `curl" forged="yes`},
	}

	for _, tc := range forged {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(NewHandler(&buf, slog.LevelDebug))
			logger.Error("save package failed", "type", "apt", "name", tc.value)

			out := buf.String()
			if got := strings.Count(out, "\n"); got != 1 {
				t.Fatalf("one record produced %d lines, so a value forged a log entry:\n%s", got, out)
			}
			if strings.Contains(out, "the server has been compromised") && !strings.Contains(out, `\n`) {
				t.Errorf("the injected text reached the stream unescaped:\n%s", out)
			}
			if strings.ContainsAny(strings.TrimSuffix(out, "\n"), "\r\n\x00") {
				t.Errorf("a raw control byte reached the stream:\n%q", out)
			}
		})
	}
}

// TestNeedsQuotingCoversControlBytes pins the predicate the test above depends
// on, across the whole range rather than at the few values a table would name.
func TestNeedsQuotingCoversControlBytes(t *testing.T) {
	for b := 0; b <= 0x20; b++ {
		if !needsQuoting(string(rune(b))) {
			t.Errorf("needsQuoting(%#x) = false; a control byte would reach the log stream raw", b)
		}
	}
	if needsQuoting("ordinary-package-name") {
		t.Error("an ordinary name is being quoted, which would churn every log line")
	}
}
