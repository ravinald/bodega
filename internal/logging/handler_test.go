package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSlogLevel(t *testing.T) {
	tests := []struct {
		verbosity int
		want      slog.Level
	}{
		{0, slog.LevelError},
		{1, slog.LevelWarn},
		{2, slog.LevelInfo},
		{3, slog.LevelDebug},
		{4, LevelTrace},
		{5, LevelTrace}, // clamped
	}
	for _, tc := range tests {
		got := SlogLevel(tc.verbosity)
		if got != tc.want {
			t.Errorf("SlogLevel(%d) = %v, want %v", tc.verbosity, got, tc.want)
		}
	}
}

func TestLevelName(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelError, "ERROR"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelDebug, "DEBUG"},
		{LevelTrace, "TRACE"},
		{slog.Level(-12), "TRACE"}, // below trace
	}
	for _, tc := range tests {
		got := LevelName(tc.level)
		if got != tc.want {
			t.Errorf("LevelName(%v) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestHandlerEnabled(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, slog.LevelWarn)

	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should not be enabled when min level is Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Warn should be enabled when min level is Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error should be enabled when min level is Warn")
	}
}

func TestHandlerOutput(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, slog.LevelInfo)

	r := slog.NewRecord(time.Date(2026, 4, 6, 14, 30, 0, 0, time.UTC), slog.LevelInfo, "test message", 0)
	r.AddAttrs(slog.String("key", "value"), slog.Int("count", 42))

	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	line := buf.String()
	if !strings.Contains(line, "14:30:00") {
		t.Errorf("missing timestamp in %q", line)
	}
	if !strings.Contains(line, "INFO") {
		t.Errorf("missing level in %q", line)
	}
	if !strings.Contains(line, "test message") {
		t.Errorf("missing message in %q", line)
	}
	if !strings.Contains(line, "key=value") {
		t.Errorf("missing key=value in %q", line)
	}
	if !strings.Contains(line, "count=42") {
		t.Errorf("missing count=42 in %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Error("output should end with newline")
	}
}

func TestHandlerDropsBelowLevel(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, slog.LevelError)

	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info should not be enabled at Error level")
	}
}

func TestHandlerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, slog.LevelInfo)
	h2 := h.WithAttrs([]slog.Attr{slog.String("component", "server")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	if err := h2.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if !strings.Contains(buf.String(), "component=server") {
		t.Errorf("pre-set attr missing in %q", buf.String())
	}
}

func TestHandlerWithGroup(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, slog.LevelInfo)
	h2 := h.WithGroup("http")

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "request", 0)
	r.AddAttrs(slog.String("method", "GET"))
	if err := h2.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if !strings.Contains(buf.String(), "http.method=GET") {
		t.Errorf("grouped attr missing in %q", buf.String())
	}
}

func TestHandlerQuotesSpecialValues(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, slog.LevelInfo)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	r.AddAttrs(slog.String("path", "/foo bar"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if !strings.Contains(buf.String(), `"/foo bar"`) {
		t.Errorf("value with spaces should be quoted: %q", buf.String())
	}
}

func TestNeedsQuoting(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"", true},
		{"simple", false},
		{"has space", true},
		{"has=equals", true},
		{`has"quote`, true},
		{"has\ttab", true},
		{"normal-value", false},
	}
	for _, tc := range tests {
		got := needsQuoting(tc.s)
		if got != tc.want {
			t.Errorf("needsQuoting(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
