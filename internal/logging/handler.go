package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Handler is a slog.Handler that writes human-readable, single-line log records
// to an io.Writer. Thread-safe via an internal mutex.
//
// Format: 15:04:05 LEVEL message key=value key=value
type Handler struct {
	mu     sync.Mutex
	w      io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

// NewHandler creates a Handler that writes to w and drops records below minLevel.
func NewHandler(w io.Writer, minLevel slog.Leveler) *Handler {
	return &Handler{w: w, level: minLevel}
}

// Enabled reports whether the handler is configured to log at the given level.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

// Handle formats and writes a single log record.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var buf []byte

	// Timestamp.
	buf = append(buf, r.Time.Format(time.TimeOnly)...)
	buf = append(buf, ' ')

	// Level name, padded to 5 chars for alignment.
	name := LevelName(r.Level)
	buf = append(buf, name...)
	for i := len(name); i < 5; i++ {
		buf = append(buf, ' ')
	}
	buf = append(buf, ' ')

	// Message. Escaped rather than quoted: it is the human-readable head of
	// the line and quoting every record would churn the format, but an
	// unescaped newline in it ends the record and starts one the caller
	// wrote. Attribute values below are escaped by their own path.
	buf = appendEscaped(buf, r.Message)

	// Pre-set attrs from WithAttrs.
	for _, a := range h.attrs {
		buf = appendAttr(buf, h.groups, a)
	}

	// Record-level attrs.
	r.Attrs(func(a slog.Attr) bool {
		buf = appendAttr(buf, h.groups, a)
		return true
	})

	buf = append(buf, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf)
	return err
}

// WithAttrs returns a new Handler with the given attributes pre-set on every
// record.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := h.clone()
	h2.attrs = append(h2.attrs, attrs...)
	return h2
}

// WithGroup returns a new Handler where all subsequent attributes are nested
// under the given group name.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := h.clone()
	h2.groups = append(h2.groups, name)
	return h2
}

func (h *Handler) clone() *Handler {
	return &Handler{
		w:      h.w,
		level:  h.level,
		attrs:  append([]slog.Attr(nil), h.attrs...),
		groups: append([]string(nil), h.groups...),
	}
}

// appendAttr formats a single key=value pair into buf.
func appendAttr(buf []byte, groups []string, a slog.Attr) []byte {
	a.Value = a.Value.Resolve()

	// Skip empty attrs.
	if a.Equal(slog.Attr{}) {
		return buf
	}

	buf = append(buf, ' ')

	// Prefix with group names.
	for _, g := range groups {
		buf = append(buf, g...)
		buf = append(buf, '.')
	}

	buf = append(buf, a.Key...)
	buf = append(buf, '=')

	switch a.Value.Kind() {
	case slog.KindGroup:
		attrs := a.Value.Group()
		for _, ga := range attrs {
			buf = appendAttr(buf, append(groups, a.Key), ga)
		}
	default:
		// Every kind goes through one quoting path. An error attr renders
		// through KindAny, and "error", err is the most common attribute in
		// the tree — quoting only KindString escaped the URL a caller passed
		// as a string and left the identical URL unescaped where it arrived
		// wrapped in an error. A caller cannot be relied on to remember %q;
		// the handler is the one place that sees every value.
		buf = appendValue(buf, a.Value.String())
	}

	return buf
}

// appendValue writes one attribute value, quoted when it carries anything that
// would otherwise break the key=value framing.
func appendValue(buf []byte, val string) []byte {
	if needsQuoting(val) {
		return append(buf, fmt.Sprintf("%q", val)...)
	}
	return append(buf, val...)
}

// appendEscaped writes s with control characters replaced by their Go escapes,
// leaving printable bytes (spaces included) alone. Used where the output is not
// quoted and so cannot rely on %q to do it.
func appendEscaped(buf []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != 0x7f {
			buf = append(buf, c)
			continue
		}
		switch c {
		case '\n':
			buf = append(buf, `\n`...)
		case '\r':
			buf = append(buf, `\r`...)
		case '\t':
			buf = append(buf, `\t`...)
		default:
			buf = append(buf, fmt.Sprintf(`\x%02x`, c)...)
		}
	}
	return buf
}

// needsQuoting returns true if a string value should be quoted in log output.
func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for _, c := range s {
		if c <= ' ' || c == '"' || c == '=' {
			return true
		}
	}
	return false
}
