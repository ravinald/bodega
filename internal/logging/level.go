// Package logging provides leveled structured logging built on log/slog.
package logging

import "log/slog"

// LevelTrace is a custom slog level below Debug, used for full request/response
// body logging and detailed S3 operation tracing.
const LevelTrace = slog.Level(-8)

// SlogLevel maps a user-facing verbosity integer (0–4) to a slog.Level.
//
//	0 → Error   (errors only)
//	1 → Warn    (+ warnings)
//	2 → Info    (+ HTTP requests, lifecycle events)
//	3 → Debug   (+ headers, S3 key resolution)
//	4 → Trace   (+ request/response bodies)
func SlogLevel(verbosity int) slog.Level {
	switch {
	case verbosity >= 4:
		return LevelTrace
	case verbosity >= 3:
		return slog.LevelDebug
	case verbosity >= 2:
		return slog.LevelInfo
	case verbosity >= 1:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

// LevelName returns a human-readable name for a slog.Level, including the
// custom Trace level.
func LevelName(l slog.Level) string {
	switch {
	case l <= LevelTrace:
		return "TRACE"
	case l <= slog.LevelDebug:
		return "DEBUG"
	case l <= slog.LevelInfo:
		return "INFO"
	case l <= slog.LevelWarn:
		return "WARN"
	default:
		return "ERROR"
	}
}
