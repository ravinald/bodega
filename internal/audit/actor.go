package audit

import (
	"os"
	"os/user"
)

// CurrentActor returns the OS user invoking the current process, used as the
// Actor field on audit events from CLI and TUI callers. HTTP events should
// leave Actor empty and rely on ClientIP for attribution.
//
// Priority: os/user (portable) → $USER → $USERNAME (Windows) → "unknown".
func CurrentActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	return "unknown"
}
