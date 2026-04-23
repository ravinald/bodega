package audit

import (
	"os"
	"os/user"
)

// CurrentActor returns the human invoking the current process, used as the
// Actor field on audit events from CLI and TUI callers. HTTP events should
// leave Actor empty and rely on ClientIP for attribution.
//
// Priority: $SUDO_USER → os/user (portable) → $USER → $USERNAME → "unknown".
// $SUDO_USER wins so that `sudo bodega ...` attributes the action to the
// human who escalated rather than to "root". A direct (non-sudo) invocation
// has $SUDO_USER unset and falls through to the effective user.
func CurrentActor() string {
	if v := os.Getenv("SUDO_USER"); v != "" {
		return v
	}
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
