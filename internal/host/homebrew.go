package host

import "os"

// CheckHomebrew reports whether Homebrew is installed and configured to
// auto-update. Homebrew is not as opaque as snap or flatpak (the formulae
// are inspectable) but `brew update` reaches taps directly, and the
// default `brew install` runs `brew update` first unless HOMEBREW_NO_AUTO_UPDATE
// is set.
//
// Cross-platform: Homebrew runs on macOS (/opt/homebrew or /usr/local) and
// Linux (/home/linuxbrew/.linuxbrew).
func CheckHomebrew() Finding {
	f := Finding{Check: "homebrew"}

	installed := homebrewPrefix() != ""
	if !installed {
		f.Status = StatusOK
		f.Detail = "Homebrew not installed"
		return f
	}

	noAutoUpdate := os.Getenv("HOMEBREW_NO_AUTO_UPDATE")
	if noAutoUpdate == "" || noAutoUpdate == "0" {
		f.Status = StatusWarn
		f.Detail = "Homebrew installed with auto-update on; `brew install` will fetch tap metadata from upstream before resolving packages"
		f.Remediation = "export HOMEBREW_NO_AUTO_UPDATE=1 (per-user) or set it in the system profile"
		return f
	}

	f.Status = StatusOK
	f.Detail = "Homebrew installed with HOMEBREW_NO_AUTO_UPDATE set; auto-refresh suppressed"
	return f
}

// homebrewPrefix returns the path of the installed Homebrew root, or empty
// string when no installation is detected.
func homebrewPrefix() string {
	for _, p := range []string{
		"/opt/homebrew",          // Apple Silicon macOS
		"/usr/local/Homebrew",    // Intel macOS
		"/home/linuxbrew/.linuxbrew", // Linux
	} {
		if exists(p) {
			return p
		}
	}
	return ""
}
