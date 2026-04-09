package builder

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// DetectBuildEnv captures the current build server's environment.
// Called once per build invocation; the result is stamped onto entries.
func DetectBuildEnv(bodegaVersion string) *manifest.BuildEnv {
	env := &manifest.BuildEnv{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Bodega:   bodegaVersion,
		BuiltAt:  time.Now().UTC().Format(time.RFC3339),
	}

	env.OSRelease = readOSRelease()
	env.Python = cmdVersion("python3", "--version")
	env.Go = cmdVersion("go", "version")
	env.Rust = cmdVersion("rustc", "--version")

	return env
}

// readOSRelease parses /etc/os-release for PRETTY_NAME.
func readOSRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			val = strings.Trim(val, "\"")
			return val
		}
	}
	return ""
}

// StampGitEntry sets BuildEnv and auto-detects Platform on a git entry.
func (c *Config) StampGitEntry(store *manifest.Store, name string) {
	e := store.FindGit(name)
	if e == nil {
		return
	}
	e.BuildEnv = c.GetBuildEnv()
	if e.Platform == "" {
		e.Platform = e.BuildEnv.Platform
	}
	_ = store.SaveGit()
}

// StampBinaryEntry sets BuildEnv and auto-detects Platform on a binary entry.
func (c *Config) StampBinaryEntry(store *manifest.Store, name string) {
	e := store.FindBinary(name)
	if e == nil {
		return
	}
	e.BuildEnv = c.GetBuildEnv()
	if e.Platform == "" {
		e.Platform = e.BuildEnv.Platform
	}
	_ = store.SaveBinary()
}

// StampGomodEntry sets BuildEnv on a gomod entry (platform is always "any").
func (c *Config) StampGomodEntry(store *manifest.Store, name string) {
	e := store.FindGomod(name)
	if e == nil {
		return
	}
	e.BuildEnv = c.GetBuildEnv()
	if e.Platform == "" {
		e.Platform = "any"
	}
	_ = store.SaveGomod()
}

// StampHelmEntry sets BuildEnv on a helm entry (platform is always "any").
func (c *Config) StampHelmEntry(store *manifest.Store, name string) {
	e := store.FindHelm(name)
	if e == nil {
		return
	}
	e.BuildEnv = c.GetBuildEnv()
	if e.Platform == "" {
		e.Platform = "any"
	}
	_ = store.SaveHelm()
}

// StampNpmEntry sets BuildEnv on an npm entry (platform is always "any").
func (c *Config) StampNpmEntry(store *manifest.Store, name string) {
	e := store.FindNpm(name)
	if e == nil {
		return
	}
	e.BuildEnv = c.GetBuildEnv()
	if e.Platform == "" {
		e.Platform = "any"
	}
	_ = store.SaveNpm()
}

// cmdVersion runs a command and returns its first line of output, trimmed.
// Returns empty string if the command is not found or fails.
func cmdVersion(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	// Some tools output "Python 3.12.3" or "go version go1.24.2 linux/amd64".
	// Return the full first line -- it's descriptive enough.
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	return line
}
