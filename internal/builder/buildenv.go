package builder

import (
	"bufio"
	"context"
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

// stampVersion updates BuildEnv and Platform on a specific VersionEntry within
// a PackageManifest and saves the manifest. It matches the entry by Version or
// Ref field.
func stampVersion(ctx context.Context, store *manifest.Store, typ, name string, targetVE manifest.VersionEntry, env *manifest.BuildEnv, defaultPlatform string) {
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		return
	}

	targetKey := targetVE.Version
	if targetKey == "" {
		targetKey = targetVE.Ref
	}

	for i := range pm.Versions {
		ve := &pm.Versions[i]
		veKey := ve.Version
		if veKey == "" {
			veKey = ve.Ref
		}
		if veKey == targetKey {
			ve.BuildEnv = env
			if ve.Platform == "" {
				ve.Platform = defaultPlatform
			}
			break
		}
	}
	_ = store.SavePackage(ctx, pm)
}

// StampGitEntry sets BuildEnv and auto-detects Platform on a git entry.
func (c *Config) StampGitEntry(store *manifest.Store, name string, ve manifest.VersionEntry) {
	stampVersion(context.Background(), store, manifest.TypeGit, name, ve, c.GetBuildEnv(), c.GetBuildEnv().Platform)
}

// StampBinaryEntry sets BuildEnv and auto-detects Platform on a binary entry.
func (c *Config) StampBinaryEntry(store *manifest.Store, name string, ve manifest.VersionEntry) {
	stampVersion(context.Background(), store, manifest.TypeBinary, name, ve, c.GetBuildEnv(), c.GetBuildEnv().Platform)
}

// StampGomodEntry sets BuildEnv on a gomod entry (platform is always "any").
func (c *Config) StampGomodEntry(store *manifest.Store, name string, ve manifest.VersionEntry) {
	stampVersion(context.Background(), store, manifest.TypeGomod, name, ve, c.GetBuildEnv(), "any")
}

// StampHelmEntry sets BuildEnv on a helm entry (platform is always "any").
func (c *Config) StampHelmEntry(store *manifest.Store, name string, ve manifest.VersionEntry) {
	stampVersion(context.Background(), store, manifest.TypeHelm, name, ve, c.GetBuildEnv(), "any")
}

// StampNpmEntry sets BuildEnv on an npm entry (platform is always "any").
func (c *Config) StampNpmEntry(store *manifest.Store, name string, ve manifest.VersionEntry) {
	stampVersion(context.Background(), store, manifest.TypeNpm, name, ve, c.GetBuildEnv(), "any")
}

// stampArtifactSize records the file size on the version entry and saves.
func stampArtifactSize(ctx context.Context, store *manifest.Store, typ, name string, targetVE manifest.VersionEntry, artifactPath string) {
	fi, err := os.Stat(artifactPath)
	if err != nil {
		return
	}
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		return
	}
	targetKey := targetVE.Version
	if targetKey == "" {
		targetKey = targetVE.Ref
	}
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		veKey := ve.Version
		if veKey == "" {
			veKey = ve.Ref
		}
		if veKey == targetKey {
			ve.ArtifactSize = fi.Size()
			break
		}
	}
	_ = store.SavePackage(ctx, pm)
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
