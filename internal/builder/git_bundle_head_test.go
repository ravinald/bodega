package builder

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// git runs a git command in dir and fails the test on a non-zero exit.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runCmdCapture(dir, "git", args...)
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(out)
}

// TestPackageGitBundleClonesWithoutBranch drives the command QUICKSTART
// documents: download the bundle, "git clone <bundle> <dir>", nothing else. The
// tag is deliberately behind the branch tip, so a clone that lands anywhere but
// the packaged ref is visible in the commit subject.
func TestPackageGitBundleClonesWithoutBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	root := t.TempDir()
	d := buildDirs(root)
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}

	gitIn(t, src, "-c", "init.defaultBranch=master", "init", "-q")
	if err := os.WriteFile(filepath.Join(src, "VERSION"), []byte("1.6.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, src, "add", "VERSION")
	gitIn(t, src, "-c", "user.email=e2e@bodega.test", "-c", "user.name=bodega", "commit", "-q", "-m", "release 1.6.0")
	// Annotated, because a lightweight tag hides the peel that HEAD needs.
	gitIn(t, src, "-c", "user.email=e2e@bodega.test", "-c", "user.name=bodega", "tag", "-a", "v1.6.0", "-m", "v1.6.0")
	want := gitIn(t, src, "rev-parse", "HEAD")
	gitIn(t, src, "-c", "user.email=e2e@bodega.test", "-c", "user.name=bodega", "commit", "-q", "--allow-empty", "-m", "post-release work")

	ve := manifest.VersionEntry{URL: src, Ref: "v1.6.0", Source: "clone"}
	var log bytes.Buffer
	if err := fetchGitRepo(&log, gitBareDir(d, "uuid", ve), src); err != nil {
		t.Fatalf("fetchGitRepo: %v\n%s", err, log.String())
	}

	bundlePath, err := packageGitBundle(&log, d, "uuid", ve)
	if err != nil {
		t.Fatalf("packageGitBundle: %v\n%s", err, log.String())
	}

	clone := filepath.Join(root, "clone")
	if out, err := runCmdCapture(root, "git", "clone", "-q", bundlePath, clone); err != nil {
		t.Fatalf("git clone %s: %v\n%s", bundlePath, err, out)
	}

	if got := gitIn(t, clone, "rev-parse", "HEAD"); got != want {
		t.Errorf("clone checked out %s, want the packaged ref %s", got, want)
	}
	if _, err := os.Stat(filepath.Join(clone, "VERSION")); err != nil {
		t.Errorf("clone has no working tree: %v", err)
	}
}
