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

// aptRefUpstream builds a repository whose release commit carries a
// lightweight tag, an annotated tag and a branch, with a later commit on the
// default branch. A fetch that ignores the ref lands on the later commit.
func aptRefUpstream(t *testing.T) (dir, release, tip string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir = filepath.Join(t.TempDir(), "upstream")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := []string{"-c", "user.email=e2e@bodega.test", "-c", "user.name=bodega"}
	gitIn(t, dir, "-c", "init.defaultBranch=main", "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "VERSION")
	gitIn(t, dir, append(id, "commit", "-q", "-m", "release 0.1.1")...)
	gitIn(t, dir, "tag", "v0.1.1-light")
	gitIn(t, dir, append(id, "tag", "-a", "v0.1.1", "-m", "v0.1.1")...)
	gitIn(t, dir, "branch", "release-0.1")
	release = gitIn(t, dir, "rev-parse", "HEAD")
	gitIn(t, dir, append(id, "commit", "-q", "--allow-empty", "-m", "post-release work")...)
	tip = gitIn(t, dir, "rev-parse", "HEAD")
	return dir, release, tip
}

// fetchAptSource runs FetchApt over one source-build entry and returns the
// summary, the fetch output and the directory the build would compile.
func fetchAptSource(t *testing.T, url, ref string) (*Summary, string, string) {
	t.Helper()
	const pkg = "widget"
	ve := manifest.VersionEntry{Version: "0.1.1", URL: url, Ref: ref, BuildCmd: "true"}
	pm := &manifest.PackageManifest{Type: manifest.TypeApt, Name: pkg, Versions: []manifest.VersionEntry{ve}}
	cfg, store, _ := pinEnv(t, pm)
	var out bytes.Buffer
	cfg.Stdout = &out
	s := FetchApt(cfg, store, pkg)
	return s, out.String(), aptSourceDir(buildDirs(cfg.rootFor(manifest.TypeApt)), pkg, ve)
}

func TestFetchAptSourceChecksOutRef(t *testing.T) {
	upstream, release, _ := aptRefUpstream(t)

	for _, tc := range []struct{ kind, ref string }{
		{"lightweight tag", "v0.1.1-light"},
		{"annotated tag", "v0.1.1"},
		{"branch", "release-0.1"},
		{"full SHA", release},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			s, out, dir := fetchAptSource(t, upstream, tc.ref)
			if s.Failures != 0 {
				t.Fatalf("fetch at %s failed: %+v\n%s", tc.ref, s.Results, out)
			}
			if got := gitIn(t, dir, "rev-parse", "HEAD"); got != release {
				t.Errorf("source checked out %s, want %s at %s", got, tc.ref, release)
			}
			if !strings.Contains(out, "Commit: "+release) {
				t.Errorf("fetch output does not name the built commit %s:\n%s", release, out)
			}
		})
	}
}

func TestFetchAptSourceMissingRefFails(t *testing.T) {
	upstream, _, _ := aptRefUpstream(t)
	const ref = "v9.9.9"

	s, out, dir := fetchAptSource(t, upstream, ref)
	if s.Failures != 1 || len(s.Results) != 1 || s.Results[0].Err == nil {
		t.Fatalf("a missing ref did not fail the fetch: %+v\n%s", s.Results, out)
	}
	msg := s.Results[0].Err.Error()
	for _, want := range []string{"widget", upstream, ref} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %q", msg, want)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a failed fetch left %s behind (stat err %v), which reads as fetched", dir, err)
	}
	if strings.Contains(out, "Commit: ") {
		t.Errorf("a failed fetch reported a built commit:\n%s", out)
	}
}

func TestFetchAptSourceEmptyRefBuildsDefaultBranch(t *testing.T) {
	upstream, _, tip := aptRefUpstream(t)

	s, out, dir := fetchAptSource(t, upstream, "")
	if s.Failures != 0 {
		t.Fatalf("fetch with no ref failed: %+v\n%s", s.Results, out)
	}
	if got := gitIn(t, dir, "rev-parse", "HEAD"); got != tip {
		t.Errorf("source checked out %s, want the default branch tip %s", got, tip)
	}
	if n := strings.Count(out, "default branch: the entry names no ref"); n != 1 {
		t.Errorf("fetch output says the default branch was built %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "Commit: "+tip) {
		t.Errorf("fetch output does not name the built commit %s:\n%s", tip, out)
	}
}
