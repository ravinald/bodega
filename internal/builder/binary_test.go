package builder

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	}
	for _, tt := range tests {
		got := humanBytes(tt.input)
		if got != tt.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestVerifySHA256_Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	content := []byte("hello bootstrap")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// Compute expected sum.
	sum, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("fileSHA256: %v", err)
	}
	if err := verifySHA256(path, sum); err != nil {
		t.Errorf("verifySHA256: unexpected error: %v", err)
	}
}

func TestVerifySHA256_Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("expected error on SHA-256 mismatch, got nil")
	}
}

func TestFileSHA256_NonExistent(t *testing.T) {
	_, err := fileSHA256("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// TestFetchBinariesRefusesFilenameEscape is the B90 audit reproduction: a
// filename override of "../../../../escaped" on binary tool@1.0.0 fetched from a
// real local listener wrote <temp>/escaped outside the build root and reported
// success. Admission now refuses the manifest, so the second half plants it on
// disk the way a store written before the check would hold it, and asserts the
// fetch both writes nothing outside the root and reports the entry failed.
func TestFetchBinariesRefusesFilenameEscape(t *testing.T) {
	const hostile = "../../../../escaped"
	root := t.TempDir()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "OUTSIDE-BUILD")
	}))
	defer up.Close()

	ve := manifest.VersionEntry{Version: "1.0.0", URL: up.URL + "/payload", Filename: hostile}
	if err := manifest.NewLocalStore(t.TempDir()).AddVersion(t.Context(), manifest.TypeBinary, "tool", ve); err == nil {
		t.Errorf("AddVersion admitted filename %q", hostile)
	}

	storeDir := t.TempDir()
	store := manifest.NewLocalStore(storeDir)
	ve.Filename = "placeholder"
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", ve); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	mpath := filepath.Join(storeDir, manifest.TypeBinary, "tool", "manifest.json")
	data, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mpath, []byte(strings.Replace(string(data), `"placeholder"`, `"`+hostile+`"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	store = manifest.NewLocalStore(storeDir)
	if err := store.LoadIndex(t.Context()); err != nil {
		t.Fatal(err)
	}

	var log strings.Builder
	cfg := &Config{BuildRoot: filepath.Join(root, "build"), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}, Stdout: &log}
	sum := FetchBinaries(cfg, store, "tool")

	if got, err := os.ReadFile(filepath.Join(root, "escaped")); err == nil {
		t.Errorf("fetch wrote %q outside the build root", got)
	}
	if sum.Failures != 1 || len(sum.Results) != 1 || sum.Results[0].Err == nil {
		t.Fatalf("fetch of an escaping filename reported failures=%d results=%+v, want one failed entry\n%s", sum.Failures, sum.Results, log.String())
	}
	if !strings.Contains(sum.Results[0].Err.Error(), hostile) {
		t.Errorf("error does not name the filename it refused: %v", sum.Results[0].Err)
	}
}

// TestFetchBinariesRefusesSymlinkInBuildRoot covers the escape that needs no
// "..": a directory under the build root that is a symlink to somewhere else.
func TestFetchBinariesRefusesSymlinkInBuildRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "OUTSIDE-BUILD")
	}))
	defer up.Close()

	store := manifest.NewLocalStore(t.TempDir())
	ve := manifest.VersionEntry{Version: "1.0.0", URL: up.URL + "/payload", Filename: "tool.bin"}
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", ve); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{BuildRoot: filepath.Join(root, "build"), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}, Stdout: io.Discard}
	binaries := buildDirs(cfg.rootFor(manifest.TypeBinary)).binaries
	if err := os.MkdirAll(binaries, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(binaries, "tool")); err != nil {
		t.Fatal(err)
	}

	sum := FetchBinaries(cfg, store, "tool")

	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("fetch wrote %d entries through the symlink into %s", len(entries), outside)
	}
	if sum.Failures != 1 || len(sum.Results) != 1 || sum.Results[0].Err == nil {
		t.Fatalf("fetch through a symlink reported failures=%d results=%+v, want one failed entry", sum.Failures, sum.Results)
	}
}

func TestBinaryDestPathRefusesEveryEscapingComponent(t *testing.T) {
	d := buildDirs(t.TempDir())
	for _, tc := range []struct {
		label, name string
		ve          manifest.VersionEntry
	}{
		{"filename parent", "tool", manifest.VersionEntry{Version: "1.0.0", Filename: "../../../../escaped"}},
		{"filename absolute", "tool", manifest.VersionEntry{Version: "1.0.0", Filename: "/etc/escaped"}},
		{"filename parent inside", "tool", manifest.VersionEntry{Version: "1.0.0", Filename: "sub/../../../escaped"}},
		{"filename empty segment", "tool", manifest.VersionEntry{Version: "1.0.0", Filename: "sub//tool.bin"}},
		{"filename backslash", "tool", manifest.VersionEntry{Version: "1.0.0", Filename: `..\escaped`}},
		{"filename dot", "tool", manifest.VersionEntry{Version: "1.0.0", Filename: "."}},
		{"url basename is parent", "tool", manifest.VersionEntry{Version: "1.0.0", URL: ".."}},
		{"no url and no filename", "tool", manifest.VersionEntry{Version: "1.0.0"}},
		{"version parent", "tool", manifest.VersionEntry{Version: "../../../x", Filename: "f"}},
		{"version dotdot", "tool", manifest.VersionEntry{Version: "..", Filename: "f"}},
		{"name escapes", "../../x", manifest.VersionEntry{Version: "1.0.0", Filename: "f"}},
		{"name collapses into root", "a/..", manifest.VersionEntry{Version: "1.0.0", Filename: "f"}},
		{"name crosses into another package", "a/../b", manifest.VersionEntry{Version: "1.0.0", Filename: "f"}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got, err := binaryDestPath(d, tc.name, tc.ve); err == nil {
				t.Errorf("binaryDestPath(%q, %+v) = %q, want an error", tc.name, tc.ve, got)
			}
		})
	}
	if _, err := binaryDestPath(d, "org/tool", manifest.VersionEntry{Version: "1.0.0", Filename: "tool.bin"}); err != nil {
		t.Errorf("a name spanning two directories is confined and was refused: %v", err)
	}
	if _, err := binaryDestPath(d, "tool", manifest.VersionEntry{Filename: "~/tool"}); err != nil {
		t.Errorf("a filename with a subdirectory is confined and was refused: %v", err)
	}
}

// TestBinaryPathsRefuseLinksBelowTheRoot plants a link at each depth under the
// configured root. The binaries directory is the case that needs no ".." and no
// race: confining to it instead of the root trusted whatever it pointed at. An
// artifact already sitting at the link target must not read as fetched either,
// or the fetch skips, reports success and upload publishes the outside file.
func TestBinaryPathsRefuseLinksBelowTheRoot(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "OUTSIDE-BUILD")
	}))
	defer up.Close()

	for _, tc := range []struct {
		label string
		plant func(t *testing.T, build, outside string) string
	}{
		{"binaries directory", func(t *testing.T, build, outside string) string {
			mustMkdir(t, build)
			mustSymlink(t, outside, filepath.Join(build, "binaries"))
			return filepath.Join(outside, "tool", "1.0.0", "tool.bin")
		}},
		{"version directory", func(t *testing.T, build, outside string) string {
			mustMkdir(t, filepath.Join(build, "binaries", "tool"))
			mustSymlink(t, outside, filepath.Join(build, "binaries", "tool", "1.0.0"))
			return filepath.Join(outside, "tool.bin")
		}},
		{"leaf file", func(t *testing.T, build, outside string) string {
			dir := filepath.Join(build, "binaries", "tool", "1.0.0")
			mustMkdir(t, dir)
			mustSymlink(t, filepath.Join(outside, "tool.bin"), filepath.Join(dir, "tool.bin"))
			return filepath.Join(outside, "tool.bin")
		}},
	} {
		for _, preexisting := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/target exists %v", tc.label, preexisting), func(t *testing.T) {
				build := filepath.Join(t.TempDir(), "build")
				outside := t.TempDir()
				target := tc.plant(t, build, outside)
				if preexisting {
					mustMkdir(t, filepath.Dir(target))
					if err := os.WriteFile(target, []byte("SECRET"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				store := manifest.NewLocalStore(t.TempDir())
				ve := manifest.VersionEntry{Version: "1.0.0", URL: up.URL + "/payload", Filename: "tool.bin"}
				if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", ve); err != nil {
					t.Fatal(err)
				}
				cfg := &Config{BuildRoot: build, BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}, Stdout: io.Discard}

				sum := FetchBinaries(cfg, store, "tool")

				if got, err := os.ReadFile(target); err == nil && string(got) == "OUTSIDE-BUILD" {
					t.Errorf("fetch wrote %s through the link", target)
				}
				if sum.Failures != 1 || len(sum.Results) != 1 || sum.Results[0].Err == nil {
					t.Fatalf("fetch through a link reported failures=%d results=%+v, want one failed entry", sum.Failures, sum.Results)
				}
				if got := BinaryArtifactPaths(cfg, store, "tool"); len(got) != 0 {
					t.Errorf("upload walk returned %+v through the link", got)
				}
			})
		}
	}
}

func TestFetchBinariesThroughSymlinkedRoot(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "PAYLOAD")
	}))
	defer up.Close()

	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "build")
	mustSymlink(t, real, link)
	store := manifest.NewLocalStore(t.TempDir())
	ve := manifest.VersionEntry{Version: "1.0.0", URL: up.URL + "/payload", Filename: "tool.bin"}
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", ve); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	cfg := &Config{BuildRoot: link, BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}, Stdout: &log}

	if sum := FetchBinaries(cfg, store, "tool"); sum.Failures != 0 || sum.Total != 1 {
		t.Fatalf("fetch under a symlinked configured root reported failures=%d total=%d\n%s", sum.Failures, sum.Total, log.String())
	}
	if got, err := os.ReadFile(filepath.Join(real, "binaries", "tool", "1.0.0", "tool.bin")); err != nil || string(got) != "PAYLOAD" {
		t.Errorf("artifact under the resolved root = %q, %v", got, err)
	}
	if got := BinaryArtifactPaths(cfg, store, "tool"); len(got) != 1 {
		t.Errorf("upload walk under a symlinked root returned %+v, want one path", got)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
