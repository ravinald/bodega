package builder

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// pypiClosureEnv builds a single-entry pypi manifest against index and runs a
// full fetch over it, closure and all.
func pypiClosureEnv(t *testing.T, index string) (*Config, *manifest.Store, *audit.DB) {
	t.Helper()
	requirePip(t)
	cfg, store, db := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypePypi, Name: "six",
		Versions: []manifest.VersionEntry{{Version: "1.16.0", URL: index}},
	})
	cfg.Stdout = io.Discard
	return cfg, store, db
}

// pypiWheelhouseDigest returns the digest of one file the fetch downloaded.
func pypiWheelhouseDigest(t *testing.T, cfg *Config, file string) string {
	t.Helper()
	digest, err := computeFileSHA256(filepath.Join(pypiWheelhouseDir(cfg.rootFor(manifest.TypePypi)), file))
	if err != nil {
		t.Fatalf("digest %s: %v", file, err)
	}
	return digest
}

// R1: the manifest names one version and pip installs everything it depends on,
// so resolving only the named versions left the transitive bytes governed by
// nothing but the requirements text. The fetch resolves the closure and records
// a digest per file, keyed by the object key the wheel is served under — the
// same audit row, in the same table, that every other type writes.
func TestFetchPypiRecordsADigestPerClosureArtifact(t *testing.T) {
	srv := pypiWheelIndexOf(t,
		pypiDist{name: "six", versions: []string{"1.16.0"}, requires: []string{"attrs"}},
		pypiDist{name: "attrs", versions: []string{"24.2.0"}},
	)
	cfg, store, db := pypiClosureEnv(t, srv.URL)

	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("fetch reported failures: %+v", summary.Results)
	}

	root := cfg.rootFor(manifest.TypePypi)
	arts, err := scanPypiWheelhouse(pypiWheelhouseDir(root))
	if err != nil {
		t.Fatalf("scan the wheelhouse: %v", err)
	}
	got := map[string]string{}
	for _, a := range arts {
		got[a.File] = a.Digest
	}
	// The dependency is the point: it is in no manifest entry.
	for _, want := range []string{"six-1.16.0-py3-none-any.whl", "attrs-24.2.0-py3-none-any.whl"} {
		if got[want] == "" {
			t.Errorf("the fetch stored no %s; the wheelhouse holds %v", want, got)
		}
	}

	lock, err := os.ReadFile(pypiLockPath(root))
	if err != nil {
		t.Fatalf("read the lock: %v", err)
	}
	for _, a := range arts {
		if !strings.Contains(string(lock), "--hash=sha256:"+a.Digest) {
			t.Errorf("%s carries no digest in the lock:\n%s", a.File, lock)
		}
		row, err := db.GetChecksum(t.Context(), a.Key())
		if err != nil {
			t.Fatalf("read the checksum row for %s: %v", a.Key(), err)
		}
		if row == nil || row.Value != a.Digest {
			t.Errorf("%s: `pkg checksum list` shows %+v, not the digest the fetch recorded (%s)", a.Key(), row, a.Digest)
		}
	}
	if !strings.Contains(string(lock), "attrs==24.2.0") {
		t.Errorf("the lock does not pin the dependency the manifest never named:\n%s", lock)
	}
}

// R2/R6: pip lets a requirements file's --index-url replace a command-line one
// outright, so the build's `--index-url <selected>` was the weaker of the two
// and every spelling of an index inside a file was one more thing a parser had
// to catch. `--no-index` is the exception pip guards with `and not no_index` at
// every include depth, so the build now names it on the argv and takes bytes
// only from a directory bodega filled.
//
// The assertion is on the bytes pip stored, not on the generated text: the
// other index serves the same approved version with different content, so a
// build that read it would store a wheel with a different digest.
func TestPypiBuildIgnoresAnIndexNamedInARequirementsFile(t *testing.T) {
	selected := pypiWheelIndexOf(t, pypiDist{name: "six", versions: []string{"1.16.0"}, marker: "selected"})
	other := pypiWheelIndexOf(t, pypiDist{name: "six", versions: []string{"1.16.0"}, marker: "other"})

	cfg, store, _ := pypiClosureEnv(t, selected.URL)
	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("fetch reported failures: %+v", summary.Results)
	}

	const wheel = "six-1.16.0-py3-none-any.whl"
	approved := pypiWheelhouseDigest(t, cfg, wheel)

	// Every requirements file in the build root names the other index, which
	// covers whichever one the build happens to read. The line goes at the end
	// because that is where an application's own index landed: the generated
	// file wrote the selected index first and inlined the applications' lines
	// under it, and pip takes the last --index-url it reads.
	root := cfg.rootFor(manifest.TypePypi)
	txts, err := filepath.Glob(filepath.Join(root, "*.txt"))
	if err != nil || len(txts) == 0 {
		t.Fatalf("no requirements files to poison in %s (%v)", root, err)
	}
	for _, path := range txts {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := os.WriteFile(path, append(body, []byte("--index-url "+pypiIndexURL(other.URL)+"\n")...), 0o600); err != nil {
			t.Fatalf("rewrite %s: %v", path, err)
		}
	}

	// The bypass is real, and before this item it was the build: pip pointed at
	// the selected index with `--index-url`, reading combined-requirements.txt,
	// takes the index the file names and stores bytes nothing recorded.
	req, err := os.ReadFile(filepath.Join(root, "combined-requirements.txt"))
	if err != nil {
		t.Fatalf("read the requirements: %v", err)
	}
	stored, out := pypiWheelRunDigests(t, string(req), "--isolated", "--index-url", pypiIndexURL(selected.URL))
	if stored[wheel] == "" {
		t.Fatalf("the invocation this item replaced stored no %s, so the control is untested:\n%s", wheel, out)
	}
	if stored[wheel] == approved {
		t.Fatalf("the old invocation stored the approved bytes, so this fixture proves nothing:\n%s", out)
	}

	if summary := BuildPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("the build failed: %+v", summary.Results)
	}
	built, err := computeFileSHA256(filepath.Join(pypiWheelsDir(buildDirs(root)), wheel))
	if err != nil {
		t.Fatalf("digest the built wheel: %v", err)
	}
	if built != approved {
		t.Errorf("the build stored bytes the fetch never recorded: approved=%s built=%s — an --index-url in a requirements file moved acquisition",
			approved, built)
	}
}

// pypiWheelRunDigests runs real pip over a requirements file the way the build
// used to run it, and returns the digest of every wheel it stored. A filename
// is not the evidence here: two indexes serving one approved version produce
// the same name and different bytes.
func pypiWheelRunDigests(t *testing.T, requirements string, args ...string) (map[string]string, string) {
	t.Helper()
	requirePip(t)
	dir := t.TempDir()
	reqPath := filepath.Join(dir, "combined-requirements.txt")
	if err := os.WriteFile(reqPath, []byte(requirements), 0o600); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	cmd := exec.Command("python3", append(append([]string{"-m", "pip", "wheel"}, args...),
		"--no-cache-dir", "--disable-pip-version-check", "--wheel-dir", dir, "-r", reqPath)...)
	cmd.Env = pypiPipEnv()
	out, _ := cmd.CombinedOutput()

	whls, _ := filepath.Glob(filepath.Join(dir, "*.whl"))
	digests := make(map[string]string, len(whls))
	for _, whl := range whls {
		digest, err := computeFileSHA256(whl)
		if err != nil {
			t.Fatalf("digest %s: %v", whl, err)
		}
		digests[filepath.Base(whl)] = digest
	}
	return digests, string(out)
}

// R3: --require-hashes is in force, and the closure is re-digested before pip
// is pointed at it so the failure names the distribution and both digests
// rather than whichever candidate pip reached first.
func TestPypiBuildRefusesAnArtifactWhoseBytesChanged(t *testing.T) {
	srv := pypiWheelIndex(t, "six", "1.16.0")
	cfg, store, _ := pypiClosureEnv(t, srv.URL)
	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("fetch reported failures: %+v", summary.Results)
	}

	const wheel = "six-1.16.0-py3-none-any.whl"
	root := cfg.rootFor(manifest.TypePypi)
	recorded := pypiWheelhouseDigest(t, cfg, wheel)
	path := filepath.Join(pypiWheelhouseDir(root), wheel)
	if err := os.WriteFile(path, []byte("not the wheel that was approved"), 0o600); err != nil {
		t.Fatalf("substitute the wheel: %v", err)
	}
	received, err := computeFileSHA256(path)
	if err != nil {
		t.Fatalf("digest the substitute: %v", err)
	}

	summary := BuildPypi(cfg, store)
	if !summary.HasFailures() {
		t.Fatalf("a build over substituted bytes succeeded: %+v", summary.Results)
	}
	var msg string
	for _, r := range summary.Results {
		if r.Err != nil {
			msg = r.Err.Error()
		}
	}
	for _, want := range []string{"six", recorded, received} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not name %q: %s", want, msg)
		}
	}
}

// R4: the same per-version rule the other seven types get. An index serving a
// second set of bytes for a version already on record is refused, and the
// wheelhouse it wrote into goes with the refusal so no build can reach those
// bytes through --find-links.
func TestFetchPypiRefusesASecondFetchWithDifferentBytes(t *testing.T) {
	first := pypiWheelIndexOf(t, pypiDist{name: "six", versions: []string{"1.16.0"}, marker: "first"})
	second := pypiWheelIndexOf(t, pypiDist{name: "six", versions: []string{"1.16.0"}, marker: "second"})

	cfg, store, _ := pypiClosureEnv(t, first.URL)
	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("the first fetch failed: %+v", summary.Results)
	}
	pinned := pypiWheelhouseDigest(t, cfg, "six-1.16.0-py3-none-any.whl")

	pm, err := store.GetPackage(t.Context(), manifest.TypePypi, "six")
	if err != nil || pm == nil {
		t.Fatalf("read the manifest back: %v", err)
	}
	pm.Versions[0].URL = second.URL
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	summary := FetchPypi(cfg, store)
	if !summary.HasFailures() {
		t.Fatalf("a second set of bytes for an approved version was stored: %+v", summary.Results)
	}
	var msg string
	for _, r := range summary.Results {
		if r.Err != nil {
			msg = r.Err.Error()
		}
	}
	for _, want := range []string{"six", pinned, manifest.PypiWheelKey("six-1.16.0-py3-none-any.whl")} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}
	root := cfg.rootFor(manifest.TypePypi)
	if _, err := os.Stat(pypiWheelhouseDir(root)); !os.IsNotExist(err) {
		t.Error("a refused fetch left its wheelhouse behind, so the build can still reach the bytes")
	}
	if CheckPypiStage(cfg, store).Fetched {
		t.Error("a refused fetch still reports the fetch stage as done, so the pipeline skips the retry")
	}
}

// The lock is what --require-hashes enforces, so it has to read back the way it
// was written. A line neither reader agrees on is the gap this item closed.
func TestReadPypiLockRoundTrips(t *testing.T) {
	arts := []pypiArtifact{
		{File: "six-1.16.0-py3-none-any.whl", Dist: "six", Version: "1.16.0", Digest: strings.Repeat("a", 64)},
		{File: "six-1.16.0.tar.gz", Dist: "six", Version: "1.16.0", Digest: strings.Repeat("b", 64)},
		{File: "attrs-24.2.0-py3-none-any.whl", Dist: "attrs", Version: "24.2.0", Digest: strings.Repeat("c", 64)},
	}
	path := filepath.Join(t.TempDir(), "resolved-requirements.txt")
	if err := os.WriteFile(path, []byte(pypiLockBody(arts)), 0o600); err != nil {
		t.Fatalf("write the lock: %v", err)
	}
	pins, err := readPypiLock(path)
	if err != nil {
		t.Fatalf("read the lock: %v", err)
	}
	if got := pins["six==1.16.0"]; len(got) != 2 {
		t.Errorf("a version served as both a wheel and an sdist kept %v, want both digests", got)
	}
	if got := pins["attrs==24.2.0"]; len(got) != 1 || got[0] != strings.Repeat("c", 64) {
		t.Errorf("attrs==24.2.0 read back as %v", got)
	}
}

// An sdist is pinned like a wheel, and the name it is pinned under has to be
// the one the index served.
func TestParsePypiArtifactName(t *testing.T) {
	for _, tc := range []struct {
		base, dist, version string
		ok                  bool
	}{
		{"six-1.16.0-py2.py3-none-any.whl", "six", "1.16.0", true},
		{"six-1.16.0.tar.gz", "six", "1.16.0", true},
		{"zope.interface-7.2.zip", "zope-interface", "7.2", true},
		{"ruamel.yaml.clib-0.2.12.tar.gz", "ruamel-yaml-clib", "0.2.12", true},
		{"MANIFEST.sha256", "", "", false},
		{"six.tar.gz", "", "", false},
	} {
		dist, version, ok := parsePypiArtifactName(tc.base)
		if ok != tc.ok || dist != tc.dist || version != tc.version {
			t.Errorf("parsePypiArtifactName(%q) = %q, %q, %v; want %q, %q, %v",
				tc.base, dist, version, ok, tc.dist, tc.version, tc.ok)
		}
	}
}
