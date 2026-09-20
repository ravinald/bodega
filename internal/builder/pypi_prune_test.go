package builder

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// R6: pip writes into a flat --wheel-dir and removes nothing, so a re-pin
// leaves the superseded wheel beside the new one. MANIFEST.sha256 attests it,
// the sync uploads it, and the simple index publishes it.
func TestPrunePypiWheelsDropsWhatNoPinNames(t *testing.T) {
	root := t.TempDir()
	wheelsDir := filepath.Join(root, "wheels")
	if err := os.MkdirAll(wheelsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	req := filepath.Join(root, "combined-requirements.txt")
	// `six` is pinned; `urllib3` is a transitive member of the closure that no
	// entry names, so nothing here decides its version.
	if err := os.WriteFile(req, []byte("six===1.16.0\n# a comment\nrequests\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"six-1.16.0-py2.py3-none-any.whl",
		"six-1.17.0-py2.py3-none-any.whl",
		"urllib3-2.2.0-py3-none-any.whl",
		"not-a-wheel.txt",
	} {
		if err := os.WriteFile(filepath.Join(wheelsDir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := prunePypiWheels(io.Discard, req, wheelsDir); err != nil {
		t.Fatalf("prunePypiWheels: %v", err)
	}

	left, err := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range left {
		left[i] = filepath.Base(left[i])
	}
	sort.Strings(left)
	want := []string{"six-1.16.0-py2.py3-none-any.whl", "urllib3-2.2.0-py3-none-any.whl"}
	if len(left) != len(want) || left[0] != want[0] || left[1] != want[1] {
		t.Errorf("the wheels directory holds %v, want %v", left, want)
	}
}

// A requirements file with no === lines pins nothing, and pruning against an
// empty set must not empty the directory.
func TestPrunePypiWheelsKeepsEverythingWithNoPins(t *testing.T) {
	root := t.TempDir()
	wheelsDir := filepath.Join(root, "wheels")
	if err := os.MkdirAll(wheelsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	req := filepath.Join(root, "combined-requirements.txt")
	if err := os.WriteFile(req, []byte("requests\nurllib3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	whl := filepath.Join(wheelsDir, "six-1.17.0-py2.py3-none-any.whl")
	if err := os.WriteFile(whl, []byte("wheel"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := prunePypiWheels(io.Discard, req, wheelsDir); err != nil {
		t.Fatalf("prunePypiWheels: %v", err)
	}
	if _, err := os.Stat(whl); err != nil {
		t.Errorf("an unpinned wheel was pruned: %v", err)
	}
}
