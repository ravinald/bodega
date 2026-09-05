package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestManifestDirIgnoresExecutableSiblings pins the manifest root against the
// layout that made the shipped config lie: /opt/bodega/bin/bodega beside
// /opt/bodega/manifests. The resolver probed <exeDir>/manifests and
// <exeDir>/../manifests before storage_path, so an ordinary install served a
// directory the config never named while _comment_manifest_dir promised that a
// backup of storage_path was a backup of the whole repository.
//
// It runs the real binary because the probe read os.Executable(): a test
// calling Load in-process asks about the test binary's directory, which is
// wherever `go test` put it.
func TestManifestDirIgnoresExecutableSiblings(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the bodega binary")
	}

	root := t.TempDir()
	binDir := filepath.Join(root, "probe", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	sibling := filepath.Join(root, "probe", "manifests")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir sibling manifests: %v", err)
	}

	bin := filepath.Join(binDir, "bodega")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	store := filepath.Join(root, "store")
	cfgPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"storage_path":`+quoteJSON(store)+`}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// reset names the manifest root before it asks for anything. Answering the
	// audit prompt "n" and the confirmation word with a wrong one leaves every
	// path on disk untouched.
	cmd := exec.Command(bin, "reset")
	cmd.Env = append(os.Environ(), "BODEGA_CONFIG_FILE="+cfgPath)
	cmd.Stdin = strings.NewReader("n\nno\n")
	out, _ := cmd.CombinedOutput()

	want := filepath.Join(store, "manifests")
	if !strings.Contains(string(out), want) {
		t.Errorf("reset did not name %q as the manifest root:\n%s", want, out)
	}
	if strings.Contains(string(out), sibling) {
		t.Errorf("reset named the executable's sibling %q as the manifest root:\n%s", sibling, out)
	}
}

// quoteJSON renders a path as a JSON string.
func quoteJSON(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}
