package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

func TestFindVersion(t *testing.T) {
	pm := &manifest.PackageManifest{
		Versions: []manifest.VersionEntry{
			{Version: "1.0.0"},
			{Ref: "v2.0.0"},
			{Version: "3.0.0", Ref: "main"},
		},
	}
	cases := map[string]int{
		"1.0.0":  0,
		"v2.0.0": 1,
		"3.0.0":  2,
		"main":   2,
		"99":     -1,
		"":       -1,
	}
	for q, want := range cases {
		if got := findVersion(pm, q); got != want {
			t.Errorf("findVersion(%q) = %d, want %d", q, got, want)
		}
	}
}

func TestKnownVersions(t *testing.T) {
	empty := &manifest.PackageManifest{}
	if got := knownVersions(empty); got != "(none)" {
		t.Errorf("empty package = %q, want (none)", got)
	}

	pm := &manifest.PackageManifest{
		Versions: []manifest.VersionEntry{
			{Version: "1.0.0"},
			{Ref: "v2.0.0"},
		},
	}
	got := knownVersions(pm)
	if !strings.Contains(got, "1.0.0") || !strings.Contains(got, "v2.0.0") {
		t.Errorf("knownVersions = %q, want both 1.0.0 and v2.0.0", got)
	}
}

func TestResolveEditor(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	if got := resolveEditor(""); got != "vi" {
		t.Errorf("no env, no flag = %q, want vi", got)
	}

	t.Setenv("EDITOR", "nano")
	if got := resolveEditor(""); got != "nano" {
		t.Errorf("EDITOR=nano = %q, want nano", got)
	}

	t.Setenv("VISUAL", "code --wait")
	if got := resolveEditor(""); got != "code --wait" {
		t.Errorf("VISUAL should win = %q, want code --wait", got)
	}

	if got := resolveEditor("emacs"); got != "emacs" {
		t.Errorf("flag should win over env, got %q", got)
	}
}

// Regression: pre-hash vs post-editor hash must agree when the editor is
// a no-op. writeEditBuffer appends a trailing newline; the pre-hash needs
// to read what's actually on disk or the no-op check always fires false.
func TestWriteEditBuffer_TrailingNewlineIsStable(t *testing.T) {
	payload := []byte(`{"x":1}`) // no trailing newline on purpose
	path, err := writeEditBuffer("npm", "pkg", "", payload)
	if err != nil {
		t.Fatalf("writeEditBuffer: %v", err)
	}
	defer os.Remove(path)

	a, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("buffer bytes changed between reads")
	}
	if !strings.HasSuffix(string(a), "\n") {
		t.Error("on-disk buffer should end with a newline")
	}
}

func TestWriteEditBuffer_SafeName(t *testing.T) {
	path, err := writeEditBuffer("npm", "@bitwarden/cli", "2026.4.0", []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("writeEditBuffer: %v", err)
	}
	defer os.Remove(path)

	base := filepath.Base(path)
	if strings.Contains(base, "@") || strings.Contains(base, "/") {
		t.Errorf("buffer name %q still contains @ or /", base)
	}
	if !strings.HasPrefix(base, "bodega-edit-npm-bitwarden_cli-2026.4.0-") {
		t.Errorf("prefix wrong: %q", base)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Error("buffer should end with newline")
	}
	if !strings.Contains(string(body), `"x":1`) {
		t.Errorf("body missing payload: %q", string(body))
	}
}

func TestRunEditor(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "buf.json")
	if err := os.WriteFile(target, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// runEditor splits by whitespace, so the "editor" must be a single
	// callable (no shell metacharacters) that accepts the file as $1.
	script := filepath.Join(dir, "stub-editor.sh")
	body := "#!/bin/sh\nprintf '{\"a\":2}' > \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	if err := runEditor(script, target); err != nil {
		t.Fatalf("runEditor: %v", err)
	}
	out, _ := os.ReadFile(target)
	if strings.TrimSpace(string(out)) != `{"a":2}` {
		t.Errorf("after edit = %q, want {\"a\":2}", string(out))
	}
}

// relabelFixture seeds one binary version recorded on the default backend, with
// the artifact present on whichever backends are named, and points the process
// at a config defining "bulk" alongside the default.
func relabelFixture(t *testing.T, objectOn ...string) {
	t.Helper()
	defaultPath, bulkPath, manifestDir := t.TempDir(), t.TempDir(), t.TempDir()

	body, err := json.Marshal(map[string]any{
		"build_root":      t.TempDir(),
		"storage_backend": "local",
		"storage_path":    defaultPath,
		"manifest_dir":    manifestDir,
		"storage_backends": map[string]any{
			"bulk": map[string]string{"driver": "local", "path": bulkPath},
		},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvManifestDir, "")
	t.Setenv(config.EnvBucket, "")

	key := filepath.FromSlash(manifest.BinaryKey("awscli-v2", "2.15.0", "awscli.zip"))
	for _, backend := range objectOn {
		root := defaultPath
		if backend == "bulk" {
			root = bulkPath
		}
		obj := filepath.Join(root, key)
		if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", backend, err)
		}
		if err := os.WriteFile(obj, []byte("awscli"), 0o644); err != nil {
			t.Fatalf("write object on %s: %v", backend, err)
		}
	}

	store := manifest.NewLocalStore(manifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli-v2", manifest.VersionEntry{
		Version:  "2.15.0",
		Filename: "awscli.zip",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
}

// relabelEditor writes a VersionEntry naming backend, standing in for the
// operator who changed one line in $EDITOR.
func relabelEditor(t *testing.T, backend string) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "stub-editor.sh")
	body := "#!/bin/sh\ncat > \"$1\" <<'EOF'\n{\n  \"version\": \"2.15.0\",\n" +
		"  \"filename\": \"awscli.zip\",\n  \"storage\": \"" + backend + "\"\n}\nEOF\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write stub editor: %v", err)
	}
	return script
}

// TestEditRefusesAStorageChangeThatStrandsTheArtifact. admit.CheckBackendName
// passes "bulk" — it is a configured backend — and the object is not on it, so
// the edit would leave the bytes on the default and turn every read of the
// version into a 404 for content that exists.
func TestEditRefusesAStorageChangeThatStrandsTheArtifact(t *testing.T) {
	relabelFixture(t, "default")

	cmd := newEditCmd(&globalFlags{})
	cmd.SetArgs([]string{manifest.TypeBinary, "awscli-v2", "2.15.0", "--editor", relabelEditor(t, "bulk")})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("edit accepted a relabel that strands the artifact")
	}
	if !strings.Contains(err.Error(), "bodega pkg move") {
		t.Errorf("error = %q, want it to name the command that moves the bytes", err)
	}
}

// TestEditAcceptsAStorageChangeThatCorrectsTheRecord. The other reading of the
// same edit: the object is on the backend being named, so the record was wrong.
func TestEditAcceptsAStorageChangeThatCorrectsTheRecord(t *testing.T) {
	relabelFixture(t, "bulk")

	cmd := newEditCmd(&globalFlags{})
	cmd.SetArgs([]string{manifest.TypeBinary, "awscli-v2", "2.15.0", "--editor", relabelEditor(t, "bulk")})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("edit refused a correction: %v", err)
	}
}
