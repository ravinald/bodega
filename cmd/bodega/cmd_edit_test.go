package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func TestFindVersion_MatchesVersionOrRef(t *testing.T) {
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

func TestResolveEditor_Precedence(t *testing.T) {
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

// TestWriteEditBuffer_TrailingNewlineIsStable confirms the buffer we hash
// pre-edit matches what we'd read post-edit from a no-op editor run —
// otherwise the no-op detection in the edit command would always fire false.
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

// TestRunEditor_AppliesEdit uses a shell-script "editor" that rewrites the
// file it was handed. Proves the stdio wiring works and that our argv
// parsing passes the path as the final argument.
func TestRunEditor_AppliesEdit(t *testing.T) {
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
