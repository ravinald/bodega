package clientconf

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCrtTreeFollowsUpdateCACertificates(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"bodega-ca.crt", "corporate/issuer.crt", "corporate/notes.pem", "deep/a/b/c.crt"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "corporate"), filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	got := crtTree(dir)
	for i := range got {
		got[i], _ = filepath.Rel(dir, got[i])
	}
	want := []string{"bodega-ca.crt", "corporate/issuer.crt", "deep/a/b/c.crt", "linked/issuer.crt"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("crtTree = %q, want %q", got, want)
	}
}

func TestConfAnchorsFollowsUpdateCACertificates(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"mozilla/A.crt", "mozilla/B.crt", "mozilla/C.crt", "corp/issuer.crt"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	conf := "# comment\nmozilla/A.crt\n!mozilla/B.crt\n\n  corp/issuer.crt\t\nmissing/gone.crt\n #indented/not-a-comment.crt\nmozilla/C.crt"
	got := confAnchors(dir, []byte(conf))
	for i := range got {
		got[i], _ = filepath.Rel(dir, got[i])
	}
	want := []string{"mozilla/A.crt", "corp/issuer.crt", "mozilla/C.crt"}
	if !slices.Equal(got, want) {
		t.Fatalf("confAnchors = %q, want %q", got, want)
	}
}
