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
