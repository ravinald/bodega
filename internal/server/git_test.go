package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// TestGitRefFromFile pins the shape check the bundle route runs before it
// builds a storage key. Both halves matter: a filename it accepts becomes the
// manifest entry's identity, and one it rejects has to stop at the handler
// rather than reach the object store as a key no uploader ever wrote.
func TestGitRefFromFile(t *testing.T) {
	for _, tc := range []struct {
		name, file  string
		wantRef     string
		wantRelease bool
		wantOK      bool
	}{
		{"netbox", "netbox-v4.5.5.bundle", "v4.5.5", false, true},
		{"netbox", "netbox-v4.5.5.tar.gz", "v4.5.5", true, true},
		// A ref may carry the separator the filename uses; only the first
		// occurrence delimits the name.
		{"netbox", "netbox-feature-x.bundle", "feature-x", false, true},
		// Someone else's artifact under this package's path.
		{"netbox", "other-v4.5.5.bundle", "", false, false},
		// The suffix is present and the ref is not, which addresses nothing.
		{"netbox", "netbox-.bundle", "", false, false},
		{"netbox", "netbox-.tar.gz", "", false, false},
		// Neither shape. This is where the npm parser and this one part
		// company: npmVersionFromTarball strips the prefix off a name with no
		// .tgz and returns it, because an npm version is the whole remainder.
		// A git ref is not, so a filename carrying neither suffix names no
		// object and the handler owes the caller a 404.
		{"netbox", "netbox-v4.5.5.zip", "", false, false},
		{"netbox", "netbox-v4.5.5", "", false, false},
		{"netbox", "netbox", "", false, false},
		{"netbox", "", "", false, false},
	} {
		ref, release, ok := gitRefFromFile(tc.name, tc.file)
		if ref != tc.wantRef || release != tc.wantRelease || ok != tc.wantOK {
			t.Errorf("gitRefFromFile(%q, %q) = (%q, %v, %v), want (%q, %v, %v)",
				tc.name, tc.file, ref, release, ok, tc.wantRef, tc.wantRelease, tc.wantOK)
		}
	}
}

// newGitBundleServer builds a server holding one uploaded bundle, so the 404
// cases below are distinguishable from a route that never worked.
func newGitBundleServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeGit, "netbox", manifest.VersionEntry{
		URL: "https://github.com/netbox-community/netbox",
		Ref: "v4.5.5",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	mem := storage.NewMemory()
	if err := mem.Put(t.Context(), manifest.GitKey("netbox", "v4.5.5", false), []byte("fake-bundle")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s := newServer(&config.Config{AptCodename: "noble", LogDir: t.TempDir()},
		store, storage.NewSingle(mem), "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestGitBundleUnparseableFilenameIs404 is the handler half. An unparseable
// filename is a request for nothing, which is a 404 — not a 500 from a parse
// that panicked downstream, and not a 200 on some key the shape check invented.
func TestGitBundleUnparseableFilenameIs404(t *testing.T) {
	ts := newGitBundleServer(t)

	// The control. Without it a 404 below proves only that the route is broken.
	if got := gitGetStatus(t, ts.URL+"/git/netbox/netbox-v4.5.5.bundle"); got != http.StatusOK {
		t.Fatalf("GET the uploaded bundle = %d, want 200", got)
	}

	for _, file := range []string{
		"netbox-v4.5.5.zip", // neither suffix
		"netbox-.bundle",    // empty ref
		"other-v4.5.5.bundle",
		"netbox-v4.5.5",
	} {
		if got := gitGetStatus(t, ts.URL+"/git/netbox/"+file); got != http.StatusNotFound {
			t.Errorf("GET /git/netbox/%s = %d, want 404", file, got)
		}
	}
}

func gitGetStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
