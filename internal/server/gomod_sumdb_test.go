package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

func (u *recordingUpstream) hits(p string) int {
	n := 0
	for _, got := range u.paths() {
		if got == p {
			n++
		}
	}
	return n
}

// expireMetadata makes every mutable object the cache holds stale, so the next
// request for one has to go upstream again.
func expireMetadata(s *Server) {
	s.cache.MetadataTTL = time.Nanosecond
	time.Sleep(5 * time.Millisecond)
}

// sumdbServer is a proxying server whose checksum database is a recording
// fixture.
func sumdbServer(t *testing.T) (*Server, *recordingUpstream) {
	t.Helper()
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	s.cfg.GomodSumdbURL = up.ts.URL
	s.cfg.GomodUpstream = up.ts.URL
	return s, up
}

func TestSumdbSupportedContactsNoUpstream(t *testing.T) {
	s, up := sumdbServer(t)
	status, body := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/supported")
	if status != http.StatusOK || body != "" {
		t.Errorf("supported = %d %q, want 200 and an empty body", status, body)
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("supported reached the upstream: %v", got)
	}
}

// With the proxy off, a 200 on supported would route lookups to a server
// that cannot answer them; the 404 sends the go command to the database.
func TestSumdbSupportedIs404WithTheProxyOff(t *testing.T) {
	s, _ := sumdbServer(t)
	s.cache.Enabled = false
	if status, _ := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/supported"); status != http.StatusNotFound {
		t.Errorf("supported with the proxy off = %d, want 404", status)
	}
}

func TestSumdbMutableDocumentsRefetchAfterTTL(t *testing.T) {
	for _, p := range []string{"latest", "lookup/golang.org/toolchain@v0.0.1-go1.25.3.linux-amd64"} {
		t.Run(p, func(t *testing.T) {
			s, up := sumdbServer(t)
			up.route("/"+p, "signed tree head\n")
			for range 2 {
				status, body := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
				if status != http.StatusOK || body != "signed tree head\n" {
					t.Fatalf("GET %s = %d %q, want 200 with the upstream bytes", p, status, body)
				}
			}
			if n := up.hits("/" + p); n != 1 {
				t.Fatalf("%s fetched %d times inside the TTL, want 1", p, n)
			}
			expireMetadata(s)
			getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
			if n := up.hits("/" + p); n != 2 {
				t.Errorf("%s fetched %d times after the TTL, want 2", p, n)
			}
		})
	}
}

func TestSumdbTiles(t *testing.T) {
	const full, partial = "tile/8/0/x001/234", "tile/8/0/x001/235.p/5"
	s, up := sumdbServer(t)
	up.route("/"+full, "full tile")
	up.route("/"+partial, "partial tile")
	for _, p := range []string{full, partial} {
		if status, body := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p); status != http.StatusOK {
			t.Fatalf("GET %s = %d %q", p, status, body)
		}
	}
	expireMetadata(s)
	for _, p := range []string{full, partial} {
		getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
	}
	if n := up.hits("/" + full); n != 1 {
		t.Errorf("a full tile was fetched %d times, want 1: it never changes", n)
	}
	if n := up.hits("/" + partial); n != 2 {
		t.Errorf("a partial tile was fetched %d times after the TTL, want 2: it grows under one name", n)
	}
}

func TestSumdbRefusesOtherPaths(t *testing.T) {
	s, up := sumdbServer(t)
	for _, p := range []string{
		"/go/sumdb/sum.example.com/latest",
		"/go/sumdb/sum.golang.org/../latest",
		"/go/sumdb/sum.golang.org/lookup/%2e%2e/x",
		"/go/sumdb/sum.golang.org/verifier",
		"/go/sumdb/sum.golang.org/",
	} {
		if status, _ := getStatusAndBody(t, s, p); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, status)
		}
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("a refused path reached the upstream: %v", got)
	}
}

func TestGomodLatestProxies(t *testing.T) {
	s, up := sumdbServer(t)
	const doc = `{"Version":"v0.0.1-go1.25.3.linux-amd64","Time":"2025-10-13T00:00:00Z"}`
	up.route("/golang.org/toolchain/@latest", doc)
	status, body := getStatusAndBody(t, s, "/go/golang.org/toolchain/@latest")
	if status != http.StatusOK || body != doc {
		t.Fatalf("@latest = %d %q, want 200 with the upstream document", status, body)
	}
	expireMetadata(s)
	getStatusAndBody(t, s, "/go/golang.org/toolchain/@latest")
	if n := up.hits("/golang.org/toolchain/@latest"); n != 2 {
		t.Errorf("@latest fetched %d times across a TTL, want 2: it is a mutable document", n)
	}
}

func TestGomodLatestHiddenModuleRefused(t *testing.T) {
	s, up := sumdbServer(t)
	up.route("/example.com/mod/@latest", `{"Version":"v1.0.0"}`)
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "example.com/mod",
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.0.0", Mode: manifest.ModeProxy, Hidden: true}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}
	if status, _ := getStatusAndBody(t, s, "/go/example.com/mod/@latest"); status == http.StatusOK {
		t.Errorf("@latest of a hidden module answered 200")
	}
	if up.sawPath("/example.com/mod/@latest") {
		t.Errorf("@latest of a hidden module reached the upstream")
	}
}

func TestProfileRefusesAGomodLatestItWouldFilter(t *testing.T) {
	s, up := sumdbServer(t)
	up.route("/example.com/mod/@latest", `{"Version":"v2.0.0"}`)
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "example.com/mod",
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.0.0", Mode: manifest.ModeProxy}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeGomod, Name: "example.com/mod",
			Constraint: manifest.ConstraintExact, Version: "v1.1.0",
		}})
	if status, body := f.get(t, "/go/example.com/mod/@latest"); status != http.StatusNotFound {
		t.Errorf("@latest naming a version the pin refuses = %d %q, want 404", status, body)
	}
	up.route("/example.com/mod/@latest", `{"Version":"v1.1.0"}`)
	expireMetadata(s)
	if status, body := f.get(t, "/go/example.com/mod/@latest"); status != http.StatusOK {
		t.Errorf("@latest naming the pinned version = %d %q, want 200", status, body)
	}
}

func TestBinaryRevalidatePatterns(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	const channel, tarball = "dist/channel-rust-stable.toml", "dist/2026-01-01/rust-std.tar.xz"
	tarBytes := "\xfd7zXZ\x00 rust-std bytes"
	up.route("/"+channel, "[pkg.rust]\n")
	up.route("/"+tarball, tarBytes)
	s.cfg.BinaryUpstreams = map[string]config.BinaryUpstream{
		"rust": {URL: up.ts.URL + "/", Mode: config.UpstreamModeOpen, Revalidate: []string{"dist/channel-rust-*"}},
	}
	for _, p := range []string{channel, tarball} {
		if status, body := getStatusAndBody(t, s, "/binaries/rust/"+p); status != http.StatusOK {
			t.Fatalf("GET %s = %d %q", p, status, body)
		}
	}
	expireMetadata(s)
	status, body := getStatusAndBody(t, s, "/binaries/rust/"+tarball)
	if status != http.StatusOK || body != tarBytes {
		t.Errorf("cached tarball = %d %q, want 200 with the upstream bytes unchanged", status, body)
	}
	getStatusAndBody(t, s, "/binaries/rust/"+channel)
	if n := up.hits("/" + channel); n != 2 {
		t.Errorf("the channel manifest was fetched %d times after the TTL, want 2", n)
	}
	if n := up.hits("/" + tarball); n != 1 {
		t.Errorf("the dated tarball was fetched %d times, want 1: it never changes", n)
	}
}
