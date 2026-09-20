package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// The two layouts observed on pkg.freebsd.org, copied out of the real
// catalogues: latest/ publishes under All/Hashed/ and base_latest/ under
// Hashed/, both carrying the "~" and "$" a hashed filename holds. Neither is
// derivable from a package name and version, so both are fixtures rather than
// one with a rule applied to it.
const (
	freeBSDABI          = "FreeBSD:14:amd64"
	freeBSDHashedPath   = "All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg"
	freeBSDBasePath     = "Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg"
	freeBSDCatalogBytes = "\x28\xb5\x2f\xfd not really zstd, but never decoded on this side"
	freeBSDMetaBytes    = "version = 2;\npacking_format = \"tzst\";\nmanifests = \"packagesite.yaml\";\n"
)

// mirrored seeds a hosted repository: a manifest entry plus objects in the
// store, which is what the mirror leaves behind.
func mirrored(t *testing.T, s *Server, repo string, objects map[string]string) {
	t.Helper()
	addVersion(t, s, manifest.TypeFreeBSD, repo, manifest.VersionEntry{Version: freeBSDABI})
	keyed := make(map[string]string, len(objects))
	for repoPath, body := range objects {
		keyed[manifest.FreeBSDKey(freeBSDABI, repo, repoPath)] = body
	}
	seed(t, s, manifest.TypeFreeBSD, keyed)
}

func freeBSDURL(repo, repoPath string) string {
	return "/freebsd/" + freeBSDABI + "/" + repo + "/" + repoPath
}

// R2, R3: meta.conf and the catalogue archives come back exactly as stored.
// The catalogue carries FreeBSD's own signature as a tar member, so a single
// byte of transformation anywhere on this path is a signature failure the
// client reports against bytes bodega changed on purpose.
func TestFreeBSDServesTheRepositoryRootByteForByte(t *testing.T) {
	s := hostedServer(t)
	mirrored(t, s, "latest", map[string]string{
		manifest.FreeBSDMetaFile:    freeBSDMetaBytes,
		manifest.FreeBSDCatalogFile: freeBSDCatalogBytes,
		manifest.FreeBSDDataFile:    "data archive bytes",
	})

	for _, file := range manifest.FreeBSDCatalogFiles {
		want := map[string]string{
			manifest.FreeBSDMetaFile:    freeBSDMetaBytes,
			manifest.FreeBSDCatalogFile: freeBSDCatalogBytes,
			manifest.FreeBSDDataFile:    "data archive bytes",
		}[file]
		status, body := getStatusAndBody(t, s, freeBSDURL("latest", file))
		if status != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", file, status, body)
		}
		if body != want {
			t.Errorf("%s served %q, want the stored bytes %q", file, body, want)
		}
	}
}

// R3 again, on the response headers rather than the body. A Content-Encoding
// negotiated over an already-compressed archive is the transformation that
// costs nothing to add and breaks the embedded signature in transit.
func TestFreeBSDNegotiatesNoContentEncoding(t *testing.T) {
	s := hostedServer(t)
	mirrored(t, s, "latest", map[string]string{manifest.FreeBSDCatalogFile: freeBSDCatalogBytes})

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		ts.URL+freeBSDURL("latest", manifest.FreeBSDCatalogFile), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET the catalogue: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want none: re-encoding the archive breaks the signature inside it", enc)
	}
}

// R4: both layouts are served off the catalogue's own repopath. The key
// scheme carries ":", "~" and "$" literally, so a request composed from a
// real catalogue record resolves; one that encoded them would 404 here and
// pass against a fixture that avoided the characters.
func TestFreeBSDServesBothCatalogueLayouts(t *testing.T) {
	for _, tc := range []struct {
		repo     string
		repoPath string
		body     string
	}{
		{"latest", freeBSDHashedPath, "latest layout package"},
		{"base_latest", freeBSDBasePath, "base_latest layout package"},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			s := hostedServer(t)
			mirrored(t, s, tc.repo, map[string]string{
				manifest.FreeBSDCatalogFile: freeBSDCatalogBytes,
				tc.repoPath:                 tc.body,
			})

			status, body := getStatusAndBody(t, s, freeBSDURL(tc.repo, tc.repoPath))
			if status != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200: %s", tc.repoPath, status, body)
			}
			if body != tc.body {
				t.Errorf("served %q, want %q", body, tc.body)
			}
		})
	}
}

// R5. The mirror writes objects first and the catalogue last, so the only
// half-finished state a store can be left in is one with objects and no
// catalogue — and in that state the catalogue must 404 rather than reach
// upstream, whose catalogue is by construction newer and names packages this
// store has never held. Both halves are driven against one store, because the
// failure is a relationship between two requests rather than a property of
// either.
func TestFreeBSDNeverServesACatalogueNewerThanItsObjects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream catalogue, naming packages this mirror does not hold"))
	}))
	t.Cleanup(upstream.Close)

	s := proxyingServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     upstream.URL,
	})
	seed(t, s, manifest.TypeFreeBSD, map[string]string{
		manifest.FreeBSDKey(freeBSDABI, "latest", freeBSDHashedPath): "one mirrored package",
	})

	// The object half: mirrored, and served.
	status, body := getStatusAndBody(t, s, freeBSDURL("latest", freeBSDHashedPath))
	if status != http.StatusOK {
		t.Fatalf("GET a mirrored object = %d, want 200: %s", status, body)
	}
	if body != "one mirrored package" {
		t.Errorf("object served %q, want the stored bytes", body)
	}

	// The catalogue half: absent, and refused rather than proxied. The
	// upstream is reachable and configured, which is what makes this an
	// assertion about the refusal rather than about a dead URL.
	status, body = getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDCatalogFile))
	if status != http.StatusNotFound {
		t.Fatalf("GET the catalogue of a half-mirrored repository = %d, want 404: %s", status, body)
	}
	if strings.Contains(body, "upstream catalogue") {
		t.Error("the catalogue was proxied from upstream, so a client would resolve packages this store does not hold")
	}
	if keys := storedKeys(t, s, manifest.TypeFreeBSD, manifest.FreeBSDRepoPrefix(freeBSDABI, "latest")); len(keys) != 1 {
		t.Errorf("store holds %v, want only the one mirrored object: the refused catalogue must not have been cached", keys)
	}
}

// R6. All three 404 on every current FreeBSD repository, so they are refused
// by name: proxying them would spend a round trip per client per update to
// cache somebody else's 404, and mirroring them would mean generating files
// upstream does not publish. The message names what pkg reads instead,
// because a client asking for these is old enough that the answer is a fact
// about pkg rather than about this repository.
func TestFreeBSDRefusesPathsNoCurrentRepositoryPublishes(t *testing.T) {
	for _, file := range []string{"digests.pkg", "packagesite.txz", "repo.txz"} {
		t.Run(file, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("%s was fetched from upstream; it is refused here by name", r.URL.Path)
			}))
			t.Cleanup(upstream.Close)

			s := proxyingServer(t)
			addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
				Version: freeBSDABI,
				URL:     upstream.URL,
				Mode:    manifest.ModeProxy,
			})

			status, body := getStatusAndBody(t, s, freeBSDURL("latest", file))
			if status != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want 404: %s", file, status, body)
			}
			if !strings.Contains(body, "packagesite.pkg") {
				t.Errorf("the refusal does not name what pkg reads instead: %q", body)
			}
		})
	}
}

// R7, the hosted half: an entry whose mode is hosted is served out of the
// store and never reaches upstream, which is what makes the mirror a mirror
// rather than a cache.
func TestFreeBSDHostedEntryNeverReachesUpstream(t *testing.T) {
	var reached int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		_, _ = w.Write([]byte("upstream bytes"))
	}))
	t.Cleanup(upstream.Close)

	s := proxyingServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     upstream.URL,
	})
	seed(t, s, manifest.TypeFreeBSD, map[string]string{
		manifest.FreeBSDKey(freeBSDABI, "latest", manifest.FreeBSDCatalogFile): freeBSDCatalogBytes,
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the mirrored catalogue = %d, want 200: %s", status, body)
	}
	if body != freeBSDCatalogBytes {
		t.Errorf("served %q, want the stored bytes", body)
	}
	if reached != 0 {
		t.Errorf("upstream was contacted %d times for a hosted entry", reached)
	}
}

// R7, the proxy half: an entry whose mode is proxy holds no snapshot, so both
// the catalogue and the objects come from upstream on a miss and land in the
// store. Upstream serves both here, so the pair is self-consistent and the
// ordering rule the hosted half enforces has nothing to enforce.
func TestFreeBSDProxyModeFetchesFromUpstreamAndCaches(t *testing.T) {
	bodies := map[string]string{
		"/" + manifest.FreeBSDCatalogFile: freeBSDCatalogBytes,
		"/" + manifest.FreeBSDMetaFile:    freeBSDMetaBytes,
		"/" + freeBSDHashedPath:           "a proxied package",
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(upstream.Close)

	s := proxyingServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     upstream.URL,
		Mode:    manifest.ModeProxy,
	})

	for path, want := range map[string]string{
		manifest.FreeBSDMetaFile:    freeBSDMetaBytes,
		manifest.FreeBSDCatalogFile: freeBSDCatalogBytes,
		freeBSDHashedPath:           "a proxied package",
	} {
		status, body := getStatusAndBody(t, s, freeBSDURL("latest", path))
		if status != http.StatusOK {
			t.Fatalf("GET %s on a proxy-mode entry = %d, want 200: %s", path, status, body)
		}
		if body != want {
			t.Errorf("%s served %q, want the upstream bytes %q", path, body, want)
		}
	}

	keys := storedKeys(t, s, manifest.TypeFreeBSD, manifest.FreeBSDRepoPrefix(freeBSDABI, "latest"))
	if len(keys) != 3 {
		t.Errorf("store holds %v, want all three proxied objects cached under the repository prefix", keys)
	}
}

// A repository no manifest entry names has no upstream to compose, so it 404s
// rather than reaching some default. There is no public default for this
// type: a pkg repository root is an operator's to name.
func TestFreeBSDWithNoEntryHasNoUpstream(t *testing.T) {
	s := proxyingServer(t)
	status, _ := getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDCatalogFile))
	if status != http.StatusNotFound {
		t.Errorf("GET a repository no entry names = %d, want 404", status)
	}
}

// The route composes an object key, so a path that walked out of the
// repository prefix would read another repository's bytes under this one's
// name. Refused at the split, before a key exists to be wrong.
func TestFreeBSDRefusesAPathThatEscapesItsRepository(t *testing.T) {
	for _, p := range []string{
		"FreeBSD:14:amd64/latest/../../other/secret.pkg",
		"FreeBSD:14:amd64/latest/All/../../../etc/passwd",
		"FreeBSD:14:amd64/latest/",
		"FreeBSD:14:amd64/latest/All//double.pkg",
		`FreeBSD:14:amd64/latest/All\Hashed\x.pkg`,
		"FreeBSD:14:amd64",
		"../../etc/passwd/latest/x.pkg",
	} {
		if _, _, _, ok := splitFreeBSDPath(p); ok {
			t.Errorf("splitFreeBSDPath(%q) accepted a path that does not resolve inside one repository", p)
		}
	}
	for _, p := range []string{
		"FreeBSD:14:amd64/latest/" + freeBSDHashedPath,
		"FreeBSD:14:amd64/base_latest/" + freeBSDBasePath,
		"FreeBSD:15:aarch64/quarterly/meta.conf",
	} {
		if _, _, _, ok := splitFreeBSDPath(p); !ok {
			t.Errorf("splitFreeBSDPath(%q) refused a path a real pkg client composes", p)
		}
	}
}
