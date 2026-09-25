package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
	"github.com/ravinald/bodega/internal/pkgsign"
)

// statusFreeBSD reads the freebsd block off the wire rather than calling the
// composer, because the wire shape is what the web UI and doctor consume: a
// field renamed in Go and not in its tag is a block nothing reads.
func statusFreeBSD(t *testing.T, s *Server) freebsdStatus {
	t.Helper()
	return statusFreeBSDFrom(t, s, "192.0.2.1:1234")
}

// statusFreeBSDFrom is the same read from a named caller, for the fields this
// block gates. A server built with no admin_permit_cidr permits nobody, so
// the address statusFreeBSD leaves at httptest's default is a non-admin one.
func statusFreeBSDFrom(t *testing.T, s *Server, remote string) freebsdStatus {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/status = %d", rec.Code)
	}
	var out struct {
		FreeBSD freebsdStatus `json:"freebsd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse status: %v\n%s", err, rec.Body.String())
	}
	return out.FreeBSD
}

// A mirrored repository's client configuration verifies against the stock
// trust store and disables the tags its ABI's release defines. Both are facts
// the server holds and no emitter derived correctly on its own.
func TestFreeBSDStatusRendersAMirroredRepository(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: "FreeBSD:14:amd64",
		URL:     "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
	})

	st := statusFreeBSD(t, s)
	repo := st.RepoFor("latest", "FreeBSD:14:amd64")
	if repo == nil {
		t.Fatalf("no rendered configuration for latest@FreeBSD:14:amd64, got %+v", st.Repos)
	}
	if repo.SignatureType != "fingerprints" || repo.Fingerprints != pkgrepos.StockFingerprints {
		t.Errorf("signature_type %q fingerprints %q, want fingerprints against the stock trust store",
			repo.SignatureType, repo.Fingerprints)
	}
	if !strings.Contains(repo.Conf, "FreeBSD: { enabled: no }") {
		t.Errorf("the conf leaves the upstream repository enabled beside bodega's:\n%s", repo.Conf)
	}
	if !strings.Contains(repo.URL, "https://bodega.internal/freebsd/${ABI}/latest") {
		t.Errorf("url = %q, want the public URL with ${ABI} literal", repo.URL)
	}
}

// A generated repository is signed by bodega, so its configuration names
// bodega's fingerprint rather than the stock trust store. Serving the stock
// one fails pkg update with an error naming the signature, which sends the
// reader to the wrong file.
func TestFreeBSDStatusRendersAGeneratedRepositoryAgainstBodegasKey(t *testing.T) {
	t.Setenv(pkgsign.CredentialsEnv, "")
	kr := installPkgKey(t, pkgsign.KeyRSA)
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "house", manifest.VersionEntry{
		Version: "FreeBSD:15:aarch64", Generated: true,
	})

	st := statusFreeBSD(t, s)
	if !st.Signed || st.Fingerprint != kr.Fingerprint() {
		t.Fatalf("signed %v fingerprint %q, want the loaded key %q reported", st.Signed, st.Fingerprint, kr.Fingerprint())
	}
	repo := st.RepoFor("house", "FreeBSD:15:aarch64")
	if repo == nil {
		t.Fatalf("no rendered configuration for house@FreeBSD:15:aarch64, got %+v", st.Repos)
	}
	if repo.Fingerprints != pkgrepos.BodegaFingerprints {
		t.Errorf("fingerprints = %q, want %q: the stock store holds no key that signed this",
			repo.Fingerprints, pkgrepos.BodegaFingerprints)
	}
	// FreeBSD 15 split the ports repository three ways, and an override that
	// names only the pre-15 tag leaves all three enabled.
	for _, tag := range pkgrepos.UpstreamTags(15) {
		if !strings.Contains(repo.Conf, tag+": { enabled: no }") {
			t.Errorf("the conf does not disable %s on a FreeBSD:15 ABI:\n%s", tag, repo.Conf)
		}
	}
}

// An entry the server will not route is reported as refused rather than
// dropped. Dropped, it is indistinguishable from an entry that is not
// configured, and the manifest that caused it stays uncorrected.
//
// Both contradictions manifest.VersionEntry.FreeBSDGenerated refuses reach
// this list. Either one rendered instead is a stanza published for a
// repository whose every path answers 500, with an empty refusal list beside
// it saying nothing is wrong.
//
// The third row is the renderer's alone and the route does not share it: an
// entry naming neither a url nor generated is served from the store and has
// no trust store anybody can name. See
// TestFreeBSDStatusStillServesTheEntryItRefusesToConfigure for the half that
// keeps a later pass from closing the gap at the route.
//
// The reason is the admin caller's. TestFreeBSDStatusWithholdsARefusalFromAnonymousCallers
// covers what everyone else sees.
func TestFreeBSDStatusReportsARefusedEntryRatherThanDroppingIt(t *testing.T) {
	for _, tc := range []struct {
		repo  string
		entry manifest.VersionEntry
		names string
	}{
		{"muddle", manifest.VersionEntry{
			Version: "FreeBSD:14:amd64", Generated: true,
			URL: "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
		}, "url"},
		{"drift", manifest.VersionEntry{
			Version: "FreeBSD:14:amd64", Generated: true, Mode: manifest.ModeProxy,
		}, "proxy"},
		{"imported", manifest.VersionEntry{Version: "FreeBSD:14:amd64"}, "url"},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			s := hostedServer(t)
			s.cfg.PublicURL = "https://bodega.internal"
			addVersion(t, s, manifest.TypeFreeBSD, tc.repo, tc.entry)

			st := statusFreeBSDFrom(t, s, adminCaller(t, s))
			if len(st.Repos) != 0 {
				t.Fatalf("a contradictory entry rendered a configuration: %+v", st.Repos)
			}
			if len(st.Refused) != 1 || st.Refused[0].Repo != tc.repo {
				t.Fatalf("Refused = %+v, want one row naming %s", st.Refused, tc.repo)
			}
			for _, want := range []string{"generated", tc.names} {
				if !strings.Contains(st.Refused[0].Error, want) {
					t.Errorf("the refusal does not name %q, so the manifest field to change is a guess: %q", want, st.Refused[0].Error)
				}
			}
		})
	}
}

// adminCaller admits one address through admin_permit_cidr and returns it as a
// RemoteAddr.
func adminCaller(t *testing.T, s *Server) string {
	t.Helper()
	_, admin, err := net.ParseCIDR("198.51.100.7/32")
	if err != nil {
		t.Fatalf("parse the admin cidr: %v", err)
	}
	s.adminNets = []*net.IPNet{admin}
	s.refreshACLs(context.Background())
	return "198.51.100.7:40000"
}

// A refusal quotes the entry's url, and a url may carry the credential its
// upstream wants, so the reason reaches an admin caller alone. repo and abi
// stay public: without them a client cannot tell a refused repository from an
// absent one.
func TestFreeBSDStatusWithholdsARefusalFromAnonymousCallers(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "muddle", manifest.VersionEntry{
		Version: "FreeBSD:14:amd64", Generated: true,
		URL: "https://audit-user:audit-secret@private-upstream.example/" + freeBSDABI + "/latest",
	})
	adminAddr := adminCaller(t, s)

	anon := statusFreeBSDFrom(t, s, "203.0.113.9:40000")
	if len(anon.Refused) != 1 || anon.Refused[0].Repo != "muddle" || anon.Refused[0].ABI != "FreeBSD:14:amd64" {
		t.Fatalf("Refused = %+v for a non-admin caller, want one row naming muddle@FreeBSD:14:amd64", anon.Refused)
	}
	if leaked := withheldFrom(anon.Refused[0].Error, "audit-secret"); leaked != "" {
		t.Errorf("refused[].error hands a caller with no token the url's password: %q", anon.Refused[0].Error)
	}
	if leaked := withheldFrom(anon.Refused[0].Error, "audit-user"); leaked != "" {
		t.Errorf("refused[].error hands a caller with no token the url's username: %q", anon.Refused[0].Error)
	}

	admin := statusFreeBSDFrom(t, s, adminAddr)
	if len(admin.Refused) != 1 || !strings.Contains(admin.Refused[0].Error, "generated") {
		t.Errorf("Refused = %+v for an admin caller, want the reason naming the field to change", admin.Refused)
	}
}

// The entry the renderer refuses is still served, and that asymmetry is the
// design rather than a gap to close.
//
// The route asks whether it can serve these bytes and reads the store to do
// it, which needs no url; pkgrepos.Render asks which trust store verifies
// them, and the url is the only authority for that. Guarding
// manifest.VersionEntry.FreeBSDGenerated to match the renderer would answer
// 500 for every repository seeded the way internal/server/freebsd_test.go's
// own mirrored() helper seeds one.
func TestFreeBSDStatusStillServesTheEntryItRefusesToConfigure(t *testing.T) {
	const repo = "imported"
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, repo, manifest.VersionEntry{Version: freeBSDABI})
	seed(t, s, manifest.TypeFreeBSD, map[string]string{
		manifest.FreeBSDKey(freeBSDABI, repo, manifest.FreeBSDMetaFile): freeBSDMetaBytes,
	})

	st := statusFreeBSD(t, s)
	if st.RepoFor(repo, freeBSDABI) != nil {
		t.Fatalf("rendered configuration for an entry naming neither a url nor generated: %+v", st.Repos)
	}
	if len(st.Refused) != 1 {
		t.Fatalf("Refused = %+v, want the one row a reader needs to fix the manifest", st.Refused)
	}

	status, body := getStatusAndBody(t, s, freeBSDURL(repo, manifest.FreeBSDMetaFile))
	if status != http.StatusOK || body != freeBSDMetaBytes {
		t.Fatalf("GET %s = %d %q, want 200 and the stored bytes: the route serves what the store holds and the refusal above is the emitter's alone",
			manifest.FreeBSDMetaFile, status, body)
	}
}

// hide is the quarantine control and the route already 404s a hidden ABI.
// Publishing configuration for one hands an operator a file pointing at a
// repository that answers nothing.
func TestFreeBSDStatusOmitsHiddenRepositories(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "quarantined", manifest.VersionEntry{
		Version: "FreeBSD:14:amd64", URL: "https://example.invalid/latest", Hidden: true,
	})
	addVersion(t, s, manifest.TypeFreeBSD, "quarantined", manifest.VersionEntry{
		Version: "FreeBSD:15:amd64", URL: "https://example.invalid/latest",
	})

	st := statusFreeBSD(t, s)
	if st.RepoFor("quarantined", "FreeBSD:14:amd64") != nil {
		t.Error("a hidden ABI has a rendered configuration, which points at a route that 404s it")
	}
	if st.RepoFor("quarantined", "FreeBSD:15:amd64") == nil {
		t.Error("hiding one ABI took the sibling's configuration with it; the two are configured apart")
	}
}

// One ABI's entry never answers for another's. They carry separate modes,
// URLs and generated flags, and the release in the override comes off the
// ABI: matching on the repository name alone hands a FreeBSD:14 host a file
// whose overrides name tags only a 15 host defines.
func TestFreeBSDStatusRendersOnePerABI(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	for _, abi := range []string{"FreeBSD:14:amd64", "FreeBSD:15:amd64"} {
		addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
			Version: abi, URL: "https://pkg.freebsd.org/" + abi + "/latest",
		})
	}

	st := statusFreeBSD(t, s)
	for abi, want := range map[string][]string{
		"FreeBSD:14:amd64": pkgrepos.UpstreamTags(14),
		"FreeBSD:15:amd64": pkgrepos.UpstreamTags(15),
	} {
		repo := st.RepoFor("latest", abi)
		if repo == nil {
			t.Fatalf("no rendered configuration for latest@%s", abi)
		}
		if strings.Join(repo.Disabled, ",") != strings.Join(want, ",") {
			t.Errorf("%s disables %v, want %v", abi, repo.Disabled, want)
		}
	}
}

// A key file that is present and will not load is a third state. An operator
// who installed one believes the repository is signed, and every generated
// catalogue refuses until it loads, so the status says so rather than
// reporting the unsigned configuration an absent key would produce.
//
// It says so to an admin caller alone. The text is a load failure verbatim,
// and the one planted here is pkgsign's likeliest: it names the key file by
// path and reports that the private key is readable beyond its owner. That is
// the datum spool.Dir and the build stamp are already withheld for. signed
// stays public on both sides, because a client that cannot tell a signed
// repository from an unsigned one configures the wrong signature_type.
func TestFreeBSDStatusReportsAnUnusableKeyToAdminsOnly(t *testing.T) {
	t.Setenv(pkgsign.CredentialsEnv, "")
	kr := installPkgKey(t, pkgsign.KeyRSA)
	if err := os.Chmod(kr.Path(), 0o644); err != nil {
		t.Fatalf("chmod the key readable beyond its owner: %v", err)
	}
	s := hostedServer(t)
	_, admin, err := net.ParseCIDR("198.51.100.7/32")
	if err != nil {
		t.Fatalf("parse the admin cidr: %v", err)
	}
	s.adminNets = []*net.IPNet{admin}
	s.refreshACLs(context.Background())

	st := statusFreeBSDFrom(t, s, "198.51.100.7:40000")
	if st.Signed {
		t.Error("signed is true for a key the server could not load")
	}
	if !strings.Contains(st.KeyError, kr.Path()) {
		t.Errorf("key_error = %q, want the load failure naming the file an operator has to fix", st.KeyError)
	}

	anon := statusFreeBSDFrom(t, s, "203.0.113.9:40000")
	if anon.KeyError != "" {
		t.Errorf("key_error = %q for a caller outside admin_permit_cidr, which hands anyone who can reach the listener the key's path and its mode", anon.KeyError)
	}
	if anon.Signed != st.Signed {
		t.Errorf("signed = %v for a non-admin caller and %v for an admin one; the gate is on the error text, not on whether the repository is signed", anon.Signed, st.Signed)
	}
}

// A mirror of a release-engineered base repository is not handed the ports
// trust store. Both key sets ship on a FreeBSD 15 host and only one of them
// verifies what release engineering signed; the wrong one fetches the
// catalogue, processes no entries and exits 0, so nothing between the client
// and this response reports it.
//
// The upstream URL is what says which it is — the repository name is the
// operator's — and it never crosses the wire, so this reads the endpoint
// rather than the renderer.
func TestFreeBSDStatusDoesNotHandAPkgbaseMirrorThePortsTrustStore(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "house-base", manifest.VersionEntry{
		Version: "FreeBSD:15:amd64",
		URL:     "https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1",
	})

	st := statusFreeBSD(t, s)
	repo := st.RepoFor("house-base", "FreeBSD:15:amd64")
	if repo == nil {
		t.Fatalf("no rendered configuration for house-base@FreeBSD:15:amd64, got %+v", st.Repos)
	}
	if repo.Fingerprints != pkgrepos.PkgbaseFingerprints {
		t.Fatalf("fingerprints = %q, want %q: the ports store holds no key that signed this repository",
			repo.Fingerprints, pkgrepos.PkgbaseFingerprints)
	}
	if !repo.Pkgbase {
		t.Errorf("pkgbase is absent from the response, so a client re-rendering this configuration resolves it back to the ports store")
	}
	if strings.Contains(repo.Conf, `"`+pkgrepos.StockFingerprints+`"`) {
		t.Errorf("the conf names the ports trust store:\n%s", repo.Conf)
	}
}

// A mirror of a base snapshot repository keeps the ports trust store, which
// is what verifies it: base_latest and base_weekly come off the package
// builders' key like ports do. Deciding this on the name alone would point
// the base repository bodega's own create prompt suggests at a store holding
// nothing that signed it.
func TestFreeBSDStatusKeepsTheStockStoreForABaseSnapshotMirror(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "base_latest", manifest.VersionEntry{
		Version: "FreeBSD:15:amd64",
		URL:     "https://pkg.freebsd.org/FreeBSD:15:amd64/base_latest",
	})

	st := statusFreeBSD(t, s)
	repo := st.RepoFor("base_latest", "FreeBSD:15:amd64")
	if repo == nil {
		t.Fatalf("no rendered configuration for base_latest@FreeBSD:15:amd64, got %+v", st.Repos)
	}
	if repo.Fingerprints != pkgrepos.StockFingerprints {
		t.Fatalf("fingerprints = %q, want %q: base_latest is signed by the package builders' key",
			repo.Fingerprints, pkgrepos.StockFingerprints)
	}
	if repo.Pkgbase {
		t.Errorf("pkgbase is set for a snapshot repository the pkgbase key set never signed")
	}
}

// A proxied mirror of a base repository does not tell an operator to run
// `pkg bootstrap`. Proxying resolves the two paths pkg's bootstrapper fetches
// and upstream publishes neither under a base repository, so the client gets
// a 502: the claim is keyed off the upstream URL, which never
// crosses the wire, so this reads the endpoint rather than the renderer.
func TestFreeBSDStatusDoesNotPromiseBootstrapOnAProxiedBaseMirror(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "house-base", manifest.VersionEntry{
		Version: "FreeBSD:15:amd64",
		URL:     "https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1",
		Mode:    manifest.ModeProxy,
	})

	st := statusFreeBSD(t, s)
	repo := st.RepoFor("house-base", "FreeBSD:15:amd64")
	if repo == nil {
		t.Fatalf("no rendered configuration for house-base@FreeBSD:15:amd64, got %+v", st.Repos)
	}
	if repo.Bootstrap != pkgrepos.BootstrapAbsent {
		t.Errorf("bootstrap = %q, want %q: upstream answers 403 for both Latest/pkg.pkg paths under a base repository",
			repo.Bootstrap, pkgrepos.BootstrapAbsent)
	}
	if strings.Contains(repo.Conf, "`pkg bootstrap` works here") {
		t.Errorf("the conf tells the operator to run a command that cannot resolve:\n%s", repo.Conf)
	}
}

// A hosted mirror on a server with the proxy cache on does not claim to be
// isolated, because it is not: the route composes an upstream URL for any
// path outside the catalogue whenever the entry records a url, and fetches
// the miss when the cache is enabled or the mode is proxy
// (internal/server/freebsd.go:127,155, internal/server/proxy.go:116).
//
// Both halves run against one server on purpose. The defect this covers is a
// disagreement between what the route answers for Latest/pkg.pkg and what the
// emitted configuration claims about it, and neither half alone shows it: the
// route served 200 off pkg.FreeBSD.org while the conf told the operator the
// path was dead and that nothing under this repository reached the internet.
func TestFreeBSDHostedMirrorWithTheCacheOnDoesNotClaimToBeIsolated(t *testing.T) {
	const bootstrapPkg = "the pkg bootstrap package upstream publishes"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(bootstrapPkg))
	}))
	t.Cleanup(upstream.Close)

	// No Mode, so this entry is hosted. proxyingServer is the cache-enabled
	// one, which is the only other term the route reads. The url ends in
	// "latest" because the second half of the bootstrap answer comes off the
	// upstream repository's name, and a name nobody measured hedges.
	s := proxyingServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     upstream.URL + "/latest",
	})

	// The route half: the bootstrapper's path resolves, and the bytes came
	// from upstream rather than from this store.
	status, body := getStatusAndBody(t, s, freeBSDURL("latest", "Latest/pkg.pkg"))
	if status != http.StatusOK || body != bootstrapPkg {
		t.Fatalf("GET Latest/pkg.pkg on a hosted mirror with the cache on = %d %q, want 200 and upstream's bytes", status, body)
	}

	// The configuration half: it describes that same path.
	st := statusFreeBSD(t, s)
	repo := st.RepoFor("latest", freeBSDABI)
	if repo == nil {
		t.Fatalf("no rendered configuration for latest@%s, got %+v", freeBSDABI, st.Repos)
	}
	if !repo.UpstreamFallthrough {
		t.Errorf("upstream_fallthrough is false for an entry whose Latest/pkg.pkg this server just fetched from upstream")
	}
	if repo.Bootstrap != pkgrepos.BootstrapWorks {
		t.Errorf("bootstrap = %q, want %q: the path answered 200 through this server", repo.Bootstrap, pkgrepos.BootstrapWorks)
	}
	if strings.Contains(repo.Conf, "`pkg bootstrap` does not work") {
		t.Errorf("the conf calls a path dead that answers 200, costing the operator a bootstrap by hand:\n%s", repo.Conf)
	}
	if strings.Contains(repo.Conf, "every request stops here") {
		t.Errorf("the conf claims this repository reaches nothing upstream while the server fetches %s from it:\n%s", upstream.URL, repo.Conf)
	}
	if !strings.Contains(repo.Note(), "reaches the internet") {
		t.Errorf("no note says the bootstrap path leaves the building: %q", repo.Note())
	}
}

// The same entry on a server with the cache off is isolated, and says so.
// This is the row that makes the test above an assertion about the toggle
// rather than about hosted mirrors.
func TestFreeBSDHostedMirrorWithTheCacheOffIsIsolatedAndSaysSo(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     "https://pkg.freebsd.org/" + freeBSDABI + "/latest",
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("latest", "Latest/pkg.pkg"))
	if status != http.StatusNotFound {
		t.Fatalf("GET Latest/pkg.pkg with the proxy cache off = %d, want 404: %s", status, body)
	}

	st := statusFreeBSD(t, s)
	repo := st.RepoFor("latest", freeBSDABI)
	if repo == nil {
		t.Fatalf("no rendered configuration for latest@%s, got %+v", freeBSDABI, st.Repos)
	}
	if repo.UpstreamFallthrough {
		t.Errorf("upstream_fallthrough is true on a server that fetches no miss: the request 404'd")
	}
	if repo.Bootstrap != pkgrepos.BootstrapAbsent {
		t.Errorf("bootstrap = %q, want %q", repo.Bootstrap, pkgrepos.BootstrapAbsent)
	}
	if !strings.Contains(repo.Conf, "every request stops here") {
		t.Errorf("the conf withholds the isolation claim from a repository that is isolated:\n%s", repo.Conf)
	}
}

// A proxied repository fetches its catalogue from upstream too, and the
// emitted file may not tell its operator otherwise.
//
// The conf claimed one path left the building, which was written for a hosted
// mirror whose bootstrap pair fell through and printed unchanged here, where
// `pkg update` itself comes off pkg.FreeBSD.org. Both halves run against one
// server for the reason the hosted pair below does: the defect is a
// disagreement between what the route answers for meta.conf and what the
// configuration says about it, and neither half alone shows it.
func TestFreeBSDProxiedRepositoryDoesNotClaimOnlyOnePathLeavesTheHost(t *testing.T) {
	const upstreamCatalog = "upstream's own meta.conf"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamCatalog))
	}))
	t.Cleanup(upstream.Close)

	s := proxyingServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "quarterly", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     upstream.URL + "/quarterly",
		Mode:    manifest.ModeProxy,
	})

	// The route half. Nothing was uploaded to this repository, and the
	// catalogue answers anyway, with upstream's bytes.
	status, body := getStatusAndBody(t, s, freeBSDURL("quarterly", manifest.FreeBSDMetaFile))
	if status != http.StatusOK || body != upstreamCatalog {
		t.Fatalf("GET %s on a proxied repository = %d %q, want 200 and upstream's bytes",
			manifest.FreeBSDMetaFile, status, body)
	}

	// The configuration half, describing that same request.
	st := statusFreeBSD(t, s)
	repo := st.RepoFor("quarterly", freeBSDABI)
	if repo == nil {
		t.Fatalf("no rendered configuration for quarterly@%s, got %+v", freeBSDABI, st.Repos)
	}
	if repo.HoldsCatalogue() {
		t.Errorf("HoldsCatalogue is true for an entry whose meta.conf this server just fetched from upstream")
	}
	if strings.Contains(confProse(repo.Conf), "unlike every other request this repository answers") {
		t.Errorf("the conf claims one path reaches the internet on a repository where every path does:\n%s", repo.Conf)
	}
	if strings.Contains(confProse(repo.Conf), "mirrored byte for byte") {
		t.Errorf("the conf calls a proxy a finished mirror; it holds what earlier requests cached and nothing else:\n%s", repo.Conf)
	}
	if !strings.Contains(confProse(repo.Conf), "catalogue included") {
		t.Errorf("the conf does not say the catalogue is one of the paths that reaches upstream:\n%s", repo.Conf)
	}
}

// A hosted mirror on a cache-enabled server fills a package it never held
// from upstream and serves it under its own name, and the file says so.
//
// The pair above it drives Latest/pkg.pkg, which is the bootstrapper's path
// and the one the old text carved out as the exception. This drives an
// ordinary package, which is the half that exception left open: an operator
// told that every request but one stops at bodega is told the mirror is
// complete, and an install resolving against a package nobody mirrored is how
// they find out otherwise.
func TestFreeBSDHostedMirrorFillsAMissFromUpstreamAndSaysSo(t *testing.T) {
	const pkg = "a package this mirror never held"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(pkg))
	}))
	t.Cleanup(upstream.Close)

	s := proxyingServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     upstream.URL + "/latest",
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("latest", "All/pv-1.9.31.pkg"))
	if status != http.StatusOK || body != pkg {
		t.Fatalf("GET All/pv-1.9.31.pkg on a hosted mirror with the cache on = %d %q, want 200 and upstream's bytes", status, body)
	}
	// The catalogue is the half that does not fall through, which is what
	// makes this case neither of the other two.
	if catalogStatus, _ := getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDMetaFile)); catalogStatus != http.StatusNotFound {
		t.Fatalf("GET %s on a hosted mirror holding no catalogue = %d, want 404: a mirror's catalogue is refused rather than fetched",
			manifest.FreeBSDMetaFile, catalogStatus)
	}

	st := statusFreeBSD(t, s)
	repo := st.RepoFor("latest", freeBSDABI)
	if repo == nil {
		t.Fatalf("no rendered configuration for latest@%s, got %+v", freeBSDABI, st.Repos)
	}
	if !repo.HoldsCatalogue() {
		t.Errorf("HoldsCatalogue is false for an entry whose catalogue this server refused to fetch")
	}
	if strings.Contains(confProse(repo.Conf), "unlike every other request this repository answers") {
		t.Errorf("the conf tells an operator every package request stops here while this server just filled one from %s:\n%s", upstream.URL, repo.Conf)
	}
	if !strings.Contains(confProse(repo.Conf), "an install can succeed here against a package nobody mirrored") {
		t.Errorf("the conf does not say a package the mirror lacks is served from upstream under its name:\n%s", repo.Conf)
	}
}

// confProse is the emitted file's comment block as one line, so a claim
// asserted here survives a rewrap of the paragraph carrying it.
func confProse(conf string) string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if trimmed := strings.TrimPrefix(line, "#"); trimmed != line {
			out = append(out, strings.TrimSpace(trimmed))
		}
	}
	return strings.Join(out, " ")
}
