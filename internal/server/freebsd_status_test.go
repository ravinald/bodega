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
	} {
		t.Run(tc.repo, func(t *testing.T) {
			s := hostedServer(t)
			s.cfg.PublicURL = "https://bodega.internal"
			addVersion(t, s, manifest.TypeFreeBSD, tc.repo, tc.entry)

			st := statusFreeBSD(t, s)
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
