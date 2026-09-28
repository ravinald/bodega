package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
	"github.com/ravinald/bodega/internal/pkgsign"
)

// Three records the way pkg.freebsd.org publishes them: one compact JSON
// document per line, the version carrying a port revision and an epoch.
const (
	fbsdNginxPath = "All/Hashed/nginx-1.26.2_1,3~abc123.pkg"
	fbsdCurlPath  = "All/Hashed/curl-8.9.1~def456.pkg"
	fbsdTreePath  = "All/Hashed/tree-2.1.1~789aaa.pkg"
)

var fbsdRecords = []string{
	`{"name":"nginx","origin":"www/nginx","version":"1.26.2_1,3","repopath":"` + fbsdNginxPath + `"}`,
	`{"name":"curl","origin":"ftp/curl","version":"8.9.1","repopath":"` + fbsdCurlPath + `"}`,
	`{"name":"tree","origin":"sysutils/tree","version":"2.1.1","repopath":"` + fbsdTreePath + `"}`,
}

// upstreamPkgKey is a key that is not bodega's, standing in for FreeBSD's:
// the published catalogue is signed with it, and nothing on the bound host
// should be asked to trust it for a filtered one.
func upstreamPkgKey(t *testing.T) *pkgSigning {
	t.Helper()
	kr, err := pkgsign.Generate(pkgsign.KeyRSA)
	if err != nil {
		t.Fatalf("generate the upstream key: %v", err)
	}
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("render the upstream public key: %v", err)
	}
	member, err := kr.PublicKeyMember()
	if err != nil {
		t.Fatalf("render the upstream public key member: %v", err)
	}
	return &pkgSigning{signer: kr, pub: pub, pubMember: member, fingerprint: kr.Fingerprint()}
}

// publishedCatalog is packagesite.pkg as upstream publishes it, signed by
// upstream's key.
func publishedCatalog(t *testing.T, s *Server, up *pkgSigning) string {
	t.Helper()
	body, err := s.freeBSDArchive(freeBSDCatalogDoc, []byte(strings.Join(fbsdRecords, "\n")+"\n"), up)
	if err != nil {
		t.Fatalf("build the published catalogue: %v", err)
	}
	return string(body)
}

// webProfile binds a host to a profile listing nginx at any version and curl
// held at a version the repository no longer carries, so one record passes on
// membership, one fails on the constraint and one on membership.
func webProfile(t *testing.T, s *Server) *profileFixture {
	t.Helper()
	return bindProfile(t, s, "web", "web-host",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeFreeBSD, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeFreeBSD, Name: "nginx"},
			{Type: manifest.TypeFreeBSD, Name: "curl", Constraint: manifest.ConstraintExact, Version: "8.8.0"},
		})
}

func profileURL(profile, repo, repoPath string) string {
	return pkgrepos.ProfilePath(profile) + "/" + freeBSDABI + "/" + repo + "/" + repoPath
}

// catalogNames reads the package names out of a served packagesite.pkg, after
// checking it verifies against want and not against refuse.
func catalogNames(t *testing.T, body string, doc string, want, refuse []byte) []string {
	t.Helper()
	members := archiveMembers(t, body)
	sig, text := members[doc+".sig"], members[doc]
	if sig == nil || text == nil {
		t.Fatalf("the archive carries %v, want %s and its .sig", keysOfBytes(members), doc)
	}
	if err := pkgsign.Verify(want, text, sig); err != nil {
		t.Errorf("%s does not verify against bodega's key: %v", doc, err)
	}
	if err := pkgsign.Verify(refuse, text, sig); err == nil {
		t.Errorf("%s verifies against the upstream key, so it was served under upstream's signature", doc)
	}
	var names []string
	if doc == freeBSDDataDoc {
		var d struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(text, &d); err != nil {
			t.Fatalf("parse the data document: %v", err)
		}
		for _, p := range d.Packages {
			names = append(names, p.Name)
		}
		return names
	}
	for _, line := range strings.Split(strings.TrimSpace(string(text)), "\n") {
		var rec struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse record %q: %v", line, err)
		}
		names = append(names, rec.Name)
	}
	return names
}

// R2: the view carries what the profile permits and nothing else, in both
// documents, and it verifies against bodega's key and not the one the
// published catalogue was signed with. Two upstream shapes, because the
// requirement names the proxied one and the mirrored one reads from the store.
func TestFreeBSDProfileCatalogIsFilteredAndResignedByBodega(t *testing.T) {
	for _, mode := range []string{"mirrored", "proxied"} {
		t.Run(mode, func(t *testing.T) {
			bodegaKey := installPkgKey(t, pkgsign.KeyRSA)
			s := proxyingServer(t)
			s.loadPkgSigner()
			up := upstreamPkgKey(t)
			catalog := publishedCatalog(t, s, up)

			if mode == "mirrored" {
				mirrored(t, s, "latest", map[string]string{manifest.FreeBSDCatalogFile: catalog})
			} else {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/"+manifest.FreeBSDCatalogFile {
						http.NotFound(w, r)
						return
					}
					_, _ = w.Write([]byte(catalog))
				}))
				t.Cleanup(upstream.Close)
				addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
					Version: freeBSDABI, URL: upstream.URL, Mode: manifest.ModeProxy,
				})
			}
			f := webProfile(t, s)
			bodegaPub, err := bodegaKey.PublicKey()
			if err != nil {
				t.Fatalf("render bodega's public key: %v", err)
			}

			for file, doc := range map[string]string{
				manifest.FreeBSDCatalogFile: freeBSDCatalogDoc,
				manifest.FreeBSDDataFile:    freeBSDDataDoc,
			} {
				status, body := f.get(t, profileURL("web", "latest", file))
				if status != http.StatusOK {
					t.Fatalf("GET the view's %s = %d, want 200: %s", file, status, body)
				}
				names := catalogNames(t, body, doc, bodegaPub, up.pub)
				if strings.Join(names, " ") != "nginx" {
					t.Errorf("the view's %s names %v, want nginx alone: curl is held at a version upstream no longer carries and tree is not listed", file, names)
				}
			}
		})
	}
}

// R2: meta.conf under the view names the archives the view builds, so a
// client never reads an upstream meta.conf naming a filesite it does not get.
func TestFreeBSDProfileViewServesItsOwnMetaConf(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	mirrored(t, s, "latest", map[string]string{manifest.FreeBSDMetaFile: freeBSDMetaBytes + "filesite = \"filesite.yaml\";\n"})
	f := webProfile(t, s)
	status, body := f.get(t, profileURL("web", "latest", manifest.FreeBSDMetaFile))
	if status != http.StatusOK || body != string(freeBSDMetaConf()) {
		t.Errorf("GET the view's meta.conf = %d %q, want 200 and bodega's own", status, body)
	}
}

// R3: the backstop. A host that composes a path the view does not list is
// refused in the profile's own vocabulary, on either root, and the one it
// does list is served.
func TestFreeBSDProfileRefusesAPackageTheCatalogueDoesNotList(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	mirrored(t, s, "latest", map[string]string{
		fbsdNginxPath: "nginx bytes",
		fbsdCurlPath:  "curl bytes",
		fbsdTreePath:  "tree bytes",
	})
	f := webProfile(t, s)

	for _, root := range []func(string) string{
		func(p string) string { return freeBSDURL("latest", p) },
		func(p string) string { return profileURL("web", "latest", p) },
	} {
		if status, body := f.get(t, root(fbsdNginxPath)); status != http.StatusOK || body != "nginx bytes" {
			t.Errorf("GET %s = %d %q, want 200 and the package", root(fbsdNginxPath), status, body)
		}
		status, body := f.get(t, root(fbsdTreePath))
		if status != http.StatusForbidden || !strings.HasPrefix(body, entitle.RefusalMembership+":") {
			t.Errorf("GET %s = %d %q, want 403 opening on %q", root(fbsdTreePath), status, body, entitle.RefusalMembership)
		}
		status, body = f.get(t, root(fbsdCurlPath))
		if status != http.StatusForbidden || !strings.HasPrefix(body, entitle.RefusalConstraint+":") {
			t.Errorf("GET %s = %d %q, want 403 opening on %q", root(fbsdCurlPath), status, body, entitle.RefusalConstraint)
		}
	}

	// A host no profile binds reads the repository as published.
	if status, body := getStatusAndBody(t, s, freeBSDURL("latest", fbsdTreePath)); status != http.StatusOK || body != "tree bytes" {
		t.Errorf("an unbound GET of tree = %d %q, want 200", status, body)
	}
}

// R2: the published catalogue is not a way around the view. A bound host still
// pointed at it is refused and told which stanza to install.
func TestFreeBSDProfileRefusesTheUnfilteredCatalogueToABoundHost(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	up := upstreamPkgKey(t)
	mirrored(t, s, "latest", map[string]string{manifest.FreeBSDCatalogFile: publishedCatalog(t, s, up)})
	f := webProfile(t, s)

	status, body := f.get(t, freeBSDURL("latest", manifest.FreeBSDCatalogFile))
	if status != http.StatusForbidden || !strings.Contains(body, pkgrepos.ProfilePath("web")) || !strings.Contains(body, "--write-pkg-repo") {
		t.Errorf("a bound GET of the published catalogue = %d %q, want 403 naming the view and the doctor command", status, body)
	}
	if status, _ := getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDCatalogFile)); status != http.StatusOK {
		t.Errorf("an unbound GET of the published catalogue = %d, want 200", status)
	}
}

// A view with no key behind it refuses rather than serving an unsigned
// catalogue: that would move a host from FreeBSD's signature to none.
func TestFreeBSDProfileViewRefusesWithoutAKey(t *testing.T) {
	s := proxyingServer(t)
	s.pkgSign.Store(nil)
	mirrored(t, s, "latest", map[string]string{manifest.FreeBSDCatalogFile: publishedCatalog(t, s, upstreamPkgKey(t))})
	f := webProfile(t, s)
	if status, body := f.get(t, profileURL("web", "latest", manifest.FreeBSDCatalogFile)); status != http.StatusInternalServerError {
		t.Errorf("GET the view's catalogue with no key = %d %q, want 500", status, body)
	}
}

// R4: the status block a bound host reads is its profile's stanza, pointed at
// the view and trusting bodega's key; an unbound host's is the published one.
func TestFreeBSDStatusRendersTheProfileViewForABoundHost(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI, URL: "https://pkg.example.org/" + freeBSDABI + "/latest", Mode: manifest.ModeProxy,
	})
	f := webProfile(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out struct {
		FreeBSD freebsdStatus `json:"freebsd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse status: %v\n%s", err, rec.Body.String())
	}
	bound := out.FreeBSD.RepoFor("latest", freeBSDABI)
	if bound == nil {
		t.Fatalf("status names no latest@%s for the bound host: %+v", freeBSDABI, out.FreeBSD)
	}
	if bound.Profile != "web" || !strings.HasSuffix(bound.URL, pkgrepos.ProfilePath("web")+"/${ABI}/latest") ||
		bound.Fingerprints != pkgrepos.BodegaFingerprints || bound.SignatureType != "fingerprints" {
		t.Errorf("the bound host's stanza = profile %q url %q %s %q, want the web view trusting %s",
			bound.Profile, bound.URL, bound.SignatureType, bound.Fingerprints, pkgrepos.BodegaFingerprints)
	}

	unbound := statusFreeBSD(t, s).RepoFor("latest", freeBSDABI)
	if unbound == nil || unbound.Profile != "" || !strings.HasSuffix(unbound.URL, "/freebsd/${ABI}/latest") ||
		unbound.Fingerprints != pkgrepos.StockFingerprints {
		t.Errorf("an unbound host's stanza = %+v, want the published repository trusting %s", unbound, pkgrepos.StockFingerprints)
	}
}

func TestFreeBSDObjectIdentity(t *testing.T) {
	for _, tc := range []struct{ path, name, version string }{
		{fbsdNginxPath, "nginx", "1.26.2_1,3"},
		{"All/py311-requests-2.31.0.pkg", "py311-requests", "2.31.0"},
		{freeBSDBasePath, "FreeBSD-telnet", "14.snap20260920075547"},
		{"Latest/pkg.pkg", "pkg", ""},
		{"Latest/pkg.pkg.sig", "pkg", ""},
		{"All/old-1.0.txz", "old", "1.0"},
	} {
		if name, version := freeBSDObjectIdentity(tc.path); name != tc.name || version != tc.version {
			t.Errorf("freeBSDObjectIdentity(%q) = %q %q, want %q %q", tc.path, name, version, tc.name, tc.version)
		}
	}
}
