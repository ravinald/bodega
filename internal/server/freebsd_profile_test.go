package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
		manifest.FreeBSDCatalogFile: publishedCatalog(t, s, upstreamPkgKey(t)),
		fbsdNginxPath:               "nginx bytes",
		fbsdCurlPath:                "curl bytes",
		fbsdTreePath:                "tree bytes",
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

// R3: the gate judges the identity the catalogue record declares, not the one
// a filename suggests. A generated repository takes identity from the
// package's own manifest and stores it wherever the operator put it, so every
// disagreement between the two is built here: a refused package under a
// permitted name, a pinned package at a version its filename does not say, and
// a permitted package under an unrelated name.
func TestFreeBSDObjectGateJudgesTheRecordNotTheFilename(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	const (
		treeAsNginx   = "All/nginx-1.0.pkg"
		nginxAsOther  = "All/renamed-1.0.pkg"
		nginx2AsNginx = "All/Hashed/nginx-1.0~abc.pkg"
	)
	generatedRepo(t, s, "house", map[string]string{
		treeAsNginx:   pkgArchive(t, `{"name":"tree","origin":"sysutils/tree","version":"2.0"}`),
		nginxAsOther:  pkgArchive(t, `{"name":"nginx","origin":"www/nginx","version":"1.0"}`),
		nginx2AsNginx: pkgArchive(t, `{"name":"nginx","origin":"www/nginx","version":"2.0"}`),
	})
	f := bindProfile(t, s, "web", "web-host",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeFreeBSD, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeFreeBSD, Name: "nginx", Constraint: manifest.ConstraintExact, Version: "1.0"}})

	status, body := f.get(t, profileURL("web", "house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the view's catalogue = %d: %s", status, body)
	}
	if doc := string(archiveMembers(t, body)[freeBSDCatalogDoc]); !strings.Contains(doc, nginxAsOther) || strings.Contains(doc, treeAsNginx) || strings.Contains(doc, nginx2AsNginx) {
		t.Errorf("the filtered catalogue should list %s alone:\n%s", nginxAsOther, doc)
	}

	for _, root := range []func(string) string{
		func(p string) string { return freeBSDURL("house", p) },
		func(p string) string { return profileURL("web", "house", p) },
	} {
		for _, tc := range []struct {
			path, refusal string
		}{
			{treeAsNginx, entitle.RefusalMembership},
			{nginx2AsNginx, entitle.RefusalConstraint},
			{nginxAsOther, ""},
		} {
			status, body := f.get(t, root(tc.path))
			switch {
			case tc.refusal == "" && status != http.StatusOK:
				t.Errorf("GET %s = %d %q, want 200: its record is nginx 1.0", root(tc.path), status, body)
			case tc.refusal != "" && (status != http.StatusForbidden || !strings.HasPrefix(body, tc.refusal+":")):
				t.Errorf("GET %s = %d %q, want 403 opening on %q", root(tc.path), status, body, tc.refusal)
			}
		}
	}
}

// R3: an object no record names is refused to a governed host whatever its
// filename claims, on either root. Latest/pkg.pkg is the case that matters: it
// names no version, so judging it by name alone would skip every pin on pkg.
// The package it aliases stays reachable at its own repopath, under a floating
// entry and not under a pin it breaks.
func TestFreeBSDObjectGateRefusesAnObjectNoRecordNames(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	const pkgPath = "All/pkg-2.0.pkg"
	catalog, err := s.freeBSDArchive(freeBSDCatalogDoc,
		[]byte(`{"name":"pkg","origin":"ports-mgmt/pkg","version":"2.0","repopath":"`+pkgPath+`"}`+"\n"), upstreamPkgKey(t))
	if err != nil {
		t.Fatalf("build the published catalogue: %v", err)
	}
	mirrored(t, s, "latest", map[string]string{
		manifest.FreeBSDCatalogFile: string(catalog),
		pkgPath:                     "pkg 2.0 bytes",
		pkgPath + ".sig":            "pkg 2.0 signature",
		"Latest/pkg.pkg":            "pkg 2.0 bytes",
		"Latest/pkg.pkg.sig":        "pkg 2.0 signature",
	})
	rule := []audit.ProfileTypeRule{closedRule(manifest.TypeFreeBSD, audit.VersionFloating, audit.ExpansionBlock)}
	pinned := bindProfile(t, s, "pin", "pin-host", rule,
		[]audit.ProfileEntry{{Type: manifest.TypeFreeBSD, Name: "pkg", Constraint: manifest.ConstraintExact, Version: "1.0"}})
	floating := bindProfile(t, s, "float", "float-host", rule,
		[]audit.ProfileEntry{{Type: manifest.TypeFreeBSD, Name: "pkg"}})

	for _, tc := range []struct {
		f       *profileFixture
		profile string
		path    string
		refusal string
	}{
		{pinned, "pin", "Latest/pkg.pkg", entitle.RefusalMembership},
		{pinned, "pin", "Latest/pkg.pkg.sig", entitle.RefusalMembership},
		{pinned, "pin", pkgPath, entitle.RefusalConstraint},
		{pinned, "pin", pkgPath + ".sig", entitle.RefusalConstraint},
		{floating, "float", "Latest/pkg.pkg", entitle.RefusalMembership},
		{floating, "float", "Latest/pkg.pkg.sig", entitle.RefusalMembership},
		{floating, "float", pkgPath, ""},
		{floating, "float", pkgPath + ".sig", ""},
	} {
		for _, url := range []string{freeBSDURL("latest", tc.path), profileURL(tc.profile, "latest", tc.path)} {
			status, body := tc.f.get(t, url)
			switch {
			case tc.refusal == "" && status != http.StatusOK:
				t.Errorf("%s: GET %s = %d %q, want 200", tc.profile, url, status, body)
			case tc.refusal != "" && (status != http.StatusForbidden || !strings.HasPrefix(body, tc.refusal+":")):
				t.Errorf("%s: GET %s = %d %q, want 403 opening on %q", tc.profile, url, status, body, tc.refusal)
			}
		}
	}

	// Without a catalogue there is no record to judge by, so a governed host
	// is served nothing and an unbound one is served as before.
	mirrored(t, s, "bare", map[string]string{pkgPath: "pkg 2.0 bytes"})
	if status, body := floating.get(t, freeBSDURL("bare", pkgPath)); status != http.StatusServiceUnavailable {
		t.Errorf("a governed GET with no catalogue = %d %q, want 503", status, body)
	}
	if status, body := getStatusAndBody(t, s, freeBSDURL("bare", pkgPath)); status != http.StatusOK {
		t.Errorf("an unbound GET with no catalogue = %d %q, want 200", status, body)
	}
}

// R1, R2, R4: every rule shape the vocabulary expresses is filtered by the
// whole predicate, not closed-and-block alone. With curl pinned to a version
// upstream no longer carries, open membership and closed with warn or ignore
// all keep the unlisted tree and drop curl 8.9.1, and the host's stanza points
// at the view that does so.
func TestFreeBSDProfileFiltersEveryRuleShape(t *testing.T) {
	for _, rule := range []audit.ProfileTypeRule{
		{Type: manifest.TypeFreeBSD, Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating},
		closedRule(manifest.TypeFreeBSD, audit.VersionFloating, audit.ExpansionWarn),
		closedRule(manifest.TypeFreeBSD, audit.VersionFloating, audit.ExpansionIgnore),
	} {
		t.Run(rule.Membership+"-"+rule.Expansion, func(t *testing.T) {
			bodegaKey := installPkgKey(t, pkgsign.KeyRSA)
			s := proxyingServer(t)
			s.loadPkgSigner()
			up := upstreamPkgKey(t)
			// A url, so the status block has an upstream to name a trust store
			// for; the mode keeps every read in the store.
			addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
				Version: freeBSDABI, URL: "https://pkg.example.org/" + freeBSDABI + "/latest",
			})
			seed(t, s, manifest.TypeFreeBSD, map[string]string{
				manifest.FreeBSDKey(freeBSDABI, "latest", manifest.FreeBSDCatalogFile): publishedCatalog(t, s, up),
				manifest.FreeBSDKey(freeBSDABI, "latest", fbsdCurlPath):                "curl bytes",
				manifest.FreeBSDKey(freeBSDABI, "latest", fbsdTreePath):                "tree bytes",
			})
			f := bindProfile(t, s, "web", "web-host", []audit.ProfileTypeRule{rule}, []audit.ProfileEntry{
				{Type: manifest.TypeFreeBSD, Name: "nginx"},
				{Type: manifest.TypeFreeBSD, Name: "curl", Constraint: manifest.ConstraintExact, Version: "8.8.0"},
			})
			bodegaPub, err := bodegaKey.PublicKey()
			if err != nil {
				t.Fatalf("render bodega's public key: %v", err)
			}

			status, body := f.get(t, profileURL("web", "latest", manifest.FreeBSDCatalogFile))
			if status != http.StatusOK {
				t.Fatalf("GET the view's catalogue = %d: %s", status, body)
			}
			if names := catalogNames(t, body, freeBSDCatalogDoc, bodegaPub, up.pub); strings.Join(names, " ") != "nginx tree" {
				t.Errorf("the view names %v, want nginx and tree: curl 8.9.1 breaks its pin", names)
			}
			if status, body := f.get(t, freeBSDURL("latest", fbsdCurlPath)); status != http.StatusForbidden || !strings.HasPrefix(body, entitle.RefusalConstraint+":") {
				t.Errorf("GET curl = %d %q, want a constraint refusal", status, body)
			}
			if status, _ := f.get(t, freeBSDURL("latest", fbsdTreePath)); status != http.StatusOK {
				t.Errorf("GET tree = %d, want 200: the rule permits a package it does not list", status)
			}
			if status, _ := f.get(t, freeBSDURL("latest", manifest.FreeBSDCatalogFile)); status != http.StatusForbidden {
				t.Errorf("a bound GET of the published catalogue = %d, want 403", status)
			}
			if repo := boundStatus(t, s, f.token).RepoFor("latest", freeBSDABI); repo == nil || repo.Profile != "web" {
				t.Errorf("the bound host's stanza = %+v, want the web view", repo)
			}
		})
	}
}

// R4: any name a profile accepts becomes a URL that routes back to the same
// profile. Each of these is valid for bodega profile create and each breaks a
// URL written by concatenation: '#' ends the path, '?' starts a query, '%'
// begins an escape, '$' is expanded by pkg, and a dot segment is resolved away.
func TestFreeBSDProfileURLRoutesEveryValidName(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	generatedRepo(t, s, "latest", map[string]string{})
	rule := []audit.ProfileTypeRule{closedRule(manifest.TypeFreeBSD, audit.VersionFloating, audit.ExpansionBlock)}
	entries := []audit.ProfileEntry{{Type: manifest.TypeFreeBSD, Name: "nginx"}}

	for i, name := range []string{"web#prod", "web?prod", "50%off", "${ABI}", "a.b", "ünï", "a+b=c@d:e&f"} {
		f := bindProfile(t, s, name, "host-"+strconv.Itoa(i), rule, entries)
		repo := boundStatus(t, s, f.token).RepoFor("latest", freeBSDABI)
		if repo == nil {
			t.Errorf("%q: status names no stanza", name)
			continue
		}
		if strings.Contains(strings.ReplaceAll(repo.URL, "${ABI}", ""), "$") {
			t.Errorf("%q: url %q carries a '$' pkg would expand", name, repo.URL)
		}
		u, err := url.Parse(strings.ReplaceAll(repo.URL, "${ABI}", freeBSDABI) + "/" + manifest.FreeBSDCatalogFile)
		if err != nil {
			t.Errorf("%q: url %q does not parse: %v", name, repo.URL, err)
			continue
		}
		if u.Fragment != "" || u.RawQuery != "" {
			t.Errorf("%q: url %q puts part of the path in a fragment or query", name, repo.URL)
		}
		if status, body := f.get(t, u.EscapedPath()); status != http.StatusOK {
			t.Errorf("%q: GET %s = %d %q, want the profile's catalogue", name, u.EscapedPath(), status, body)
		}
		again, err := repo.WithRelease(14)
		if err != nil || again.URL != repo.URL {
			t.Errorf("%q: WithRelease changed the url to %q (%v)", name, again.URL, err)
		}
	}

	// A dot segment has no escaped form a server will route, so the stanza is
	// refused with a reason the bound host is allowed to read.
	for i, name := range []string{".", ".."} {
		f := bindProfile(t, s, name, "dot-host-"+strconv.Itoa(i), rule, entries)
		st := boundStatus(t, s, f.token)
		if st.RepoFor("latest", freeBSDABI) != nil || len(st.Refused) != 1 || !strings.Contains(st.Refused[0].Error, "cannot be one segment of a URL") {
			t.Errorf("%q: status = %+v, want the stanza refused naming why", name, st)
		}
	}
}

// boundStatus reads the freebsd block of /api/v1/status as the host holding
// token reads it.
func boundStatus(t *testing.T, s *Server, token string) freebsdStatus {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out struct {
		FreeBSD freebsdStatus `json:"freebsd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse status: %v\n%s", err, rec.Body.String())
	}
	return out.FreeBSD
}

// R4: with no pkg key, the bound host's stanza is refused, and the reason
// reaches the host itself. It quotes no upstream URL, so the blanking the
// other refusals get for a caller outside admin_permit_cidr would only take
// away the one sentence that names the fix.
func TestFreeBSDStatusTellsABoundHostWhyItHasNoStanza(t *testing.T) {
	s := proxyingServer(t)
	s.pkgSign.Store(nil)
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI, URL: "https://audit-user:audit-secret@pkg.example.org/" + freeBSDABI + "/latest", Mode: manifest.ModeProxy,
	})
	f := webProfile(t, s)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "audit-secret") {
		t.Fatalf("status handed a non-admin caller the entry's credentials:\n%s", rec.Body.String())
	}
	var out struct {
		FreeBSD freebsdStatus `json:"freebsd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if len(out.FreeBSD.Refused) != 1 || !strings.Contains(out.FreeBSD.Refused[0].Error, "freebsd key generate") {
		t.Errorf("refused = %+v, want one row naming the key to generate", out.FreeBSD.Refused)
	}
}
