package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const (
	rpmNginxPkgid = "e94f74f8d2e2009fac82676036d52d67aaf0549c275e4ec3be4aa6442728bb63"
	rpmHttpdPkgid = "0784a80e16a3f681c7202f6640d3fbe471cf01cac6f86024fda8cf566d7a11aa"
)

func rpmGzip(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func rpmGunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rpmDataEntry(typ, href string, gz, open []byte) string {
	return `  <data type="` + typ + `">
    <checksum type="sha256">` + rpmSHA256(gz) + `</checksum>
    <open-checksum type="sha256">` + rpmSHA256(open) + `</open-checksum>
    <location href="` + href + `"/>
    <timestamp>1761523200</timestamp>
    <size>` + strconv.Itoa(len(gz)) + `</size>
    <open-size>` + strconv.Itoa(len(open)) + `</open-size>
  </data>
`
}

// rpmFullRepo extends the fixture's repomd.xml with filelists, other and a
// modules entry, and returns the modules <data> element as written, which a
// filtered repomd.xml must carry byte for byte.
func rpmFullRepo(t *testing.T, m *rpmMirror) (repomd []byte, modules string) {
	t.Helper()
	filelists := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="2">
<package pkgid="` + rpmNginxPkgid + `" name="nginx" arch="x86_64">
  <version epoch="2" ver="1.20.1" rel="20.el9"/>
  <file>/usr/sbin/nginx</file>
</package>
<package pkgid="` + rpmHttpdPkgid + `" name="httpd" arch="x86_64">
  <version epoch="0" ver="2.4.57" rel="5.el9"/>
  <file>/usr/sbin/httpd</file>
</package>
</filelists>
`)
	other := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="2">
<package pkgid="` + rpmNginxPkgid + `" name="nginx" arch="x86_64">
  <version epoch="2" ver="1.20.1" rel="20.el9"/>
  <changelog author="nginx packager" date="1700000000">- rebuilt</changelog>
</package>
<package pkgid="` + rpmHttpdPkgid + `" name="httpd" arch="x86_64">
  <version epoch="0" ver="2.4.57" rel="5.el9"/>
  <changelog author="httpd packager" date="1700000000">- rebuilt</changelog>
</package>
</otherdata>
`)
	mods := []byte("---\ndocument: modulemd\nversion: 2\ndata:\n  name: nginx\n  stream: \"1.22\"\n  artifacts:\n    rpms: [nginx-1:1.22.1-3.module+el9.x86_64]\n...\n")
	fgz, ogz, mgz := rpmGzip(t, filelists), rpmGzip(t, other), rpmGzip(t, mods)
	fhref := "repodata/" + rpmSHA256(fgz) + "-filelists.xml.gz"
	ohref := "repodata/" + rpmSHA256(ogz) + "-other.xml.gz"
	mhref := "repodata/" + rpmSHA256(mgz) + "-modules.yaml.gz"
	m.set(fhref, fgz)
	m.set(ohref, ogz)
	m.set(mhref, mgz)
	modules = rpmDataEntry("modules", mhref, mgz, mods)
	base := string(rpmFixture(t, "repodata/repomd.xml"))
	repomd = []byte(strings.Replace(base, "</repomd>",
		rpmDataEntry("filelists", fhref, fgz, filelists)+rpmDataEntry("other", ohref, ogz, other)+modules+"</repomd>", 1))
	m.set("repodata/repomd.xml", repomd)
	return repomd, modules
}

// addProfileHost binds a second credential and identity to an existing
// profile, the way a fleet's next host joins it.
func addProfileHost(t *testing.T, s *Server, profile, identity string) *profileFixture {
	t.Helper()
	ctx := context.Background()
	token := "bodega_ak_" + identity
	tokenID := "tok-" + identity
	if err := s.auditDB.InsertToken(ctx, tokenID, identity, audit.HashToken(token, s.pepper), "", nil); err != nil {
		t.Fatalf("insert token for %s: %v", identity, err)
	}
	if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{Kind: audit.BindToken, Key: tokenID, Identity: identity}); err != nil {
		t.Fatalf("bind identity %s: %v", identity, err)
	}
	bindProfileTo(t, s, profile, identity)
	return &profileFixture{s: s, token: token}
}

type rpmRepomdDoc struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Checksum string `xml:"checksum"`
		Open     string `xml:"open-checksum"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Size     int `xml:"size"`
		OpenSize int `xml:"open-size"`
	} `xml:"data"`
}

func TestRpmProfileFiltersMetadataAndRefusesTheRest(t *testing.T) {
	m := newRPMMirror(t)
	upstream, modules := rpmFullRepo(t, m)
	s, kr := rpmServer(t, m)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeRpm, Name: "nginx"}})

	status, doc := pf.get(t, rpmRepoPath+"repodata/repomd.xml")
	if status != http.StatusOK {
		t.Fatalf("repomd.xml for web01: %d %s", status, doc)
	}
	if doc == string(upstream) {
		t.Fatal("a governed host was served the upstream's repomd.xml unchanged")
	}

	t.Run("the signature verifies over the filtered repomd.xml", func(t *testing.T) {
		status, sig := pf.get(t, rpmRepoPath+"repodata/repomd.xml.asc")
		if status != http.StatusOK {
			t.Fatalf("repomd.xml.asc: %d %s", status, sig)
		}
		pub, _ := kr.PublicKey()
		ring, _ := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
		if _, err := openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(doc), strings.NewReader(sig), nil); err != nil {
			t.Errorf("the signature does not verify over the repomd.xml web01 was served: %v", err)
		}
	})

	t.Run("every other entry is the upstream's, byte for byte", func(t *testing.T) {
		if !strings.Contains(doc, strings.TrimSpace(modules)) {
			t.Errorf("the modules entry was changed:\n%s", doc)
		}
		if !strings.Contains(doc, "<revision>1761523200</revision>") {
			t.Errorf("the revision was lost:\n%s", doc)
		}
	})

	var md rpmRepomdDoc
	if err := xml.Unmarshal([]byte(doc), &md); err != nil {
		t.Fatalf("filtered repomd.xml does not parse: %v\n%s", err, doc)
	}
	seen := map[string]bool{}
	for _, d := range md.Data {
		seen[d.Type] = true
		if d.Type == "modules" {
			continue
		}
		t.Run(d.Type+" matches its entry and holds nginx alone", func(t *testing.T) {
			if !strings.HasPrefix(d.Location.Href, "repodata/"+d.Checksum+"-") {
				t.Errorf("href %s does not carry its checksum %s", d.Location.Href, d.Checksum)
			}
			status, body := pf.get(t, rpmRepoPath+d.Location.Href)
			if status != http.StatusOK {
				t.Fatalf("%s: %d %s", d.Location.Href, status, body)
			}
			if got := rpmSHA256([]byte(body)); got != d.Checksum || len(body) != d.Size {
				t.Errorf("%s: checksum %s size %d, repomd.xml gives %s and %d", d.Type, got, len(body), d.Checksum, d.Size)
			}
			open := rpmGunzip(t, []byte(body))
			if got := rpmSHA256(open); got != d.Open || len(open) != d.OpenSize {
				t.Errorf("%s: open-checksum %s open-size %d, repomd.xml gives %s and %d", d.Type, got, len(open), d.Open, d.OpenSize)
			}
			if !bytes.Contains(open, []byte(`packages="1"`)) || !bytes.Contains(open, []byte(rpmNginxPkgid)) && !bytes.Contains(open, []byte("<name>nginx</name>")) {
				t.Errorf("%s does not list nginx alone with packages=\"1\":\n%s", d.Type, open)
			}
			if bytes.Contains(open, []byte("httpd")) || bytes.Count(open, []byte("<package")) != 1 {
				t.Errorf("%s still lists httpd, or lists other than one package:\n%s", d.Type, open)
			}
		})
	}
	for _, typ := range []string{"primary", "filelists", "other", "modules"} {
		if !seen[typ] {
			t.Errorf("the filtered repomd.xml lists no %s entry", typ)
		}
	}
	if idx, err := parseRpmPrimary(rpmPrimaryOf(t, pf, md), ".gz"); err != nil || len(idx) != 1 {
		t.Errorf("the filtered primary parses to %d packages (%v), want 1", len(idx), err)
	}

	t.Run("httpd's href answers 403 and nginx's 200", func(t *testing.T) {
		if status, body := pf.get(t, rpmRepoPath+rpmHttpdHref); status != http.StatusForbidden || !strings.Contains(body, "membership") {
			t.Errorf("httpd for web01: %d, want a 403 naming membership: %s", status, body)
		}
		if status, body := pf.get(t, rpmRepoPath+rpmNginxHref); status != http.StatusOK {
			t.Errorf("nginx for web01: %d %s", status, body)
		}
	})

	t.Run("the unfiltered primary is not listed for a governed host", func(t *testing.T) {
		if status, _ := pf.get(t, rpmRepoPath+rpmPrimaryGz); status != http.StatusNotFound {
			t.Errorf("upstream primary for web01: %d, want 404", status)
		}
	})

	t.Run("an ungoverned host gets the upstream's metadata, and none of the filtered files", func(t *testing.T) {
		status, body := getWithToken(t, s, "", rpmRepoPath+"repodata/repomd.xml")
		if status != http.StatusOK || body != string(upstream) {
			t.Errorf("repomd.xml with no profile: %d, want 200 and the upstream's bytes\n%s", status, body)
		}
		if status, body := getWithToken(t, s, "", rpmRepoPath+rpmPrimaryGz); status != http.StatusOK || body != string(rpmFixture(t, rpmPrimaryGz)) {
			t.Errorf("upstream primary with no profile: %d", status)
		}
		for _, d := range md.Data {
			if d.Type == "modules" {
				continue
			}
			if status, _ := getWithToken(t, s, "", rpmRepoPath+d.Location.Href); status != http.StatusNotFound {
				t.Errorf("filtered %s with no profile: %d, want 404", d.Type, status)
			}
		}
	})

	t.Run("a host on another profile sees none of web's files", func(t *testing.T) {
		db := bindProfile(t, s, "db", "db01",
			[]audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)},
			[]audit.ProfileEntry{{Type: manifest.TypeRpm, Name: "httpd"}})
		for _, d := range md.Data {
			if d.Type == "modules" {
				continue
			}
			if status, _ := db.get(t, rpmRepoPath+d.Location.Href); status != http.StatusNotFound {
				t.Errorf("web's filtered %s for db01: %d, want 404", d.Type, status)
			}
		}
		if status, _ := db.get(t, rpmRepoPath+rpmNginxHref); status != http.StatusForbidden {
			t.Errorf("nginx for db01: %d, want 403", status)
		}
	})
}

func rpmPrimaryOf(t *testing.T, pf *profileFixture, md rpmRepomdDoc) []byte {
	t.Helper()
	for _, d := range md.Data {
		if d.Type == "primary" {
			_, body := pf.get(t, rpmRepoPath+d.Location.Href)
			return []byte(body)
		}
	}
	t.Fatal("no primary entry")
	return nil
}

// A fleet on one profile costs one build per upstream change: the second
// host is served the first host's filtered files, and a new upstream primary
// is what builds again.
func TestRpmProfileBuildIsSharedAcrossAProfilesHosts(t *testing.T) {
	m := newRPMMirror(t)
	rpmFullRepo(t, m)
	s, _ := rpmServer(t, m)
	web01 := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeRpm, Name: "nginx"}})
	web02 := addProfileHost(t, s, "web", "web02")

	_, first := web01.get(t, rpmRepoPath+"repodata/repomd.xml")
	if n := s.rpmProfileBuilds.count(); n != 1 {
		t.Fatalf("builds after web01's repomd.xml = %d, want 1", n)
	}
	status, second := web02.get(t, rpmRepoPath+"repodata/repomd.xml")
	if status != http.StatusOK || second != first {
		t.Errorf("web02 was served another repomd.xml than web01 (%d):\n%s\n---\n%s", status, second, first)
	}
	var md rpmRepomdDoc
	if err := xml.Unmarshal([]byte(second), &md); err != nil {
		t.Fatal(err)
	}
	for _, d := range md.Data {
		if status, _ := web02.get(t, rpmRepoPath+d.Location.Href); status != http.StatusOK {
			t.Errorf("%s for web02: %d", d.Type, status)
		}
	}
	if status, _ := web02.get(t, rpmRepoPath+"repodata/repomd.xml.asc"); status != http.StatusOK {
		t.Errorf("repomd.xml.asc for web02: %d", status)
	}
	if n := s.rpmProfileBuilds.count(); n != 1 {
		t.Errorf("builds after web02 read the same tree = %d, want 1: the second host rebuilt", n)
	}
	if n := m.hitsFor(rpmPrimaryGz); n != 1 {
		t.Errorf("upstream asked for primary %d times, want 1", n)
	}
}

func rpmVerifies(t *testing.T, kr interface{ PublicKey() ([]byte, error) }, doc, sig string) error {
	t.Helper()
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatal(err)
	}
	_, err = openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(doc), strings.NewReader(sig), nil)
	return err
}

func rpmParseRepomd(t *testing.T, doc string) rpmRepomdDoc {
	t.Helper()
	var md rpmRepomdDoc
	if err := xml.Unmarshal([]byte(doc), &md); err != nil {
		t.Fatalf("repomd.xml does not parse: %v\n%s", err, doc)
	}
	return md
}

func rpmEntryHref(t *testing.T, doc, typ string) string {
	t.Helper()
	for _, d := range rpmParseRepomd(t, doc).Data {
		if d.Type == typ {
			return d.Location.Href
		}
	}
	t.Fatalf("repomd.xml lists no %s:\n%s", typ, doc)
	return ""
}

// A profile edit is a permission change, not an upstream rollover: the host's
// next repomd.xml lists what the edited profile admits, the pair it is signed
// as verifies, and the previous listing's filtered files are no longer served
// to it.
func TestRpmProfileEditMovesTheHostToTheNewListing(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name          string
		entry         audit.ProfileEntry
		edit          func(t *testing.T, s *Server)
		before, after []string
	}{
		{
			name:   "removal",
			entry:  audit.ProfileEntry{Type: manifest.TypeRpm, Name: "nginx"},
			before: []string{"nginx"},
			edit: func(t *testing.T, s *Server) {
				if _, err := s.auditDB.RemoveProfileEntry(ctx, "web", manifest.TypeRpm, "nginx"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "changed version pin",
			entry:  audit.ProfileEntry{Type: manifest.TypeRpm, Name: "nginx", Constraint: manifest.ConstraintExact, Version: "2:1.20.1-20.el9"},
			before: []string{"nginx"},
			edit: func(t *testing.T, s *Server) {
				if _, err := s.auditDB.PutProfileEntry(ctx, audit.ProfileEntry{Profile: "web", Type: manifest.TypeRpm, Name: "nginx",
					Constraint: manifest.ConstraintExact, Version: "2:9.0-1.el9"}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "expansion",
			entry:  audit.ProfileEntry{Type: manifest.TypeRpm, Name: "nginx"},
			before: []string{"nginx"},
			after:  []string{"nginx", "httpd"},
			edit: func(t *testing.T, s *Server) {
				if err := s.auditDB.SetProfileTypeRule(ctx, audit.ProfileTypeRule{Profile: "web", Type: manifest.TypeRpm,
					Membership: audit.MembershipClosed, VersionDefault: audit.VersionFloating, Expansion: audit.ExpansionWarn}); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newRPMMirror(t)
			rpmFullRepo(t, m)
			s, kr := rpmServer(t, m)
			pf := bindProfile(t, s, "web", "web01",
				[]audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)},
				[]audit.ProfileEntry{tc.entry})
			lists := func(doc string) string {
				open := string(rpmGunzip(t, rpmPrimaryOf(t, pf, rpmParseRepomd(t, doc))))
				var names []string
				for _, n := range []string{"nginx", "httpd"} {
					if strings.Contains(open, "<name>"+n+"</name>") {
						names = append(names, n)
					}
				}
				return strings.Join(names, ",")
			}

			_, before := pf.get(t, rpmRepoPath+"repodata/repomd.xml")
			if got, want := lists(before), strings.Join(tc.before, ","); got != want {
				t.Fatalf("before the edit the primary lists %q, want %q", got, want)
			}
			oldPrimary := rpmEntryHref(t, before, "primary")

			tc.edit(t, s)
			s.refreshProfiles(ctx)

			status, after := pf.get(t, rpmRepoPath+"repodata/repomd.xml")
			if status != http.StatusOK {
				t.Fatalf("repomd.xml after the edit: %d %s", status, after)
			}
			if got, want := lists(after), strings.Join(tc.after, ","); got != want {
				t.Errorf("after the edit the primary lists %q, want %q", got, want)
			}
			status, sig := pf.get(t, rpmRepoPath+"repodata/repomd.xml.asc")
			if status != http.StatusOK {
				t.Fatalf("repomd.xml.asc after the edit: %d %s", status, sig)
			}
			if err := rpmVerifies(t, kr, after, sig); err != nil {
				t.Errorf("the signature does not verify over the repomd.xml served after the edit: %v", err)
			}
			if status, _ := pf.get(t, rpmRepoPath+oldPrimary); status != http.StatusNotFound {
				t.Errorf("the pre-edit filtered primary for web01 after the edit: %d, want 404", status)
			}
		})
	}
}

// An unchanged profile keeps upstream rollover behavior: a key handed a
// filtered repomd.xml moments ago keeps it, and its signature, while the
// upstream moves underneath, and a profile refresh that changes nothing does
// not move it either.
func TestRpmProfileUnchangedHoldsItsRevisionAcrossAnUpstreamMove(t *testing.T) {
	m := newRPMMirror(t)
	upstream, _ := rpmFullRepo(t, m)
	s, kr := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeRpm, Name: "nginx"}})

	_, first := pf.get(t, rpmRepoPath+"repodata/repomd.xml")
	m.set("repodata/repomd.xml", append(bytes.Clone(upstream), "<!-- moved -->\n"...))
	s.refreshProfiles(context.Background())
	_, second := pf.get(t, rpmRepoPath+"repodata/repomd.xml")
	if second != first {
		t.Errorf("a key inside rpmSignatureWait was moved to the upstream's next revision:\n%s\n---\n%s", second, first)
	}
	_, sig := pf.get(t, rpmRepoPath+"repodata/repomd.xml.asc")
	if err := rpmVerifies(t, kr, first, sig); err != nil {
		t.Errorf("the signature does not cover the revision the key holds: %v", err)
	}
}

// The filtered repomd.xml is a function of the profile and the upstream
// metadata alone, so a signature asked of a process that never served the
// document (a restart, or a second instance on the same store and key)
// verifies over the bytes the first one served.
func TestRpmProfileSignatureVerifiesAfterARestartAndOnASecondInstance(t *testing.T) {
	m := newRPMMirror(t)
	rpmFullRepo(t, m)
	rules := func() []audit.ProfileTypeRule {
		return []audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)}
	}
	entries := func() []audit.ProfileEntry { return []audit.ProfileEntry{{Type: manifest.TypeRpm, Name: "nginx"}} }
	s, kr := rpmServer(t, m)
	pf := bindProfile(t, s, "web", "web01", rules(), entries())
	other, _ := rpmServer(t, m)
	other.stores = s.stores
	other.aptSign.Store(s.aptSign.Load())
	pf2 := bindProfile(t, other, "web", "web01", rules(), entries())

	status, doc := pf.get(t, rpmRepoPath+"repodata/repomd.xml")
	if status != http.StatusOK {
		t.Fatalf("repomd.xml: %d %s", status, doc)
	}
	// A wall-clock timestamp in the filtered entries would differ from here on.
	time.Sleep(1100 * time.Millisecond)

	t.Run("a second instance on the same store and key", func(t *testing.T) {
		status, sig := pf2.get(t, rpmRepoPath+"repodata/repomd.xml.asc")
		if status != http.StatusOK {
			t.Fatalf("repomd.xml.asc: %d %s", status, sig)
		}
		if err := rpmVerifies(t, kr, doc, sig); err != nil {
			t.Errorf("the second instance signed other bytes than the first served: %v", err)
		}
	})
	t.Run(".asc first after a restart", func(t *testing.T) {
		s.rpmServed = rpmServedRepomds{}
		s.rpmProfileBuilds = rpmProfileBuilds{}
		status, sig := pf.get(t, rpmRepoPath+"repodata/repomd.xml.asc")
		if status != http.StatusOK {
			t.Fatalf("repomd.xml.asc: %d %s", status, sig)
		}
		if err := rpmVerifies(t, kr, doc, sig); err != nil {
			t.Errorf("after a restart the signature is over other bytes than were served: %v", err)
		}
	})
}

// The root's packages count is set whatever XML quoting and spacing the
// upstream wrote it with, and no other attribute is touched.
func TestRpmFilterPackagesSetsTheRootCount(t *testing.T) {
	primaryPkg := func(id string) string {
		return `<package type="rpm"><name>` + id + `</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/>` +
			`<checksum type="sha256" pkgid="YES">` + id + `</checksum><location href="Packages/` + id + `-1-1.x86_64.rpm"/></package>`
	}
	attrPkg := func(id string) string { return `<package pkgid='` + id + `' name="` + id + `" arch="x86_64"/>` }
	roots := []struct {
		typ, root string
		pkg       func(string) string
	}{
		{"primary", "metadata", primaryPkg},
		{"filelists", "filelists", attrPkg},
		{"other", "otherdata", attrPkg},
	}
	attrs := []struct{ name, attr, keepsVerbatim string }{
		{"double quotes", `packages="2"`, ""},
		{"single quotes", `packages='2'`, ""},
		{"spaced equals", `packages = "2"`, ""},
		{"newline and tab", "packages\n=\t'2'", ""},
		{"beside a prefixed packages attribute", `xmlns:x="urn:x" x:packages="2" packages="2"`, `x:packages="2"`},
		{"beside a value that names packages", `xml:lang="u packages='2'" packages='2'`, `xml:lang="u packages='2'"`},
	}
	for _, rt := range roots {
		for _, at := range attrs {
			t.Run(rt.typ+"/"+at.name, func(t *testing.T) {
				raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n<" + rt.root + ` xmlns="urn:test" ` + at.attr + ">\n" +
					rt.pkg("keep") + "\n" + rt.pkg("drop") + "\n</" + rt.root + ">\n")
				gz, open, err := rpmFilterPackages(raw, ".xml", 1, map[string]bool{"keep": true}, rt.typ == "primary")
				if err != nil {
					t.Fatal(err)
				}
				out := rpmGunzip(t, gz)
				if rpmSHA256(out) != open.sum || int64(len(out)) != open.size {
					t.Errorf("open-checksum %s open-size %d do not describe the output (%s, %d)", open.sum, open.size, rpmSHA256(out), len(out))
				}
				var got struct {
					Attrs    []xml.Attr `xml:",any,attr"`
					Packages []struct{} `xml:"package"`
				}
				if err := xml.Unmarshal(out, &got); err != nil {
					t.Fatalf("output does not parse: %v\n%s", err, out)
				}
				count := ""
				for _, a := range got.Attrs {
					if a.Name.Space == "" && a.Name.Local == "packages" {
						count = a.Value
					}
				}
				if len(got.Packages) != 1 || count != "1" {
					t.Errorf("packages=%q with %d <package> elements, want 1 and 1:\n%s", count, len(got.Packages), out)
				}
				if at.keepsVerbatim != "" && !bytes.Contains(out, []byte(at.keepsVerbatim)) {
					t.Errorf("%s was rewritten:\n%s", at.keepsVerbatim, out)
				}
			})
		}
	}
}
