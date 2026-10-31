package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
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
				gz, open, err := rpmFilterPackages(context.Background(), raw, ".xml", 1, map[string]bool{"keep": true}, rt.typ == "primary")
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

// rpmBuildFixture is one governed host on a filtered rocky-baseos, behind a
// real listener so a request can be canceled the way a client hanging up
// cancels it.
type rpmBuildFixture struct {
	m        *rpmMirror
	s        *Server
	ts       *httptest.Server
	web01    *profileFixture
	upstream []byte
}

func newRpmBuildFixture(t *testing.T) *rpmBuildFixture {
	t.Helper()
	f := &rpmBuildFixture{m: newRPMMirror(t)}
	f.upstream, _ = rpmFullRepo(t, f.m)
	f.s, _ = rpmServer(t, f.m)
	// Registered before any stall, so it runs after the stall is released:
	// a build still writing when the test's store is removed fails cleanup.
	t.Cleanup(f.s.rpmProfileBuilds.running.Wait)
	f.web01 = bindProfile(t, f.s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRpm, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeRpm, Name: "nginx"}})
	f.ts = httptest.NewServer(f.s.Handler())
	t.Cleanup(f.ts.Close)
	return f
}

// get is pf's GET of path under ctx, and how long the answer took.
func (f *rpmBuildFixture) get(ctx context.Context, pf *profileFixture, path string) (*http.Response, string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.ts.URL+path, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+pf.token)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", time.Since(start), err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, string(body), time.Since(start), err
}

func (f *rpmBuildFixture) filelistsHref(t *testing.T) string {
	t.Helper()
	return rpmEntryHref(t, string(f.upstream), "filelists")
}

// A client that gives up on repomd.xml mid-build does not cancel the build:
// the upstream read it started finishes, the filtered files are stored, and
// the next request is served them without a second build.
func TestRpmProfileBuildOutlivesTheRequestThatStartedIt(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.s.rpmProfileBuilds.wait = time.Minute
	fhref := f.filelistsHref(t)
	release := f.m.stall(t, fhref)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, _, err := f.get(ctx, f.web01, rpmRepoPath+"repodata/repomd.xml")
		done <- err
	}()
	waitFor(t, func() bool { return f.m.hitsFor(fhref) > 0 })
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the canceled request was answered; it was meant to be cut off mid-build")
	}
	release()
	waitFor(t, func() bool { return f.s.rpmProfileBuilds.count() == 1 })

	resp, doc, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("repomd.xml after the stall cleared: %v %v %s", err, resp, doc)
	}
	if doc == string(f.upstream) || rpmEntryHref(t, doc, "filelists") == fhref {
		t.Errorf("web01 was served the unfiltered repomd.xml:\n%s", doc)
	}
	if n := f.s.rpmProfileBuilds.count(); n != 1 {
		t.Errorf("builds = %d, want 1: the canceled request's build was started over", n)
	}
	if n := f.m.hitsFor(fhref); n != 1 {
		t.Errorf("upstream asked for filelists %d times, want 1", n)
	}
}

// With no previous build to serve, a request meeting a build that outlasts
// rpm_profile_cold_wait is told to come back once the wait ends, logs why at
// warn, and is never handed the unfiltered document.
func TestRpmProfileColdBuildPastTheColdWaitAnswers503(t *testing.T) {
	f := newRpmBuildFixture(t)
	var logs syncBuffer
	f.s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	f.s.rpmProfileBuilds.coldWait = time.Second
	f.m.stall(t, f.filelistsHref(t))

	resp, body, took, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Errorf("repomd.xml during the first build: %d Retry-After=%q, want 503 with Retry-After\n%s", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	if took < time.Second || took >= 5*time.Second {
		t.Errorf("answered after %s, want after the 1s cold wait and under 5s", took)
	}
	if strings.Contains(body, "<repomd") {
		t.Errorf("the 503 carried a repomd.xml:\n%s", body)
	}
	var warned string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "answered 503 while the profile's filtered metadata builds") {
			warned = line
		}
	}
	for _, want := range []string{"profile=web", "repository=" + rpmFixtureRepoID + "/9/x86_64", "build_running_for="} {
		if !strings.Contains(warned, want) {
			t.Errorf("the 503's warn record lacks %q:\n%s", want, logs.String())
		}
	}
	if strings.Contains(warned, "build_running_for=0s") {
		t.Errorf("the warn record says the build has not run:\n%s", warned)
	}
}

// With no previous build to serve and the default rpm_profile_cold_wait, a
// build that takes longer than the 4-second budget but finishes inside the
// cold wait answers the request that met it with the filtered document: dnf
// does not retry a 503 on repomd.xml, so that 503 would have failed the
// install.
func TestRpmProfileColdBuildIsAnsweredWhenItFinishesInsideTheColdWait(t *testing.T) {
	f := newRpmBuildFixture(t)
	if f.s.rpmProfileBuilds.coldWait != 0 {
		t.Fatalf("the fixture set coldWait %s; this test is of the default", f.s.rpmProfileBuilds.coldWait)
	}
	fhref := f.filelistsHref(t)
	release := f.m.stall(t, fhref)
	timer := time.AfterFunc(6*time.Second, release)
	defer timer.Stop()

	resp, doc, took, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repomd.xml over a 6s build: %d, want 200\n%s", resp.StatusCode, doc)
	}
	if took < 6*time.Second {
		t.Errorf("answered after %s, before the stall cleared", took)
	}
	if doc == string(f.upstream) || rpmEntryHref(t, doc, "filelists") == fhref {
		t.Errorf("web01 was served the unfiltered repomd.xml:\n%s", doc)
	}
}

// A profile edit starts a build for each tree a host on that profile asked
// for, with no request, and the next request is served it from the store.
func TestRpmProfileChangePrebuildsTheTreesItsHostsAsked(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	var logs syncBuffer
	f.s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	before := f.s.rpmProfileBuilds.count()

	if _, err := f.s.auditDB.PutProfileEntry(context.Background(), audit.ProfileEntry{Profile: "web", Type: manifest.TypeRpm, Name: "httpd"}); err != nil {
		t.Fatal(err)
	}
	f.s.refreshProfiles(context.Background())
	waitFor(t, func() bool { return f.s.rpmProfileBuilds.count() > before })
	f.s.rpmProfileBuilds.running.Wait()
	if got := f.s.rpmProfileBuilds.count() - before; got != 1 {
		t.Fatalf("builds after the edit = %d, want 1", got)
	}
	if !strings.Contains(logs.String(), `msg="rpm profile build started" profile=web repository=`+rpmFixtureRepoID+`/9/x86_64 cause="profile change"`) {
		t.Errorf("no start record naming the profile change:\n%s", logs.String())
	}
	sl, _ := f.slot(t)
	sl.mu.Lock()
	built := sl.recent[0]
	sl.mu.Unlock()

	resp, doc, took, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("repomd.xml after the edit: %v %v %s", err, resp, doc)
	}
	if took >= time.Second {
		t.Errorf("answered after %s; the build was meant to be ready", took)
	}
	if got, want := rpmEntryHref(t, doc, "primary"), built.files["primary"].href; got != want {
		t.Errorf("primary after the edit = %s, want the prebuilt %s", got, want)
	}
	f.s.rpmProfileBuilds.running.Wait()
	if got := f.s.rpmProfileBuilds.count() - before; got != 1 {
		t.Errorf("builds after the request = %d, want still 1", got)
	}
}

// A build logs its start, naming what started it, and its end with its
// duration and outcome, both at info.
func TestRpmProfileBuildLogsItsStartAndEnd(t *testing.T) {
	f := newRpmBuildFixture(t)
	var logs syncBuffer
	f.s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	f.warm(t)
	f.s.rpmProfileBuilds.running.Wait()
	var start, end string
	for _, line := range strings.Split(logs.String(), "\n") {
		switch {
		case strings.Contains(line, `msg="rpm profile build started"`):
			start = line
		case strings.Contains(line, `msg="rpm profile build ended"`):
			end = line
		}
	}
	tree := "repository=" + rpmFixtureRepoID + "/9/x86_64"
	for _, want := range []string{"level=INFO", "profile=web", tree, "cause=request"} {
		if !strings.Contains(start, want) {
			t.Errorf("the start record lacks %q:\n%s", want, logs.String())
		}
	}
	for _, want := range []string{"level=INFO", "profile=web", tree, "cause=request", "duration=", "outcome=stored"} {
		if !strings.Contains(end, want) {
			t.Errorf("the end record lacks %q:\n%s", want, logs.String())
		}
	}
}

// rpm_profile_cold_wait past dnf's low-speed window is refused when the
// config loads, naming the key and the limit.
func TestRpmProfileColdWaitAboveTheLimitIsRefusedAtLoad(t *testing.T) {
	t.Setenv(config.EnvBucket, "")
	t.Setenv(config.EnvRegion, "")
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvListenAddr, "")
	for _, tc := range []struct{ val, want string }{
		{"28s", ""},
		{"28.5s", `invalid rpm_profile_cold_wait "28.5s": the limit is 28s`},
		{"1m", `invalid rpm_profile_cold_wait "1m": the limit is 28s`},
	} {
		t.Run(tc.val, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"rpm_profile_cold_wait": "`+tc.val+`"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(config.EnvConfigFile, path)
			_, err := config.Load(t.TempDir(), "", "", "", false, false)
			if tc.want == "" {
				if err != nil {
					t.Errorf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load error = %v, want %q", err, tc.want)
			}
		})
	}
}

// With a previous build held, a request during the next build is served the
// previous build's listing, signed so dnf's repo_gpgcheck passes.
func TestRpmProfileBuildRunningServesThePreviousBuild(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.s.rpmProfileBuilds.wait = 200 * time.Millisecond
	resp, first, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("first repomd.xml: %v %v %s", err, resp, first)
	}
	if n := f.s.rpmProfileBuilds.count(); n != 1 {
		t.Fatalf("builds after the first repomd.xml = %d, want 1", n)
	}

	// The upstream moves: a new filelists, which is a new build key.
	fhref := f.filelistsHref(t)
	f.m.mu.Lock()
	oldGz := f.m.override[rpmUpstreamTree+fhref]
	f.m.mu.Unlock()
	oldOpen := rpmGunzip(t, oldGz)
	newOpen := append(bytes.Clone(oldOpen), "<!-- republished -->\n"...)
	newGz := rpmGzip(t, newOpen)
	newHref := "repodata/" + rpmSHA256(newGz) + "-filelists.xml.gz"
	f.m.set(newHref, newGz)
	moved := strings.Replace(string(f.upstream), rpmDataEntry("filelists", fhref, oldGz, oldOpen), rpmDataEntry("filelists", newHref, newGz, newOpen), 1)
	if moved == string(f.upstream) {
		t.Fatal("the fixture's filelists entry was not replaced")
	}
	f.m.set("repodata/repomd.xml", []byte(moved))
	f.s.cache.MetadataTTL = time.Nanosecond
	f.m.stall(t, newHref)

	web02 := addProfileHost(t, f.s, "web", "web02")
	resp, doc, took, err := f.get(context.Background(), web02, rpmRepoPath+"repodata/repomd.xml")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("repomd.xml during the second build: %v %v %s", err, resp, doc)
	}
	if took >= 5*time.Second {
		t.Errorf("answered after %s, want under 5s", took)
	}
	for _, typ := range rpmFilteredTypes {
		if got, want := rpmEntryHref(t, doc, typ), rpmEntryHref(t, first, typ); got != want {
			t.Errorf("%s during the second build = %s, want the previous build's %s", typ, got, want)
		}
	}
	_, sig, _, err := f.get(context.Background(), web02, rpmRepoPath+"repodata/repomd.xml.asc")
	if err != nil {
		t.Fatal(err)
	}
	if err := rpmVerifies(t, f.s.aptSign.Load().signer, doc, sig); err != nil {
		t.Errorf("the previous build's repomd.xml does not verify against its signature: %v", err)
	}
	for _, typ := range rpmFilteredTypes {
		if resp, _, _, err := f.get(context.Background(), web02, rpmRepoPath+rpmEntryHref(t, doc, typ)); err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("the previous build's %s for web02: %v %v", typ, err, resp)
		}
	}
}

// Ten hosts arriving during one build share it.
func TestRpmProfileBuildIsSharedByConcurrentRequests(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.s.rpmProfileBuilds.wait = time.Minute
	fhref := f.filelistsHref(t)
	release := f.m.stall(t, fhref)

	const n = 10
	var wg sync.WaitGroup
	docs := make([]string, n)
	codes := make([]int, n)
	for i := range n {
		wg.Go(func() {
			resp, doc, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
			if err == nil {
				codes[i], docs[i] = resp.StatusCode, doc
			}
		})
	}
	waitFor(t, func() bool { return f.m.hitsFor(fhref) > 0 })
	time.Sleep(200 * time.Millisecond)
	release()
	wg.Wait()
	for i := range n {
		if codes[i] != http.StatusOK || docs[i] != docs[0] {
			t.Errorf("request %d: %d, want 200 and the same repomd.xml as request 0", i, codes[i])
		}
	}
	if got := f.s.rpmProfileBuilds.count(); got != 1 {
		t.Errorf("builds = %d, want 1", got)
	}
	if got := f.m.hitsFor(rpmPrimaryGz); got != 1 {
		t.Errorf("upstream asked for primary %d times, want 1", got)
	}
}

// rpmGatedStore holds each store call hold matches until release runs, and
// closes entered the first time it holds one.
type rpmGatedStore struct {
	storage.ObjectStore
	hold    func(ctx context.Context, op, key string) bool
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func gateStore(t *testing.T, s *Server, hold func(ctx context.Context, op, key string) bool) (g *rpmGatedStore, release func()) {
	t.Helper()
	g = &rpmGatedStore{ObjectStore: s.typeStore(manifest.TypeRpm), hold: hold, gate: make(chan struct{}), entered: make(chan struct{})}
	s.stores = rpmOneStore{Resolver: s.stores, store: g}
	var once sync.Once
	release = func() { once.Do(func() { close(g.gate) }) }
	t.Cleanup(release)
	return g, release
}

func (g *rpmGatedStore) wait(ctx context.Context, op, key string) {
	if g.hold(ctx, op, key) {
		g.once.Do(func() { close(g.entered) })
		<-g.gate
	}
}

func (g *rpmGatedStore) Get(ctx context.Context, key string) ([]byte, error) {
	g.wait(ctx, "Get", key)
	return g.ObjectStore.Get(ctx, key)
}

func (g *rpmGatedStore) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	info, err := g.ObjectStore.Head(ctx, key)
	g.wait(ctx, "Head", key)
	return info, err
}

func (g *rpmGatedStore) Put(ctx context.Context, key string, body []byte) error {
	g.wait(ctx, "Put", key)
	return g.ObjectStore.Put(ctx, key, body)
}

type rpmOneStore struct {
	storage.Resolver
	store storage.ObjectStore
}

func (r rpmOneStore) ForType(string) storage.ObjectStore { return r.store }

func (f *rpmBuildFixture) tree() rpmTree {
	return rpmTree{repo: rpmFixtureRepoID, releasever: "9", basearch: "x86_64", base: f.m.ts.URL + rpmUpstreamTree}
}

func (f *rpmBuildFixture) slot(t *testing.T) (*rpmProfileSlot, *entitle.Profile) {
	t.Helper()
	p := f.s.profileNow().profileFor("web01")
	return f.s.rpmProfileBuilds.slot(rpmProfileView(f.tree(), p)), p
}

func (f *rpmBuildFixture) warm(t *testing.T) string {
	t.Helper()
	resp, doc, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("first repomd.xml: %v %v %s", err, resp, doc)
	}
	f.s.rpmProfileBuilds.running.Wait()
	return doc
}

// A build whose deadline has passed is not published, even when every
// upstream file it reads is already cached and no network read is left to
// notice the deadline.
func TestRpmProfileBuildPastItsDeadlineIsNotPublished(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	sl, p := f.slot(t)
	sl.mu.Lock()
	sl.recent = nil
	sl.mu.Unlock()
	f.s.rpmProfileBuilds.timeout = time.Nanosecond
	data, _ := parseRpmRepomd(f.upstream)
	b, err := f.s.rpmProfileFiles(httptest.NewRequest(http.MethodGet, "/", nil), f.tree(), p, data)
	if err == nil || b != nil {
		t.Fatalf("a build past its deadline returned build=%v error=%v, want a deadline error", b != nil, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want one wrapping context.DeadlineExceeded", err)
	}
	if n := f.s.rpmProfileBuilds.count(); n != 1 {
		t.Errorf("builds = %d, want only the warm-up's", n)
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if len(sl.recent) != 0 {
		t.Errorf("a build past its deadline was published: %d held", len(sl.recent))
	}
}

// rpmCountdownCtx reports itself canceled from its nth Err call on, which is
// a deadline passing partway through a filter.
type rpmCountdownCtx struct {
	context.Context
	left atomic.Int32
}

func (c *rpmCountdownCtx) Err() error {
	if c.left.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

func TestRpmFiltersStopWhenTheBuildContextEnds(t *testing.T) {
	var doc bytes.Buffer
	doc.WriteString(`<?xml version="1.0"?>` + "\n" + `<filelists packages="2000">` + "\n")
	for i := range 2000 {
		fmt.Fprintf(&doc, `<package pkgid="%064d" name="p%d" arch="x86_64"><file>/usr/bin/p%d</file></package>`+"\n", i, i, i)
	}
	doc.WriteString("</filelists>\n")
	ctx := &rpmCountdownCtx{Context: context.Background()}
	ctx.left.Store(3)
	if _, _, err := rpmFilterPackages(ctx, doc.Bytes(), ".xml", 1, map[string]bool{}, false); !errors.Is(err, context.Canceled) {
		t.Errorf("filter canceled partway: error = %v, want context.Canceled", err)
	}
	if ctx.left.Load() >= 0 {
		t.Errorf("the filter finished inside 3 reads of a %d-byte file; the test does not cancel it partway", doc.Len())
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	primary := rpmFixture(t, rpmPrimaryGz)
	if _, _, err := rpmAdmittedPkgids(canceled, primary, ".gz", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("reading primary under a canceled context: error = %v, want context.Canceled", err)
	}
}

// A request that checked the store before another request's build of the
// same key finished does not build that key again once it has.
func TestRpmProfileBuildRegistrationSeesABuildThatJustFinished(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	sl, p := f.slot(t)
	sl.mu.Lock()
	b := sl.recent[0]
	sl.mu.Unlock()
	key := rpmFilteredKey(f.tree(), b.files["primary"])
	if err := f.s.typeStore(manifest.TypeRpm).Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	type paused struct{}
	g, release := gateStore(t, f.s, func(ctx context.Context, op, k string) bool {
		return op == "Head" && k == key && ctx.Value(paused{}) != nil
	})
	data, _ := parseRpmRepomd(f.upstream)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	done := make(chan error, 1)
	go func() {
		_, err := f.s.rpmProfileFiles(req.WithContext(context.WithValue(req.Context(), paused{}, true)), f.tree(), p, data)
		done <- err
	}()
	<-g.entered
	if _, err := f.s.rpmProfileFiles(req, f.tree(), p, data); err != nil {
		t.Fatalf("the rebuild: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Errorf("the request that checked first: %v", err)
	}
	f.s.rpmProfileBuilds.running.Wait()
	if n := f.s.rpmProfileBuilds.count(); n != 2 {
		t.Errorf("builds = %d, want 2: the warm-up and one shared rebuild", n)
	}
}

// The 5 seconds cover the upstream repomd.xml's refresh as well as the wait on
// the build: a stale_grace that alone fills most of them, or one past them,
// still leaves the client answered inside them, and with a 503 dnf retries
// rather than the unfiltered document.
func TestRpmProfileBudgetCoversTheRepomdRefresh(t *testing.T) {
	for _, grace := range []time.Duration{3 * time.Second, 10 * time.Second} {
		t.Run(grace.String(), func(t *testing.T) {
			f := newRpmBuildFixture(t)
			f.s.cache.MetadataTTL = time.Nanosecond
			f.s.cache.StaleGrace = grace
			f.s.rpmProfileBuilds.coldWait = time.Second
			f.m.stall(t, f.filelistsHref(t))
			if resp, _, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml"); err != nil || resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("starting the build: %v %v", err, resp)
			}
			f.m.stall(t, "repodata/repomd.xml")
			for _, path := range []string{"repodata/repomd.xml", f.filelistsHref(t)} {
				web02 := addProfileHost(t, f.s, "web", "web02-"+strconv.Itoa(len(path)))
				resp, body, took, err := f.get(context.Background(), web02, rpmRepoPath+path)
				if err != nil {
					t.Fatal(err)
				}
				if took >= 5*time.Second {
					t.Errorf("%s answered after %s, want under 5s", path, took)
				}
				if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
					t.Errorf("%s: %d Retry-After=%q, want 503 with Retry-After\n%s", path, resp.StatusCode, resp.Header.Get("Retry-After"), body)
				}
			}
		})
	}
}

// A filtered file whose store read does not return inside the budget is
// answered 503 rather than left hanging.
func TestRpmProfileBudgetCoversTheFilteredFileRead(t *testing.T) {
	f := newRpmBuildFixture(t)
	doc := f.warm(t)
	href := rpmEntryHref(t, doc, "filelists")
	gateStore(t, f.s, func(_ context.Context, op, key string) bool {
		return op == "Get" && strings.HasSuffix(key, path.Base(href))
	})
	resp, body, took, err := f.get(context.Background(), f.web01, rpmRepoPath+href)
	if err != nil {
		t.Fatal(err)
	}
	if took >= 5*time.Second || resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Errorf("filtered filelists behind a stalled store: %d Retry-After=%q after %s, want 503 with Retry-After under 5s\n%s", resp.StatusCode, resp.Header.Get("Retry-After"), took, body)
	}
}

// The previous build stands in only for a document naming the filtered types
// it built: one that gained filelists would otherwise list the upstream's
// unfiltered filelists, and one that lost them would serve a primary filtered
// alongside files the document no longer names.
func TestRpmProfileFallbackRefusesAnotherSetOfFilteredTypes(t *testing.T) {
	t.Run("upstream adds filelists and other", func(t *testing.T) {
		f := newRpmBuildFixture(t)
		f.s.cache.MetadataTTL = time.Nanosecond
		f.s.rpmProfileBuilds.wait = 100 * time.Millisecond
		f.m.set("repodata/repomd.xml", rpmFixture(t, "repodata/repomd.xml"))
		f.warm(t)
		f.m.set("repodata/repomd.xml", f.upstream)
		f.m.stall(t, f.filelistsHref(t))
		web02 := addProfileHost(t, f.s, "web", "web02")
		resp, doc, _, err := f.get(context.Background(), web02, rpmRepoPath+"repodata/repomd.xml")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(doc, f.filelistsHref(t)) {
			t.Errorf("repomd.xml during a build that adds filelists: %d, want 503 and no upstream filelists\n%s", resp.StatusCode, doc)
		}
	})
	t.Run("upstream drops filelists and other", func(t *testing.T) {
		f := newRpmBuildFixture(t)
		f.s.cache.MetadataTTL = time.Nanosecond
		f.s.rpmProfileBuilds.wait = 100 * time.Millisecond
		f.warm(t)
		f.m.set("repodata/repomd.xml", rpmFixture(t, "repodata/repomd.xml"))
		_, release := gateStore(t, f.s, func(_ context.Context, op, key string) bool {
			return op == "Put" && strings.HasSuffix(key, "-primary.xml.gz")
		})
		web02 := addProfileHost(t, f.s, "web", "web02")
		resp, doc, _, err := f.get(context.Background(), web02, rpmRepoPath+"repodata/repomd.xml")
		release()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("repomd.xml during a build that drops filelists: %d, want 503\n%s", resp.StatusCode, doc)
		}
	})
}

// A build that fails is recorded once, with the profile, the repository, the
// file and the upstream's own error, however many requests were waiting on it.
func TestRpmProfileBuildFailureIsLoggedOnceWithItsCause(t *testing.T) {
	f := newRpmBuildFixture(t)
	var logs syncBuffer
	f.s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	f.s.rpmProfileBuilds.timeout = 200 * time.Millisecond
	f.s.rpmProfileBuilds.wait = time.Minute
	release := f.m.stall(t, f.filelistsHref(t))
	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := range codes {
		wg.Go(func() {
			if resp, _, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml"); err == nil {
				codes[i] = resp.StatusCode
			}
		})
	}
	wg.Wait()
	f.s.rpmProfileBuilds.running.Wait()
	for i, c := range codes {
		if c != http.StatusBadGateway {
			t.Errorf("request %d: %d, want 502 for the failed build", i, c)
		}
	}
	var errs []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=ERROR") {
			errs = append(errs, line)
		}
	}
	if len(errs) != 1 {
		t.Fatalf("error records = %d, want 1:\n%s", len(errs), strings.Join(errs, "\n"))
	}
	for _, want := range []string{"profile=web", "repository=" + rpmFixtureRepoID, "file=filelists", "context deadline exceeded"} {
		if !strings.Contains(errs[0], want) {
			t.Errorf("the failure record lacks %q:\n%s", want, errs[0])
		}
	}
	release()
	f.s.rpmProfileBuilds.timeout = 0
	if resp, _, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml"); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("the request after the failure: %v %v, want 200 from a new build", err, resp)
	}
}

// rpmStepStore blocks each call hold matches until the test releases that
// call, handing the release out on calls. returned receives once each such
// call has finished, so a test can tell when abandoned work went on.
type rpmStepStore struct {
	storage.ObjectStore
	hold     func(op, key string) bool
	calls    chan func()
	returned chan string
	mu       sync.Mutex
	gates    []chan struct{}
}

func stepStore(t *testing.T, s *Server, hold func(op, key string) bool) *rpmStepStore {
	t.Helper()
	st := &rpmStepStore{ObjectStore: s.typeStore(manifest.TypeRpm), hold: hold, calls: make(chan func(), 16), returned: make(chan string, 16)}
	s.stores = rpmOneStore{Resolver: s.stores, store: st}
	t.Cleanup(func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		for _, g := range st.gates {
			select {
			case <-g:
			default:
				close(g)
			}
		}
	})
	return st
}

func (st *rpmStepStore) step(op, key string) func() {
	if !st.hold(op, key) {
		return func() {}
	}
	g := make(chan struct{})
	st.mu.Lock()
	st.gates = append(st.gates, g)
	st.mu.Unlock()
	var once sync.Once
	st.calls <- func() { once.Do(func() { close(g) }) }
	<-g
	return func() { st.returned <- op + " " + key }
}

func (st *rpmStepStore) Get(ctx context.Context, key string) ([]byte, error) {
	defer st.step("Get", key)()
	return st.ObjectStore.Get(ctx, key)
}

func (st *rpmStepStore) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	defer st.step("GetStream", key)()
	return st.ObjectStore.GetStream(ctx, key)
}

func (st *rpmStepStore) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	defer st.step("Head", key)()
	return st.ObjectStore.Head(ctx, key)
}

func (st *rpmStepStore) Put(ctx context.Context, key string, body []byte) error {
	defer st.step("Put", key)()
	return st.ObjectStore.Put(ctx, key, body)
}

// A build stuck in a store call that ignores its context is retired at its
// deadline all the same: its waiters get the failure, the next request starts
// a new build, and the stuck call finishing afterwards neither publishes the
// abandoned build nor retires the one that replaced it.
func TestRpmProfileBuildBlockedInTheStoreIsRetiredAtItsDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		hold func(upstreamFilelists string) func(op, key string) bool
	}{
		{"filtered write", func(string) func(op, key string) bool {
			// The last write, so the abandoned build returns a whole build
			// once it is let go.
			return func(op, key string) bool { return op == "Put" && strings.HasSuffix(key, "-other.xml.gz") }
		}},
		{"cached upstream read", func(sum string) func(op, key string) bool {
			return func(op, key string) bool { return op != "Put" && strings.Contains(key, sum) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRpmBuildFixture(t)
			f.warm(t)
			var logs syncBuffer
			f.s.logger = slog.New(slog.NewTextHandler(&logs, nil))
			sl, p := f.slot(t)
			sl.mu.Lock()
			sl.recent = nil
			sl.mu.Unlock()
			data, _ := parseRpmRepomd(f.upstream)
			var filelistsSum string
			for _, d := range data {
				if d.Type == "filelists" {
					filelistsSum = d.Checksum.Value
				}
			}
			// Only each build's first matching call is held: a read may Head
			// the key and then Get it, and holding both would leave the second
			// build waiting on a release the test never hands out.
			hold, holds := tc.hold(filelistsSum), atomic.Int32{}
			st := stepStore(t, f.s, func(op, key string) bool { return hold(op, key) && holds.Add(1) <= 2 })
			f.s.rpmProfileBuilds.timeout = 200 * time.Millisecond
			f.s.rpmProfileBuilds.wait = time.Minute
			build := func() <-chan error {
				done := make(chan error, 1)
				go func() {
					_, err := f.s.rpmProfileFiles(httptest.NewRequest(http.MethodGet, "/", nil), f.tree(), p, data)
					done <- err
				}()
				return done
			}

			first := build()
			releaseFirst := <-st.calls
			var err error
			select {
			case err = <-first:
			case <-time.After(5 * time.Second):
				t.Fatal("a build stuck in the store was not retired at its deadline")
			}
			var failed *rpmProfileBuildError
			if !errors.As(err, &failed) || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the stuck build's waiter got %v, want a build error wrapping the deadline", err)
			}
			sl.mu.Lock()
			running := len(sl.running)
			sl.mu.Unlock()
			if running != 0 {
				t.Fatalf("running builds after the deadline = %d, want 0", running)
			}

			f.s.rpmProfileBuilds.timeout = time.Minute
			second := build()
			releaseSecond := <-st.calls
			sl.mu.Lock()
			replacement := sl.running[sl.runningKey()]
			sl.mu.Unlock()
			if replacement == nil {
				t.Fatal("the request after the retired build started no build of its own")
			}

			releaseFirst()
			<-st.returned
			// The abandoned build returns within microseconds of its store
			// call; give it far longer to do anything it should not.
			time.Sleep(100 * time.Millisecond)
			sl.mu.Lock()
			still, held := sl.running[sl.runningKey()], len(sl.recent)
			sl.mu.Unlock()
			if still != replacement {
				t.Error("the abandoned build finishing retired the build that replaced it")
			}
			if held != 0 {
				t.Errorf("the abandoned build finishing published %d builds, want none", held)
			}
			if n := f.s.rpmProfileBuilds.count(); n != 1 {
				t.Errorf("builds = %d after the abandoned one finished, want only the warm-up's", n)
			}

			releaseSecond()
			if err := <-second; err != nil {
				t.Fatalf("the replacement build: %v", err)
			}
			if n := f.s.rpmProfileBuilds.count(); n != 2 {
				t.Errorf("builds = %d, want the warm-up's and the replacement's", n)
			}
			var errs []string
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.Contains(line, "level=ERROR") {
					errs = append(errs, line)
				}
			}
			if len(errs) != 1 || !strings.Contains(errs[0], "build timeout") {
				t.Errorf("error records = %d, want 1 naming the build timeout:\n%s", len(errs), strings.Join(errs, "\n"))
			}
		})
	}
}

// runningKey is the key of the one build sl has running. The caller
// holds sl.mu.
func (sl *rpmProfileSlot) runningKey() string {
	for k := range sl.running {
		return k
	}
	return ""
}

// A filtered file the host's repomd.xml names that has gone from the store
// while its view rebuilds answers 503 with Retry-After, not a 404 telling the
// client it is gone; an href that repomd.xml does not name is still a 404.
func TestRpmProfileMissingHeldFileDuringARebuildAnswers503(t *testing.T) {
	f := newRpmBuildFixture(t)
	doc := f.warm(t)
	sl, _ := f.slot(t)
	sl.mu.Lock()
	old := sl.recent[0]
	sl.mu.Unlock()
	key := rpmFilteredKey(f.tree(), old.files["filelists"])
	if err := f.s.typeStore(manifest.TypeRpm).Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	st := stepStore(t, f.s, func(op, k string) bool { return op == "Put" && k == key })
	f.s.rpmProfileBuilds.wait = 100 * time.Millisecond
	f.s.rpmProfileBuilds.coldWait = time.Second
	if resp, body, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml"); err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("repomd.xml during the rebuild: %v %v %s, want 503", err, resp, body)
	}
	release := <-st.calls

	href := rpmEntryHref(t, doc, "filelists")
	resp, body, took, err := f.get(context.Background(), f.web01, rpmRepoPath+href)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || took > 5*time.Second {
		t.Errorf("the missing filelists during its rebuild: %d Retry-After=%q in %s, want 503 with Retry-After inside 5s: %s",
			resp.StatusCode, resp.Header.Get("Retry-After"), took, body)
	}

	release()
	f.s.rpmProfileBuilds.running.Wait()
	if resp, _, _, err := f.get(context.Background(), f.web01, rpmRepoPath+href); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("the filelists once the rebuild finished: %v %v, want 200", err, resp)
	}
	if resp, _, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/"+strings.Repeat("0", 64)+"-filelists.xml.gz"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("an href the host's repomd.xml does not name: %v %v, want 404", err, resp)
	}
}

// An upstream file the proxy refuses on its checksum fails the build with one
// record, at any level, which keeps the refusal's incident and reason.
func TestRpmProfileChecksumRefusalIsLoggedOnce(t *testing.T) {
	f := newRpmBuildFixture(t)
	var logs syncBuffer
	f.s.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.m.set(f.filelistsHref(t), []byte("not the filelists repomd.xml describes"))
	resp, _, _, err := f.get(context.Background(), f.web01, rpmRepoPath+"repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	f.s.rpmProfileBuilds.running.Wait()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("repomd.xml over a corrupt filelists: %d, want 502", resp.StatusCode)
	}
	var records []string
	for _, line := range strings.Split(logs.String(), "\n") {
		// Every level but INFO, which traces the fetch rather than its
		// failure; a line naming the incident counts at any level.
		failure := strings.Contains(line, "filelists") && !strings.Contains(line, "level=INFO")
		if failure || strings.Contains(line, "incident") || strings.Contains(line, "refused") {
			records = append(records, line)
		}
	}
	if len(records) != 1 {
		t.Fatalf("records of the refusal = %d, want 1:\n%s", len(records), strings.Join(records, "\n"))
	}
	for _, want := range []string{"level=ERROR", "profile=web", "file=filelists", "checksum", "incident"} {
		if !strings.Contains(records[0], want) {
			t.Errorf("the record lacks %q:\n%s", want, records[0])
		}
	}
}

// rpmFailingStore fails the reads and writes its predicates match, after gate
// closes when gate is set, so a test can hold a failure past a build's
// deadline.
type rpmFailingStore struct {
	storage.ObjectStore
	failRead  func(key string) bool
	failWrite func(key string) bool
	gate      <-chan struct{}
}

var errRpmTestStore = errors.New("test: the store refused")

func (s rpmFailingStore) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	if s.failRead != nil && s.failRead(key) {
		if s.gate != nil {
			<-s.gate
		}
		return nil, errRpmTestStore
	}
	return s.ObjectStore.GetStream(ctx, key)
}

func (s rpmFailingStore) PutFile(ctx context.Context, localPath, key string) error {
	if s.failWrite != nil && s.failWrite(key) {
		return errRpmTestStore
	}
	return s.ObjectStore.PutFile(ctx, localPath, key)
}

// rpmFailureRecords is every record in logs at warning or above.
func rpmFailureRecords(logs string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "level=WARN") || strings.Contains(line, "level=ERROR") {
			out = append(out, line)
		}
	}
	return out
}

// coldBuild clears f's recent builds and sends logs to a buffer, so the next
// rpmProfileFiles builds and its records can be counted.
func (f *rpmBuildFixture) coldBuild(t *testing.T) (*entitle.Profile, *syncBuffer) {
	t.Helper()
	sl, p := f.slot(t)
	sl.mu.Lock()
	sl.recent = nil
	sl.mu.Unlock()
	logs := &syncBuffer{}
	f.s.logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return p, logs
}

func (f *rpmBuildFixture) build(p *entitle.Profile) (*rpmProfileBuild, error) {
	data, _ := parseRpmRepomd(f.upstream)
	return f.s.rpmProfileFiles(httptest.NewRequest(http.MethodGet, "/", nil), f.tree(), p, data)
}

// A cached upstream file the store cannot read fails the build with one
// record, the build's, carrying the store's error; the proxy route the read
// went through writes none of its own, and the next build starts over.
func TestRpmProfileBuildOwnsACachedReadFailure(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	good := f.s.stores
	cached := path.Base(f.filelistsHref(t))
	p, logs := f.coldBuild(t)
	f.s.stores = rpmOneStore{Resolver: good, store: rpmFailingStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		failRead: func(k string) bool { return strings.HasSuffix(k, cached) }}}

	if _, err := f.build(p); !errors.Is(err, errRpmTestStore) {
		t.Fatalf("build error = %v, want one carrying the store's error", err)
	}
	f.s.rpmProfileBuilds.running.Wait()
	recs := rpmFailureRecords(logs.String())
	if len(recs) != 1 || !strings.Contains(recs[0], "rpm metadata could not be filtered for a profile") ||
		!strings.Contains(recs[0], errRpmTestStore.Error()) || !strings.Contains(recs[0], "file=filelists") {
		t.Fatalf("want one record, the build's, naming the file and the store's error; got:\n%s", strings.Join(recs, "\n"))
	}

	f.s.stores = good
	before := f.s.rpmProfileBuilds.built
	if b, err := f.build(p); err != nil || b == nil {
		t.Fatalf("the build after a failed one: %v", err)
	}
	if got := f.s.rpmProfileBuilds.built - before; got != 1 {
		t.Errorf("the build after a failed one counted %d builds, want 1", got)
	}
}

// A cached read that fails after its build was retired at the deadline writes
// nothing: the build's one record is already written, and the log is no
// longer the abandoned work's to write to.
func TestRpmProfileBuildRetiredReadFailureIsSilent(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	cached := path.Base(f.filelistsHref(t))
	p, logs := f.coldBuild(t)
	gate := make(chan struct{})
	f.s.stores = rpmOneStore{Resolver: f.s.stores, store: rpmFailingStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		failRead: func(k string) bool { return strings.HasSuffix(k, cached) }, gate: gate}}
	f.s.rpmProfileBuilds.timeout = 100 * time.Millisecond

	// The supervisor writes its record before it closes the job, and a
	// deadline error reaches the caller only through that close.
	if _, err := f.build(p); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("build error = %v, want the build's deadline", err)
	}
	before := logs.String()
	close(gate)
	f.s.rpmProfileBuilds.running.Wait()
	if after := logs.String(); after != before {
		t.Errorf("the retired build's read wrote to the log after its failure was recorded:\n%s", strings.TrimPrefix(after, before))
	}
	if recs := rpmFailureRecords(before); len(recs) != 1 {
		t.Errorf("want the build's one record; got:\n%s", strings.Join(recs, "\n"))
	}
}

// A read that succeeds around a failure, here the cache write the proxy
// treats as best effort, still gets one record, the build's, naming the
// file and the store's error, and the build is kept.
func TestRpmProfileBuildRecordsAFailureItSucceededAround(t *testing.T) {
	f := newRpmBuildFixture(t)
	upstream := path.Base(f.filelistsHref(t))
	p, logs := f.coldBuild(t)
	f.s.stores = rpmOneStore{Resolver: f.s.stores, store: rpmFailingStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		failWrite: func(k string) bool { return strings.HasSuffix(k, upstream) }}}

	if b, err := f.build(p); err != nil || b == nil {
		t.Fatalf("a build whose cache write failed: %v", err)
	}
	f.s.rpmProfileBuilds.running.Wait()
	// The pin advisory is a note every cold metadata fill writes, at warning
	// level, and not a failure of the read.
	var recs []string
	for _, rec := range rpmFailureRecords(logs.String()) {
		if !strings.Contains(rec, "pinned an object with no admission decision") {
			recs = append(recs, rec)
		}
	}
	if len(recs) != 1 || !strings.Contains(recs[0], "succeeded around a failure") ||
		!strings.Contains(recs[0], errRpmTestStore.Error()) || !strings.Contains(recs[0], "file=filelists") {
		t.Fatalf("want one record, the build's, naming the file and the store's error; got:\n%s", strings.Join(recs, "\n"))
	}
}

// A metadata read no build owns logs its failure where it happens, as every
// other proxied read does.
func TestRpmMetadataReadOutsideABuildLogsItsOwnFailure(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	cached := path.Base(f.filelistsHref(t))
	_, logs := f.coldBuild(t)
	f.s.stores = rpmOneStore{Resolver: f.s.stores, store: rpmFailingStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		failRead: func(k string) bool { return strings.HasSuffix(k, cached) }}}
	data, _ := parseRpmRepomd(f.upstream)
	var entry rpmRepomdData
	for _, d := range data {
		if d.Type == "filelists" {
			entry = d
		}
	}
	w := httptest.NewRecorder()
	f.s.serveRpmMetadataEntry(w, httptest.NewRequest(http.MethodGet, "/", nil), f.tree(), entry)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if recs := rpmFailureRecords(logs.String()); len(recs) != 1 || !strings.Contains(recs[0], "object proxy error") {
		t.Errorf("want the proxy's own record; got:\n%s", strings.Join(recs, "\n"))
	}
}

var errRpmTestBody = errors.New("test: the stored body failed mid-stream")

// rpmCutBodyStore opens every object, and makes the body of a key cut
// matches fail: at once, or after its last byte in place of EOF when deliver
// is set, which leaves the reader holding the whole document. A gate holds
// the failing Read until it closes.
type rpmCutBodyStore struct {
	storage.ObjectStore
	cut     func(key string) bool
	deliver bool
	gate    <-chan struct{}
}

func (s rpmCutBodyStore) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	res, err := s.ObjectStore.GetStream(ctx, key)
	if err == nil && res != nil && s.cut(key) {
		res.Body = &rpmCutBody{ReadCloser: res.Body, deliver: s.deliver, gate: s.gate}
	}
	return res, err
}

type rpmCutBody struct {
	io.ReadCloser
	deliver bool
	gate    <-chan struct{}
}

func (b *rpmCutBody) Read(p []byte) (int, error) {
	if b.deliver {
		n, err := b.ReadCloser.Read(p)
		if err == io.EOF {
			err = errRpmTestBody
		}
		return n, err
	}
	if b.gate != nil {
		<-b.gate
	}
	return 0, errRpmTestBody
}

// A cached file whose body fails after the store opened it fails the build
// with one record, the build's, carrying the store's error; the next build
// starts over and is counted once.
func TestRpmProfileBuildOwnsACachedBodyFailure(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	good := f.s.stores
	cached := path.Base(f.filelistsHref(t))
	p, logs := f.coldBuild(t)
	f.s.stores = rpmOneStore{Resolver: good, store: rpmCutBodyStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		cut: func(k string) bool { return strings.HasSuffix(k, cached) }}}

	if _, err := f.build(p); !errors.Is(err, errRpmTestBody) {
		t.Fatalf("build error = %v, want one carrying the body's error", err)
	}
	f.s.rpmProfileBuilds.running.Wait()
	recs := rpmFailureRecords(logs.String())
	if len(recs) != 1 || !strings.Contains(recs[0], "rpm metadata could not be filtered for a profile") ||
		!strings.Contains(recs[0], errRpmTestBody.Error()) || !strings.Contains(recs[0], "file=filelists") {
		t.Fatalf("want one record, the build's, naming the file and the body's error; got:\n%s", strings.Join(recs, "\n"))
	}

	f.s.stores = good
	before := f.s.rpmProfileBuilds.count()
	if b, err := f.build(p); err != nil || b == nil {
		t.Fatalf("the build after a failed one: %v", err)
	}
	if got := f.s.rpmProfileBuilds.count() - before; got != 1 {
		t.Errorf("the build after a failed one counted %d builds, want 1", got)
	}
}

// Bytes that parse are not a delivered document when the read ended in an
// error rather than EOF: the build fails, is not published and is not
// counted.
func TestRpmProfileBuildFailsOnACutBodyThatParses(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	cached := path.Base(f.filelistsHref(t))
	p, logs := f.coldBuild(t)
	f.s.stores = rpmOneStore{Resolver: f.s.stores, store: rpmCutBodyStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		cut: func(k string) bool { return strings.HasSuffix(k, cached) }, deliver: true}}

	before := f.s.rpmProfileBuilds.count()
	b, err := f.build(p)
	f.s.rpmProfileBuilds.running.Wait()
	if b != nil || !errors.Is(err, errRpmTestBody) {
		t.Fatalf("build=%v error=%v, want no build and the body's error", b != nil, err)
	}
	if got := f.s.rpmProfileBuilds.count() - before; got != 0 {
		t.Errorf("a build whose read failed counted %d builds, want 0", got)
	}
	sl, _ := f.slot(t)
	sl.mu.Lock()
	held := len(sl.recent)
	sl.mu.Unlock()
	if held != 0 {
		t.Errorf("a build whose read failed was published: %d held", held)
	}
	if recs := rpmFailureRecords(logs.String()); len(recs) != 1 || !strings.Contains(recs[0], errRpmTestBody.Error()) {
		t.Errorf("want the build's one record naming the body's error; got:\n%s", strings.Join(recs, "\n"))
	}
}

// A body that fails after its build was retired at the deadline writes
// nothing past the build's one record.
func TestRpmProfileBuildRetiredBodyFailureIsSilent(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	cached := path.Base(f.filelistsHref(t))
	p, logs := f.coldBuild(t)
	gate := make(chan struct{})
	f.s.stores = rpmOneStore{Resolver: f.s.stores, store: rpmCutBodyStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		cut: func(k string) bool { return strings.HasSuffix(k, cached) }, gate: gate}}
	f.s.rpmProfileBuilds.timeout = 100 * time.Millisecond

	if _, err := f.build(p); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("build error = %v, want the build's deadline", err)
	}
	before := logs.String()
	close(gate)
	f.s.rpmProfileBuilds.running.Wait()
	if after := logs.String(); after != before {
		t.Errorf("the retired build's read wrote to the log after its failure was recorded:\n%s", strings.TrimPrefix(after, before))
	}
	if recs := rpmFailureRecords(before); len(recs) != 1 {
		t.Errorf("want the build's one record; got:\n%s", strings.Join(recs, "\n"))
	}
}

// A client's own request for the same file is served as before: the status
// is already out when the body fails, and nothing is logged in its name.
func TestRpmMetadataCutBodyToAClientIsUnchanged(t *testing.T) {
	f := newRpmBuildFixture(t)
	f.warm(t)
	cached := path.Base(f.filelistsHref(t))
	_, logs := f.coldBuild(t)
	f.s.stores = rpmOneStore{Resolver: f.s.stores, store: rpmCutBodyStore{ObjectStore: f.s.typeStore(manifest.TypeRpm),
		cut: func(k string) bool { return strings.HasSuffix(k, cached) }}}
	data, _ := parseRpmRepomd(f.upstream)
	var entry rpmRepomdData
	for _, d := range data {
		if d.Type == "filelists" {
			entry = d
		}
	}
	w := httptest.NewRecorder()
	f.s.serveRpmMetadataEntry(w, httptest.NewRequest(http.MethodGet, "/", nil), f.tree(), entry)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want the 200 already written", w.Code)
	}
	if recs := rpmFailureRecords(logs.String()); len(recs) != 0 {
		t.Errorf("a client's cut read logged:\n%s", strings.Join(recs, "\n"))
	}
}
