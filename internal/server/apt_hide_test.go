package server

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// The fixture archive's htop is the vulnerable build being withdrawn: a binary
// in the mirrored codename with no manifest entry anywhere.
const hiddenHtopVersion = "3.3.0-4build1"

// hideMirrored records a hide the way the CLI does and rebuilds, which is what
// the SIGHUP the CLI sends triggers on a running server.
func hideMirrored(t *testing.T, s *Server, name, version string) {
	t.Helper()
	if err := s.auditDB.InsertAptMirrorHide(context.Background(), audit.AptMirrorHide{
		Name: name, Version: version, Codenames: []string{mirroredCodename}, HiddenBy: "tester",
	}); err != nil {
		t.Fatalf("record the hide: %v", err)
	}
	s.rebuildAptSnapshot(context.Background())
}

// verifyBodegaInRelease checks a served InRelease against bodega's published
// key and returns the signed Release.
func verifyBodegaInRelease(t *testing.T, s *Server, codename string) map[string]string {
	t.Helper()
	code, inRelease := mirrorGet(t, s, "/apt/dists/"+codename+"/InRelease")
	if code != http.StatusOK {
		t.Fatalf("GET InRelease for %s = %d, want 200", codename, code)
	}
	block, _ := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatalf("InRelease for %s is not clearsigned", codename)
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(s.aptSign.Load().pub())))
	if err != nil {
		t.Fatalf("read bodega's published key: %v", err)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, bytesReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Fatalf("InRelease for %s does not verify against bodega's key: %v", codename, err)
	}
	return mustParseRelease(t, block.Plaintext)
}

func TestMirroredHideDropsTheStanzaAndReSignsTheCodename(t *testing.T) {
	s, _ := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	code, body := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath)
	if code != http.StatusOK {
		t.Fatalf("GET the mirrored Packages = %d, want 200", code)
	}
	index := string(body)
	if strings.Contains(index, "Package: htop") {
		t.Errorf("the mirrored Packages still lists the hidden htop:\n%s", index)
	}
	if !strings.Contains(index, "Package: nginx\n") || !strings.Contains(index, "\n a continuation line the filter must not reflow\n") {
		t.Errorf("the rewrite lost or reflowed a stanza nobody hid:\n%s", index)
	}

	release := verifyBodegaInRelease(t, s, mirroredCodename)
	if got := aptReleaseDigests(release)[packagesPath]; got != sha256Hex(index) {
		t.Errorf("the signed Release names %s for Packages and the served body hashes to %s", got, sha256Hex(index))
	}
	// apt refuses an update whose Origin or Label changed, so the rewrite has
	// to keep the archive's.
	for field, want := range map[string]string{"Origin": "Ubuntu", "Label": "Ubuntu", "Codename": mirroredCodename, "Suite": mirroredCodename} {
		if release[field] != want {
			t.Errorf("rewritten Release %s = %q, want the archive's %q", field, release[field], want)
		}
	}

	// The sources stanza for the codename now names bodega's keyring.
	var stanza *aptsources.Sources
	for _, src := range s.aptStatusFor(nil).Sources {
		if src.Suite == mirroredCodename {
			stanza = &src
		}
	}
	if stanza == nil {
		t.Fatalf("no sources stanza for %s", mirroredCodename)
	}
	if stanza.Mirrored || !strings.Contains(stanza.Deb822, "Signed-By: "+aptsources.ClientKeyringPath) {
		t.Errorf("the stanza for a rewritten codename does not name bodega's keyring:\n%s", stanza.Deb822)
	}
}

// restartMirrorServer is a new server process on s's audit database and
// upstreams, with nothing else carried over: no snapshot, no cached upstream
// document, no cached dists/ object.
func restartMirrorServer(t *testing.T, s *Server) *Server {
	t.Helper()
	cfg := *s.cfg
	next := newServer(&cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	next.cache = s.cache
	t.Cleanup(func() { _ = next.auditDB.Close() })
	if next.aptSign.Load() == nil {
		t.Fatal("the restarted server loaded no apt signing key")
	}
	return next
}

// An Ubuntu release pocket's Release is dated once and never again. apt keeps
// a stored Release over a fetched one dated earlier, so a host that read the
// hidden rewrite would keep its filtered Packages if the codename went back to
// the archive's Release when the hide was lifted.
func TestMirroredUnhideKeepsAFrozenCodenameSignedUntilUpstreamRedates(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase: {"amd64": hideStanza("htop", "1.0-1", "amd64") + hideStanza("nginx", "1.24-1", "amd64")},
	})
	rel := "dists/" + hideGroupBase + "/Release"
	undated, _ := archive.object(rel)
	frozen := time.Now().UTC().Add(-200 * 24 * time.Hour)
	archive.setObject(rel, "Date: "+frozen.Format(time.RFC1123Z)+"\n"+undated)
	ctx := t.Context()
	packages := "/apt/dists/" + hideGroupBase + "/main/binary-amd64/Packages"
	releaseDate := func(s *Server) time.Time {
		t.Helper()
		d, err := aptReleaseDate(verifyBodegaInRelease(t, s, hideGroupBase))
		if err != nil {
			t.Fatalf("the served rewrite: %v", err)
		}
		return d
	}

	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	s.rebuildAptSnapshot(ctx)
	if !s.aptMirrorRewritten(hideGroupBase) {
		t.Fatal("the hide did not rewrite the codename")
	}
	if got := aptIndexVersions(t, s, packages, "htop"); len(got) != 0 {
		t.Fatalf("the hidden rewrite lists htop %v", got)
	}
	hiddenDate := releaseDate(s)

	held := func(stage string, s *Server) {
		t.Helper()
		if !s.aptMirrorRewritten(hideGroupBase) {
			t.Fatalf("%s: the codename went back to proxy while its upstream Release (%s) is older than the rewrite hosts hold (%s)",
				stage, frozen.Format(time.RFC1123Z), hiddenDate.Format(time.RFC1123Z))
		}
		if got := aptIndexVersions(t, s, packages, "htop"); !slices.Equal(got, []string{"1.0-1"}) {
			t.Errorf("%s: the held rewrite lists htop %v, want the unhidden 1.0-1", stage, got)
		}
		if got := aptIndexVersions(t, s, packages, "nginx"); !slices.Equal(got, []string{"1.24-1"}) {
			t.Errorf("%s: the held rewrite lists nginx %v, want 1.24-1", stage, got)
		}
		if d := releaseDate(s); d.Before(hiddenDate) {
			t.Errorf("%s: the held rewrite is dated %s, earlier than the hidden rewrite's %s, so apt would keep the hidden one",
				stage, d.Format(time.RFC1123Z), hiddenDate.Format(time.RFC1123Z))
		}
	}

	if _, err := s.auditDB.DeleteAptMirrorHide(ctx, "htop", "1.0-1"); err != nil {
		t.Fatalf("remove the hide: %v", err)
	}
	s.rebuildAptSnapshot(ctx)
	held("after the unhide", s)

	restarted := restartMirrorServer(t, s)
	restarted.rebuildAptSnapshot(ctx)
	held("after a restart", restarted)

	redated := "Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\n" + undated
	archive.setObject(rel, redated)
	restarted.aptUpstreamIdx.Clear()
	restarted.rebuildAptSnapshot(ctx)
	if restarted.aptMirrorRewritten(hideGroupBase) {
		t.Fatal("the codename stayed rewritten after its upstream Release was re-dated past the last rewrite")
	}
	if code, body := mirrorGet(t, restarted, "/apt/"+rel); code != http.StatusOK || string(body) != redated {
		t.Errorf("after upstream re-dated, Release = %d, want the archive's own bytes:\n%s", code, body)
	}
	dates, err := restarted.auditDB.AptMirrorRewriteDates(ctx)
	if err != nil {
		t.Fatalf("read the rewrite dates: %v", err)
	}
	if d, ok := dates[hideGroupBase]; ok {
		t.Errorf("the proxied codename still has a rewrite date on record: %s", d)
	}
}

func TestMirroredHideDropsTheStanzaFromAFilteredCodename(t *testing.T) {
	s, _ := aptProfileServer(t)
	aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx", "htop")
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	if index := aptProfileIndex(t, s, "fixture-web"); strings.Contains(index, "Package: htop") {
		t.Errorf("the filtered codename lists the hidden htop although the profile permits it:\n%s", index)
	}
}

func TestMirroredHidePoolRefusesWithAnAuditRow(t *testing.T) {
	s, archive := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	code, body := mirrorGet(t, s, "/apt/"+profileHtopDeb)
	if code != http.StatusForbidden {
		t.Fatalf("pool fetch of a hidden mirrored version = %d, want 403:\n%s", code, body)
	}
	if got := archive.count(profileHtopDeb); got != 0 {
		t.Errorf("upstream GETs for a hidden version = %d, want 0", got)
	}
	ev := profileDenial(t, s, audit.DenialHidden)
	if ev.PkgName != "htop" || ev.PkgVersion != hiddenHtopVersion {
		t.Errorf("denial row names %s %s, want htop %s", ev.PkgName, ev.PkgVersion, hiddenHtopVersion)
	}

	if code, _ := mirrorGet(t, s, "/apt/"+profileNginxDeb); code != http.StatusOK {
		t.Errorf("pool fetch of a version nobody hid = %d, want 200", code)
	}
}

func TestMirroredUnhideRestoresTheUpstreamIndex(t *testing.T) {
	s, archive := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	if _, err := s.auditDB.DeleteAptMirrorHide(context.Background(), "htop", hiddenHtopVersion); err != nil {
		t.Fatalf("remove the hide: %v", err)
	}
	s.rebuildAptSnapshot(context.Background())

	code, body := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath)
	if code != http.StatusOK {
		t.Fatalf("GET the mirrored Packages = %d, want 200", code)
	}
	upstream, _ := archive.object("dists/" + mirroredCodename + "/" + packagesPath)
	if string(body) != upstream {
		t.Errorf("after unhide the Packages is not the archive's bytes:\n%s", body)
	}
	_, inRelease := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/InRelease")
	if want, _ := archive.object("dists/" + mirroredCodename + "/InRelease"); string(inRelease) != want {
		t.Errorf("after unhide the InRelease is not the archive's signed document")
	}
	if code, _ := mirrorGet(t, s, "/apt/"+profileHtopDeb); code != http.StatusOK {
		t.Errorf("pool fetch after unhide = %d, want 200", code)
	}
}

func TestLocateMirroredAptVersion(t *testing.T) {
	s, _ := aptProfileServer(t)

	found, err := LocateMirroredAptVersion(context.Background(), s.cfg, nil, "htop", hiddenHtopVersion)
	if err != nil || len(found) != 1 || found[0] != mirroredCodename {
		t.Fatalf("locate a version the mirror serves = %v, %v; want [%s]", found, err, mirroredCodename)
	}

	_, err = LocateMirroredAptVersion(context.Background(), s.cfg, nil, "htop", "9.9.9-1")
	if err == nil {
		t.Fatal("a version no mirror serves was accepted")
	}
	if !strings.Contains(err.Error(), "searched "+mirroredCodename) {
		t.Errorf("the refusal does not name the codenames searched: %v", err)
	}
}

// A pool filename drops the epoch, so the pool refusal has to match a hide
// recorded with one against a path that carries none.
func TestMirroredHidePoolRefusesAnEpochVersion(t *testing.T) {
	const (
		epochVersion = "1:2.0-1"
		epochDeb     = "pool/main/e/epochpkg/epochpkg_2.0-1_amd64.deb"
		spelledDeb   = "pool/main/e/epochpkg/epochpkg_1%3a2.0-1_amd64.deb"
		otherDeb     = "pool/main/e/epochpkg/epochpkg_3%3a2.0-1_amd64.deb"
	)
	packages := aptProfilePackages() + strings.Join([]string{
		"Package: epochpkg",
		"Version: " + epochVersion,
		"Architecture: amd64",
		"Filename: " + epochDeb,
		"Size: " + strconv.Itoa(len("\x21<arch>\nepochpkg bytes")),
		"SHA256: " + sha256Hex("\x21<arch>\nepochpkg bytes"),
		"Description: fixture package with an epoch",
		"", "",
	}, "\n")
	pool := aptProfilePool()
	pool[epochDeb] = "\x21<arch>\nepochpkg bytes"
	pool[spelledDeb] = "\x21<arch>\nepochpkg bytes"
	pool[otherDeb] = "\x21<arch>\nepochpkg epoch 3 bytes"
	s, archive := aptProfileServerWith(t, "amd64", packages, pool)

	found, err := LocateMirroredAptVersion(context.Background(), s.cfg, nil, "epochpkg", epochVersion)
	if err != nil || len(found) != 1 {
		t.Fatalf("locate the epoch'd version = %v, %v; want it found", found, err)
	}
	hideMirrored(t, s, "epochpkg", epochVersion)

	if _, body := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath); strings.Contains(string(body), "Package: epochpkg") {
		t.Errorf("the mirrored Packages still lists the hidden epochpkg:\n%s", body)
	}
	for i, deb := range []string{epochDeb, spelledDeb} {
		code, body := mirrorGet(t, s, "/apt/"+deb)
		if code != http.StatusForbidden {
			t.Fatalf("pool fetch of %s = %d, want 403:\n%s", deb, code, body)
		}
		if got := archive.count(deb); got != 0 {
			t.Errorf("upstream GETs for %s = %d, want 0", deb, got)
		}
		if i > 0 {
			continue
		}
		ev := profileDenial(t, s, audit.DenialHidden)
		if ev.PkgName != "epochpkg" || ev.PkgVersion != epochVersion {
			t.Errorf("denial row names %s %s, want epochpkg %s", ev.PkgName, ev.PkgVersion, epochVersion)
		}
	}

	if code, _ := mirrorGet(t, s, "/apt/"+otherDeb); code == http.StatusForbidden {
		t.Errorf("pool fetch of a different epoch spelled in the path was refused as hidden")
	}
}

func TestAptStripEpoch(t *testing.T) {
	for in, want := range map[string]string{
		"2:9.1.0016-1ubuntu7": "9.1.0016-1ubuntu7",
		"9.1.0016-1ubuntu7":   "9.1.0016-1ubuntu7",
		"0:1.0":               "1.0",
		"1.0:2-1":             "1.0:2-1",
		":1.0":                ":1.0",
	} {
		if got := aptStripEpoch(in); got != want {
			t.Errorf("aptStripEpoch(%q) = %q, want %q", in, got, want)
		}
	}
}

// A backports pocket publishes NotAutomatic and ButAutomaticUpgrades, which
// set its default pin to 100. apt update fails on a host whose cached pin for
// the archive differs from the one it just fetched, so a rewrite that dropped
// the two fields broke apt on every host the moment a hide landed.
func TestMirroredHideKeepsTheArchiveDefaultPin(t *testing.T) {
	s, archive := aptProfileServer(t)
	rel := "dists/" + mirroredCodename + "/Release"
	upstream, ok := archive.object(rel)
	if !ok {
		t.Fatalf("the fixture archive publishes no %s", rel)
	}
	archive.setObject(rel, strings.Replace(upstream, "Components:", "NotAutomatic: yes\nButAutomaticUpgrades: yes\nComponents:", 1))
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	release := verifyBodegaInRelease(t, s, mirroredCodename)
	for _, field := range []string{"NotAutomatic", "ButAutomaticUpgrades"} {
		if release[field] != "yes" {
			t.Errorf("rewritten Release %s = %q, want the archive's %q", field, release[field], "yes")
		}
	}
}

// A pocket that publishes neither field keeps the default pin of 500, so the
// rewrite must not invent one.
func TestMirroredHideAddsNoDefaultPinTheArchiveLacks(t *testing.T) {
	s, _ := aptProfileServer(t)
	hideMirrored(t, s, "htop", hiddenHtopVersion)

	release := verifyBodegaInRelease(t, s, mirroredCodename)
	for _, field := range []string{"NotAutomatic", "ButAutomaticUpgrades"} {
		if v, ok := release[field]; ok {
			t.Errorf("rewritten Release carries %s: %q, which the archive does not publish", field, v)
		}
	}
}

// ---- reuse of filtered mirror indexes across rebuilds -------------------------

const (
	hideGroupBase    = mirroredCodename
	hideGroupUpdates = mirroredCodename + "-updates"
	hideGroupOther   = "other"
)

// hideStanza is one binary paragraph of a synthetic upstream index.
func hideStanza(pkg, version, arch string) string {
	return fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nFilename: pool/main/%c/%s/%s_%s_%s.deb\nSize: 42\nSHA256: %s\nDescription: fixture %s\n a continuation line\n\n",
		pkg, version, arch, pkg[0], pkg, pkg, version, arch, strings.Repeat("0", 64), pkg)
}

// hideGroupIndexes is the upstream content the reuse tests start from,
// codename then architecture: a base and its -updates pocket carrying two
// architectures each, and a second base of its own.
func hideGroupIndexes() map[string]map[string]string {
	return map[string]map[string]string{
		hideGroupBase: {
			"amd64": hideStanza("htop", "1.0-1", "amd64") + hideStanza("nginx", "1.24-1", "amd64"),
			"arm64": hideStanza("htop", "1.0-1", "arm64") + hideStanza("nginx", "1.24-1", "arm64"),
		},
		hideGroupUpdates: {
			"amd64": hideStanza("htop", "1.0-2", "amd64") + hideStanza("curl", "8.5-1", "amd64"),
			"arm64": hideStanza("htop", "1.0-2", "arm64") + hideStanza("curl", "8.5-1", "arm64"),
		},
		hideGroupOther: {
			"amd64": hideStanza("otherpkg", "2.0-1", "amd64") + hideStanza("vim", "9.1-1", "amd64"),
		},
	}
}

// hideGroupDists renders one codename's dists/ tree the way an archive
// publishes it: plain and gzip Packages per architecture, and a Release
// naming the SHA256 of each.
func hideGroupDists(codename string, byArch map[string]string) map[string]string {
	base := "dists/" + codename + "/"
	objects := map[string]string{}
	arches := slices.Sorted(maps.Keys(byArch))
	var digests []string
	for _, arch := range arches {
		rest := "main/binary-" + arch + "/Packages"
		gz := string(gzipFixture(byArch[arch]))
		objects[base+rest] = byArch[arch]
		objects[base+rest+".gz"] = gz
		digests = append(digests,
			fmt.Sprintf(" %s %d %s", sha256Hex(byArch[arch]), len(byArch[arch]), rest),
			fmt.Sprintf(" %s %d %s.gz", sha256Hex(gz), len(gz), rest))
	}
	objects[base+"Release"] = strings.Join(append([]string{
		"Origin: Ubuntu",
		"Label: Ubuntu",
		"Suite: " + codename,
		"Codename: " + codename,
		"Components: main",
		"Architectures: " + strings.Join(arches, " "),
		"SHA256:",
	}, append(digests, "")...), "\n")
	return objects
}

// hideGroupServer is a mirroring server with a bodega signing key over the
// codenames indexes names, every one of them served by the same archive.
func hideGroupServer(tb testing.TB, indexes map[string]map[string]string) (*Server, *fixtureArchive) {
	tb.Helper()
	dir := tb.TempDir()
	tb.Setenv(aptsign.CredentialsEnv, dir)
	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		tb.Fatalf("generate signing key: %v", err)
	}
	if err := kr.WritePrivate(filepath.Join(dir, aptsign.KeyFileName)); err != nil {
		tb.Fatalf("write signing key: %v", err)
	}
	objects := map[string]string{}
	for codename, byArch := range indexes {
		maps.Copy(objects, hideGroupDists(codename, byArch))
	}
	archive := newFixtureArchive(tb, objects)
	s := mirrorServer(tb, archive)
	for codename := range indexes {
		s.cfg.AptUpstreams[codename] = []config.AptUpstream{{URL: archive.URL()}}
	}
	if s.aptSign.Load() == nil {
		tb.Fatal("no apt signing key loaded; no mirrored group would be rewritten")
	}
	return s, archive
}

// recordHide records one hide without rebuilding, so the test chooses which
// snapshot the next build starts from.
func recordHide(t *testing.T, s *Server, name, version, codename string) {
	t.Helper()
	if err := s.auditDB.InsertAptMirrorHide(context.Background(), audit.AptMirrorHide{
		Name: name, Version: version, Codenames: []string{codename}, HiddenBy: "tester",
	}); err != nil {
		t.Fatalf("record the hide: %v", err)
	}
}

// buildFrom builds a snapshot with prev as the one being served, publishes
// it, and returns it. A nil prev is a cold build.
func buildFrom(t *testing.T, s *Server, prev *aptSnapshot) *aptSnapshot {
	t.Helper()
	s.aptSnap.Store(prev)
	snap, err := s.buildAptSnapshot(context.Background())
	if err != nil {
		t.Fatalf("build the apt snapshot: %v", err)
	}
	s.aptSnap.Store(snap)
	return snap
}

// countMirrorFilter counts the filter runs a rewrite makes from here on.
func countMirrorFilter(t *testing.T) *int {
	t.Helper()
	calls := new(int)
	saved := aptMirrorFilter
	aptMirrorFilter = func(index []byte, keep func(map[string]string) bool) ([]byte, int, int, error) {
		*calls++
		return saved(index, keep)
	}
	t.Cleanup(func() { aptMirrorFilter = saved })
	return calls
}

// assertSameRewrite fails unless two snapshots rewrite the same codenames and
// serve byte-identical Packages, Packages.gz and Release SHA256 blocks for
// each. Date, Valid-Until and the signature are allowed to differ.
func assertSameRewrite(t *testing.T, want, got *aptSnapshot) {
	t.Helper()
	if !maps.Equal(want.mirrorRewritten, got.mirrorRewritten) {
		t.Fatalf("rewritten codenames = %v, want %v", got.mirrorRewritten, want.mirrorRewritten)
	}
	for codename := range want.mirrorRewritten {
		w, g := want.suites[codename], got.suites[codename]
		if !slices.Equal(w.components, g.components) {
			t.Errorf("%s components = %v, want %v", codename, g.components, w.components)
		}
		for comp := range w.packages {
			for arch := range w.packages[comp] {
				if !bytes.Equal(w.packages[comp][arch], g.packages[comp][arch]) {
					t.Errorf("%s %s/%s Packages differs from the cold build", codename, comp, arch)
				}
				if !bytes.Equal(w.packagesGz[comp][arch], g.packagesGz[comp][arch]) {
					t.Errorf("%s %s/%s Packages.gz differs from the cold build", codename, comp, arch)
				}
			}
		}
		wr, gr := mustParseRelease(t, w.release), mustParseRelease(t, g.release)
		if wr["SHA256"] != gr["SHA256"] {
			t.Errorf("%s Release SHA256 block differs from the cold build:\n%s\nwant:\n%s", codename, gr["SHA256"], wr["SHA256"])
		}
	}
}

// sameBacking reports whether two slices share their backing array.
func sameBacking(a, b []byte) bool {
	return len(a) > 0 && len(a) == len(b) && &a[0] == &b[0]
}

// hideGroupIndexCount is how many Packages the fixture's two rewritten
// groups carry: two architectures in each of base and pocket, one in other.
const hideGroupIndexCount = 5

func TestMirrorRewriteWarmMatchesCold(t *testing.T) {
	s, _ := hideGroupServer(t, hideGroupIndexes())
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	recordHide(t, s, "otherpkg", "2.0-1", hideGroupOther)
	calls := countMirrorFilter(t)

	cold := buildFrom(t, s, nil)
	if *calls != hideGroupIndexCount {
		t.Fatalf("cold build filtered %d indexes, want %d", *calls, hideGroupIndexCount)
	}
	if len(cold.mirrorRewritten) != 3 || len(cold.mirrorIndexes) != hideGroupIndexCount {
		t.Fatalf("cold build rewrote %v and kept %d indexes; want 3 codenames and %d", cold.mirrorRewritten, len(cold.mirrorIndexes), hideGroupIndexCount)
	}
	if strings.Contains(string(cold.suites[hideGroupBase].packages["main"]["amd64"]), "Package: htop") {
		t.Fatal("the cold rewrite still lists the hidden htop")
	}

	*calls = 0
	warm := buildFrom(t, s, cold)
	if *calls != 0 {
		t.Errorf("warm build with nothing changed filtered %d indexes, want 0", *calls)
	}
	assertSameRewrite(t, cold, warm)
	// Reused, not rebuilt: the warm snapshot serves the cold one's bytes.
	if !sameBacking(cold.suites[hideGroupUpdates].packagesGz["main"]["arm64"], warm.suites[hideGroupUpdates].packagesGz["main"]["arm64"]) {
		t.Error("the warm build served a copy of the Packages.gz rather than the one the cold build made")
	}
}

func TestMirrorRewriteHideChangeRefiltersAndMatchesCold(t *testing.T) {
	s, _ := hideGroupServer(t, hideGroupIndexes())
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	recordHide(t, s, "otherpkg", "2.0-1", hideGroupOther)
	first := buildFrom(t, s, nil)

	recordHide(t, s, "curl", "8.5-1", hideGroupUpdates)
	calls := countMirrorFilter(t)
	warm := buildFrom(t, s, first)
	// The hide set is one digest in every key, so a change to it reaches
	// every index of every rewritten group.
	if *calls != hideGroupIndexCount {
		t.Errorf("a hide change refiltered %d indexes, want %d", *calls, hideGroupIndexCount)
	}
	if strings.Contains(string(warm.suites[hideGroupUpdates].packages["main"]["arm64"]), "Package: curl") {
		t.Error("the rebuild after a new hide still lists the newly hidden curl")
	}
	cold := buildFrom(t, s, nil)
	assertSameRewrite(t, cold, warm)
}

func TestMirrorRewriteUpstreamChangeRefiltersOnlyThatIndex(t *testing.T) {
	indexes := hideGroupIndexes()
	s, archive := hideGroupServer(t, indexes)
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	recordHide(t, s, "otherpkg", "2.0-1", hideGroupOther)
	first := buildFrom(t, s, nil)

	indexes[hideGroupUpdates]["arm64"] += hideStanza("jq", "1.7-1", "arm64")
	for rel, body := range hideGroupDists(hideGroupUpdates, indexes[hideGroupUpdates]) {
		archive.setObject(rel, body)
	}
	s.aptUpstreamIdx.Clear()

	calls := countMirrorFilter(t)
	warm := buildFrom(t, s, first)
	if *calls != 1 {
		t.Errorf("one changed upstream index refiltered %d indexes, want 1", *calls)
	}
	if !strings.Contains(string(warm.suites[hideGroupUpdates].packages["main"]["arm64"]), "Package: jq") {
		t.Error("the rebuild after an upstream change still serves the old index")
	}
	if !sameBacking(first.suites[hideGroupUpdates].packages["main"]["amd64"], warm.suites[hideGroupUpdates].packages["main"]["amd64"]) {
		t.Error("the unchanged index beside the changed one was rebuilt rather than reused")
	}
	cold := buildFrom(t, s, nil)
	assertSameRewrite(t, cold, warm)
}

// A path the Release publishes no SHA256 for names no particular bytes, so
// nothing recorded under it may stand in for what the archive serves now.
func TestMirrorIndexWithoutUpstreamDigestIsNeverReused(t *testing.T) {
	key := aptMirrorIndexKey{codename: hideGroupBase, path: "main/binary-amd64/Packages.gz", hides: "h"}
	pass := &aptMirrorPass{prev: map[aptMirrorIndexKey]aptMirrorIndex{key: {dropped: 1}}}
	if _, ok := pass.reuse(key); ok {
		t.Error("an index keyed with no upstream digest was reused")
	}
	key.upstreamSHA256 = strings.Repeat("a", 64)
	pass.prev[key] = aptMirrorIndex{dropped: 1}
	if _, ok := pass.reuse(key); !ok {
		t.Error("an index keyed with its upstream digest was not reused")
	}
}

func TestMirrorIndexCacheFollowsThePublishedSnapshot(t *testing.T) {
	s, archive := hideGroupServer(t, hideGroupIndexes())
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	recordHide(t, s, "otherpkg", "2.0-1", hideGroupOther)
	first := buildFrom(t, s, nil)

	// Every entry is a byte slice the snapshot serves, not a copy of one.
	for key, idx := range first.mirrorIndexes {
		served := false
		for _, byArch := range first.suites[key.codename].packages {
			for arch, body := range byArch {
				if sameBacking(body, idx.body.plain) && sameBacking(first.suites[key.codename].packagesGz["main"][arch], idx.body.gz) {
					served = true
				}
			}
		}
		if !served {
			t.Errorf("the cache entry for %s %s holds bytes the snapshot does not serve", key.codename, key.path)
		}
	}

	// A failed group is carried with its entries.
	rel := "dists/" + hideGroupUpdates + "/Release"
	release, _ := archive.object(rel)
	archive.removeObject(rel)
	s.aptUpstreamIdx.Clear()
	carried := buildFrom(t, s, first)
	if !carried.mirrorRewritten[hideGroupUpdates] {
		t.Fatal("the group whose upstream read failed was not carried")
	}
	if !maps.EqualFunc(first.mirrorIndexes, carried.mirrorIndexes, func(a, b aptMirrorIndex) bool {
		return sameBacking(a.body.plain, b.body.plain) && sameBacking(a.body.gz, b.body.gz)
	}) {
		t.Errorf("a carried group lost or copied its cache entries: %d before, %d after", len(first.mirrorIndexes), len(carried.mirrorIndexes))
	}
	archive.setObject(rel, release)
	s.aptUpstreamIdx.Clear()

	// A group whose last hide is removed goes back to proxy and drops its
	// entries; the other group keeps its own.
	if _, err := s.auditDB.DeleteAptMirrorHide(context.Background(), "otherpkg", "2.0-1"); err != nil {
		t.Fatalf("remove the hide: %v", err)
	}
	proxied := buildFrom(t, s, carried)
	if proxied.mirrorRewritten[hideGroupOther] {
		t.Fatal("the group with no hide left is still rewritten")
	}
	for key := range proxied.mirrorIndexes {
		if key.codename == hideGroupOther {
			t.Errorf("the proxied group still holds a cache entry for %s", key.path)
		}
	}
	if got := len(proxied.mirrorIndexes); got != hideGroupIndexCount-1 {
		t.Errorf("cache holds %d entries after the other group returned to proxy, want %d", got, hideGroupIndexCount-1)
	}
}

// BenchmarkAptMirrorRewrite measures one group's rewrite over a synthetic
// archive-sized index, from nothing and from the previous rebuild. The
// upstream reads are served from the metadata cache in both, so the figures
// are the filter, compression and hashing a reuse skips.
func BenchmarkAptMirrorRewrite(b *testing.B) {
	const stanzas = 50_000
	var body strings.Builder
	for i := range stanzas {
		body.WriteString(hideStanza(fmt.Sprintf("pkg%05d", i), "1.0-1", "amd64"))
	}
	s, _ := hideGroupServer(b, map[string]map[string]string{hideGroupBase: {"amd64": body.String()}})
	hidden := aptHidesByArchive{"": {"pkg00042": {"1.0-1": true}}}
	now := time.Now().UTC()
	ctx := context.Background()

	rewrite := func(b *testing.B) (map[string]*aptSuiteIndex, map[aptMirrorIndexKey]aptMirrorIndex) {
		out, reusable := s.aptMirrorRewrites(ctx, hidden, now, now.Add(aptValidity))
		if out[hideGroupBase] == nil {
			b.Fatal("the benchmark group was not rewritten")
		}
		return out, reusable
	}

	b.Run("cold", func(b *testing.B) {
		s.aptSnap.Store(nil)
		for b.Loop() {
			rewrite(b)
		}
	})
	b.Run("warm", func(b *testing.B) {
		s.aptSnap.Store(nil)
		out, reusable := rewrite(b)
		s.aptSnap.Store(&aptSnapshot{suites: out, mirrorRewritten: map[string]bool{hideGroupBase: true}, mirrorIndexes: reusable})
		for b.Loop() {
			rewrite(b)
		}
	})
}

func TestReviewE30WarmRebuildRetriesAgeEvidence(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase: {"amd64": hideStanza("htop", "1.0-1", "amd64")},
	})
	setAptAge(t, s, policy.ActionBlock)
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	now := time.Now().UTC().Truncate(time.Second)
	publish := func(body string, date time.Time) {
		for rel, data := range hideGroupDists(hideGroupBase, map[string]string{"amd64": body}) {
			if strings.HasSuffix(rel, "/Release") {
				data = "Date: " + date.Format(time.RFC1123Z) + "\n" + data
			}
			archive.setObject(rel, data)
		}
		s.aptUpstreamIdx.Clear()
	}
	publish(hideStanza("htop", "1.0-1", "amd64"), now.Add(-30*24*time.Hour))
	first := buildFrom(t, s, nil)

	db, err := sql.Open("sqlite", s.cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER review_e30_fail_observation BEFORE INSERT ON apt_observed_indexes
		BEGIN SELECT RAISE(FAIL, 'temporary observation write failure'); END`); err != nil {
		t.Fatal(err)
	}
	publish(hideStanza("htop", "1.0-1", "amd64")+hideStanza("nginx", "1.24-1", "amd64"), now.Add(-time.Hour))
	failedObservation := buildFrom(t, s, first)
	poolPath := "pool/main/n/nginx/nginx_1.24-1_amd64.deb"
	if _, why := s.aptMirrorStanzas(t.Context(), manifest.AptKey(poolPath)); why != "" {
		t.Fatal(why)
	}
	if _, ok, err := s.auditDB.GetAptVersionDate(t.Context(), s.aptArchiveCodenames(""), "nginx", "1.24-1"); err != nil || ok {
		t.Fatalf("failed-write setup: recorded=%v err=%v, want no date", ok, err)
	}
	if _, err := db.Exec("DROP TRIGGER review_e30_fail_observation"); err != nil {
		t.Fatal(err)
	}

	buildFrom(t, s, failedObservation)
	if result, ran := s.aptMirrorAge(t.Context(), manifest.AptKey(poolPath)); !ran || result.Action != policy.ActionBlock {
		t.Errorf("age gate after database recovery and warm rebuild: ran=%v action=%s reason=%s; want block for a one-hour-old version under the seven-day policy", ran, result.Action, result.Reason)
	}
}

// TestUsageDocumentsMirrorRewriteCost holds the bodega pkg hide section of
// docs/usage.md to the reuse aptMirrorRewrite performs: a hide change or an
// upstream index change refilters what it reaches, and every other rebuild
// reuses the previous filtered index.
func TestUsageDocumentsMirrorRewriteCost(t *testing.T) {
	raw, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatalf("read usage.md: %v", err)
	}
	_, after, ok := strings.Cut(string(raw), "\n### `bodega pkg hide")
	if !ok {
		t.Fatal("usage.md has no `bodega pkg hide` section")
	}
	section, _, _ := strings.Cut(after, "\n### ")
	for _, want := range []string{
		"**Rebuild cost while a hide is active.**",
		"The first rebuild after a hide is added or removed, or after the archive publishes a new `Packages`, refilters the indexes that change reaches",
		"only the changed index for an upstream change",
		"Every other rebuild, the hourly one and the one each profile write triggers, reuses the filtered `Packages`, its gzip and both digests from the previous rebuild",
		"An index is reused only while the `SHA256` its upstream `Release` publishes is unchanged.",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the `bodega pkg hide` section of usage.md does not say %q", want)
		}
	}
}

func TestUsageDocumentsWhenAnUnhiddenCodenameReturnsToProxy(t *testing.T) {
	raw, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatalf("read usage.md: %v", err)
	}
	_, after, ok := strings.Cut(string(raw), "\n### `bodega pkg hide")
	if !ok {
		t.Fatal("usage.md has no `bodega pkg hide` section")
	}
	section, _, _ := strings.Cut(after, "\n### ")
	for _, want := range []string{
		"A codename with no hidden stanza in it stays proxied byte-for-byte, unless bodega has already served a rewrite of it.",
		"returns it to the archive's own `InRelease` at the first rebuild where every codename in the group has an upstream `Release` dated later than the last rewrite bodega served for it",
		"apt treats a `Release` dated earlier than the one it holds as unchanged",
		"a host that read the rewrite would keep the filtered `Packages`",
		"once that rewrite's `Valid-Until` passed it would fail `apt update` on the codename",
		"A frozen pocket such as an Ubuntu release pocket (`resolute`) is dated once, at release, so its group stays bodega-signed after its first hide.",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the `bodega pkg hide` section of usage.md does not say %q", want)
		}
	}
}

func TestReviewE30DelayedReadKeepsSnapshotEvidence(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase: {"amd64": hideStanza("htop", "1.0-1", "amd64")},
	})
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	publish := func(body string, date time.Time) {
		for rel, data := range hideGroupDists(hideGroupBase, map[string]string{"amd64": body}) {
			if strings.HasSuffix(rel, "/Release") {
				data = "Date: " + date.Format(time.RFC1123Z) + "\n" + data
			}
			archive.setObject(rel, data)
		}
		s.aptUpstreamIdx.Clear()
	}
	publish(hideStanza("htop", "1.0-1", "amd64"), now.Add(-30*24*time.Hour))
	if _, err := s.aptUpstreamFetch(t.Context(), hideGroupBase, "main/binary-amd64/Packages.gz"); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", s.cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER review_e30_fail_observation BEFORE INSERT ON apt_observed_indexes
		BEGIN SELECT RAISE(FAIL, 'temporary observation write failure'); END`); err != nil {
		t.Fatal(err)
	}

	older := hideStanza("htop", "1.0-1", "amd64") + hideStanza("curl", "8.5-1", "amd64")
	publish(older, now.Add(-2*time.Hour))
	rel := "dists/" + hideGroupBase + "/main/binary-amd64/Packages.gz"
	started, unblock := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/ubuntu/"+rel && first.CompareAndSwap(false, true) {
			close(started)
			<-unblock
			_, _ = w.Write(gzipFixture(older))
			return
		}
		archive.ts.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	s.cfg.AptUpstreams[hideGroupBase] = []config.AptUpstream{{URL: upstream.URL + "/ubuntu"}}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unblock) }) }
	response := httptest.NewRecorder()
	done := make(chan struct{})
	handler := s.Handler()
	go func() {
		defer close(done)
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/apt/"+rel, nil))
	}()
	defer func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("delayed request did not exit")
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("client request did not reach upstream")
	}

	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	publish(hideStanza("htop", "1.0-1", "amd64")+hideStanza("nginx", "1.24-1", "amd64"), now.Add(-time.Hour))
	failedObservation := buildFrom(t, s, nil)
	poolPath := "pool/main/n/nginx/nginx_1.24-1_amd64.deb"
	if _, why := s.aptMirrorStanzas(t.Context(), manifest.AptKey(poolPath)); why != "" {
		t.Fatal(why)
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("delayed request did not complete")
	}
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), gzipFixture(older)) {
		t.Fatalf("delayed request = %d, want the older upstream Packages", response.Code)
	}
	if _, ok, err := s.auditDB.GetAptVersionDate(t.Context(), s.aptArchiveCodenames(""), "nginx", "1.24-1"); err != nil || ok {
		t.Fatalf("failed-write setup: recorded=%v err=%v, want no date", ok, err)
	}
	if _, err := db.Exec("DROP TRIGGER review_e30_fail_observation"); err != nil {
		t.Fatal(err)
	}

	buildFrom(t, s, failedObservation)
	if result, ran := s.aptMirrorAge(t.Context(), manifest.AptKey(poolPath)); !ran || result.Action != policy.ActionBlock {
		t.Errorf("age gate after delayed read, database recovery and warm rebuild: ran=%v action=%s reason=%s; want block for a one-hour-old version under the seven-day policy", ran, result.Action, result.Reason)
	}
}

// F120 requirement 4: Ubuntu and Debian both list htop 1.0-1 at one pool
// path. The hide the command records reaches both: each archive's pool refuses
// it, and each rebuilt index, the mirrored codenames' and a profile's filtered
// codename over resolute, is served without it at its own archive's root.
func TestMirroredHideReachesEveryArchiveListingTheVersion(t *testing.T) {
	s, _ := hideGroupServer(t, map[string]map[string]string{
		"resolute": {"amd64": hideStanza("htop", "1.0-1", "amd64") + hideStanza("nginx", "1.24-1", "amd64")},
		"trixie":   {"amd64": hideStanza("htop", "1.0-1", "amd64") + hideStanza("vim", "9.1-1", "amd64")},
	})
	s.cfg.AptArchives = map[string][]string{"ubuntu": {"resolute"}, "debian": {"trixie"}}
	aptProfileBindBase(t, s, "web", "resolute", audit.ExpansionBlock, "htop", "nginx")
	ctx := t.Context()
	codenames, err := s.locateMirroredAptVersion(ctx, "htop", "1.0-1")
	if err != nil || !slices.Equal(codenames, []string{"resolute", "trixie"}) {
		t.Fatalf("locate htop 1.0-1 = %v %v, want both archives' codenames", codenames, err)
	}
	if err := s.auditDB.InsertAptMirrorHide(ctx, audit.AptMirrorHide{
		Name: "htop", Version: "1.0-1", Codenames: codenames, HiddenBy: "tester",
	}); err != nil {
		t.Fatalf("record the hide: %v", err)
	}
	s.rebuildAptSnapshot(ctx)

	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(s.aptSign.Load().pub())))
	if err != nil {
		t.Fatalf("read bodega's published key: %v", err)
	}
	const htopDeb = "pool/main/h/htop/htop_1.0-1_amd64.deb"
	for archive, codename := range map[string]string{"ubuntu": "resolute", "debian": "trixie"} {
		root := "/apt/" + archive + "/"
		code, body := mirrorGet(t, s, root+"dists/"+codename+"/main/binary-amd64/Packages")
		if code != http.StatusOK || strings.Contains(string(body), "Package: htop") || !strings.Contains(string(body), "Package: ") {
			t.Errorf("GET %s's rewritten Packages at %s = %d, want 200 without htop:\n%s", codename, root, code, body)
		}
		code, inRelease := mirrorGet(t, s, root+"dists/"+codename+"/InRelease")
		block, _ := clearsign.Decode(inRelease)
		if code != http.StatusOK || block == nil {
			t.Fatalf("GET %s's InRelease at %s = %d, want bodega's clearsigned rewrite", codename, root, code)
		}
		if _, err := openpgp.CheckDetachedSignature(ring, bytesReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
			t.Errorf("%s's rewritten InRelease does not verify against bodega's key: %v", codename, err)
		}
		if got := aptReleaseDigests(mustParseRelease(t, block.Plaintext))["main/binary-amd64/Packages"]; got != sha256Hex(string(body)) {
			t.Errorf("%s's Release names %s for the Packages it serves, which hashes to %s", codename, got, sha256Hex(string(body)))
		}
		if code, body := mirrorGet(t, s, root+htopDeb); code != http.StatusForbidden {
			t.Errorf("GET %s%s = %d, want 403 for the hidden version:\n%s", root, htopDeb, code, body)
		}
	}
	code, filtered := mirrorGet(t, s, "/apt/ubuntu/dists/resolute-web/main/binary-amd64/Packages")
	if code != http.StatusOK || strings.Contains(string(filtered), "Package: htop") || !strings.Contains(string(filtered), "Package: nginx") {
		t.Errorf("GET the filtered resolute-web Packages at /apt/ubuntu/ = %d, want 200 carrying nginx without the hidden htop:\n%s", code, filtered)
	}
}

func TestReviewB201RewriteMustBeDurableBeforeItIsServed(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase: {"amd64": hideStanza("htop", "1.0-1", "amd64")},
	})
	rel := "dists/" + hideGroupBase + "/Release"
	original, _ := archive.object(rel)
	archive.setObject(rel, "Date: "+time.Now().UTC().Add(-200*24*time.Hour).Format(time.RFC1123Z)+"\n"+original)
	s.rebuildAptSnapshot(t.Context())
	db, err := sql.Open("sqlite", s.cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER review_b201_fail_date BEFORE INSERT ON apt_mirror_rewrite_dates
        BEGIN SELECT RAISE(FAIL, 'temporary rewrite date write failure'); END`); err != nil {
		t.Fatal(err)
	}
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	s.rebuildAptSnapshot(t.Context())
	published := s.aptMirrorRewritten(hideGroupBase)
	if published {
		date, err := aptReleaseDate(verifyBodegaInRelease(t, s, hideGroupBase))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := s.auditDB.AptMirrorRewriteDates(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !stored[hideGroupBase].Equal(date) {
			t.Errorf("served rewrite Date %s without its durable record (stored %s)", date, stored[hideGroupBase])
		}
	}
	if _, err := db.Exec("DROP TRIGGER review_b201_fail_date"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.auditDB.DeleteAptMirrorHide(t.Context(), "htop", "1.0-1"); err != nil {
		t.Fatal(err)
	}
	s.rebuildAptSnapshot(t.Context())
	if published && !s.aptMirrorRewritten(hideGroupBase) {
		t.Error("the first rebuild after write recovery and unhide returned the frozen codename to proxy although a client can hold its filtered rewrite")
	}
	restarted := restartMirrorServer(t, s)
	restarted.rebuildAptSnapshot(t.Context())
	if published && !restarted.aptMirrorRewritten(hideGroupBase) {
		t.Error("restart forgot the served rewrite and proxied the older upstream Release")
	}
}

// A rewrite is served only once its Date is on record. A rebuild whose write
// fails keeps serving the group's previous rewrite, whose Date is on record,
// and the record never moves back to an earlier Date.
func TestMirroredRewriteWhoseDateWriteFailsKeepsThePreviousRewrite(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase: {"amd64": hideStanza("htop", "1.0-1", "amd64")},
	})
	rel := "dists/" + hideGroupBase + "/Release"
	original, _ := archive.object(rel)
	archive.setObject(rel, "Date: "+time.Now().UTC().Add(-200*24*time.Hour).Format(time.RFC1123Z)+"\n"+original)
	ctx := t.Context()
	packages := "/apt/dists/" + hideGroupBase + "/main/binary-amd64/Packages"
	servedMatchesRecord := func(stage string) time.Time {
		t.Helper()
		if !s.aptMirrorRewritten(hideGroupBase) {
			t.Fatalf("%s: the codename is proxied", stage)
		}
		date, err := aptReleaseDate(verifyBodegaInRelease(t, s, hideGroupBase))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := s.auditDB.AptMirrorRewriteDates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !stored[hideGroupBase].Equal(date) {
			t.Fatalf("%s: served rewrite Date %s, recorded %s", stage, date, stored[hideGroupBase])
		}
		return date
	}

	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	s.rebuildAptSnapshot(ctx)
	hiddenDate := servedMatchesRecord("after the hide")

	db, err := sql.Open("sqlite", s.cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER fail_rewrite_date BEFORE INSERT ON apt_mirror_rewrite_dates
        BEGIN SELECT RAISE(FAIL, 'rewrite date write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.auditDB.DeleteAptMirrorHide(ctx, "htop", "1.0-1"); err != nil {
		t.Fatal(err)
	}
	s.rebuildAptSnapshot(ctx)
	if d := servedMatchesRecord("unhide with the write failing"); !d.Equal(hiddenDate) {
		t.Errorf("unhide with the write failing served a new rewrite dated %s", d)
	}
	if got := aptIndexVersions(t, s, packages, "htop"); len(got) != 0 {
		t.Errorf("the carried rewrite lists htop %v, want the previous rewrite's bytes", got)
	}

	if _, err := db.Exec("DROP TRIGGER fail_rewrite_date"); err != nil {
		t.Fatal(err)
	}
	s.rebuildAptSnapshot(ctx)
	servedMatchesRecord("after the write recovered")
	if got := aptIndexVersions(t, s, packages, "htop"); !slices.Equal(got, []string{"1.0-1"}) {
		t.Errorf("after the write recovered the rewrite lists htop %v, want 1.0-1", got)
	}

	recorded, err := s.auditDB.AptMirrorRewriteDates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.RecordAptMirrorRewriteDate(ctx, hideGroupBase, hiddenDate.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := s.auditDB.AptMirrorRewriteDates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !after[hideGroupBase].Equal(recorded[hideGroupBase]) {
		t.Errorf("an earlier write moved the record from %s to %s", recorded[hideGroupBase], after[hideGroupBase])
	}
}

func TestReviewB201OverlappingRebuildMustNotForgetServedRewrite(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase: {"amd64": hideStanza("htop", "1.0-1", "amd64")},
	})
	ctx := t.Context()
	rel := "dists/" + hideGroupBase + "/Release"
	original, _ := archive.object(rel)
	upstreamDate := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	archive.setObject(rel, "Date: "+upstreamDate.Format(time.RFC1123Z)+"\n"+original)
	s.cache.MetadataTTL = 0
	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	hidden := s.aptMirrorHidesFrom(ctx)
	seedDate := upstreamDate.Add(-24 * time.Hour)
	indexes, reusable := s.aptMirrorRewrites(ctx, hidden, seedDate, seedDate.Add(aptValidity))
	if indexes[hideGroupBase] == nil {
		t.Fatal("seed rewrite missing")
	}
	s.aptSnap.Store(&aptSnapshot{suites: indexes, hidden: hidden, mirrorRewritten: map[string]bool{hideGroupBase: true}, mirrorIndexes: reusable})

	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	first := func() { firstOnce.Do(func() { close(releaseFirst) }) }
	second := func() { secondOnce.Do(func() { close(releaseSecond) }) }
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/ubuntu/"+rel {
			switch requests.Add(1) {
			case 1:
				close(firstStarted)
				<-releaseFirst
			case 2:
				close(secondStarted)
				<-releaseSecond
			}
		}
		archive.ts.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	s.cfg.AptUpstreams[hideGroupBase] = []config.AptUpstream{{URL: upstream.URL + "/ubuntu"}}
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	secondLaunched := false
	defer func() {
		first()
		second()
		<-firstDone
		if secondLaunched {
			<-secondDone
		}
	}()
	go func() { s.rebuildAptSnapshot(ctx); close(firstDone) }()
	select {
	case <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("hidden rebuild did not reach upstream")
	}
	if _, err := s.auditDB.DeleteAptMirrorHide(ctx, "htop", "1.0-1"); err != nil {
		t.Fatal(err)
	}
	secondLaunched = true
	go func() { s.rebuildAptSnapshot(ctx); close(secondDone) }()
	// A serialized rebuild cannot reach upstream until the first completes.
	select {
	case <-secondStarted:
	case <-time.After(5 * time.Second):
	}
	first()
	<-firstDone
	servedDate, err := aptReleaseDate(verifyBodegaInRelease(t, s, hideGroupBase))
	if err != nil {
		t.Fatal(err)
	}
	if !servedDate.After(upstreamDate) {
		t.Fatalf("served %s must be newer than upstream %s", servedDate, upstreamDate)
	}
	second()
	<-secondDone
	dates, err := s.auditDB.AptMirrorRewriteDates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dates[hideGroupBase].Before(servedDate) {
		t.Errorf("overlapping unhide erased served rewrite Date %s (record now %s)", servedDate, dates[hideGroupBase])
	}
	if !s.aptMirrorRewritten(hideGroupBase) {
		t.Errorf("unhide proxied upstream Date %s although a client can hold filtered rewrite Date %s", upstreamDate, servedDate)
	}
	if s.aptMirrorRewritten(hideGroupBase) {
		got := aptIndexVersions(t, s, "/apt/dists/"+hideGroupBase+"/main/binary-amd64/Packages", "htop")
		if !slices.Equal(got, []string{"1.0-1"}) {
			t.Errorf("unhide kept filtered Packages: %v", got)
		}
	}
	restarted := restartMirrorServer(t, s)
	if !restarted.aptMirrorRewritten(hideGroupBase) {
		t.Error("restart forgot the concurrently served rewrite and proxied the older upstream Release")
	}
}

// ageAptUpstreamCache moves every cached upstream document back by d, which is
// what d of wall time does to it.
func ageAptUpstreamCache(s *Server, d time.Duration) {
	s.aptUpstreamIdx.Range(func(k, v any) bool {
		doc := *v.(*aptUpstreamDoc)
		doc.at = doc.at.Add(-d)
		doc.confirmed = doc.confirmed.Add(-d)
		s.aptUpstreamIdx.Store(k, &doc)
		return true
	})
}

// A held group is rewritten on every rebuild and reuses its filtered Packages
// while the Release digests are unchanged. When the hourly rebuild refetched
// an expired Release and reused the Packages without reading them, the cached
// Release became an hour younger than the cached Packages. The pocket's next
// republish then left a pass that had to read Packages (a new hide) fetching
// them fresh and checking them against the cached, older Release: the digest
// check failed, the hide never reached the index, and every profile codename
// over the same pocket failed with it, until that Release expired.
func TestReviewB201HeldRewriteKeepsReleaseAndPackagesFromOneUpstreamRead(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase:    {"amd64": hideStanza("htop", "1.0-1", "amd64")},
		hideGroupUpdates: {"amd64": hideStanza("curl", "8.5-1", "amd64")},
	})
	ctx := t.Context()
	rel := "dists/" + hideGroupBase + "/Release"
	undated, _ := archive.object(rel)
	archive.setObject(rel, "Date: "+time.Now().UTC().Add(-200*24*time.Hour).Format(time.RFC1123Z)+"\n"+undated)

	recordHide(t, s, "htop", "1.0-1", hideGroupBase)
	s.rebuildAptSnapshot(ctx)
	if _, err := s.auditDB.DeleteAptMirrorHide(ctx, "htop", "1.0-1"); err != nil {
		t.Fatalf("remove the hide: %v", err)
	}
	s.rebuildAptSnapshot(ctx)
	if !s.aptMirrorRewritten(hideGroupUpdates) {
		t.Fatal("the unhidden group is not held")
	}

	ageAptUpstreamCache(s, 2*s.cache.MetadataTTL)
	s.rebuildAptSnapshot(ctx)

	for rest, body := range hideGroupDists(hideGroupUpdates, map[string]string{
		"amd64": hideStanza("curl", "8.5-1", "amd64") + hideStanza("curl", "8.5-2", "amd64"),
	}) {
		archive.setObject(rest, body)
	}
	recordHide(t, s, "curl", "8.5-1", hideGroupUpdates)
	s.rebuildAptSnapshot(ctx)

	packages := "/apt/dists/" + hideGroupUpdates + "/main/binary-amd64/Packages"
	if got := aptIndexVersions(t, s, packages, "curl"); slices.Contains(got, "8.5-1") {
		t.Errorf("the hide's rebuild did not reach the index: %s lists curl %v, want 8.5-1 dropped", hideGroupUpdates, got)
	}
}

// The two other ways a path-keyed cache pairs a Packages with a Release from
// another sync: a cached Packages outliving the Release it matched, and a
// Release cached before the archive finished publishing the Packages beside
// it. Both have to recover at the next rebuild, not when metadata_ttl runs
// out.
func TestReviewB201UpstreamCachePairsPackagesWithTheReleaseInHand(t *testing.T) {
	s, archive := hideGroupServer(t, map[string]map[string]string{
		hideGroupBase:    {"amd64": hideStanza("htop", "1.0-1", "amd64")},
		hideGroupUpdates: {"amd64": hideStanza("curl", "8.5-1", "amd64")},
	})
	ctx := t.Context()
	packages := "/apt/dists/" + hideGroupUpdates + "/main/binary-amd64/Packages"
	publish := func(withRelease bool, stanzas string) {
		t.Helper()
		for rest, body := range hideGroupDists(hideGroupUpdates, map[string]string{"amd64": stanzas}) {
			if withRelease || !strings.HasSuffix(rest, "/Release") {
				archive.setObject(rest, body)
			}
		}
	}
	age := func(rest string) {
		t.Helper()
		key := hideGroupUpdates + "/" + rest
		v, ok := s.aptUpstreamIdx.Load(key)
		if !ok {
			t.Fatalf("%s is not cached", key)
		}
		doc := *v.(*aptUpstreamDoc)
		doc.confirmed = doc.confirmed.Add(-2 * s.cache.MetadataTTL)
		s.aptUpstreamIdx.Store(key, &doc)
	}

	recordHide(t, s, "curl", "8.5-1", hideGroupUpdates)
	s.rebuildAptSnapshot(ctx)

	publish(true, hideStanza("curl", "8.5-1", "amd64")+hideStanza("curl", "8.5-2", "amd64"))
	age("Release")
	s.rebuildAptSnapshot(ctx)
	if got := aptIndexVersions(t, s, packages, "curl"); !slices.Equal(got, []string{"8.5-2"}) {
		t.Errorf("after the archive republished, the rewrite lists curl %v, want 8.5-2: the cached Packages from the earlier sync stood in for the one the new Release names", got)
	}

	publish(false, hideStanza("curl", "8.5-1", "amd64")+hideStanza("curl", "8.5-2", "amd64")+hideStanza("curl", "8.5-3", "amd64"))
	age("main/binary-amd64/Packages.gz")
	recordHide(t, s, "curl", "8.5-2", hideGroupUpdates)
	s.rebuildAptSnapshot(ctx)
	publish(true, hideStanza("curl", "8.5-1", "amd64")+hideStanza("curl", "8.5-2", "amd64")+hideStanza("curl", "8.5-3", "amd64"))
	s.rebuildAptSnapshot(ctx)
	if got := aptIndexVersions(t, s, packages, "curl"); !slices.Equal(got, []string{"8.5-3"}) {
		t.Errorf("once the archive finished publishing, the rewrite lists curl %v, want 8.5-3: the Release cached mid-sync kept failing the digest check", got)
	}
}

func TestAuditB201CacheRevalidationKeepsNamedPoolAuthority(t *testing.T) {
	a := newFixtureArchive(t, map[string]string{})
	b := newFixtureArchive(t, map[string]string{})
	if a.URL() > b.URL() {
		a, b = b, a
	}
	decoy, home := a, b
	const decoyBody = "\x21<arch>\nnginx from the other archive root"
	now := time.Now().UTC().Truncate(time.Second)
	original := hideGroupDists("named", map[string]string{"amd64": fixturePackages(fixtureDeb, fixtureDebBody)})
	original["dists/named/Release"] = "Date: " + now.Add(-48*time.Hour).Format(time.RFC1123Z) + "\n" + original["dists/named/Release"]
	for rest, body := range original {
		home.setObject(rest, body)
	}
	home.setObject(fixtureDeb, fixtureDebBody)
	for rest, body := range hideGroupDists("other", map[string]string{"amd64": fixturePackages(fallbackDeb, fallbackDebBody)}) {
		decoy.setObject(rest, body)
	}
	decoy.setObject(fixtureDeb, decoyBody)
	s := mirrorServer(t)
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"named": {{URL: home.URL()}}, "other": {{URL: decoy.URL()}},
	}
	ctx := t.Context()
	names := s.cfg.MirroredAptCodenames()
	before := s.buildAptPoolIndex(ctx, names)
	if len(before.failed) != 0 {
		t.Fatal(before.failed)
	}
	if _, ok := before.byKey[manifest.AptKey(fixtureDeb)]; !ok {
		t.Fatal("initial paragraph missing")
	}

	for rest, body := range hideGroupDists("named", map[string]string{"amd64": ""}) {
		if strings.HasSuffix(rest, "/Release") {
			body = "Date: " + now.Add(-24*time.Hour).Format(time.RFC1123Z) + "\n" + body
		}
		home.setObject(rest, body)
	}
	for _, rest := range []string{"Release", "main/binary-amd64/Packages.gz"} {
		if code, _ := mirrorGet(t, s, "/apt/dists/named/"+rest); code != http.StatusOK {
			t.Fatalf("read temporary %s: %d", rest, code)
		}
	}
	original["dists/named/Release"] = strings.Replace(original["dists/named/Release"], now.Add(-48*time.Hour).Format(time.RFC1123Z), now.Format(time.RFC1123Z), 1)
	for rest, body := range original {
		home.setObject(rest, body)
	}
	ageAptUpstreamCache(s, 2*s.cache.MetadataTTL)
	after := s.buildAptPoolIndexFrom(ctx, names, before)
	if len(after.failed) != 0 {
		t.Fatal(after.failed)
	}
	s.aptPoolIdx.idx = after
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusOK || string(body) != fixtureDebBody {
		t.Errorf("GET restored named path = %d %q, want 200 and %q from its declaring root", code, body, fixtureDebBody)
	}
	if n := decoy.count(fixtureDeb); n != 0 {
		t.Errorf("unnamed root served restored named path %d times; want 0", n)
	}
}
