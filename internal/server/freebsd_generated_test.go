package server

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgsign"
	"github.com/ravinald/bodega/internal/storage"
)

// The two package layouts F19 measured against pkg.freebsd.org, which a
// generated repository has to reproduce because the client reads repopath and
// nothing else: a hashed path under All/, and a package at the repository
// root. Neither is derivable from a name and a version.
const (
	genHashedPath = "All/Hashed/widget-1.2.0~2$abcdefgh.pkg"
	genRootPath   = "tool-3.1.pkg"
)

// generatedRepo seeds a repository whose catalogue bodega builds: an entry
// carrying no URL, and package objects in the store. No root files, because
// those are the generator's to produce.
func generatedRepo(t *testing.T, s *Server, repo string, packages map[string]string) {
	t.Helper()
	addVersion(t, s, manifest.TypeFreeBSD, repo, manifest.VersionEntry{Version: freeBSDABI, Generated: true})
	keyed := make(map[string]string, len(packages))
	for repoPath, body := range packages {
		keyed[manifest.FreeBSDKey(freeBSDABI, repo, repoPath)] = body
	}
	seed(t, s, manifest.TypeFreeBSD, keyed)
}

// pkgArchive builds a .pkg the way pkg does: a compressed tarball whose first
// member is the compact manifest. Built here rather than fixtured, because
// what is under test is that the generator reads a package's own metadata
// through rather than re-deriving it from a filename.
func pkgArchive(t *testing.T, compact string) string {
	t.Helper()
	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatalf("open a zstd writer: %v", err)
	}
	tw := tar.NewWriter(zw)
	for _, m := range []struct{ name, body string }{
		{"+COMPACT_MANIFEST", compact},
		{"/usr/local/bin/widget", "not really a binary"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write the %s header: %v", m.name, err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatalf("write %s: %v", m.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close the tar stream: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close the zstd stream: %v", err)
	}
	return out.String()
}

// installPkgKey writes a throwaway key where the server searches, before the
// server is built: the key is loaded once at construction, so a key written
// afterwards is one the running process never sees.
func installPkgKey(t *testing.T, kt pkgsign.KeyType) *pkgsign.KeyRing {
	t.Helper()
	kr, err := pkgsign.Generate(kt)
	if err != nil {
		t.Fatalf("generate a %s key: %v", kt, err)
	}
	path := filepath.Join(t.TempDir(), pkgsign.KeyFileName)
	if err := kr.WritePrivate(path); err != nil {
		t.Fatalf("write the key: %v", err)
	}
	was := pkgsign.SystemKeyPath
	pkgsign.SystemKeyPath = path
	t.Cleanup(func() { pkgsign.SystemKeyPath = was })
	return kr
}

// archiveMembers reads a generated archive back, in the order it packs them.
func archiveMembers(t *testing.T, body string) map[string][]byte {
	t.Helper()
	dec, err := zstd.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("open a zstd reader over the archive: %v", err)
	}
	defer dec.Close()
	out := map[string][]byte{}
	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read the archive: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read the %s member: %v", hdr.Name, err)
		}
		out[hdr.Name] = data
	}
	return out
}

// R1, R2: a catalogue built from the objects the repository holds, with
// repopath equal to the key each object is stored under.
//
// The repopath assertion is the one that costs an outage rather than a test
// failure. F19's serving path reads it as the only authority on where an
// object lives, so a record whose repopath disagrees with the key resolves an
// install and then 404s, after `pkg update` has already reported success.
func TestFreeBSDGeneratedCatalogNamesEveryStoredPackage(t *testing.T) {
	s := hostedServer(t)
	widget := pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0","comment":"a widget","desc":"a widget, at length","arch":"freebsd:14:x86:64","prefix":"/usr/local","flatsize":4096,"licenselogic":"single"}`)
	tool := pkgArchive(t, `{"name":"tool","origin":"misc/tool","version":"3.1","comment":"a tool","desc":"a tool, at length","arch":"freebsd:14:x86:64","prefix":"/usr/local","flatsize":8192,"licenselogic":"single"}`)
	generatedRepo(t, s, "house", map[string]string{genHashedPath: widget, genRootPath: tool})

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the generated catalogue = %d, want 200: %s", status, body)
	}
	doc := archiveMembers(t, body)[freeBSDCatalogDoc]
	if doc == nil {
		t.Fatalf("the archive carries no %s member", freeBSDCatalogDoc)
	}

	records := packagesiteRecords(t, doc)
	if len(records) != 2 {
		t.Fatalf("the catalogue holds %d records, want one per stored package", len(records))
	}
	byPath := map[string]map[string]any{}
	for _, rec := range records {
		path, _ := rec["repopath"].(string)
		byPath[path] = rec
	}
	for repoPath, object := range map[string]string{genHashedPath: widget, genRootPath: tool} {
		rec, ok := byPath[repoPath]
		if !ok {
			t.Fatalf("no record names repopath %q; the catalogue names %v", repoPath, keysOf(byPath))
			continue
		}
		// The four fields only the repository knows, against the object the
		// key holds. A digest taken over anything but the whole .pkg is one
		// the client computes differently and refuses.
		sum := sha256.Sum256([]byte(object))
		if got := rec["sum"]; got != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: sum = %v, want the sha256 of the stored object %s", repoPath, got, hex.EncodeToString(sum[:]))
		}
		if got, want := rec["pkgsize"], float64(len(object)); got != want {
			t.Errorf("%s: pkgsize = %v, want %v", repoPath, got, want)
		}
		if got := rec["path"]; got != repoPath {
			t.Errorf("%s: path = %v, want the repopath", repoPath, got)
		}
		// Carried through from the package's own +COMPACT_MANIFEST rather
		// than re-derived: a field pkg reads and bodega has never heard of
		// has to survive the same way.
		if rec["origin"] == nil || rec["comment"] == nil || rec["flatsize"] == nil {
			t.Errorf("%s: the record dropped fields the package's compact manifest carried: %v", repoPath, rec)
		}
	}
}

// R2 again, from the client's side: every repopath the generated catalogue
// names resolves to the bytes the object holds. A catalogue whose records
// point at nothing passes every assertion above and still 404s at install
// time.
func TestFreeBSDGeneratedRepoPathsResolve(t *testing.T) {
	s := hostedServer(t)
	widget := pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0"}`)
	generatedRepo(t, s, "house", map[string]string{genHashedPath: widget})

	_, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	for _, rec := range packagesiteRecords(t, archiveMembers(t, body)[freeBSDCatalogDoc]) {
		repoPath, _ := rec["repopath"].(string)
		status, got := getStatusAndBody(t, s, freeBSDURL("house", repoPath))
		if status != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: the catalogue names an object no request reaches", repoPath, status)
		}
		if got != widget {
			t.Errorf("%s served %d bytes, want the stored object's %d", repoPath, len(got), len(widget))
		}
	}
}

// R4, R8: three members, named for the document they sign, with the signature
// verifying against the public key beside it. Upstream's archives carry
// exactly this shape — F19 measured a 256-byte .sig, a 451-byte .pub and the
// document — and there is no .sig on the wire for a client to find.
func TestFreeBSDGeneratedArchiveCarriesThreeMembers(t *testing.T) {
	for _, kt := range []pkgsign.KeyType{pkgsign.KeyRSA, pkgsign.KeyEd25519} {
		t.Run(string(kt), func(t *testing.T) {
			installPkgKey(t, kt)
			s := hostedServer(t)
			generatedRepo(t, s, "house", map[string]string{
				genHashedPath: pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0"}`),
			})

			for file, doc := range map[string]string{
				manifest.FreeBSDCatalogFile: freeBSDCatalogDoc,
				manifest.FreeBSDDataFile:    freeBSDDataDoc,
			} {
				status, body := getStatusAndBody(t, s, freeBSDURL("house", file))
				if status != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200: %s", file, status, body)
				}
				members := archiveMembers(t, body)
				if len(members) != 3 {
					t.Fatalf("%s carries %d members (%v), want %s plus its .sig and .pub", file, len(members), keysOfBytes(members), doc)
				}
				pub, sig := members[doc+".pub"], members[doc+".sig"]
				if pub == nil || sig == nil {
					t.Fatalf("%s carries %v, want %s.sig and %s.pub", file, keysOfBytes(members), doc, doc)
				}
				if err := pkgsign.Verify(pub, members[doc], sig); err != nil {
					t.Errorf("%s: the signature does not verify against the public key the archive ships: %v", file, err)
				}
			}
		})
	}
}

// R8: no key configured still serves, with the document alone. pkg's own
// signature_type defaults to NONE, so unsigned is a configuration rather than
// a degraded state — and a repository that refused to serve without a key
// would take an operator's first `pkg update` down for a signature they never
// asked for.
func TestFreeBSDGeneratedServesUnsignedWithNoKey(t *testing.T) {
	// Point the search at a directory with nothing in it, so a key installed
	// on the host running the tests cannot make this pass or fail.
	was := pkgsign.SystemKeyPath
	pkgsign.SystemKeyPath = filepath.Join(t.TempDir(), pkgsign.KeyFileName)
	t.Cleanup(func() { pkgsign.SystemKeyPath = was })

	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath: pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0"}`),
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the catalogue = %d, want 200 unsigned: %s", status, body)
	}
	members := archiveMembers(t, body)
	if len(members) != 1 || members[freeBSDCatalogDoc] == nil {
		t.Fatalf("the unsigned archive carries %v, want %s alone", keysOfBytes(members), freeBSDCatalogDoc)
	}
}

// R1: the data member is one JSON object with all three keys, where
// packagesite.yaml is one record per line. pkg reads all three, and a document
// carrying only the one a given release happens to need breaks on the next.
func TestFreeBSDGeneratedDataDocumentShape(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath: pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0"}`),
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDDataFile))
	if status != http.StatusOK {
		t.Fatalf("GET data.pkg = %d, want 200: %s", status, body)
	}
	var doc struct {
		Groups          []json.RawMessage `json:"groups"`
		Packages        []json.RawMessage `json:"packages"`
		ExpiredPackages []json.RawMessage `json:"expired_packages"`
	}
	raw := archiveMembers(t, body)[freeBSDDataDoc]
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the data member is not one JSON object: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Errorf("the data member names %d packages, want 1", len(doc.Packages))
	}
	if doc.Groups == nil || doc.ExpiredPackages == nil {
		t.Errorf("the data member omits groups or expired_packages: %s", raw)
	}
	for _, key := range []string{`"groups"`, `"packages"`, `"expired_packages"`} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Errorf("the data member carries no %s key: %s", key, raw)
		}
	}
}

// The generated meta.conf names the members the archives beside it actually
// carry. pkg reads it first on every update and takes the member names from
// it, so a meta.conf naming a document the archive spells differently is a
// repository that fetches and then finds nothing.
func TestFreeBSDGeneratedMetaNamesTheMembersItShips(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath: pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0"}`),
	})

	status, meta := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDMetaFile))
	if status != http.StatusOK {
		t.Fatalf("GET meta.conf = %d, want 200: %s", status, meta)
	}
	for _, want := range []string{
		`manifests = "` + freeBSDCatalogDoc + `"`,
		`data = "` + freeBSDDataDoc + `"`,
		`packing_format = "tzst"`,
	} {
		if !strings.Contains(meta, want) {
			t.Errorf("meta.conf does not carry %s:\n%s", want, meta)
		}
	}
}

// R5: a mirrored repository is served from its stored bytes and never
// regenerated. The failure this prevents is silent at the point it happens:
// the client's signature_type is FINGERPRINTS against FreeBSD's key, and a
// regenerated catalogue fails that check naming the signature rather than the
// configuration.
func TestFreeBSDMirroredIsNeverRegenerated(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI,
		URL:     "https://pkg.freebsd.org/" + freeBSDABI + "/latest",
	})
	seed(t, s, manifest.TypeFreeBSD, map[string]string{
		manifest.FreeBSDKey(freeBSDABI, "latest", manifest.FreeBSDCatalogFile): freeBSDCatalogBytes,
		manifest.FreeBSDKey(freeBSDABI, "latest", genHashedPath):               pkgArchive(t, `{"name":"widget","version":"1.2.0"}`),
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("latest", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the mirrored catalogue = %d, want 200: %s", status, body)
	}
	if body != freeBSDCatalogBytes {
		t.Errorf("a mirrored catalogue was regenerated: served %q, want the stored bytes %q", body, freeBSDCatalogBytes)
	}
}

// R5, the other half: an entry claiming both is refused rather than resolved.
// Guessing either way publishes a repository whose signature contradicts the
// one its client was configured for. The refusal quotes the url, and a url
// can carry upstream credentials, so it reaches the log and never the body
// of a route that takes no token.
func TestFreeBSDEntryClaimingBothIsRefused(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "muddle", manifest.VersionEntry{
		Version:   freeBSDABI,
		URL:       "https://audit-user:audit-secret@private-upstream.example/" + freeBSDABI + "/latest",
		Generated: true,
	})

	logged := captureErrorLog(s)
	status, body := getStatusAndBody(t, s, freeBSDURL("muddle", manifest.FreeBSDCatalogFile))
	if status != http.StatusInternalServerError {
		t.Fatalf("GET a contradictory entry's catalogue = %d, want 500: %s", status, body)
	}
	if leaked := withheldFrom(body, "audit-secret", "audit-user", "private-upstream.example"); leaked != "" {
		t.Errorf("the anonymous 500 carries %q from the manifest url: %s", leaked, body)
	}
	for _, want := range []string{"generated", "private-upstream.example"} {
		if !strings.Contains(logged(), want) {
			t.Errorf("the logged refusal does not name %q, so the operator has to guess which field to change: %s", want, logged())
		}
	}
}

// A package object the generator cannot read stops the whole build. Refused
// rather than skipped: a catalogue silently missing one package answers
// `pkg install` with the message a typo produces, and nothing anywhere names
// the object that could not be read.
func TestFreeBSDGeneratedRefusesAnUnreadablePackage(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath: pkgArchive(t, `{"name":"widget","version":"1.2.0"}`),
		genRootPath:   "not an archive at all",
	})

	logged := captureErrorLog(s)
	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusInternalServerError {
		t.Fatalf("GET the catalogue over an unreadable package = %d, want 500: %s", status, body)
	}
	if !strings.Contains(logged(), genRootPath) {
		t.Errorf("the logged refusal does not name the object that could not be read: %s", logged())
	}
}

// packagesiteRecords parses the catalogue document: newline-delimited compact
// JSON, one record per package, despite the .yaml the member is named for.
func packagesiteRecords(t *testing.T, doc []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for i, line := range strings.Split(strings.TrimRight(string(doc), "\n"), "\n") {
		if line == "" {
			t.Fatalf("line %d of the catalogue is empty; it is newline-delimited JSON with one record per line", i+1)
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d of the catalogue is not a JSON record (%v): %s", i+1, err, line)
		}
		out = append(out, rec)
	}
	return out
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfBytes(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// R2, as a guarantee rather than as a case. Every path the catalogue
// publishes resolves through the route that will be asked for it, including
// the shapes a real build tree produces: a dotted version, a "~" and a "$"
// from a hashed name, a plus in a port name, a deep directory.
//
// The predicate is shared with the route for this reason, so the interesting
// half is not that these pass but that a path failing it never reaches a
// record at all — TestFreeBSDGeneratedRefusesAnUnroutableObject is that side.
func TestFreeBSDEveryPublishedRepoPathResolves(t *testing.T) {
	s := hostedServer(t)
	objects := map[string]string{}
	// One package per path, because five names for one package is the alias
	// case and the catalogue publishes it once: see
	// TestFreeBSDGeneratedNamesAnAliasedPackageOnce.
	for name, rel := range map[string]string{
		"py311-foo": "All/Hashed/py311-foo-1.2.0_3~2$abcdefgh.pkg",
		"gcc13":     "All/gcc13-13.2.0_1.pkg",
		"libx++":    "libx++-2.0.pkg",
		"kernel":    "base/a/b/c/kernel-14.0.pkg",
		"zsh":       "All/zsh-5.9_3.pkg",
	} {
		objects[rel] = pkgArchive(t, `{"name":"`+name+`","version":"1","origin":"misc/`+name+`"}`)
	}
	generatedRepo(t, s, "house", objects)

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the generated catalogue = %d, want 200: %s", status, body)
	}
	records := packagesiteRecords(t, archiveMembers(t, body)[freeBSDCatalogDoc])
	if len(records) != len(objects) {
		t.Fatalf("the catalogue holds %d records, want %d", len(records), len(objects))
	}
	for _, rec := range records {
		repoPath, _ := rec["repopath"].(string)
		if status, got := getStatusAndBody(t, s, freeBSDURL("house", repoPath)); status != http.StatusOK {
			t.Errorf("GET %q = %d, want 200: the catalogue publishes a path its own route refuses (%s)", repoPath, status, got)
		}
	}
}

// R2: an object the route could never serve fails the build by name rather
// than being published or skipped.
//
// A backslash is a legal byte in a Unix filename and every object store
// accepts one, so an operator can put such a file in the build tree and the
// walk can store it. The route refuses it — a request for it is a 400 before
// any key is composed — so a record naming it resolves an install onto a path
// no client can fetch. Skipping it instead would answer `pkg install` with
// the message a typo produces, with nothing naming the file.
func TestFreeBSDGeneratedRefusesAnUnroutableObject(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		"All/widget-1.0.pkg": pkgArchive(t, `{"name":"widget","version":"1.0"}`),
		`All/bad\name.pkg`:   pkgArchive(t, `{"name":"bad","version":"1.0"}`),
	})
	logged := captureErrorLog(s)
	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status == http.StatusOK {
		t.Fatalf("the catalogue built over an object no request can reach; members %v", keysOfBytes(archiveMembers(t, body)))
	}
	if !strings.Contains(logged(), `bad\name.pkg`) {
		t.Errorf("the logged refusal does not name the object that caused it: %q", logged())
	}
}

// R3, and the project's fail-closed posture: a key the operator installed and
// bodega cannot use never degrades the repository to unsigned.
//
// An absent key is a configuration and serves unsigned. A key that is present
// and rejected is not that: the operator installed one, so every client is
// configured with signature_type: FINGERPRINTS and has no unsigned fallback.
// Serving them an unsigned catalogue trades a 500 naming the key file for a
// `pkg update` failure naming the signature and nothing else.
func TestFreeBSDGeneratedRefusesWhenTheInstalledKeyIsUnusable(t *testing.T) {
	t.Setenv(pkgsign.CredentialsEnv, "")
	kr := installPkgKey(t, pkgsign.KeyRSA)
	if err := os.Chmod(kr.Path(), 0o644); err != nil {
		t.Fatalf("chmod the key: %v", err)
	}
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{"widget-1.0.pkg": pkgArchive(t, `{"name":"widget","version":"1.0"}`)})

	logged := captureErrorLog(s)
	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status == http.StatusOK {
		t.Fatalf("an installed but rejected key served an unsigned catalogue; members %v", keysOfBytes(archiveMembers(t, body)))
	}
	if !strings.Contains(logged(), kr.Path()) {
		t.Errorf("the logged refusal does not name the key file an operator has to fix: %q", logged())
	}
	// This route takes no token, so the body is what an anonymous poller
	// reads: the key's path and the mode that exposes it would tell them
	// which file on this host holds a readable private key.
	if leaked := withheldFrom(body, kr.Path(), filepath.Dir(kr.Path()), "0644", "-rw-r--r--"); leaked != "" {
		t.Errorf("the 500 body hands an anonymous caller %q: %q", leaked, body)
	}

	// Fixing the key and reloading recovers, because a refusal that outlived
	// its cause would need a restart to clear and nothing would say so.
	if err := os.Chmod(kr.Path(), 0o600); err != nil {
		t.Fatalf("chmod the key back: %v", err)
	}
	s.loadPkgSigner()
	status, body = getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("after the key was fixed and reloaded, GET = %d, want 200: %s", status, body)
	}
	if members := keysOfBytes(archiveMembers(t, body)); len(members) != 3 {
		t.Errorf("the recovered catalogue carries %v, want the signed three", members)
	}
}

// Removing the key is how an operator asks for an unsigned repository, and it
// has to clear a refusal the same key caused. A stored failure that outlived
// the file would refuse every request citing a path that is no longer there.
func TestFreeBSDGeneratedUnsignedAfterAnUnusableKeyIsRemoved(t *testing.T) {
	t.Setenv(pkgsign.CredentialsEnv, "")
	kr := installPkgKey(t, pkgsign.KeyRSA)
	if err := os.Chmod(kr.Path(), 0o644); err != nil {
		t.Fatalf("chmod the key: %v", err)
	}
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{"widget-1.0.pkg": pkgArchive(t, `{"name":"widget","version":"1.0"}`)})
	if status, _ := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile)); status == http.StatusOK {
		t.Fatal("an installed but rejected key served a catalogue")
	}
	if err := os.Remove(kr.Path()); err != nil {
		t.Fatalf("remove the key: %v", err)
	}
	s.loadPkgSigner()
	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("with no key installed anywhere, GET = %d, want an unsigned 200: %s", status, body)
	}
	if members := keysOfBytes(archiveMembers(t, body)); len(members) != 1 {
		t.Errorf("the unsigned catalogue carries %v, want the document alone", members)
	}
}

// A reload never takes signing away. The key already in memory keeps signing
// and the fault goes to the journal, because a client configured with
// FINGERPRINTS fails `pkg update` outright on an unsigned repository.
func TestFreeBSDGeneratedKeepsSigningWhenAReloadFails(t *testing.T) {
	t.Setenv(pkgsign.CredentialsEnv, "")
	kr := installPkgKey(t, pkgsign.KeyRSA)
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{"widget-1.0.pkg": pkgArchive(t, `{"name":"widget","version":"1.0"}`)})
	if status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile)); status != http.StatusOK {
		t.Fatalf("GET with a good key = %d, want 200: %s", status, body)
	}
	if err := os.Chmod(kr.Path(), 0o644); err != nil {
		t.Fatalf("chmod the key: %v", err)
	}
	s.loadPkgSigner()
	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("a failed reload took signing away: GET = %d: %s", status, body)
	}
	if members := keysOfBytes(archiveMembers(t, body)); len(members) != 3 {
		t.Errorf("the catalogue carries %v after a failed reload, want the signed three", members)
	}
}

// R4: the .pub member carries the same signer frame as the .sig for eddsa,
// and neither does for rsa.
//
// pkg records the signer per member and keeps the last one it reads, so an
// unframed .pub behind a framed .sig resets the choice to rsa and hands an
// Ed25519 key to the OpenSSL verifier. The client reports "error reading
// public key" and names no member, which is a morning spent on the key.
func TestFreeBSDGeneratedFramesThePubMemberForItsSigner(t *testing.T) {
	const frame = "$PKGSIGN:eddsa$"
	for _, tc := range []struct {
		kt     pkgsign.KeyType
		framed bool
	}{{pkgsign.KeyRSA, false}, {pkgsign.KeyEd25519, true}} {
		t.Run(string(tc.kt), func(t *testing.T) {
			t.Setenv(pkgsign.CredentialsEnv, "")
			kr := installPkgKey(t, tc.kt)
			s := hostedServer(t)
			generatedRepo(t, s, "house", map[string]string{"widget-1.0.pkg": pkgArchive(t, `{"name":"widget","version":"1.0"}`)})

			status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
			if status != http.StatusOK {
				t.Fatalf("GET = %d, want 200: %s", status, body)
			}
			members := archiveMembers(t, body)
			sig, pub := members[freeBSDCatalogDoc+".sig"], members[freeBSDCatalogDoc+".pub"]
			if sig == nil || pub == nil {
				t.Fatalf("the archive carries %v, want the signed three", keysOfBytes(members))
			}
			if got := bytes.HasPrefix(sig, []byte(frame)); got != tc.framed {
				t.Errorf(".sig framed = %v, want %v", got, tc.framed)
			}
			if got := bytes.HasPrefix(pub, []byte(frame)); got != tc.framed {
				t.Errorf(".pub framed = %v, want %v: pkg keeps the last signer it reads, so the two members must agree", got, tc.framed)
			}
			// The fingerprint is taken over the key a client sees after the
			// frame is stripped, which is what it installs out of band.
			bare := bytes.TrimPrefix(pub, []byte(frame))
			sum := sha256.Sum256(bare)
			if got := hex.EncodeToString(sum[:]); got != kr.Fingerprint() {
				t.Errorf("the published .pub hashes to %s, and the operator installs %s", got, kr.Fingerprint())
			}
		})
	}
}

// R1: one package stored under two keys is one record.
//
// This is what a poudriere tree looks like after an rsync that resolved its
// symlinks, and what a store looks like after an upload that followed them.
// pkg creates packages_digest UNIQUE over the records it loaded, so a
// catalogue naming the package twice fails `pkg update` with
// "UNIQUE constraint failed: packages.manifestdigest" and the client keeps the
// catalogue it had — for the whole repository, not for the duplicate.
func TestFreeBSDGeneratedNamesAnAliasedPackageOnce(t *testing.T) {
	s := hostedServer(t)
	widget := pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0","comment":"a widget","arch":"freebsd:14:x86:64"}`)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath:          widget,
		"All/widget-1.2.0.pkg": widget,
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the generated catalogue = %d, want 200: %s", status, body)
	}
	doc := archiveMembers(t, body)[freeBSDCatalogDoc]
	records := packagesiteRecords(t, doc)
	if len(records) != 1 {
		t.Fatalf("the catalogue holds %d records over one package stored twice: %v", len(records), records)
	}
	// The smallest key, so the record does not move when an alias is added or
	// removed beside it.
	if got := records[0]["repopath"]; got != genHashedPath {
		t.Errorf("repopath = %v, want the lexicographically first key %q", got, genHashedPath)
	}
	repoPath, _ := records[0]["repopath"].(string)
	if status, served := getStatusAndBody(t, s, freeBSDURL("house", repoPath)); status != http.StatusOK || served != widget {
		t.Errorf("GET %s = %d over %d bytes, want 200 and the package's %d", repoPath, status, len(served), len(widget))
	}

	// data.pkg describes the same set, because a client resolves out of one
	// and downloads out of the other.
	_, dataBody := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDDataFile))
	var data struct {
		Packages []map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(archiveMembers(t, dataBody)[freeBSDDataDoc], &data); err != nil {
		t.Fatalf("read the data document: %v", err)
	}
	if len(data.Packages) != 1 {
		t.Errorf("the data document holds %d packages over one package stored twice", len(data.Packages))
	}
}

// The document a client refetches is tied to the packages, not to the paths.
// A build that changed bytes when an alias appeared would have every client in
// a fleet refetch the catalogue over a package nobody added.
func TestFreeBSDGeneratedCatalogIsUnchangedByAnAlias(t *testing.T) {
	s := hostedServer(t)
	widget := pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64"}`)
	generatedRepo(t, s, "house", map[string]string{genHashedPath: widget})
	_, before := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))

	seed(t, s, manifest.TypeFreeBSD, map[string]string{
		manifest.FreeBSDKey(freeBSDABI, "house", "All/widget-1.2.0.pkg"): widget,
	})
	status, after := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the catalogue after the alias landed = %d: %s", status, after)
	}
	if !bytes.Equal(archiveMembers(t, before)[freeBSDCatalogDoc], archiveMembers(t, after)[freeBSDCatalogDoc]) {
		t.Error("adding a second name for a package changed the catalogue document, so every client refetches it")
	}
}

// R1: two builds of one package are refused, with both objects named.
//
// They differ in bytes, so neither stands for the other, and they are one
// package to pkg's index: description, size and stored path reach none of
// pkg_checksum_generate's field set. Publishing either would be choosing which
// package the operator meant; publishing both fails every client's update.
func TestFreeBSDGeneratedRefusesTwoBuildsOfOnePackage(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath: pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","desc":"built on Tuesday","flatsize":4096}`),
		"All/widget-1.2.0.pkg": pkgArchive(t,
			`{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","desc":"built on Wednesday","flatsize":8192}`),
	})

	logged := captureErrorLog(s)
	status, _ := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusInternalServerError {
		t.Fatalf("GET the catalogue = %d, want 500: two builds of one package were published as a catalogue pkg refuses whole", status)
	}
	for _, want := range []string{genHashedPath, "All/widget-1.2.0.pkg", "widget-1.2.0"} {
		if !strings.Contains(logged(), want) {
			t.Errorf("the logged refusal does not name %q, so nobody can tell which two objects to look at: %s", want, logged())
		}
	}
}

// The other half of the refusal above: everything pkg indexes apart is
// published. A rule that collapsed by name would drop a version, and one that
// collapsed by name and version would drop an options build — both of which
// pkg loads without complaint, because version and options are in the digest.
func TestFreeBSDGeneratedPublishesEveryPackagePkgIndexesApart(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		"All/widget-1.0.pkg":      pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.0","arch":"freebsd:14:x86:64"}`),
		"All/widget-1.1.pkg":      pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.1","arch":"freebsd:14:x86:64"}`),
		"All/widget-1.2-docs.pkg": pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2","arch":"freebsd:14:x86:64","options":{"DOCS":"on"}}`),
		"All/widget-1.2-bare.pkg": pkgArchive(t, `{"name":"widget","origin":"misc/widget","version":"1.2","arch":"freebsd:14:x86:64","options":{"DOCS":"off"}}`),
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusOK {
		t.Fatalf("GET the generated catalogue = %d, want 200: %s", status, body)
	}
	records := packagesiteRecords(t, archiveMembers(t, body)[freeBSDCatalogDoc])
	if len(records) != 4 {
		t.Fatalf("the catalogue holds %d records over four packages pkg gives four digests: %v", len(records), records)
	}
}

// The field set pkg hashes into manifestdigest, from both sides: what it
// covers has to separate two records, and what it does not has to fold them
// together. Getting the second half wrong is the expensive one — it publishes
// a pair the client refuses — so it is asserted field by field.
func TestFreeBSDPkgIdentityFollowsPkgsFieldSet(t *testing.T) {
	base := `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64",
	          "options":{"DOCS":"on"},"deps":{"libfoo":{"origin":"devel/libfoo","version":"2.0"}},
	          "shlibs_required":["libfoo.so.2"],"users":["widget"],"groups":["widget"],
	          "provides":["widget"],"requires":["libfoo"],"vital":false}`

	identity := func(t *testing.T, doc string) string {
		t.Helper()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(doc), &fields); err != nil {
			t.Fatalf("read the manifest: %v", err)
		}
		id, err := freeBSDPkgIdentity(fields)
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		return id
	}
	want := identity(t, base)

	// Outside the digest: pkg loads two records differing only in these under
	// one manifestdigest, so bodega has to treat them as one package or
	// publish a pair that takes the repository down.
	for name, doc := range map[string]string{
		"comment":    `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","comment":"a widget"}`,
		"desc":       `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","desc":"at length"}`,
		"maintainer": `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","maintainer":"someone@example.invalid"}`,
		"flatsize":   `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","flatsize":99}`,
		"pkgsize":    `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","pkgsize":99}`,
		"repopath":   `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","repopath":"All/elsewhere.pkg"}`,
		"sum":        `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","sum":"0000"}`,
		"abi":        `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64","abi":"FreeBSD:15:amd64"}`,
	} {
		bare := `{"name":"widget","origin":"misc/widget","version":"1.2.0","arch":"freebsd:14:x86:64"}`
		if identity(t, doc) != identity(t, bare) {
			t.Errorf("%s changed the identity, though pkg_checksum_generate never reads it", name)
		}
	}

	// Inside the digest: each of these is a package pkg indexes on its own,
	// and folding two of them together would drop one from the catalogue.
	for name, doc := range map[string]string{
		"name":            strings.Replace(base, `"name":"widget"`, `"name":"gadget"`, 1),
		"origin":          strings.Replace(base, `"origin":"misc/widget"`, `"origin":"misc/gadget"`, 1),
		"version":         strings.Replace(base, `"version":"1.2.0"`, `"version":"1.2.1"`, 1),
		"arch":            strings.Replace(base, `"arch":"freebsd:14:x86:64"`, `"arch":"freebsd:14:aarch64"`, 1),
		"vital":           strings.Replace(base, `"vital":false`, `"vital":true`, 1),
		"options":         strings.Replace(base, `"DOCS":"on"`, `"DOCS":"off"`, 1),
		"deps":            strings.Replace(base, `"origin":"devel/libfoo"`, `"origin":"devel/libbar"`, 1),
		"shlibs_required": strings.Replace(base, `"libfoo.so.2"`, `"libfoo.so.3"`, 1),
		"users":           strings.Replace(base, `"users":["widget"]`, `"users":["gadget"]`, 1),
		"groups":          strings.Replace(base, `"groups":["widget"]`, `"groups":["gadget"]`, 1),
		"provides":        strings.Replace(base, `"provides":["widget"]`, `"provides":["gadget"]`, 1),
		"requires":        strings.Replace(base, `"requires":["libfoo"]`, `"requires":["libbar"]`, 1),
	} {
		if identity(t, doc) == want {
			t.Errorf("%s left the identity alone, though pkg hashes it: two packages would be published as one", name)
		}
	}
}

// A manifest field of a type pkg could not read fails the build with the
// object named. Read past instead, the field would be treated as absent, and
// two packages that differ only there would look like one and be collapsed —
// which is a package silently missing from the catalogue.
func TestFreeBSDGeneratedRefusesAManifestItCannotIdentify(t *testing.T) {
	s := hostedServer(t)
	generatedRepo(t, s, "house", map[string]string{
		genHashedPath: pkgArchive(t, `{"name":"widget","version":"1.2.0","options":["DOCS"]}`),
	})

	logged := captureErrorLog(s)
	status, _ := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusInternalServerError {
		t.Fatalf("GET the catalogue = %d, want 500 over a manifest whose options is a list", status)
	}
	if !strings.Contains(logged(), genHashedPath) || !strings.Contains(logged(), "options") {
		t.Errorf("the logged refusal names neither the object nor the field: %s", logged())
	}
}

// captureErrorLog points the server's logger at a buffer and returns the
// "error" attribute of every record written since, decoded. Decoded rather than
// matched against the handler's output, because a text or JSON handler escapes
// a backslash in a key and the substring a test looks for is then not there.
func captureErrorLog(s *Server) func() string {
	var buf syncBuffer
	s.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	return func() string {
		var out []string
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var rec struct {
				Error string `json:"error"`
			}
			if json.Unmarshal([]byte(line), &rec) == nil && rec.Error != "" {
				out = append(out, rec.Error)
			}
		}
		return strings.Join(out, "\n")
	}
}

// withheldFrom returns the first of secrets that body carries, or "" when it
// carries none. The tests assert on the absence of what leaked rather than on
// the presence of the replacement text, so rewording that text breaks nothing.
func withheldFrom(body string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" && strings.Contains(body, sec) {
			return sec
		}
	}
	return ""
}

// failingStore answers a generated repository's listing, or the read of one
// of its packages, with the error text a real backend produces for that
// failure. The text is built rather than provoked: a local store refuses a
// listing only over a permission a test running as root does not have, and
// an s3 store refuses only against a live bucket.
type failingStore struct {
	storage.ObjectStore
	listErr, getErr error
}

func (f failingStore) List(ctx context.Context, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.ObjectStore.List(ctx, prefix)
}

func (f failingStore) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.ObjectStore.GetStream(ctx, key)
}

// A storage failure under a generated catalogue is a 500 whose body names
// neither the storage root nor the bucket. The route takes no token, and the
// wrapped error is a *PathError under storage_path for a local backend
// (storage/local.go) or s3://<bucket>/<prefix> for an s3 one (s3/client.go):
// where the packages live, handed to whoever polls. The log keeps all of it.
func TestFreeBSDGeneratedRefusalWithholdsTheStorageLocation(t *testing.T) {
	const (
		root   = "/srv/bodega-private-root"
		bucket = "bodega-private-bucket"
	)
	prefix := manifest.FreeBSDRepoPrefix(freeBSDABI, "house")
	pkgKey := prefix + genRootPath
	denied := errors.New("AccessDenied: Access Denied")

	cases := []struct {
		name    string
		store   func(storage.ObjectStore) failingStore
		secrets []string
	}{
		{"local listing", func(m storage.ObjectStore) failingStore {
			return failingStore{ObjectStore: m, listErr: &fs.PathError{Op: "open", Path: filepath.Join(root, filepath.FromSlash(prefix)), Err: fs.ErrPermission}}
		}, []string{root}},
		{"s3 listing", func(m storage.ObjectStore) failingStore {
			return failingStore{ObjectStore: m, listErr: fmt.Errorf("list objects s3://%s/%s: %w", bucket, prefix, denied)}
		}, []string{bucket, "s3://"}},
		{"local package read", func(m storage.ObjectStore) failingStore {
			return failingStore{ObjectStore: m, getErr: &fs.PathError{Op: "open", Path: filepath.Join(root, filepath.FromSlash(pkgKey)), Err: fs.ErrPermission}}
		}, []string{root}},
		{"s3 package read", func(m storage.ObjectStore) failingStore {
			return failingStore{ObjectStore: m, getErr: fmt.Errorf("get object stream s3://%s/%s: %w", bucket, pkgKey, denied)}
		}, []string{bucket, "s3://"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := hostedServer(t)
			generatedRepo(t, s, "house", map[string]string{genRootPath: pkgArchive(t, `{"name":"tool","version":"3.1"}`)})
			logged := captureErrorLog(s)
			store := tc.store(s.typeStore(manifest.TypeFreeBSD))

			path := freeBSDURL("house", manifest.FreeBSDCatalogFile)
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			s.serveFreeBSDGenerated(rec, req, store, freeBSDABI, "house", manifest.FreeBSDCatalogFile,
				manifest.FreeBSDKey(freeBSDABI, "house", manifest.FreeBSDCatalogFile))

			body := rec.Body.String()
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("GET the catalogue over a failing store = %d, want 500: %s", rec.Code, body)
			}
			if leaked := withheldFrom(body, tc.secrets...); leaked != "" {
				t.Errorf("the 500 body hands an anonymous caller %q: %q", leaked, body)
			}
			for _, want := range tc.secrets {
				if !strings.Contains(logged(), want) {
					t.Errorf("the log lost %q, which the operator needs to find the failing backend: %s", want, logged())
				}
			}
		})
	}
}
