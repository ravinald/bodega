package server

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgsign"
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
// one its client was configured for.
func TestFreeBSDEntryClaimingBothIsRefused(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "muddle", manifest.VersionEntry{
		Version:   freeBSDABI,
		URL:       "https://pkg.freebsd.org/" + freeBSDABI + "/latest",
		Generated: true,
	})

	status, body := getStatusAndBody(t, s, freeBSDURL("muddle", manifest.FreeBSDCatalogFile))
	if status != http.StatusInternalServerError {
		t.Fatalf("GET a contradictory entry's catalogue = %d, want 500: %s", status, body)
	}
	for _, want := range []string{"generated", "url"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not name %q, so the operator has to guess which field to change: %s", want, body)
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

	status, body := getStatusAndBody(t, s, freeBSDURL("house", manifest.FreeBSDCatalogFile))
	if status != http.StatusInternalServerError {
		t.Fatalf("GET the catalogue over an unreadable package = %d, want 500: %s", status, body)
	}
	if !strings.Contains(body, genRootPath) {
		t.Errorf("the refusal does not name the object that could not be read: %s", body)
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
