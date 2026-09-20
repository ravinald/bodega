package builder

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/ravinald/bodega/internal/manifest"
)

// The two layouts observed on pkg.freebsd.org, copied out of the real
// catalogues rather than composed here. Both hold the "~" and "$" a hashed
// filename carries; they differ in the prefix, and base_latest/ spells its
// with a leading "." that no HTTP client ever sends.
const (
	fbABI        = "FreeBSD:14:amd64"
	fbHashedPath = "All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg"
	fbDotPath    = "./Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg"
	// What fbDotPath resolves to: the path the key is built from, the local
	// tree writes, and a client requests.
	fbDotResolved = "Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg"
	// A package at the repository root, with no directory segment at all. It
	// is the layout the numbered contract names beside All/Hashed/, and the
	// one a path-joining bug reaches first: filepath.Dir of it is the
	// repository directory itself.
	fbRootPath = "root.pkg"
)

// fbCatalog builds a packagesite archive in the shape upstream publishes it:
// the signature and the public key as members alongside packagesite.yaml,
// with one newline-delimited JSON record per repopath.
//
// The two key members are here because the mirror must walk past them without
// touching them. They are the reason a byte-exact copy of this archive carries
// FreeBSD's own attestation, and a reader that assumed packagesite.yaml came
// first would work against a fixture and fail against the real thing.
func fbCatalog(t *testing.T, pack string, repoPaths ...string) []byte {
	t.Helper()
	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	write := func(name, content string) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	write("packagesite.yaml.sig", strings.Repeat("s", 256))
	write("packagesite.yaml.pub", strings.Repeat("p", 451))

	var yaml strings.Builder
	for i, rel := range repoPaths {
		yaml.WriteString(`{"name":"pkg` + string(rune('a'+i)) + `","origin":"misc/pkg","version":"1.0","repopath":"` + rel + `"}` + "\n")
	}
	write("packagesite.yaml", yaml.String())
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}

	return fbPack(t, pack, body.Bytes())
}

// fbPack compresses body the way packing_format names.
func fbPack(t *testing.T, pack string, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	switch pack {
	case "tzst":
		enc, err := zstd.NewWriter(&out)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		if _, err := enc.Write(body); err != nil {
			t.Fatalf("zstd write: %v", err)
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("zstd close: %v", err)
		}
	case "tgz":
		gz := gzip.NewWriter(&out)
		if _, err := gz.Write(body); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	default:
		t.Fatalf("fbPack has no packing for %q", pack)
	}
	return out.Bytes()
}

// fbData builds a data.pkg in the shape upstream publishes it: data.sig,
// data.pub and a data member holding one JSON document.
//
// The member names are data's own rather than packagesite's, which is what a
// read-only fetch of FreeBSD:14:amd64/base_latest/data.pkg reports, and the
// document is one object with a packages array rather than a record per line.
// A reader written against packagesite's spelling walks past every member of
// this and reports the archive as empty.
func fbData(t *testing.T, pack string, repoPaths ...string) []byte {
	t.Helper()
	var records []string
	for i, rel := range repoPaths {
		records = append(records, `{"name":"data`+string(rune('a'+i))+`","origin":"misc/pkg","version":"1.0","repopath":"`+rel+`"}`)
	}
	doc := `{"groups":[],"expired_packages":[],"packages":[` + strings.Join(records, ",") + `]}`

	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	for _, m := range []struct{ name, content string }{
		{"data.sig", strings.Repeat("s", 256)},
		{"data.pub", strings.Repeat("p", 451)},
		{"data", doc},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.content))}); err != nil {
			t.Fatalf("tar header %s: %v", m.name, err)
		}
		if _, err := tw.Write([]byte(m.content)); err != nil {
			t.Fatalf("tar body %s: %v", m.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return fbPack(t, pack, body.Bytes())
}

// R2. packing_format is read out of meta.conf, and an absent key is reported
// rather than defaulted: a repository that does not say is one this mirror
// has not been taught to read, and guessing produces a tar error naming
// neither the repository nor the key.
func TestPackingFormatIsReadFromMetaConf(t *testing.T) {
	upstream := "version = 2;\npacking_format = \"tzst\";\nmanifests = \"packagesite.yaml\";\n" +
		"filesite = \"filesite.yaml\";\nmanifests_archive = \"packagesite\";\nfilesite_archive = \"filesite\";\n"
	got, err := freeBSDPackingFormat([]byte(upstream))
	if err != nil {
		t.Fatalf("read packing_format: %v", err)
	}
	if got != "tzst" {
		t.Errorf("packing_format = %q, want tzst", got)
	}

	if _, err := freeBSDPackingFormat([]byte("version = 2;\n")); err == nil {
		t.Error("a meta.conf naming no packing_format was accepted")
	} else if !strings.Contains(err.Error(), "packing_format") {
		t.Errorf("the refusal does not name the missing key: %v", err)
	}

	// A comment must not be read as a value; UCL takes "#" to end of line.
	commented := "# packing_format = \"txz\";\npacking_format = \"tzst\";\n"
	if got, err := freeBSDPackingFormat([]byte(commented)); err != nil || got != "tzst" {
		t.Errorf("commented meta.conf = (%q, %v), want tzst", got, err)
	}
}

// R2. txz is refused by name rather than left to fail inside the tar reader.
// Go ships no xz decoder, so the honest answer is that the catalogue cannot
// be enumerated — with the format and the way out in the message, because the
// next step is the operator's.
func TestPackingFormatRefusesXZByName(t *testing.T) {
	_, _, err := freeBSDDecompressor("txz", strings.NewReader(""))
	if err == nil {
		t.Fatal("txz was accepted; nothing here can decode it")
	}
	for _, want := range []string{"txz", "xz", "proxy mode"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// R4. The object set comes from each record's repopath and from nothing else.
// Both observed layouts are covered because neither is derivable from a name
// and a version, and All/ answers 403 upstream so there is no listing to fall
// back on.
func TestCatalogRepoPathsCoverBothLayouts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		paths []string
		want  []string
	}{
		{"latest", []string{fbHashedPath, "All/Hashed/other-1.0~2$abcdef.pkg"}, []string{fbHashedPath, "All/Hashed/other-1.0~2$abcdef.pkg"}},
		{"base_latest", []string{fbDotPath}, []string{fbDotResolved}},
		{"repository root", []string{fbRootPath}, []string{fbRootPath}},
		{"both at once", []string{fbHashedPath, fbDotPath}, []string{fbHashedPath, fbDotResolved}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), manifest.FreeBSDCatalogFile)
			if err := os.WriteFile(archive, fbCatalog(t, "tzst", tc.paths...), 0o644); err != nil {
				t.Fatalf("write catalogue: %v", err)
			}
			got, err := freeBSDCatalogRepoPaths(archive, "tzst")
			if err != nil {
				t.Fatalf("read the catalogue: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("repopaths = %v, want %v", got, tc.want)
			}
		})
	}
}

// The catalogue decides both the URL fetched and the local path written, so a
// record that resolves outside the repository would have the mirror overwrite
// a file on the build host and then serve it back under a signed catalogue.
func TestCatalogRefusesARepoPathThatEscapesTheRepository(t *testing.T) {
	for _, bad := range []string{
		"../../../../etc/ssh/sshd_config",
		"/etc/passwd",
		"All/../../escape.pkg",
		`All\Hashed\x.pkg`,
		"All//double.pkg",
		"./",
	} {
		archive := filepath.Join(t.TempDir(), manifest.FreeBSDCatalogFile)
		if err := os.WriteFile(archive, fbCatalog(t, "tzst", bad), 0o644); err != nil {
			t.Fatalf("write catalogue: %v", err)
		}
		if _, err := freeBSDCatalogRepoPaths(archive, "tzst"); err == nil {
			t.Errorf("repopath %q was accepted", bad)
		}
	}

	// A record with no repopath is refused rather than skipped: nothing else
	// in the document says where that package's bytes are, so dropping it
	// silently publishes a catalogue naming an object no mirror ever fetched.
	archive := filepath.Join(t.TempDir(), manifest.FreeBSDCatalogFile)
	if err := os.WriteFile(archive, fbCatalog(t, "tzst", ""), 0o644); err != nil {
		t.Fatalf("write catalogue: %v", err)
	}
	if _, err := freeBSDCatalogRepoPaths(archive, "tzst"); err == nil {
		t.Error("a record with no repopath was accepted")
	}
}

// fbUpstream serves one repository and records the order it was asked for
// things in.
type fbUpstream struct {
	*httptest.Server
	asked  []string
	check  func(path string)
	record func(r *http.Request)
}

func newFBUpstream(t *testing.T, bodies map[string]string) *fbUpstream {
	t.Helper()
	up := &fbUpstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		up.asked = append(up.asked, rel)
		if up.record != nil {
			up.record(r)
		}
		if up.check != nil {
			up.check(rel)
		}
		body, ok := bodies[rel]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	return up
}

// fbFixture wires one hosted repository entry against an upstream and returns
// the builder config and the manifest store.
func fbFixture(t *testing.T, upstreamURL string) (*Config, *manifest.Store) {
	t.Helper()
	cfg := &Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir(), Stdout: io.Discard}
	store := manifest.NewLocalStore(cfg.ManifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: fbABI,
		URL:     upstreamURL,
	}); err != nil {
		t.Fatalf("seed the manifest: %v", err)
	}
	return cfg, store
}

// R3, R5. The mirror copies the catalogue archive byte for byte, and it does
// not place it until every object the catalogue names is on disk. The check
// runs inside the upstream handler rather than after the fetch, because the
// failure this guards is a window rather than an end state.
func TestMirrorPlacesTheCatalogueOnlyAfterEveryObject(t *testing.T) {
	catalog := string(fbCatalog(t, "tzst", fbHashedPath, fbDotPath, fbRootPath))
	data := string(fbData(t, "tzst", fbHashedPath, fbDotPath, fbRootPath))
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "packing_format = \"tzst\";\ndata = \"data\";\n",
		manifest.FreeBSDCatalogFile: catalog,
		manifest.FreeBSDDataFile:    data,
		fbHashedPath:                "latest layout package",
		fbDotResolved:               "base_latest layout package",
		fbRootPath:                  "repository-root layout package",
	})
	cfg, store := fbFixture(t, up.URL)
	repoDir := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest")

	up.check = func(rel string) {
		if rel == manifest.FreeBSDMetaFile || rel == manifest.FreeBSDCatalogFile || rel == manifest.FreeBSDDataFile {
			return
		}
		// An object is being fetched, so the catalogue must not be readable
		// in the tree yet: a client reading it here would resolve this very
		// package and 404 on it.
		if _, err := os.Stat(filepath.Join(repoDir, manifest.FreeBSDCatalogFile)); err == nil {
			t.Errorf("the catalogue was in place while %s was still being fetched", rel)
		}
	}

	sum := FetchFreeBSD(cfg, store, "")
	if sum.Failures != 0 {
		t.Fatalf("mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}

	for rel, want := range map[string]string{
		manifest.FreeBSDCatalogFile: catalog,
		manifest.FreeBSDDataFile:    data,
		fbHashedPath:                "latest layout package",
		fbDotResolved:               "base_latest layout package",
		fbRootPath:                  "repository-root layout package",
	} {
		got, err := os.ReadFile(filepath.Join(repoDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read the mirrored %s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s mirrored %d bytes, want the %d upstream served unchanged", rel, len(got), len(want))
		}
	}
}

// R2 again, and the falsifiable half of it: the archive is named .pkg and
// packed with gzip, and meta.conf says so. A mirror that inferred the codec
// from the extension would decode this as zstd and fail.
func TestMirrorReadsPackingFormatRatherThanTheExtension(t *testing.T) {
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "version = 2;\npacking_format = \"tgz\";\n",
		manifest.FreeBSDCatalogFile: string(fbCatalog(t, "tgz", fbHashedPath)),
		manifest.FreeBSDDataFile:    string(fbData(t, "tgz", fbHashedPath)),
		fbHashedPath:                "latest layout package",
	})
	cfg, store := fbFixture(t, up.URL)

	sum := FetchFreeBSD(cfg, store, "")
	if sum.Failures != 0 {
		t.Fatalf("mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}
	mirroredObject := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest", filepath.FromSlash(fbHashedPath))
	if _, err := os.Stat(mirroredObject); err != nil {
		t.Errorf("the gzip-packed catalogue named no objects, so the codec came from the extension: %v", err)
	}
}

// R5, the upload half. UploadPaths writes the slice in order, so this
// ordering is what keeps a published catalogue from naming an object the
// backend does not hold.
func TestFreeBSDArtifactPathsPutTheCatalogueLast(t *testing.T) {
	catalog := string(fbCatalog(t, "tzst", fbHashedPath, fbDotPath))
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "packing_format = \"tzst\";\n",
		manifest.FreeBSDCatalogFile: catalog,
		manifest.FreeBSDDataFile:    string(fbData(t, "tzst", fbHashedPath, fbDotPath)),
		fbHashedPath:                "latest layout package",
		fbDotResolved:               "base_latest layout package",
	})
	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}

	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	if err != nil {
		t.Fatalf("enumerate the upload set: %v", err)
	}
	defer release()
	if len(paths) != 5 {
		t.Fatalf("upload set = %d paths, want 5 (three root files, two packages): %+v", len(paths), paths)
	}
	var lastObject, firstRoot = -1, len(paths)
	for i, ap := range paths {
		if slices.Contains(manifest.FreeBSDCatalogFiles, filepath.Base(ap.Local)) {
			firstRoot = min(firstRoot, i)
			continue
		}
		lastObject = max(lastObject, i)
	}
	if lastObject > firstRoot {
		t.Errorf("a repository-root file uploads at %d, before an object at %d; a catalogue that lands first names objects the backend does not hold", firstRoot, lastObject)
	}
	if got := filepath.Base(paths[len(paths)-1].Local); got != manifest.FreeBSDCatalogFile {
		t.Errorf("the last upload is %q, want %s: it is the file that commits the snapshot", got, manifest.FreeBSDCatalogFile)
	}

	// R1: the key is the repository path verbatim, colons, "~" and "$" and
	// all. A scheme that encoded any of them would show up here.
	wantKey := manifest.FreeBSDKey(fbABI, "latest", fbHashedPath)
	if !slices.ContainsFunc(paths, func(ap ArtifactPath) bool { return ap.ObjectKey == wantKey }) {
		var keys []string
		for _, ap := range paths {
			keys = append(keys, ap.ObjectKey)
		}
		t.Errorf("no upload is keyed %q; got %v", wantKey, keys)
	}
}

// A proxy-mode entry holds no snapshot, so the mirror places nothing for it
// and contacts nobody. Running it anyway would fetch a whole repository
// nothing serves out of the store.
func TestMirrorSkipsAProxyModeEntry(t *testing.T) {
	up := newFBUpstream(t, map[string]string{})
	cfg := &Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir(), Stdout: io.Discard}
	store := manifest.NewLocalStore(cfg.ManifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: fbABI,
		URL:     up.URL,
		Mode:    manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed the manifest: %v", err)
	}

	if sum := FetchFreeBSD(cfg, store, ""); sum.Total != 0 || sum.Failures != 0 {
		t.Errorf("mirror ran for a proxy-mode entry: total %d, failures %d", sum.Total, sum.Failures)
	}
	if len(up.asked) != 0 {
		t.Errorf("upstream was asked for %v on a proxy-mode entry", up.asked)
	}
	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	if err != nil {
		t.Fatalf("enumerate the upload set: %v", err)
	}
	defer release()
	if len(paths) != 0 {
		t.Error("a proxy-mode entry produced upload paths")
	}
}

// An entry with no URL is refused with the URL it should have been given,
// because the alternative is a fetch against "" that reports a malformed
// request and names neither the entry nor the field.
func TestMirrorNamesTheMissingURL(t *testing.T) {
	cfg := &Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir(), Stdout: io.Discard}
	store := manifest.NewLocalStore(cfg.ManifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeFreeBSD, "latest",
		manifest.VersionEntry{Version: fbABI}); err != nil {
		t.Fatalf("seed the manifest: %v", err)
	}

	sum := FetchFreeBSD(cfg, store, "")
	if sum.Failures != 1 {
		t.Fatalf("failures = %d, want 1", sum.Failures)
	}
	err := sum.Results[0].Err
	for _, want := range []string{"latest", fbABI, "url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// R5. A cut transfer leaves nothing behind that a later run can mistake for a
// mirrored object.
//
// The failure this guards shipped: downloadURL creates and truncates the
// destination before copying and leaves the stub there when the body ends
// early, and the next ordinary fetch skips an existing file. One short read
// was enough to publish a catalogue over 3 bytes of a 100-byte package, with
// no failure reported on the run that did it.
func TestMirrorRefetchesAnObjectAfterACutTransfer(t *testing.T) {
	catalog := string(fbCatalog(t, "tzst", fbHashedPath))
	data := string(fbData(t, "tzst", fbHashedPath))
	whole := strings.Repeat("x", 100)

	var objectRequests int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case manifest.FreeBSDMetaFile:
			_, _ = io.WriteString(w, "packing_format = \"tzst\";\n")
		case manifest.FreeBSDCatalogFile:
			_, _ = io.WriteString(w, catalog)
		case manifest.FreeBSDDataFile:
			_, _ = io.WriteString(w, data)
		case fbHashedPath:
			objectRequests++
			if objectRequests == 1 {
				// A declared length the body does not reach: what a reset
				// connection or a truncated origin object looks like on the
				// wire, and the only signal that the copy is short.
				w.Header().Set("Content-Length", "100")
				_, _ = io.WriteString(w, "cut")
				return
			}
			_, _ = io.WriteString(w, whole)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	cfg, store := fbFixture(t, up.URL)
	repoDir := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest")
	object := filepath.Join(repoDir, filepath.FromSlash(fbHashedPath))

	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 1 {
		t.Fatalf("a cut transfer reported %d failures, want 1: %+v", sum.Failures, sum.Results)
	}
	if _, err := os.Stat(object); err == nil {
		t.Error("the cut transfer left a file where the package belongs; the next run skips it")
	}
	if CheckFreeBSDStage(cfg, "latest", manifest.VersionEntry{Version: fbABI}).Fetched {
		t.Error("the catalogue was placed over a failed object fetch")
	}

	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the retry reported %d failures: %+v", sum.Failures, sum.Results)
	}
	if objectRequests != 2 {
		t.Errorf("the package was requested %d times, want 2: the retry skipped it", objectRequests)
	}
	body, err := os.ReadFile(object)
	if err != nil {
		t.Fatalf("read the mirrored package: %v", err)
	}
	if string(body) != whole {
		t.Errorf("the mirrored package holds %d bytes, want the %d upstream served", len(body), len(whole))
	}
	if !CheckFreeBSDStage(cfg, "latest", manifest.VersionEntry{Version: fbABI}).Fetched {
		t.Error("the retry fetched every object and still placed no catalogue")
	}

	entries, err := os.ReadDir(filepath.Dir(object))
	if err != nil {
		t.Fatalf("read the mirrored directory: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".part-") {
			t.Errorf("a staging file survived the run: %s", entry.Name())
		}
	}
}

// R5. A forced refresh that fails keeps the copy that was already good. The
// alternative is a mirror that gets worse every time an operator reaches for
// --force during an upstream wobble.
func TestMirrorKeepsAGoodObjectWhenAForcedRefreshFails(t *testing.T) {
	catalog := string(fbCatalog(t, "tzst", fbHashedPath))
	data := string(fbData(t, "tzst", fbHashedPath))
	cut := false
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case manifest.FreeBSDMetaFile:
			_, _ = io.WriteString(w, "packing_format = \"tzst\";\n")
		case manifest.FreeBSDCatalogFile:
			_, _ = io.WriteString(w, catalog)
		case manifest.FreeBSDDataFile:
			_, _ = io.WriteString(w, data)
		case fbHashedPath:
			if cut {
				w.Header().Set("Content-Length", "64")
				_, _ = io.WriteString(w, "half")
				return
			}
			_, _ = io.WriteString(w, "the good package")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("first mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}

	cut = true
	cfg.Force = true
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 1 {
		t.Fatalf("the forced refresh reported %d failures, want 1: %+v", sum.Failures, sum.Results)
	}
	body, err := os.ReadFile(filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest", filepath.FromSlash(fbHashedPath)))
	if err != nil {
		t.Fatalf("read the mirrored package after a failed refresh: %v", err)
	}
	if string(body) != "the good package" {
		t.Errorf("the failed refresh replaced a good object with %q", body)
	}
}

// R3. Every upstream request this mirror makes asks for identity bytes, and a
// body that arrives encoded anyway is refused rather than decoded.
//
// Go's transport adds "Accept-Encoding: gzip" on its own and decodes the
// answer transparently, so a mirror that says nothing stores whatever the
// transport produced. The archives carry FreeBSD's signature as a member, and
// the client reports the difference as a signature failure against bodega.
func TestMirrorAsksUpstreamForIdentityEncoding(t *testing.T) {
	var encodings []string
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "packing_format = \"tzst\";\n",
		manifest.FreeBSDCatalogFile: string(fbCatalog(t, "tzst", fbHashedPath)),
		manifest.FreeBSDDataFile:    string(fbData(t, "tzst", fbHashedPath)),
		fbHashedPath:                "latest layout package",
	})
	up.check = func(string) {}
	up.record = func(r *http.Request) { encodings = append(encodings, r.Header.Get("Accept-Encoding")) }

	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}
	if len(encodings) != 4 {
		t.Fatalf("the mirror made %d requests, want 4 (three root files and one object): %v", len(encodings), up.asked)
	}
	for i, enc := range encodings {
		if enc != "identity" {
			t.Errorf("request %d (%s) asked for Accept-Encoding %q, want identity", i, up.asked[i], enc)
		}
	}
}

// R3, the other half: an upstream that encodes anyway is a proxy rewriting
// the bytes, and the mirror writes nothing rather than store what it cannot
// vouch for.
func TestMirrorRefusesAnEncodedUpstreamBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not the bytes that were signed")
	}))
	t.Cleanup(up.Close)

	cfg, store := fbFixture(t, up.URL)
	sum := FetchFreeBSD(cfg, store, "")
	if sum.Failures != 1 {
		t.Fatalf("an encoded body reported %d failures, want 1", sum.Failures)
	}
	if err := sum.Results[0].Err; err == nil || !strings.Contains(err.Error(), "Content-Encoding") {
		t.Errorf("the refusal does not name the encoding: %v", err)
	}
	if fileExists(filepath.Join(cfg.BuildRoot, "freebsd", freeBSDStagingDir, fbABI, "latest", manifest.FreeBSDMetaFile)) {
		t.Error("an encoded body was written to staging")
	}
}

// R4, R5. Both published archives name objects, so both decide what gets
// mirrored.
//
// data.pkg is fetched a moment before packagesite.pkg from a repository that
// rebuilds continuously, so the two can describe different generations — and
// bodega publishes the pair byte for byte, because rewriting either destroys
// the signature it carries. Mirroring only what the catalogue named left
// data.pkg describing packages this store had never held, which a client
// reading data.pkg resolves and then 404s on.
func TestMirrorFetchesEveryObjectBothArchivesName(t *testing.T) {
	// The upstream rebuilt between the two reads: data.pkg is one generation
	// and packagesite.pkg the next, and they name different packages.
	data := string(fbData(t, "tzst", fbDotPath))
	catalog := string(fbCatalog(t, "tzst", fbHashedPath))
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "packing_format = \"tzst\";\ndata = \"data\";\n",
		manifest.FreeBSDCatalogFile: catalog,
		manifest.FreeBSDDataFile:    data,
		fbHashedPath:                "the generation packagesite.pkg names",
		fbDotResolved:               "the generation data.pkg names",
	})

	cfg, store := fbFixture(t, up.URL)
	repoDir := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest")
	up.check = func(rel string) {
		if slices.Contains(manifest.FreeBSDCatalogFiles, rel) {
			return
		}
		// Neither archive may be readable while an object is still in
		// flight: a client reading either one here resolves this package.
		for _, name := range []string{manifest.FreeBSDCatalogFile, manifest.FreeBSDDataFile} {
			if _, err := os.Stat(filepath.Join(repoDir, name)); err == nil {
				t.Errorf("%s was in place while %s was still being fetched", name, rel)
			}
		}
	}

	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}
	for rel, want := range map[string]string{
		fbHashedPath:                "the generation packagesite.pkg names",
		fbDotResolved:               "the generation data.pkg names",
		manifest.FreeBSDCatalogFile: catalog,
		manifest.FreeBSDDataFile:    data,
	} {
		got, err := os.ReadFile(filepath.Join(repoDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read the mirrored %s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s mirrored %d bytes, want the %d upstream served", rel, len(got), len(want))
		}
	}
}

// R4. data.pkg carries its records under its own member names, in one JSON
// document rather than a record per line, and meta.conf says which member.
// A reader written against packagesite's spelling walks past all three
// members and reports an archive that names 535 packages as empty.
func TestDataArchiveNamesItsOwnObjects(t *testing.T) {
	archive := filepath.Join(t.TempDir(), manifest.FreeBSDDataFile)
	if err := os.WriteFile(archive, fbData(t, "tzst", fbDotPath, fbRootPath, fbHashedPath), 0o644); err != nil {
		t.Fatalf("write data.pkg: %v", err)
	}

	member, err := freeBSDDataMember([]byte("version = 2;\npacking_format = \"tzst\";\ndata = \"data\";\n"))
	if err != nil {
		t.Fatalf("read the data key: %v", err)
	}
	got, err := freeBSDDataRepoPaths(archive, "tzst", member)
	if err != nil {
		t.Fatalf("read data.pkg: %v", err)
	}
	if want := []string{fbDotResolved, fbRootPath, fbHashedPath}; !slices.Equal(got, want) {
		t.Errorf("data.pkg named %v, want %v", got, want)
	}

	// meta.conf version 1 predates the key, so the customary name stands in.
	if member, err := freeBSDDataMember([]byte("packing_format = \"tzst\";\n")); err != nil || member != "data" {
		t.Errorf("an absent data key = (%q, %v), want data", member, err)
	}
	// A member meta.conf names and the archive does not hold is reported by
	// that name: it is the case where the default above was the wrong guess.
	if _, err := freeBSDDataRepoPaths(archive, "tzst", "records"); err == nil {
		t.Error("an archive holding no such member was accepted")
	} else if !strings.Contains(err.Error(), "records") {
		t.Errorf("the refusal does not name the member: %v", err)
	}
}

// R5. Two mirrors of one repository overlap — a scheduled run meeting a
// manual one — and upstream rebuilds between them. Each publishes the
// archives it fetched and parsed; neither publishes the other's.
//
// The failure this replaces was silent in every place anyone looks: both
// transfers succeeded, both archives were valid, and the published catalogue
// named a package that was still in flight for the other run. The client
// found out, part way through an install.
func TestConcurrentMirrorsPublishOnlyTheArchivesTheyFetched(t *testing.T) {
	catA, catB := fbCatalog(t, "tzst", "a.pkg"), fbCatalog(t, "tzst", "b.pkg")
	dataA, dataB := fbData(t, "tzst", "a.pkg"), fbData(t, "tzst", "b.pkg")

	// The rebuild is pinned to the moment the first mirror starts fetching
	// its object: from then on upstream serves the second generation, which
	// is the window the shared staging path published into.
	rebuilt, secondStarted := make(chan struct{}), make(chan struct{})
	releaseA, releaseB := make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cat, data := catA, dataA
		select {
		case <-rebuilt:
			cat, data = catB, dataB
		default:
		}
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case manifest.FreeBSDMetaFile:
			_, _ = io.WriteString(w, "packing_format = \"tzst\";\n")
		case manifest.FreeBSDDataFile:
			_, _ = w.Write(data)
		case manifest.FreeBSDCatalogFile:
			_, _ = w.Write(cat)
		case "a.pkg":
			close(rebuilt)
			<-releaseA
			_, _ = io.WriteString(w, "a.pkg")
		case "b.pkg":
			close(secondStarted)
			<-releaseB
			_, _ = io.WriteString(w, "b.pkg")
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()

	cfg, _ := fbFixture(t, up.URL)
	d := buildDirs(cfg.BuildRoot)
	ve := manifest.VersionEntry{Version: fbABI, URL: up.URL}
	mirror := func(done chan<- error) {
		_, _, err := mirrorFreeBSDRepo(cfg, d, "latest", ve)
		done <- err
	}

	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go mirror(firstDone)
	<-rebuilt
	go mirror(secondDone)
	<-secondStarted

	close(releaseA)
	if err := <-firstDone; err != nil {
		t.Fatalf("the first mirror failed: %v", err)
	}

	// The second mirror is still holding b.pkg open, so anything the first
	// mirror published has to be the generation it fetched.
	repoDir := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest")
	published, err := os.ReadFile(filepath.Join(repoDir, manifest.FreeBSDCatalogFile))
	if err != nil {
		t.Fatalf("read the published catalogue: %v", err)
	}
	if !bytes.Equal(published, catA) {
		t.Errorf("the first mirror published %d bytes, want the %d-byte catalogue it fetched; publishing the other run's names an object that is still in flight", len(published), len(catA))
	}
	if !fileExists(filepath.Join(repoDir, "a.pkg")) {
		t.Error("the published catalogue names a.pkg, which is not on disk")
	}

	close(releaseB)
	if err := <-secondDone; err != nil {
		t.Fatalf("the second mirror failed: %v", err)
	}
	published, err = os.ReadFile(filepath.Join(repoDir, manifest.FreeBSDCatalogFile))
	if err != nil {
		t.Fatalf("read the published catalogue after the second mirror: %v", err)
	}
	if !bytes.Equal(published, catB) {
		t.Errorf("the second mirror published %d bytes, want its own %d-byte catalogue", len(published), len(catB))
	}
	if !fileExists(filepath.Join(repoDir, "b.pkg")) {
		t.Error("the second catalogue names b.pkg, which is not on disk")
	}

	// The scratch areas are the mirrors' own and end with them; a staging
	// tree that accumulated them would be a growing copy of the repository.
	staging := filepath.Join(cfg.BuildRoot, "freebsd", freeBSDStagingDir, fbABI, "latest")
	left, err := os.ReadDir(staging)
	if err != nil {
		t.Fatalf("read the staging area: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("%d staging directories outlived their mirrors: %v", len(left), left)
	}
}
