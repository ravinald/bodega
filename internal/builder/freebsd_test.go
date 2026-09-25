package builder

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// fbOversizedHeader builds an archive whose member header declares size bytes
// with no body behind it, which is enough to prove the refusal names the
// member, its size and the cap without producing a gigabyte to say so.
func fbOversizedHeader(t *testing.T, pack, member string, size int64) []byte {
	t.Helper()
	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o644, Size: size}); err != nil {
		t.Fatalf("tar header %s: %v", member, err)
	}
	// Deliberately not closed: the writer refuses a member whose body never
	// arrived, and the header block it has already emitted is the fixture.
	return fbPack(t, pack, body.Bytes())
}

// fbOversized caches the two archives below. Each costs about a second to
// produce and four tests want them; the padding compresses to nothing, so
// what is held is kilobytes.
var fbOversized sync.Map

// fbOversizedArchive builds an archive whose member runs past the cap with a
// record on either side of it, and whose prefix parses cleanly.
//
// The prefix is the point. An archive that is merely truncated fails in the
// tar reader and would let a mirror that stops at the cap and publishes
// anyway pass this fixture; this one enumerates a.pkg, reads legal padding up
// to the limit, and names b.pkg past it. Only refusing at the cap keeps b.pkg
// from being an object the published catalogue names and nothing fetched.
func fbOversizedArchive(t *testing.T, kind string) []byte {
	t.Helper()
	if cached, ok := fbOversized.Load(kind); ok {
		return cached.([]byte)
	}
	var member, head, tail string
	switch kind {
	case "packagesite":
		member, head, tail = "packagesite.yaml", `{"name":"a","version":"1","repopath":"a.pkg"}`+"\n", `{"name":"b","version":"1","repopath":"b.pkg"}`+"\n"
	case "data":
		member, head, tail = "data", `{"groups":[],"packages":[{"name":"a","version":"1","repopath":"a.pkg"}`, `,{"name":"b","version":"1","repopath":"b.pkg"}]}`
	default:
		t.Fatalf("fbOversizedArchive has no %q fixture", kind)
	}

	// Padding in lines rather than one run: a record over freeBSDCatalogLineCap
	// is its own refusal, and this fixture is about the member cap.
	line := strings.Repeat(" ", (1<<20)-1) + "\n"
	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o644, Size: int64(freeBSDCatalogMemberCap + len(tail))}); err != nil {
		t.Fatalf("tar header %s: %v", member, err)
	}
	if _, err := io.WriteString(tw, head); err != nil {
		t.Fatalf("tar body %s: %v", member, err)
	}
	for left := freeBSDCatalogMemberCap - len(head); left > 0; {
		n := min(len(line), left)
		if _, err := io.WriteString(tw, line[:n]); err != nil {
			t.Fatalf("tar body %s: %v", member, err)
		}
		left -= n
	}
	if _, err := io.WriteString(tw, tail); err != nil {
		t.Fatalf("tar body %s: %v", member, err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	packed := fbPack(t, "tzst", body.Bytes())
	fbOversized.Store(kind, packed)
	return packed
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
	return fbDataDoc(t, pack, `{"groups":[],"expired_packages":[],"packages":[`+strings.Join(records, ",")+`]}`)
}

// fbDataDoc packs one data document under the three members data.pkg
// publishes, whatever the document says.
func fbDataDoc(t *testing.T, pack, doc string) []byte {
	t.Helper()
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

// A package under a directory named for one of pkg's catalogue fallbacks is
// an ordinary package. Nothing writes a file under that name, so there is no
// catalogue for the directory to collide with, and refusing it would fail the
// mirror of a repository whose every package the route can serve.
func TestAPackageUnderAFallbackNamedDirectoryIsMirrored(t *testing.T) {
	const rel = "data.tzst/example.pkg"
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "version = 2;\npacking_format = \"tzst\";\n",
		manifest.FreeBSDCatalogFile: string(fbCatalog(t, "tzst", rel)),
		manifest.FreeBSDDataFile:    string(fbData(t, "tzst", rel)),
		rel:                         "package bytes",
	})
	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the mirror refused a package under %s: %+v", rel, sum.Results)
	}
	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	if err != nil {
		t.Fatalf("enumerate the upload set: %v", err)
	}
	defer release()
	want := manifest.FreeBSDKey(fbABI, "latest", rel)
	if !slices.ContainsFunc(paths, func(ap ArtifactPath) bool { return ap.ObjectKey == want }) {
		t.Errorf("the upload set has no %s: %+v", want, paths)
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

// R4, R5. The member cap is a refusal, not an end of file. io.LimitReader
// reports the end of the stream at its limit, and a catalogue reader that took
// that for the end of the document would hand back a prefix as the
// repository's whole object list.
func TestCatalogMemberCapRefusesRatherThanEndingTheStream(t *testing.T) {
	read := func(src string, limit int64) (string, error) {
		r := &freeBSDCappedReader{r: strings.NewReader(src), limit: limit, archive: "packagesite.pkg", member: "packagesite.yaml"}
		b, err := io.ReadAll(r)
		return string(b), err
	}
	// A member of exactly the cap is complete, and reads clean.
	if got, err := read("12345678", 8); err != nil || got != "12345678" {
		t.Errorf("a member of exactly the cap read (%q, %v), want it whole with no error", got, err)
	}
	got, err := read("123456789", 8)
	if err == nil {
		t.Fatalf("a member past the cap read %q and reported the end of the stream", got)
	}
	for _, want := range []string{"packagesite.pkg", "packagesite.yaml", "8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// R4, R5. A member the archive itself declares over the cap is refused by
// name, before anything reads a byte of it.
func TestArchiveMemberOverTheCapIsRefusedByName(t *testing.T) {
	oversize := int64(freeBSDCatalogMemberCap) + 1
	for _, tc := range []struct {
		name, file, member string
		read               func(archive string) ([]string, error)
	}{
		{"packagesite.pkg", manifest.FreeBSDCatalogFile, "packagesite.yaml",
			func(a string) ([]string, error) { return freeBSDCatalogRepoPaths(a, "tzst") }},
		{"data.pkg", manifest.FreeBSDDataFile, "data",
			func(a string) ([]string, error) { return freeBSDDataRepoPaths(a, "tzst", "data") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), tc.file)
			if err := os.WriteFile(archive, fbOversizedHeader(t, "tzst", tc.member, oversize), 0o644); err != nil {
				t.Fatalf("write %s: %v", tc.file, err)
			}
			paths, err := tc.read(archive)
			if err == nil {
				t.Fatalf("an oversized %s enumerated %d paths, want a refusal", tc.member, len(paths))
			}
			for _, want := range []string{tc.member, fmt.Sprint(oversize), fmt.Sprint(freeBSDCatalogMemberCap)} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %q: %v", want, err)
				}
			}
		})
	}
}

// R4, R5. A member over the cap fails the mirror before any repository-root
// file is placed, and the object named past the cap is never published as one
// this repository holds.
//
// The cap is legitimate. Reading the prefix it allows, fetching that prefix's
// objects and then publishing the untruncated archive over them is not, and
// nothing downstream reports it: every transfer succeeds, and the archive a
// client validates against FreeBSD's fingerprint is the real one. The
// repository is short by whatever sat past the limit, and only the client
// finds out.
func TestMirrorRefusesAnOversizedCatalogueMember(t *testing.T) {
	for _, tc := range []struct{ kind, file, member string }{
		{"packagesite", manifest.FreeBSDCatalogFile, "packagesite.yaml"},
		{"data", manifest.FreeBSDDataFile, "data"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			bodies := map[string]string{
				manifest.FreeBSDMetaFile:    "packing_format = \"tzst\";\ndata = \"data\";\n",
				manifest.FreeBSDCatalogFile: string(fbCatalog(t, "tzst", "a.pkg")),
				manifest.FreeBSDDataFile:    string(fbData(t, "tzst", "a.pkg")),
				"a.pkg":                     "the object before the cap",
				"b.pkg":                     "the object past it",
			}
			bodies[tc.file] = string(fbOversizedArchive(t, tc.kind))
			up := newFBUpstream(t, bodies)
			cfg, store := fbFixture(t, up.URL)

			sum := FetchFreeBSD(cfg, store, "")
			if sum.Failures != 1 {
				t.Fatalf("an oversized %s reported %d failures, want 1: %+v", tc.member, sum.Failures, sum.Results)
			}
			if err := sum.Results[0].Err; err == nil || !strings.Contains(err.Error(), tc.member) {
				t.Errorf("the failure does not name the member that could not be read: %v", err)
			}
			repoDir := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest")
			for _, root := range manifest.FreeBSDCatalogFiles {
				if fileExists(filepath.Join(repoDir, root)) {
					t.Errorf("%s was published over an object list that stopped at the cap", root)
				}
			}
			if fileExists(filepath.Join(repoDir, "b.pkg")) {
				t.Error("b.pkg sits past the cap, so nothing should have enumerated it")
			}
		})
	}
}

// R5. The refusal keeps the generation already published, and it reaches the
// upload the same way: an archive whose object list cannot be read is one
// neither half of this mirror publishes.
func TestAnUnreadableCatalogueKeepsThePublishedGeneration(t *testing.T) {
	good := string(fbCatalog(t, "tzst", fbHashedPath))
	oversized := string(fbOversizedArchive(t, "packagesite"))
	data := string(fbData(t, "tzst", fbHashedPath))

	var mu sync.Mutex
	catalog := good
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served := catalog
		mu.Unlock()
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case manifest.FreeBSDMetaFile:
			_, _ = io.WriteString(w, "packing_format = \"tzst\";\n")
		case manifest.FreeBSDCatalogFile:
			_, _ = io.WriteString(w, served)
		case manifest.FreeBSDDataFile:
			_, _ = io.WriteString(w, data)
		case fbHashedPath, "a.pkg", "b.pkg":
			_, _ = io.WriteString(w, "package bytes")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the first mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}
	published := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest", manifest.FreeBSDCatalogFile)

	mu.Lock()
	catalog = oversized
	mu.Unlock()
	cfg.Force = true
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 1 {
		t.Fatalf("a forced refresh over an unreadable catalogue reported %d failures, want 1: %+v", sum.Failures, sum.Results)
	}
	if got, err := os.ReadFile(published); err != nil {
		t.Fatalf("read the published catalogue: %v", err)
	} else if string(got) != good {
		t.Errorf("the forced refresh replaced the published catalogue with %d bytes; a refusal keeps the generation that works", len(got))
	}

	// The upload reads its pinned copy through the same reader, so an archive
	// that fails enumeration fails the upload rather than being published off
	// a list nothing established.
	if err := os.WriteFile(published, []byte(oversized), 0o644); err != nil {
		t.Fatalf("write the unreadable catalogue into the tree: %v", err)
	}
	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	release()
	if err == nil {
		t.Fatalf("the upload enumerated %d paths out of an archive whose object list could not be read", len(paths))
	}
	if !strings.Contains(err.Error(), "packagesite.yaml") {
		t.Errorf("the upload refusal does not name the member that could not be read: %v", err)
	}
}

// R4, R5. A data document cut part way through is refused rather than read as
// a complete and smaller repository. Both cuts are covered: one inside the
// packages array, one before the key appears at all.
//
// Which layer refuses is deliberately not asserted. Today the decoder errors
// on the next read; the closing-delimiter checks in freeBSDDataPackages are
// there because More's answer on a failed read is not part of its contract,
// and this test holds whichever of the two catches it.
func TestATruncatedDataDocumentIsRefused(t *testing.T) {
	whole := `{"groups":[],"packages":[{"name":"a","version":"1","repopath":"a.pkg"},{"name":"b","version":"1","repopath":"b.pkg"}]}`
	for _, tc := range []struct{ name, doc string }{
		{"inside the packages array", whole[:strings.Index(whole, `,{"name":"b"`)]},
		{"before the packages key", `{"groups":[],`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), manifest.FreeBSDDataFile)
			if err := os.WriteFile(archive, fbDataDoc(t, "tzst", tc.doc), 0o644); err != nil {
				t.Fatalf("write data.pkg: %v", err)
			}
			paths, err := freeBSDDataRepoPaths(archive, "tzst", "data")
			if err == nil {
				t.Fatalf("a document cut %s enumerated %v as the repository's whole object list", tc.name, paths)
			}
		})
	}
}

// R4, R5. The record cap is the other limit in this reader. bufio already
// reports it as an error rather than as an end; what it does not report is
// which catalogue stopped or how much of it went unread.
func TestARecordOverTheLineCapIsRefused(t *testing.T) {
	archive := filepath.Join(t.TempDir(), manifest.FreeBSDCatalogFile)
	if err := os.WriteFile(archive, fbCatalog(t, "tzst", fbHashedPath, strings.Repeat("x", freeBSDCatalogLineCap+1)), 0o644); err != nil {
		t.Fatalf("write packagesite.pkg: %v", err)
	}
	paths, err := freeBSDCatalogRepoPaths(archive, "tzst")
	if err == nil {
		t.Fatalf("a record over the cap enumerated %d paths, want a refusal", len(paths))
	}
	for _, want := range []string{"packagesite.yaml", fmt.Sprint(freeBSDCatalogLineCap)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// R4, R5. A repopath that lands on a repository-root file is refused where it
// enters the mirror, in both documents.
//
// The repository root is this mirror's namespace: the three files a client
// reads to find everything else, and the legacy names the route answers 404
// by. A record claiming one of them is a package whose bytes would be written
// over the metadata, or stored under a name no request ever reaches. Dot
// segments normalize before the check because "./data.pkg" is the spelling
// base_latest uses for everything it publishes, and case folds into it
// because the build tree and storage.Local are filesystems: APFS answers
// "Data.pkg" with data.pkg whatever the key scheme thinks.
func TestCatalogRefusesARepoPathOntoARepositoryRootFile(t *testing.T) {
	for _, bad := range []string{
		manifest.FreeBSDMetaFile,
		manifest.FreeBSDDataFile,
		manifest.FreeBSDCatalogFile,
		"./" + manifest.FreeBSDDataFile,
		"Data.PKG",
		// A directory under the name instead of a file. One filesystem entry
		// cannot be both, so this collides with the root file just as surely.
		manifest.FreeBSDCatalogFile + "/inside.pkg",
		"digests.pkg",
		"repo.txz",
		// A fallback name is refused as the file pkg asks for, not as a
		// directory: see TestAPackageUnderAFallbackNamedDirectoryIsMirrored.
		"data.tzst",
		"Meta.TXZ",
	} {
		dir := t.TempDir()
		catalog := filepath.Join(dir, manifest.FreeBSDCatalogFile)
		if err := os.WriteFile(catalog, fbCatalog(t, "tzst", bad), 0o644); err != nil {
			t.Fatalf("write catalogue: %v", err)
		}
		if _, err := freeBSDCatalogRepoPaths(catalog, "tzst"); err == nil {
			t.Errorf("packagesite.yaml repopath %q was accepted", bad)
		}
		data := filepath.Join(dir, manifest.FreeBSDDataFile)
		if err := os.WriteFile(data, fbData(t, "tzst", bad), 0o644); err != nil {
			t.Fatalf("write data.pkg: %v", err)
		}
		if _, err := freeBSDDataRepoPaths(data, "tzst", "data"); err == nil {
			t.Errorf("data repopath %q was accepted", bad)
		}
	}

	// The boundary is the repository root itself, not the spelling of a name.
	// A package at the root is an ordinary layout, and one nested under a
	// directory that happens to share a root file's name keys somewhere no
	// root file lives.
	for _, ok := range []string{fbRootPath, fbHashedPath, "All/" + manifest.FreeBSDMetaFile, "data.tzst/example.pkg", "Packagesite.tgz/All/x.pkg"} {
		archive := filepath.Join(t.TempDir(), manifest.FreeBSDCatalogFile)
		if err := os.WriteFile(archive, fbCatalog(t, "tzst", ok), 0o644); err != nil {
			t.Fatalf("write catalogue: %v", err)
		}
		if _, err := freeBSDCatalogRepoPaths(archive, "tzst"); err != nil {
			t.Errorf("repopath %q was refused: %v", ok, err)
		}
	}
}

// R5. The refusal reaches both writers on this side, and it lands before
// either of them has written anything.
//
// A catalogue naming a root file is untrusted input rather than a repository
// pkg.freebsd.org publishes, and what it costs is a served repository: the
// mirror would fetch that package into the tree during the object phase,
// which is the phase that runs before the archives are placed, and the upload
// would put it in the object half of its publication — so the metadata a
// client reads gets replaced ahead of the object set, and an object failing
// after it leaves the repository serving a catalogue for packages that are
// not there.
func TestMirrorRefusesACatalogueNamingARepositoryRootFile(t *testing.T) {
	good := string(fbCatalog(t, "tzst", fbHashedPath))
	goodData := string(fbData(t, "tzst", fbHashedPath))
	// Complete and valid in every other respect: both archives parse, both
	// objects are upstream, and one record spells data.pkg the way
	// base_latest spells every path it publishes.
	poisoned := string(fbData(t, "tzst", fbHashedPath, "new.pkg", "./"+manifest.FreeBSDDataFile))

	var mu sync.Mutex
	data := goodData
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served := data
		mu.Unlock()
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case manifest.FreeBSDMetaFile:
			_, _ = io.WriteString(w, "packing_format = \"tzst\";\n")
		case manifest.FreeBSDCatalogFile:
			_, _ = io.WriteString(w, good)
		case manifest.FreeBSDDataFile:
			_, _ = io.WriteString(w, served)
		case fbHashedPath, "new.pkg":
			_, _ = io.WriteString(w, "package bytes")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the first mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}
	repoDir := filepath.Join(cfg.BuildRoot, "freebsd", fbABI, "latest")
	published := map[string]string{}
	for _, name := range manifest.FreeBSDCatalogFiles {
		body, err := os.ReadFile(filepath.Join(repoDir, name))
		if err != nil {
			t.Fatalf("read the published %s: %v", name, err)
		}
		published[name] = string(body)
	}

	mu.Lock()
	data = poisoned
	mu.Unlock()
	cfg.Force = true
	sum := FetchFreeBSD(cfg, store, "")
	if sum.Failures != 1 {
		t.Fatalf("a catalogue naming a repository-root file reported %d failures, want 1: %+v", sum.Failures, sum.Results)
	}
	if err := sum.Results[0].Err; err == nil || !strings.Contains(err.Error(), manifest.FreeBSDDataFile) {
		t.Errorf("the refusal does not name the root file the record landed on: %v", err)
	}
	for name, want := range published {
		got, err := os.ReadFile(filepath.Join(repoDir, name))
		if err != nil {
			t.Fatalf("read %s after the refusal: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("the refused mirror replaced the published %s", name)
		}
	}
	if fileExists(filepath.Join(repoDir, "new.pkg")) {
		t.Error("the refusal came after the object phase had already written to the tree")
	}

	// The upload reads its pinned copy through the same reader, so a
	// repository mirrored by something else with such a record in it is one
	// this uploader refuses rather than publishes.
	if err := os.WriteFile(filepath.Join(repoDir, manifest.FreeBSDDataFile), []byte(poisoned), 0o644); err != nil {
		t.Fatalf("write the poisoned data.pkg into the tree: %v", err)
	}
	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	release()
	if err == nil {
		t.Fatalf("the upload enumerated %d path(s) out of a catalogue naming a repository-root file", len(paths))
	}
	if !strings.Contains(err.Error(), manifest.FreeBSDDataFile) {
		t.Errorf("the upload refusal does not name the root file the record landed on: %v", err)
	}
}

// fbGeneratedFixture seeds a repository bodega hosts rather than mirrors: an
// entry with no URL, and packages in the build tree where whoever built them
// put them.
func fbGeneratedFixture(t *testing.T, packages map[string]string) (*Config, *manifest.Store) {
	t.Helper()
	cfg := &Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir(), Stdout: io.Discard}
	store := manifest.NewLocalStore(cfg.ManifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeFreeBSD, "house", manifest.VersionEntry{
		Version:   fbABI,
		Generated: true,
	}); err != nil {
		t.Fatalf("seed the manifest: %v", err)
	}
	repoDir := filepath.Join(buildDirs(cfg.rootFor(manifest.TypeFreeBSD)).freebsd, fbABI, "house")
	for rel, body := range packages {
		dest := filepath.Join(repoDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatalf("create %s: %v", filepath.Dir(dest), err)
		}
		if err := os.WriteFile(dest, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", dest, err)
		}
	}
	return cfg, store
}

// A generated repository has no upstream, so the fetch stage has nothing to
// do and must not fail on the URL it does not carry. Reported complete rather
// than skipped-with-an-error, because the pipeline reads the stage to decide
// whether to run it again.
func TestGeneratedRepositoryHasNoFetchStage(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{fbHashedPath: "a package"})
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("fetch reported %d failures over a repository with nothing to fetch: %+v", sum.Failures, sum.Results)
	}
	ve := manifest.VersionEntry{Version: fbABI, Generated: true}
	if got := CheckFreeBSDStage(cfg, "house", ve); !got.Fetched {
		t.Errorf("CheckFreeBSDStage = %+v, want complete: there is no fetch whose absence would mean it had not run", got)
	}
}

// Every package in the tree uploads, and no repository-root file does. The
// three root names are the generator's namespace — the route answers them
// from the build — so an object stored under one is one no request reaches.
func TestGeneratedRepositoryUploadsPackagesAndNoRootFile(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{
		fbHashedPath:                "a hashed package",
		fbRootPath:                  "a repository-root package",
		manifest.FreeBSDMetaFile:    "left over from a mirror",
		manifest.FreeBSDCatalogFile: "left over from a mirror",
		"README":                    "not a package",
		"meta.txz":                  "a catalogue fallback name",
		"packagesite.tzst/x.pkg":    "a package under a fallback-named directory",
	})

	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	if err != nil {
		t.Fatalf("enumerate the upload set: %v", err)
	}
	defer release()

	var keys []string
	for _, ap := range paths {
		keys = append(keys, ap.ObjectKey)
	}
	want := []string{
		manifest.FreeBSDKey(fbABI, "house", fbHashedPath),
		manifest.FreeBSDKey(fbABI, "house", fbRootPath),
		manifest.FreeBSDKey(fbABI, "house", "packagesite.tzst/x.pkg"),
	}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("upload set = %v, want exactly the three packages %v", keys, want)
	}
}

// A package whose name no request can spell is refused at the walk, where it
// still has a path an operator can rename.
//
// Cheap precondition, expensive operation: the alternative is uploading it,
// then having every catalogue build afterwards refuse the whole repository
// over one file that is already in the store.
func TestGeneratedRepositoryRefusesAnUnroutablePackageName(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{
		fbHashedPath:       "a hashed package",
		`All/bad\name.pkg`: "a package no route can reach",
	})
	_, release, err := FreeBSDArtifactPaths(cfg, store, "")
	if release != nil {
		defer release()
	}
	if err == nil {
		t.Fatal("the upload set admitted a package name the serving route refuses")
	}
	if !strings.Contains(err.Error(), `bad\name.pkg`) {
		t.Errorf("the refusal does not name the file to rename: %v", err)
	}
}

// Whatever the mirror admits, the route serves. That is the invariant, and it
// is not that the two predicates agree: cleanFreeBSDRepoPath normalizes as
// well as admits, so it accepts "./Hashed/x.pkg" and stores it under the
// normalized key the route then sees. What must hold is the composition —
// every path the mirror returns passes the admission the generated catalogue
// and the route share — because a mirrored object keyed where no request
// reaches is the same outage as a generated record naming one.
func TestEveryPathTheMirrorAdmitsIsOneTheRouteServes(t *testing.T) {
	for _, p := range []string{
		"All/zsh-5.9_3.pkg",
		"All/Hashed/py311-foo-1.2.0_3~2$abcdefgh.pkg",
		"./Hashed/FreeBSD-telnet-14.snap.pkg",
		"libx++-2.0.pkg",
		`All/bad\name.pkg`,
		"/All/absolute.pkg",
		"All//empty.pkg",
		"../escape.pkg",
		"All/../escape.pkg",
		"All/ctrl\x01.pkg",
		"",
	} {
		rel, err := cleanFreeBSDRepoPath(p)
		if err != nil {
			continue
		}
		if err := manifest.FreeBSDValidRepoPath(rel); err != nil {
			t.Errorf("the mirror admits %q as %q, which the route refuses: %v", p, rel, err)
		}
	}
}

// fbUploadKeys is the repository-relative path of everything an upload of the
// generated repository would place.
func fbUploadKeys(t *testing.T, cfg *Config, store *manifest.Store) []string {
	t.Helper()
	paths, release, err := FreeBSDArtifactPaths(cfg, store, "")
	if release != nil {
		defer release()
	}
	if err != nil {
		t.Fatalf("enumerate the upload set: %v", err)
	}
	var out []string
	for _, ap := range paths {
		out = append(out, strings.TrimPrefix(ap.ObjectKey, manifest.FreeBSDRepoPrefix(fbABI, "house")))
	}
	slices.Sort(out)
	return out
}

// fbSymlink points rel at target inside the repository tree.
func fbSymlink(t *testing.T, cfg *Config, rel, target string) {
	t.Helper()
	repoDir := filepath.Join(buildDirs(cfg.rootFor(manifest.TypeFreeBSD)).freebsd, fbABI, "house")
	link := filepath.Join(repoDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(link), err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("link %s: %v", rel, err)
	}
}

// R1: a second name for a package the upload already carries is skipped.
//
// poudriere publishes most of a tree twice — Latest/pkg.pkg, and an ordinary
// name beside every hashed one — and WalkDir reports a link as an entry of its
// own while PutFile stores the bytes it points at. Uploading both puts one
// package under two keys, and the generated catalogue then carries two records
// pkg hashes alike: `pkg update` fails on
// "UNIQUE constraint failed: packages.manifestdigest" for the whole
// repository. pkg's own walk skips the same links (2.8.2,
// libpkg/pkg_repo_create.c:216).
func TestGeneratedUploadSkipsASecondNameForAPackage(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{fbHashedPath: "a package"})
	repoDir := filepath.Join(buildDirs(cfg.rootFor(manifest.TypeFreeBSD)).freebsd, fbABI, "house")
	fbSymlink(t, cfg, "All/widget-2025.02.23_1.pkg", filepath.Join(repoDir, filepath.FromSlash(fbHashedPath)))
	fbSymlink(t, cfg, "Latest/widget.pkg", filepath.Join(repoDir, filepath.FromSlash(fbHashedPath)))

	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, []string{fbHashedPath}) {
		t.Fatalf("upload set = %v, want the package alone: its two aliases are the same bytes under other names", got)
	}
}

// The same link, reached through a relative target and through a build root
// that is itself a symlink — /var is /private/var on macOS, and a tree
// assembled with `ln -s` carries relative targets. Both resolve inside the
// repository and neither may upload twice.
func TestGeneratedUploadResolvesBothSidesBeforeComparing(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{"All/widget-1.2.0.pkg": "a package"})
	fbSymlink(t, cfg, "All/widget.pkg", "widget-1.2.0.pkg")

	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, []string{"All/widget-1.2.0.pkg"}) {
		t.Fatalf("upload set = %v, want the package alone: a relative link into the repository is a second name for it", got)
	}
}

// A link out of the tree is the only name those bytes have here, so it is
// followed — which is what pkg's own walk does with one.
func TestGeneratedUploadFollowsALinkOutOfTheRepository(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, nil)
	outside := filepath.Join(t.TempDir(), "widget-1.2.0.pkg")
	if err := os.WriteFile(outside, []byte("a package built elsewhere"), 0o644); err != nil {
		t.Fatalf("write %s: %v", outside, err)
	}
	fbSymlink(t, cfg, "All/widget-1.2.0.pkg", outside)

	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, []string{"All/widget-1.2.0.pkg"}) {
		t.Fatalf("upload set = %v, want the linked package: nothing else in the repository names those bytes", got)
	}
}

// R1: a name is dropped only when something else publishes the same file.
//
// The rule that skips an in-repository link is not that rule, and this is the
// tree where the two part company. A .pkg symlink at a .txz — what a tree
// carries when it predates pkg 1.17 spelling them .pkg — has its target
// skipped for the extension and itself skipped for resolving inside the
// repository, so the package leaves the repository entirely with two log lines
// and no error. The link is the only name those bytes have here.
func TestGeneratedUploadKeepsALinkWhoseTargetItDoesNotPublish(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{"All/widget-1.2.0.txz": "a package"})
	fbSymlink(t, cfg, "All/widget-1.2.0.pkg", "widget-1.2.0.txz")

	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, []string{"All/widget-1.2.0.pkg"}) {
		t.Fatalf("upload set = %v, want the link: nothing else in the repository publishes those bytes", got)
	}
}

// The same parting, one directory over: the target is a staging name the walk
// does not publish, and the package beside it must not be taken down with it.
func TestGeneratedUploadKeepsALinkAtAnUnpublishedTarget(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{
		"All/real-1.0.pkg":           "a package",
		"spool/widget-1.2.0.pkg.tmp": "another package",
	})
	fbSymlink(t, cfg, "All/widget-1.2.0.pkg", "../spool/widget-1.2.0.pkg.tmp")

	want := []string{"All/real-1.0.pkg", "All/widget-1.2.0.pkg"}
	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, want) {
		t.Fatalf("upload set = %v, want both packages %v", got, want)
	}
}

// Two links at one file outside the tree are two names for one package, and
// neither of them resolves inside anything. Publishing both is the duplicate
// record pkg refuses the whole repository over, reached without a single
// in-repository link.
func TestGeneratedUploadPublishesOneNameForAFileOutsideTheTree(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, nil)
	outside := filepath.Join(t.TempDir(), "widget-1.2.0.pkg")
	if err := os.WriteFile(outside, []byte("a package built elsewhere"), 0o644); err != nil {
		t.Fatalf("write %s: %v", outside, err)
	}
	fbSymlink(t, cfg, "All/widget-1.2.0.pkg", outside)
	fbSymlink(t, cfg, "Latest/widget.pkg", outside)

	// Walk order, which filepath.WalkDir makes lexical: two names of equal
	// standing have to resolve the same way on the next build, or the
	// catalogue's repopath moves and every client refetches a package that
	// did not change.
	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, []string{"All/widget-1.2.0.pkg"}) {
		t.Fatalf("upload set = %v, want one name for one package", got)
	}
}

// A dead link is named and skipped rather than failing the upload. A
// repository tree is whatever an operator rsynced into it, and one broken link
// is not a reason to publish none of the packages beside it.
func TestGeneratedUploadSkipsADeadLink(t *testing.T) {
	cfg, store := fbGeneratedFixture(t, map[string]string{fbHashedPath: "a package"})
	fbSymlink(t, cfg, "All/widget-gone.pkg", filepath.Join(t.TempDir(), "never-written.pkg"))

	if got := fbUploadKeys(t, cfg, store); !slices.Equal(got, []string{fbHashedPath}) {
		t.Fatalf("upload set = %v, want the package alone", got)
	}
}
