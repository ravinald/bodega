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

	var out bytes.Buffer
	switch pack {
	case "tzst":
		enc, err := zstd.NewWriter(&out)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		if _, err := enc.Write(body.Bytes()); err != nil {
			t.Fatalf("zstd write: %v", err)
		}
		if err := enc.Close(); err != nil {
			t.Fatalf("zstd close: %v", err)
		}
	case "tgz":
		gz := gzip.NewWriter(&out)
		if _, err := gz.Write(body.Bytes()); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	default:
		t.Fatalf("fbCatalog has no packing for %q", pack)
	}
	return out.Bytes()
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
	asked []string
	check func(path string)
}

func newFBUpstream(t *testing.T, bodies map[string]string) *fbUpstream {
	t.Helper()
	up := &fbUpstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		up.asked = append(up.asked, rel)
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
	catalog := string(fbCatalog(t, "tzst", fbHashedPath, fbDotPath))
	up := newFBUpstream(t, map[string]string{
		manifest.FreeBSDMetaFile:    "packing_format = \"tzst\";\n",
		manifest.FreeBSDCatalogFile: catalog,
		manifest.FreeBSDDataFile:    "data archive bytes",
		fbHashedPath:                "latest layout package",
		fbDotResolved:               "base_latest layout package",
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
		manifest.FreeBSDDataFile:    "data archive bytes",
		fbHashedPath:                "latest layout package",
		fbDotResolved:               "base_latest layout package",
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
		manifest.FreeBSDDataFile:    "data archive bytes",
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
		manifest.FreeBSDDataFile:    "data archive bytes",
		fbHashedPath:                "latest layout package",
		fbDotResolved:               "base_latest layout package",
	})
	cfg, store := fbFixture(t, up.URL)
	if sum := FetchFreeBSD(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("mirror reported %d failures: %+v", sum.Failures, sum.Results)
	}

	paths := FreeBSDArtifactPaths(cfg, store, "")
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
	if len(FreeBSDArtifactPaths(cfg, store, "")) != 0 {
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
