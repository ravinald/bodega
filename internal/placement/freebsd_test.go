package placement

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const fbUploadABI = "FreeBSD:14:amd64"

// fbArchive packs one member into a tar, which is what packing_format = "tar"
// names. Uncompressed on purpose: these tests are about which generation of
// the archive reaches the backend, and a codec between the fixture and the
// reader is one more thing that can be blamed for a failure that is not it.
func fbArchive(t *testing.T, member, payload string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o644, Size: int64(len(payload))}); err != nil {
		t.Fatalf("tar header %s: %v", member, err)
	}
	if _, err := tw.Write([]byte(payload)); err != nil {
		t.Fatalf("tar body %s: %v", member, err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func fbGeneration(t *testing.T, repoPath string) (catalog, data []byte) {
	t.Helper()
	record := `{"name":"pkg","origin":"misc/pkg","version":"1.0","repopath":"` + repoPath + `"}`
	return fbArchive(t, "packagesite.yaml", record+"\n"),
		fbArchive(t, "data", `{"groups":[],"expired_packages":[],"packages":[`+record+`]}`)
}

// fbUpstream serves one of two generations, switched by the returned pointer.
func fbUpstream(t *testing.T, generation *atomic.Int32, first, second [2][]byte) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gen := first
		if generation.Load() == 1 {
			gen = second
		}
		switch rel := strings.TrimPrefix(r.URL.Path, "/"); rel {
		case manifest.FreeBSDMetaFile:
			_, _ = io.WriteString(w, "packing_format = \"tar\";\ndata = \"data\";\n")
		case manifest.FreeBSDCatalogFile:
			_, _ = w.Write(gen[0])
		case manifest.FreeBSDDataFile:
			_, _ = w.Write(gen[1])
		case "a.pkg":
			_, _ = io.WriteString(w, "a.pkg")
		case "b.pkg":
			_, _ = io.WriteString(w, "b.pkg")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)
	return up
}

func fbSeed(t *testing.T, store *manifest.Store, url string) {
	t.Helper()
	if err := store.AddVersion(t.Context(), manifest.TypeFreeBSD, "latest",
		manifest.VersionEntry{Version: fbUploadABI, URL: url}); err != nil {
		t.Fatalf("seed the manifest: %v", err)
	}
}

// R5, at the enumeration/upload boundary. A forced mirror lands between the
// moment the upload set is enumerated and the moment PutFile opens the files
// in it, and the two generations name different packages.
//
// Enumeration and upload are separated by however long the objects take to
// write, so this window is a repository's ordinary working day rather than a
// contrived one. The catalogue path is the same string in both generations,
// which is what let a stale object list be uploaded under fresh catalogue
// bytes: every transfer succeeded, the catalogue still went last, and the
// published repository named a package no upload had carried.
func TestFreeBSDUploadPublishesTheGenerationItEnumerated(t *testing.T) {
	catA, dataA := fbGeneration(t, "a.pkg")
	catB, dataB := fbGeneration(t, "b.pkg")
	var generation atomic.Int32
	up := fbUpstream(t, &generation, [2][]byte{catA, dataA}, [2][]byte{catB, dataB})

	bcfg := &builder.Config{BuildRoot: t.TempDir(), Stdout: io.Discard}
	pl, store := placerFixture(t, "")
	fbSeed(t, store, up.URL)

	if sum := builder.FetchFreeBSD(bcfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the first mirror failed: %+v", sum.Results)
	}
	paths, release, err := ArtifactPaths(bcfg, store, manifest.TypeFreeBSD, "")
	if err != nil {
		t.Fatalf("enumerate the upload set: %v", err)
	}
	defer release()

	generation.Store(1)
	bcfg.Force = true
	if sum := builder.FetchFreeBSD(bcfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the second mirror failed: %+v", sum.Results)
	}

	if _, err := pl.UploadPaths(t.Context(), manifest.TypeFreeBSD, paths); err != nil {
		t.Fatalf("upload: %v", err)
	}

	dst := pl.Stores().ForType(manifest.TypeFreeBSD)
	published, err := dst.Get(t.Context(), manifest.FreeBSDKey(fbUploadABI, "latest", manifest.FreeBSDCatalogFile))
	if err != nil {
		t.Fatalf("read the published catalogue: %v", err)
	}
	if !bytes.Equal(published, catA) {
		t.Errorf("the upload published the catalogue of a generation it never enumerated; its new object is in nobody's upload list")
	}
	for _, key := range []string{
		manifest.FreeBSDKey(fbUploadABI, "latest", "a.pkg"),
		manifest.FreeBSDKey(fbUploadABI, "latest", manifest.FreeBSDDataFile),
		manifest.FreeBSDKey(fbUploadABI, "latest", manifest.FreeBSDMetaFile),
	} {
		info, err := dst.Head(t.Context(), key)
		if err != nil {
			t.Fatalf("head %s: %v", key, err)
		}
		if !info.Exists {
			t.Errorf("the published catalogue names %s, which the backend does not hold", key)
		}
	}
}

// R5 again, from the other side: an object the mirrored catalogue names is
// missing from the tree, so there is no complete generation to publish.
//
// The enumeration refuses rather than uploading what it found. A partial
// upload that stopped short would leave the catalogue behind — it sorts last
// — but it would also leave the operator with a success count and no idea the
// snapshot was short, and the next upload would finish the job by publishing
// the catalogue over it.
func TestFreeBSDUploadRefusesACatalogueWithAMissingObject(t *testing.T) {
	catA, dataA := fbGeneration(t, "a.pkg")
	var generation atomic.Int32
	up := fbUpstream(t, &generation, [2][]byte{catA, dataA}, [2][]byte{catA, dataA})

	bcfg := &builder.Config{BuildRoot: t.TempDir(), Stdout: io.Discard}
	pl, store := placerFixture(t, "")
	fbSeed(t, store, up.URL)
	if sum := builder.FetchFreeBSD(bcfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the mirror failed: %+v", sum.Results)
	}

	object := filepath.Join(bcfg.BuildRoot, "freebsd", fbUploadABI, "latest", "a.pkg")
	if err := os.Remove(object); err != nil {
		t.Fatalf("remove the mirrored object: %v", err)
	}

	paths, release, err := ArtifactPaths(bcfg, store, manifest.TypeFreeBSD, "")
	defer release()
	if err == nil {
		t.Fatalf("enumeration returned %d paths for a catalogue whose object is missing", len(paths))
	}
	for _, want := range []string{"latest", fbUploadABI, "a.pkg", "404"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q; an operator reading it at 03:00 needs the entry, the object and the consequence: %v", want, err)
		}
	}

	// Nothing reached the backend, so whatever generation was published
	// before is still the one clients read.
	dst := pl.Stores().ForType(manifest.TypeFreeBSD)
	info, err := dst.Head(t.Context(), manifest.FreeBSDKey(fbUploadABI, "latest", manifest.FreeBSDCatalogFile))
	if err != nil {
		t.Fatalf("head the catalogue: %v", err)
	}
	if info.Exists {
		t.Error("a refused enumeration still published a catalogue")
	}
}

// fbOnUpload runs once, when the upload line for the named object is printed.
// That line goes out after the object's destination has been resolved and
// before its bytes are written, which is the window a placement edit in
// flight lands in.
type fbOnUpload struct {
	object string
	run    func()
	fired  bool
}

func (h *fbOnUpload) Write(p []byte) (int, error) {
	if !h.fired && strings.Contains(string(p), "/"+h.object) {
		h.fired = true
		h.run()
	}
	return len(p), nil
}

// fbComplete checks the two halves that make a published FreeBSD repository
// readable: the catalogue at this backend is the generation named, and the
// package that generation's repopath names is in the same backend. Either one
// alone passes on a repository a client cannot install from.
func fbComplete(t *testing.T, st storage.ObjectStore, generation []byte, repopath string) {
	t.Helper()
	published, err := st.Get(t.Context(), manifest.FreeBSDKey(fbUploadABI, "latest", manifest.FreeBSDCatalogFile))
	if err != nil {
		t.Fatalf("read the catalogue published to %s: %v", st.Label(), err)
	}
	if !bytes.Equal(published, generation) {
		t.Errorf("%s holds a catalogue from another generation than the one whose objects were written there", st.Label())
	}
	info, err := st.Head(t.Context(), manifest.FreeBSDKey(fbUploadABI, "latest", repopath))
	if err != nil {
		t.Fatalf("head %s on %s: %v", repopath, st.Label(), err)
	}
	if !info.Exists {
		t.Errorf("the catalogue published to %s names %s, which %s does not hold", st.Label(), repopath, st.Label())
	}
}

// R5 at the destination boundary: the operator repoints the version while an
// upload of it is in flight.
//
// ForVersion reads the manifest per artifact, so the edit used to reach the
// catalogue without reaching the objects that had already gone. This run
// wrote its only package to the backend it established, then replaced a
// second backend's complete generation with a catalogue naming a package that
// backend had never received. Both uploads returned a file count and no
// error, and the manifest pointed clients at the broken one.
//
// The interleaving is the shipped TUI's rather than a contrived one:
// executeSyncAll starts an upload without blocking the UI, and the JSON
// editor writes a version — Storage included — into the same store that
// upload is reading.
func TestFreeBSDUploadKeepsItsObjectsAndCatalogueInOneBackend(t *testing.T) {
	catA, dataA := fbGeneration(t, "a.pkg")
	catB, dataB := fbGeneration(t, "b.pkg")
	var generation atomic.Int32
	up := fbUpstream(t, &generation, [2][]byte{catA, dataA}, [2][]byte{catB, dataB})

	bcfg := &builder.Config{BuildRoot: t.TempDir(), Stdout: io.Discard}
	pl, store := placerFixture(t, "")
	fbSeed(t, store, up.URL)
	if sum := builder.FetchFreeBSD(bcfg, store, ""); sum.Failures != 0 {
		t.Fatalf("the first mirror failed: %+v", sum.Results)
	}

	bulk, err := pl.Stores().ByName("bulk")
	if err != nil {
		t.Fatalf("resolve the bulk backend: %v", err)
	}
	pl.out = &fbOnUpload{object: "a.pkg", run: func() {
		generation.Store(1)
		bcfg.Force = true
		if sum := builder.FetchFreeBSD(bcfg, store, ""); sum.Failures != 0 {
			t.Fatalf("the second mirror failed: %+v", sum.Results)
		}
		pm, err := store.GetPackage(t.Context(), manifest.TypeFreeBSD, "latest")
		if err != nil || pm == nil {
			t.Fatalf("load the entry: %v", err)
		}
		pm.Versions[0].Storage = "bulk"
		if err := store.SavePackage(t.Context(), pm); err != nil {
			t.Fatalf("repoint the entry at bulk: %v", err)
		}
		second := NewWith(pl.Stores(), store, io.Discard, false)
		if _, err := second.UploadType(t.Context(), bcfg, manifest.TypeFreeBSD); err != nil {
			t.Fatalf("the upload that follows the edit failed: %v", err)
		}
		// Asserted before the first upload resumes, so a later failure
		// cannot be read as bulk never having held a whole generation.
		fbComplete(t, bulk, catB, "b.pkg")
	}}

	if _, err := pl.UploadType(t.Context(), bcfg, manifest.TypeFreeBSD); err != nil {
		t.Fatalf("the upload the edit interrupted failed: %v", err)
	}

	fbComplete(t, pl.Stores().ForType(manifest.TypeFreeBSD), catA, "a.pkg")
	fbComplete(t, bulk, catB, "b.pkg")
}
