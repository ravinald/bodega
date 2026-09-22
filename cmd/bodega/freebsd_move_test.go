package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/placement"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

const (
	fbABI  = "FreeBSD:14:amd64"
	fbRepo = "latest"
)

// fbGeneration is the bytes of one published generation of a repository, kept
// so a test can ask which one reached a backend rather than inferring it from
// a size two generations share.
type fbGeneration struct {
	meta    string
	data    string
	catalog string
	objects []string
}

func fbKey(rel string) string { return manifest.FreeBSDKey(fbABI, fbRepo, rel) }

// fbGenerate writes one generation into the build tree and returns its bytes.
// The catalogue and data.pkg name their own object lists, because the two
// archives are fetched a moment apart upstream and the union of the pair is
// what a publication owes a client.
func fbGenerate(t *testing.T, buildRoot string, catalogObjs, dataObjs []string) fbGeneration {
	t.Helper()
	record := func(objs []string) string {
		var b strings.Builder
		for _, o := range objs {
			b.WriteString(`{"name":"p","version":"1","repopath":"` + o + `"}` + "\n")
		}
		return b.String()
	}
	var dataRecords []string
	for _, o := range dataObjs {
		dataRecords = append(dataRecords, `{"name":"p","version":"1","repopath":"`+o+`"}`)
	}
	g := fbGeneration{
		meta:    "packing_format = \"tar\";\n",
		data:    fbTarArchive(t, "data", `{"packages":[`+strings.Join(dataRecords, ",")+`]}`),
		catalog: fbTarArchive(t, "packagesite.yaml", record(catalogObjs)),
	}
	seen := map[string]bool{}
	for _, o := range append(append([]string{}, catalogObjs...), dataObjs...) {
		if !seen[o] {
			seen[o] = true
			g.objects = append(g.objects, o)
		}
	}
	base := "freebsd/" + fbABI + "/" + fbRepo + "/"
	writeFile(t, buildRoot, base+manifest.FreeBSDMetaFile, g.meta)
	writeFile(t, buildRoot, base+manifest.FreeBSDDataFile, g.data)
	writeFile(t, buildRoot, base+manifest.FreeBSDCatalogFile, g.catalog)
	for _, o := range g.objects {
		writeFile(t, buildRoot, base+o, o)
	}
	return g
}

// fbPublish uploads whatever is in the build tree through the production
// placement path, so a test's idea of a published repository is the one the
// uploader has.
func fbPublish(t *testing.T, ctx context.Context, cfg *builder.Config, store *manifest.Store, resolver storage.Resolver) {
	t.Helper()
	if _, err := placement.NewWith(resolver, store, io.Discard, false).UploadType(ctx, cfg, manifest.TypeFreeBSD); err != nil {
		t.Fatalf("publish the generation: %v", err)
	}
}

// fbAssertComplete reads the three repository-root files back out of store and
// asserts every repopath they name between them is an object there.
//
// It reads the backend rather than the bytes the test published, because the
// property is about the repository a client finds: whichever archives are
// being served, the packages they resolve have to be fetchable from the same
// place.
func fbAssertComplete(t *testing.T, ctx context.Context, store storage.ObjectStore, where string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range manifest.FreeBSDCatalogFiles {
		body, err := store.Get(ctx, fbKey(name))
		if err != nil {
			t.Fatalf("%s: read %s: %v", where, name, err)
		}
		if body == nil {
			t.Fatalf("%s: %s is not there, so no repository is being served", where, name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("%s: stage %s: %v", where, name, err)
		}
	}
	paths, err := builder.FreeBSDRepoPaths(dir)
	if err != nil {
		t.Fatalf("%s: enumerate the served archives: %v", where, err)
	}
	for _, rel := range paths {
		info, err := store.Head(ctx, fbKey(rel))
		if err != nil {
			t.Fatalf("%s: head %s: %v", where, rel, err)
		}
		if !info.Exists {
			t.Fatalf("%s: the archives being served name %s, which is not there", where, rel)
		}
	}
}

func fbRoots(t *testing.T, ctx context.Context, store storage.ObjectStore) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range manifest.FreeBSDCatalogFiles {
		body, err := store.Get(ctx, fbKey(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = string(body)
	}
	return out
}

// fbFixture seeds one freebsd entry and returns the manifest store, the build
// config, both backends and the resolver over them.
func fbFixture(t *testing.T) (*manifest.Store, *builder.Config, *storage.Local, *storage.Local, *testResolver) {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeFreeBSD, fbRepo, manifest.VersionEntry{
		Version: fbABI,
		URL:     "https://pkg.freebsd.org/" + fbABI + "/" + fbRepo,
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	src := storage.NewLocal(t.TempDir())
	dst := storage.NewLocal(t.TempDir())
	cfg := &builder.Config{BuildRoot: t.TempDir(), Stdout: io.Discard}
	return store, cfg, src, dst, &testResolver{def: src, bulk: dst}
}

func fbMover(t *testing.T, store *manifest.Store, resolver *testResolver, dst storage.ObjectStore, del bool) (*mover, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &mover{
		stores:  resolver,
		dst:     dst,
		dstName: "bulk",
		store:   store,
		spool:   t.TempDir(),
		out:     out,
		del:     del,
	}, out
}

func fbEntry(t *testing.T, ctx context.Context, store *manifest.Store) *manifest.PackageManifest {
	t.Helper()
	pm, err := store.GetPackage(ctx, manifest.TypeFreeBSD, fbRepo)
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	return pm
}

// headHook runs once, after the wrapped store answers its first Head.
type headHook struct {
	storage.ObjectStore
	run func()
}

func (s *headHook) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	info, err := s.ObjectStore.Head(ctx, key)
	if err == nil && s.run != nil {
		run := s.run
		s.run = nil
		run()
	}
	return info, err
}

// putRecorder remembers the order keys were written in.
type putRecorder struct {
	storage.ObjectStore
	keys []string
}

func (s *putRecorder) PutFile(ctx context.Context, local, key string) error {
	if err := s.ObjectStore.PutFile(ctx, local, key); err != nil {
		return err
	}
	s.keys = append(s.keys, key)
	return nil
}

// TestFreeBSDMovePublishesOnlyTheGenerationItCopied is the interleaving that
// sent this item back: an upload completing a whole new generation on the
// source while a move of the old one is in flight.
//
// The move used to enumerate the source by listing its prefix and then reopen
// the catalogue keys to copy them, so it carried generation A's object list
// and generation B's catalogue bytes and published the pair. The destination
// served a catalogue naming a package it did not hold; the source still had
// the complete generation; both commands reported success.
//
// The assertion is not that the move picks A. It is that whichever archives
// reach the destination, every repopath they name is there with them.
func TestFreeBSDMovePublishesOnlyTheGenerationItCopied(t *testing.T) {
	ctx := t.Context()
	store, cfg, src, dst, resolver := fbFixture(t)

	genA := fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/a-1~2$aaa.pkg"}, []string{"All/Hashed/a-1~2$aaa.pkg"})
	fbPublish(t, ctx, cfg, store, resolver)

	// The upload lands the moment the move stops reading the repository root
	// and starts on the objects, which is the one instant the old code could
	// not survive.
	hooked := &headHook{ObjectStore: src, run: func() {
		fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/b-1~2$bbb.pkg"}, []string{"All/Hashed/b-1~2$bbb.pkg"})
		_ = os.Remove(filepath.Join(cfg.BuildRoot, "freebsd", fbABI, fbRepo, "All/Hashed/a-1~2$aaa.pkg"))
		fbPublish(t, ctx, cfg, store, resolver)
	}}
	resolver.def = hooked

	m, _ := fbMover(t, store, resolver, dst, false)
	pm := fbEntry(t, ctx, store)
	if err := m.moveVersion(ctx, pm, 0); err != nil {
		t.Fatalf("move: %v", err)
	}

	fbAssertComplete(t, ctx, dst, "destination")
	if got := fbRoots(t, ctx, dst)[manifest.FreeBSDCatalogFile]; got != genA.catalog {
		t.Fatalf("destination serves a catalogue this move never copied")
	}
	if got := effectiveStorage(fbEntry(t, ctx, store).Versions[0].Storage); got != "bulk" {
		t.Fatalf("recorded backend is %q, want bulk", got)
	}
}

// TestFreeBSDMoveRefusalKeepsThePriorDestinationRepository covers the other
// half: a move that cannot establish the set must leave the destination
// serving whatever it served before, and must not repoint the manifest.
func TestFreeBSDMoveRefusalKeepsThePriorDestinationRepository(t *testing.T) {
	ctx := t.Context()
	store, cfg, src, dst, resolver := fbFixture(t)

	// The destination already holds a complete repository, published the same
	// way any other would have been.
	prior := fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/x-1~2$xxx.pkg"}, []string{"All/Hashed/x-1~2$xxx.pkg"})
	fbPublish(t, ctx, cfg, store, &testResolver{def: dst, bulk: dst})

	fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/a-1~2$aaa.pkg"}, []string{"All/Hashed/c-1~2$ccc.pkg"})
	fbPublish(t, ctx, cfg, store, resolver)
	// One object named by data.pkg goes missing from the source between the
	// upload and the move, which is what a hand-run delete or a lost write
	// looks like from here.
	if err := src.Delete(ctx, fbKey("All/Hashed/c-1~2$ccc.pkg")); err != nil {
		t.Fatalf("delete the source object: %v", err)
	}

	m, _ := fbMover(t, store, resolver, dst, false)
	pm := fbEntry(t, ctx, store)
	pm.Versions[0].Storage = ""
	err := m.moveVersion(ctx, pm, 0)
	if err == nil {
		t.Fatal("move reported success over an object the archives name and the source does not hold")
	}
	if !strings.Contains(err.Error(), "c-1~2$ccc.pkg") {
		t.Fatalf("the refusal does not name the missing object: %v", err)
	}

	roots := fbRoots(t, ctx, dst)
	if roots[manifest.FreeBSDCatalogFile] != prior.catalog || roots[manifest.FreeBSDDataFile] != prior.data {
		t.Fatal("the refused move replaced the repository the destination was already serving")
	}
	fbAssertComplete(t, ctx, dst, "destination")
	if got := effectiveStorage(fbEntry(t, ctx, store).Versions[0].Storage); got != storage.DefaultName {
		t.Fatalf("a refused move repointed the manifest at %q", got)
	}
}

// TestFreeBSDMoveWritesEveryObjectBeforeAnyRootFile pins the ordering the
// whole type is built on, on the third path a repository reaches storage by.
// The union is part of it: data.pkg names a package the catalogue does not,
// and both archives are published, so both lists have to be copied.
func TestFreeBSDMoveWritesEveryObjectBeforeAnyRootFile(t *testing.T) {
	ctx := t.Context()
	store, cfg, src, dst, resolver := fbFixture(t)

	gen := fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/a-1~2$aaa.pkg"}, []string{"root.pkg"})
	fbPublish(t, ctx, cfg, store, resolver)

	recorder := &putRecorder{ObjectStore: dst}
	m, _ := fbMover(t, store, resolver, recorder, true)
	if err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0); err != nil {
		t.Fatalf("move: %v", err)
	}

	var firstRoot = -1
	for i, key := range recorder.keys {
		if key == fbKey(manifest.FreeBSDMetaFile) {
			firstRoot = i
			break
		}
	}
	if firstRoot < 0 {
		t.Fatalf("no repository root file was written: %v", recorder.keys)
	}
	for _, rel := range gen.objects {
		var at = -1
		for i, key := range recorder.keys {
			if key == fbKey(rel) {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("%s was never copied: %v", rel, recorder.keys)
		}
		if at > firstRoot {
			t.Fatalf("%s was written after the repository root: %v", rel, recorder.keys)
		}
	}
	want := []string{manifest.FreeBSDMetaFile, manifest.FreeBSDDataFile, manifest.FreeBSDCatalogFile}
	for i, name := range want {
		if got := recorder.keys[firstRoot+i]; got != fbKey(name) {
			t.Fatalf("root file %d is %s, want %s", i, got, fbKey(name))
		}
	}

	roots := fbRoots(t, ctx, dst)
	if roots[manifest.FreeBSDCatalogFile] != gen.catalog || roots[manifest.FreeBSDDataFile] != gen.data {
		t.Fatal("the published archives are not the bytes the move copied")
	}
	fbAssertComplete(t, ctx, dst, "destination")
	if info, err := src.Head(ctx, fbKey(manifest.FreeBSDCatalogFile)); err != nil || info.Exists {
		t.Fatalf("--delete-source left the catalogue on the source: %v %v", info, err)
	}
}

// TestFreeBSDMoveRefusesACatalogueTheManifestDoesNotRecord keeps the digest
// check ahead of the first destination write. Asking after the objects are
// copied would be asking after meta.conf and data.pkg had already replaced the
// generation the destination was serving.
func TestFreeBSDMoveRefusesACatalogueTheManifestDoesNotRecord(t *testing.T) {
	ctx := t.Context()
	store, cfg, _, dst, resolver := fbFixture(t)

	fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/a-1~2$aaa.pkg"}, []string{"All/Hashed/a-1~2$aaa.pkg"})
	fbPublish(t, ctx, cfg, store, resolver)

	pm := fbEntry(t, ctx, store)
	pm.Versions[0].Checksum = &manifest.Checksum{Algorithm: "sha256", Value: strings.Repeat("0", 64)}
	if err := store.SavePackage(ctx, pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	recorder := &putRecorder{ObjectStore: dst}
	m, _ := fbMover(t, store, resolver, recorder, false)
	if err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0); err == nil {
		t.Fatal("move published a catalogue the manifest does not record")
	}
	if len(recorder.keys) != 0 {
		t.Fatalf("the refusal came after %d write(s) to the destination: %v", len(recorder.keys), recorder.keys)
	}
	if got := effectiveStorage(fbEntry(t, ctx, store).Versions[0].Storage); got != storage.DefaultName {
		t.Fatalf("a refused move repointed the manifest at %q", got)
	}
}

// TestFreeBSDMoveRefusesAnEntryWithNoPublishedRepository is the message an
// operator meets for the commonest mistake: moving an entry whose repository
// was never uploaded to the backend it is recorded on.
func TestFreeBSDMoveRefusesAnEntryWithNoPublishedRepository(t *testing.T) {
	ctx := t.Context()
	store, _, _, dst, resolver := fbFixture(t)

	recorder := &putRecorder{ObjectStore: dst}
	m, _ := fbMover(t, store, resolver, recorder, false)
	err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0)
	if err == nil {
		t.Fatal("move reported success against a backend holding no repository")
	}
	for _, want := range []string{manifest.FreeBSDMetaFile, "bodega build upload freebsd", storage.DefaultName} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q: %v", want, err)
		}
	}
	if len(recorder.keys) != 0 {
		t.Fatalf("the refusal came after %d write(s): %v", len(recorder.keys), recorder.keys)
	}
}

// TestFreeBSDMoveRefusesACatalogueNamingARepositoryRootFile covers the third
// writer against the same untrusted input.
//
// The move reads its pinned archives to learn what it owes the destination,
// and a record landing on a root file would be copied inside the object loop —
// ahead of the pinned root files, so the destination's previous catalogue is
// replaced by a generation whose remaining objects have not been copied yet.
// A source object going missing after that leaves the destination serving a
// repository nobody can install from, and the move returns an error saying
// nothing was written.
//
// data.pkg carries the record here so the refusal cannot come from the
// catalogue digest the manifest records, which is checked over
// packagesite.pkg before this.
func TestFreeBSDMoveRefusesACatalogueNamingARepositoryRootFile(t *testing.T) {
	ctx := t.Context()
	store, cfg, src, dst, resolver := fbFixture(t)

	prior := fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/x-1~2$xxx.pkg"}, []string{"All/Hashed/x-1~2$xxx.pkg"})
	fbPublish(t, ctx, cfg, store, &testResolver{def: dst, bulk: dst})

	fbGenerate(t, cfg.BuildRoot, []string{"All/Hashed/a-1~2$aaa.pkg"}, []string{"All/Hashed/a-1~2$aaa.pkg"})
	fbPublish(t, ctx, cfg, store, resolver)

	// Written straight to the backend: this uploader refuses such a record, so
	// the way one reaches a source is an older bodega, another mirror, or a
	// hand-placed file. The move's job is to refuse what it finds there.
	poisoned := fbTarArchive(t, "data", `{"packages":[`+
		`{"name":"p","version":"1","repopath":"./`+manifest.FreeBSDDataFile+`"},`+
		`{"name":"p","version":"1","repopath":"All/Hashed/missing-1~2$mmm.pkg"}]}`)
	if err := src.Put(ctx, fbKey(manifest.FreeBSDDataFile), []byte(poisoned)); err != nil {
		t.Fatalf("write the poisoned data.pkg to the source: %v", err)
	}

	recorder := &putRecorder{ObjectStore: dst}
	m, _ := fbMover(t, store, resolver, recorder, false)
	pm := fbEntry(t, ctx, store)
	pm.Versions[0].Storage = ""
	err := m.moveVersion(ctx, pm, 0)
	if err == nil {
		t.Fatal("move published a catalogue naming a repository-root file as a package")
	}
	if len(recorder.keys) != 0 {
		t.Fatalf("the refusal came after %d write(s) to the destination: %v", len(recorder.keys), recorder.keys)
	}
	roots := fbRoots(t, ctx, dst)
	if roots[manifest.FreeBSDCatalogFile] != prior.catalog || roots[manifest.FreeBSDDataFile] != prior.data {
		t.Fatal("the refused move replaced the repository the destination was already serving")
	}
	if !strings.Contains(err.Error(), manifest.FreeBSDDataFile) {
		t.Fatalf("the refusal does not name the root file the record landed on: %v", err)
	}
	fbAssertComplete(t, ctx, dst, "destination")
	if got := effectiveStorage(fbEntry(t, ctx, store).Versions[0].Storage); got != storage.DefaultName {
		t.Fatalf("a refused move repointed the manifest at %q", got)
	}
}

// ---- a repository bodega generates the catalogue for -----------------------
//
// Its packages are the whole of it: the three root files are built per request
// from whatever backend the manifest names, so nothing is stored under them
// and the listing under the prefix is the document. A move that demanded those
// files refused every generated repository outright, with the fix it suggested
// — upload again — unable to produce them.

// fbGeneratedFixture seeds a generated entry, two packages and an alias of one
// of them in the build tree, and publishes them through the production upload.
func fbGeneratedFixture(t *testing.T) (*config.Config, *manifest.Store, storage.Resolver, map[string]string) {
	t.Helper()
	ctx := t.Context()
	defaultRoot, bulkRoot, buildRoot := t.TempDir(), t.TempDir(), t.TempDir()
	cfg := &config.Config{
		ManifestDir:     "manifests",
		StorageBackend:  "local",
		StoragePath:     defaultRoot,
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: bulkRoot}},
	}
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(ctx, manifest.TypeFreeBSD, fbRepo, manifest.VersionEntry{
		Version:   fbABI,
		Generated: true,
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	packages := map[string]string{
		"All/widget-1.2.0.pkg": fbTarArchive(t, "+COMPACT_MANIFEST", `{"name":"widget","origin":"misc/widget","version":"1.2.0"}`),
		"All/tool-3.1.pkg":     fbTarArchive(t, "+COMPACT_MANIFEST", `{"name":"tool","origin":"misc/tool","version":"3.1"}`),
	}
	base := "freebsd/" + fbABI + "/" + fbRepo + "/"
	for rel, body := range packages {
		writeFile(t, buildRoot, base+rel, body)
	}
	if err := os.Symlink(filepath.Join(buildRoot, filepath.FromSlash(base+"All/widget-1.2.0.pkg")),
		filepath.Join(buildRoot, filepath.FromSlash(base+"All/widget.pkg"))); err != nil {
		t.Fatalf("link the alias: %v", err)
	}

	stores, err := storage.NewResolver(ctx, cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	fbPublish(t, ctx, &builder.Config{BuildRoot: buildRoot, ManifestDir: "manifests", Stdout: io.Discard}, store, stores)
	return cfg, store, stores, packages
}

func fbPrefixKeys(t *testing.T, ctx context.Context, store storage.ObjectStore) []string {
	t.Helper()
	keys, err := store.List(ctx, manifest.FreeBSDRepoPrefix(fbABI, fbRepo))
	if err != nil {
		t.Fatalf("list the repository prefix: %v", err)
	}
	slices.Sort(keys)
	return keys
}

// The whole chain for a generated repository: upload, move to a named backend,
// delete the source, then read the catalogue and a package the way pkg does.
//
// The serving half is the assertion that matters. A move that copied the
// objects and stopped would pass a listing comparison and still leave `pkg
// update` answering 404, because nothing but VersionEntry.Storage says which
// backend the catalogue is built over.
func TestFreeBSDGeneratedMoveServesFromTheDestination(t *testing.T) {
	ctx := t.Context()
	cfg, store, stores, packages := fbGeneratedFixture(t)
	src, dst := stores.Default(), mustByName(t, stores, "bulk")
	before := fbPrefixKeys(t, ctx, src)
	if len(before) != len(packages) {
		t.Fatalf("the upload placed %v, want one object per package", before)
	}

	m := &mover{stores: stores, dst: dst, dstName: "bulk", store: store, spool: t.TempDir(), out: &bytes.Buffer{}, del: true}
	if err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0); err != nil {
		t.Fatalf("move the generated repository: %v", err)
	}
	if got := fbPrefixKeys(t, ctx, dst); !slices.Equal(got, before) {
		t.Fatalf("%q holds %v after the move, want the source's %v", "bulk", got, before)
	}
	if got := fbPrefixKeys(t, ctx, src); len(got) != 0 {
		t.Errorf("--delete-source left %v on the source", got)
	}

	ts := httptest.NewServer(server.New(cfg, store, stores, ":0", nil).Handler())
	t.Cleanup(ts.Close)
	body := fbGet(t, ts.URL+"/freebsd/"+fbABI+"/"+fbRepo+"/"+manifest.FreeBSDCatalogFile)
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(fbArchiveMember(t, body, "packagesite.yaml")), "\n") {
		var rec struct {
			Name     string `json:"name"`
			RepoPath string `json:"repopath"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("read a catalogue record: %v", err)
		}
		names = append(names, rec.Name)
		if got := fbGet(t, ts.URL+"/freebsd/"+fbABI+"/"+fbRepo+"/"+rec.RepoPath); got != packages[rec.RepoPath] {
			t.Errorf("GET %s served %d bytes, want the package's %d", rec.RepoPath, len(got), len(packages[rec.RepoPath]))
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"tool", "widget"}) {
		t.Errorf("the catalogue served from the destination names %v, want both packages once each", names)
	}
}

// fbGet reads one URL that must answer 200.
func fbGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // the URL is this test's own httptest server
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	return string(body)
}

// fbArchiveMember reads one member out of a generated zstd archive.
func fbArchiveMember(t *testing.T, body, member string) string {
	t.Helper()
	dec, err := zstd.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("open a zstd reader: %v", err)
	}
	defer dec.Close()
	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read the archive: %v", err)
		}
		if hdr.Name != member {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", member, err)
		}
		return string(data)
	}
	t.Fatalf("the archive carries no %s member", member)
	return ""
}

// A destination already holding objects under this repository's prefix is
// refused before anything is copied.
//
// This is the check a mirror does not need: its catalogue would simply not
// name a stranger, while a generated catalogue is the listing, so the moved
// repository would publish it as a package nobody uploaded.
func TestFreeBSDGeneratedMoveRefusesADestinationHoldingAStranger(t *testing.T) {
	ctx := t.Context()
	_, store, stores, _ := fbGeneratedFixture(t)
	dst := mustByName(t, stores, "bulk")
	stranger := manifest.FreeBSDKey(fbABI, fbRepo, "All/leftover-9.9.pkg")
	if err := dst.Put(ctx, stranger, []byte("from an older move")); err != nil {
		t.Fatalf("seed the destination: %v", err)
	}

	m := &mover{stores: stores, dst: dst, dstName: "bulk", store: store, spool: t.TempDir(), out: &bytes.Buffer{}, del: true}
	err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0)
	if err == nil {
		t.Fatal("the move published a repository holding a package the source never had")
	}
	if !strings.Contains(err.Error(), stranger) {
		t.Errorf("the refusal does not name the object to remove: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeFreeBSD, fbRepo, fbABI); got != "" {
		t.Errorf("recorded storage = %q, want the source: nothing was committed", got)
	}
	if got := fbPrefixKeys(t, ctx, stores.Default()); len(got) == 0 {
		t.Error("the refusal removed the source copies")
	}
}

// An upload landing while the move is copying is refused rather than
// half-moved. Committing would point the manifest at the destination while the
// packages that landed in between sit on the backend it is about to stop
// naming — and the catalogue is built from whichever one the manifest names,
// so those packages would vanish from it with both commands reporting success.
func TestFreeBSDGeneratedMoveRefusesARepositoryThatChangedMidMove(t *testing.T) {
	ctx := t.Context()
	_, store, stores, _ := fbGeneratedFixture(t)
	src, dst := stores.Default(), mustByName(t, stores, "bulk")
	late := manifest.FreeBSDKey(fbABI, fbRepo, "All/gadget-0.1.pkg")
	hooked := &headHook{ObjectStore: src, run: func() {
		if err := src.Put(ctx, late, []byte("uploaded mid-move")); err != nil {
			t.Errorf("seed the late upload: %v", err)
		}
	}}

	m := &mover{
		stores: &testResolver{def: hooked, bulk: dst}, dst: dst, dstName: "bulk",
		store: store, spool: t.TempDir(), out: &bytes.Buffer{}, del: true,
	}
	err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0)
	if err == nil {
		t.Fatal("the move committed a repository whose object set moved under it")
	}
	if !strings.Contains(err.Error(), "changed while the move was copying it") {
		t.Errorf("the refusal does not say what happened: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeFreeBSD, fbRepo, fbABI); got != "" {
		t.Errorf("recorded storage = %q, want the source: nothing was committed", got)
	}
	if info, err := src.Head(ctx, late); err != nil || !info.Exists {
		t.Error("the package that landed mid-move is gone from the source")
	}
}

// flipStore writes the bytes it was handed with one of them changed, keeping
// the length. It stands in for the class of fault a size check cannot see: a
// storage or transport error that preserves how much arrived.
type flipStore struct {
	storage.ObjectStore
	key string
}

func (s *flipStore) PutFile(ctx context.Context, local, key string) error {
	if key != s.key {
		return s.ObjectStore.PutFile(ctx, local, key)
	}
	body, err := os.ReadFile(local) //nolint:gosec // G304: the spool file this move just wrote.
	if err != nil {
		return err
	}
	body[len(body)/2] ^= 0xff
	return s.Put(ctx, key, body)
}

// A package whose bytes change in transit is refused before the manifest moves.
//
// This is the check a mirrored repository does not need, and the reason is the
// whole difference between the two halves of this file. A mirror publishes
// archives naming a sum for every package it carries, so a copy that arrived
// wrong is refused by the client that downloads it. A generated catalogue takes
// every sum from whatever is in the store when it builds, so the same fault is
// written into the catalogue as the truth: pkg fetches the corrupted package,
// checks it against the sum computed from the corrupted package, and installs
// it. With --delete-source the copy that was right is already gone.
func TestFreeBSDGeneratedMoveRefusesAPackageThatChangedInTransit(t *testing.T) {
	ctx := t.Context()
	_, store, stores, _ := fbGeneratedFixture(t)
	src := stores.Default()
	corrupt := manifest.FreeBSDKey(fbABI, fbRepo, "All/tool-3.1.pkg")
	dst := &flipStore{ObjectStore: mustByName(t, stores, "bulk"), key: corrupt}

	m := &mover{
		stores: &testResolver{def: src, bulk: dst}, dst: dst, dstName: "bulk",
		store: store, spool: t.TempDir(), out: &bytes.Buffer{}, del: true,
	}
	err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0)
	if err == nil {
		t.Fatal("the move committed a repository holding a package whose bytes changed in transit")
	}
	if !strings.Contains(err.Error(), "changed in transit") || !strings.Contains(err.Error(), corrupt) {
		t.Errorf("the refusal does not name the object and what happened to it: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeFreeBSD, fbRepo, fbABI); got != "" {
		t.Errorf("recorded storage = %q, want the source: nothing was committed", got)
	}
	// --delete-source runs only after the commit, so the good copy is still
	// there to move again once the backend is fixed.
	if info, err := src.Head(ctx, corrupt); err != nil || !info.Exists {
		t.Error("the refusal deleted the source copy that was still correct")
	}
}

// An entry marked generated with nothing uploaded is refused by name. The
// mirror's message here sends an operator to `bodega build upload`, which is
// the right instruction for both, but only after saying which of the two
// repositories is empty.
func TestFreeBSDGeneratedMoveRefusesAnEmptyRepository(t *testing.T) {
	ctx := t.Context()
	store, _, _, dst, resolver := fbFixture(t)
	pm := fbEntry(t, ctx, store)
	pm.Versions[0].Generated = true
	pm.Versions[0].URL = ""
	if err := store.SavePackage(ctx, pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	m, _ := fbMover(t, store, resolver, dst, false)
	err := m.moveVersion(ctx, fbEntry(t, ctx, store), 0)
	if err == nil {
		t.Fatal("the move reported success over a repository with no packages")
	}
	if !strings.Contains(err.Error(), "bodega build upload freebsd") {
		t.Errorf("the refusal does not say how to fill it: %v", err)
	}
}
