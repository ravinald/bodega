package main

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// TestMovedPackagesStillServeOverHTTP walks the whole chain #67 came out of,
// once per movable type: upload, move to a named backend, delete the source,
// then fetch the artifact the way a client of that ecosystem fetches it.
//
// A test on the resolution helper alone passes against a tree where git is
// broken, which is how git stayed broken through two items. What makes this
// one falsifiable is the source delete: nothing but VersionEntry.Storage says
// where the bytes are afterwards, so a handler resolving through
// storage_by_type — or through the default backend, which is what no rule
// resolves to — answers 404.
//
// The cases are objectkeys_test.go's, so a type added there is covered here
// without a second edit, and a layout changed in manifest/keys.go stays green
// in both.
func TestMovedPackagesStillServeOverHTTP(t *testing.T) {
	for _, c := range objectKeyCases(t) {
		if c.noVersionKey {
			// pypi has no per-version object key, so 'pkg move' refuses it.
			// TestSelectForMoveGuards pins that refusal.
			continue
		}
		t.Run(c.typ, func(t *testing.T) {
			ctx := t.Context()
			defaultRoot, bulkRoot := t.TempDir(), t.TempDir()
			buildRoot := t.TempDir()
			cfg := &config.Config{
				ManifestDir:     "manifests",
				AptCodename:     "noble",
				StorageBackend:  "local",
				StoragePath:     defaultRoot,
				StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: bulkRoot}},
			}

			store := manifest.NewLocalStore(t.TempDir())
			if err := store.AddVersion(ctx, c.typ, c.pkg, c.ve); err != nil {
				t.Fatalf("seed manifest: %v", err)
			}
			for rel, body := range c.local {
				writeFile(t, buildRoot, rel, body)
			}

			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			def, bulk := stores.Default(), mustByName(t, stores, "bulk")
			bcfg := &builder.Config{BuildRoot: buildRoot, ManifestDir: "manifests"}
			if keys := c.upload(t, bcfg, store, def); len(keys) == 0 {
				t.Fatal("the uploader wrote nothing; the local artifact is not where the builder looks")
			}

			pm, err := store.GetPackage(ctx, c.typ, c.pkg)
			if err != nil || pm == nil {
				t.Fatalf("get %s/%s: %v", c.typ, c.pkg, err)
			}
			targets, err := selectForMove(stores, bulk, pm, "", "bulk")
			if err != nil {
				t.Fatalf("selectForMove: %v", err)
			}
			m := &mover{
				stores: stores, dst: bulk, dstName: "bulk", store: store,
				spool: t.TempDir(), out: &bytes.Buffer{}, del: true,
			}
			for _, i := range targets {
				if err := m.moveVersion(ctx, pm, i); err != nil {
					t.Fatalf("moveVersion: %v", err)
				}
			}
			if got := recordedStorage(t, store, c.typ, c.pkg, moveVersionArg(c)); got != "bulk" {
				t.Fatalf("recorded storage = %q, want bulk", got)
			}

			// The server is built after the move so its apt snapshot carries
			// the new placement, which is what an operator gets from the
			// hourly rebuild or a SIGHUP.
			ts := httptest.NewServer(server.New(cfg, store, stores, ":0", nil).Handler())
			t.Cleanup(ts.Close)
			assertServes(t, ts.URL+c.url, c.body)
		})
	}
}

// moveVersionArg names the entry the way recordedStorage looks it up: git
// records a Ref and no Version, every other type the reverse.
func moveVersionArg(c keyCase) string {
	if c.ve.Version != "" {
		return c.ve.Version
	}
	return c.ve.Ref
}

func mustByName(t *testing.T, stores storage.Resolver, name string) storage.ObjectStore {
	t.Helper()
	st, err := stores.ByName(name)
	if err != nil {
		t.Fatalf("ByName(%q): %v", name, err)
	}
	return st
}
