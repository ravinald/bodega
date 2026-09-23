package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// Four answers to "which object backs this manifest entry" used to exist —
// builder, server, inventory and the delete path — and three of the five types
// anybody checked disagreed. A per-type unit test in each package is what let
// that happen: each one passed in a world where the disagreement could not
// show up.
//
// So this test refuses to name a key. For every one of the eight types it
// seeds an artifact through the uploader, then asks the other three where it
// went, and the assertion is only that they agree with what the uploader
// actually wrote. Changing a layout in manifest/keys.go keeps this green;
// changing it in one consumer does not.

// keyCase describes one type's round trip from local artifact to served bytes.
type keyCase struct {
	typ  string
	pkg  string // canonical name, slashes intact
	ve   manifest.VersionEntry
	body string

	// local maps each path the builder expects to find, relative to the build
	// root, to its contents. Exactly one holds body; a type whose artifact
	// travels with siblings gives them distinct bytes so the primary key is
	// identified by what is in it rather than by where the test put it.
	local map[string]string

	// upload runs the same call 'bodega build upload' makes for this type and
	// returns every key it wrote.
	upload func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string

	// url is the path a client of this ecosystem requests.
	url string

	// configure adjusts the server's config for a type that needs more than
	// the shared one, given the temporary directory the case may write into.
	configure func(t *testing.T, cfg *config.Config)

	// noVersionKey marks a type whose artifacts are not addressable one
	// version at a time. pypi is the only one, and the agreement to assert is
	// that inventory and the delete path both refuse rather than one of them
	// inventing a key.
	noVersionKey bool
}

func artifactPathUpload(paths []builder.ArtifactPath, dst storage.ObjectStore, t *testing.T) []string {
	t.Helper()
	var keys []string
	for _, ap := range paths {
		if err := dst.PutFile(t.Context(), ap.Local, ap.ObjectKey); err != nil {
			t.Fatalf("upload %s: %v", ap.Local, err)
		}
		keys = append(keys, ap.ObjectKey)
	}
	return keys
}

// syncDirUpload is pypi's uploader, and only pypi's. Every other type resolves
// one key per version through its ArtifactPaths function; a whole-tree sync has
// no per-version granularity, which is what kept apt and git unmovable.
func syncDirUpload(t *testing.T, dst storage.ObjectStore, localDir, prefix string) []string {
	t.Helper()
	if _, err := dst.SyncDir(t.Context(), io.Discard, localDir, prefix); err != nil {
		t.Fatalf("sync %s: %v", localDir, err)
	}
	keys, err := dst.List(t.Context(), prefix)
	if err != nil {
		t.Fatalf("list %s: %v", prefix, err)
	}
	return keys
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// fbTarArchive is one repository archive with one member, packed with
// packing_format = "tar". Uncompressed on purpose: this test is about which
// key an object lands under, and a codec between the fixture and the reader
// would only be one more thing to get wrong.
func fbTarArchive(t *testing.T, member, payload string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o644, Size: int64(len(payload))}); err != nil {
		t.Fatalf("write the %s header: %v", member, err)
	}
	if _, err := tw.Write([]byte(payload)); err != nil {
		t.Fatalf("write %s: %v", member, err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}
	return buf.String()
}

func objectKeyCases(t *testing.T) []keyCase {
	t.Helper()
	return []keyCase{
		{
			typ:  manifest.TypeBinary,
			pkg:  "example-tool-v2",
			ve:   manifest.VersionEntry{Version: "2.34.24", URL: "https://example.com/example-tool-exe.zip"},
			body: "binary-bytes",
			local: map[string]string{
				"binaries/example-tool-v2/2.34.24/example-tool-exe.zip": "binary-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.BinaryArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/binaries/example-tool-v2/2.34.24/example-tool-exe.zip",
		},
		{
			// A slash in the name is the whole hazard: git stores it encoded.
			typ:  manifest.TypeGit,
			pkg:  "example-corp/widget",
			ve:   manifest.VersionEntry{URL: "https://example.com/example-corp/widget", Ref: "v4.5.7", Source: "clone"},
			body: "bundle-bytes",
			local: map[string]string{
				"bundles/example-corp--widget/example-corp--widget-v4.5.7.bundle": "bundle-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.GitArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/git/example-corp--widget/example-corp--widget-v4.5.7.bundle",
		},
		{
			typ: manifest.TypeApt,
			pkg: "acme",
			ve: manifest.VersionEntry{
				Version:    "1.0",
				SourceName: "acme",
				Metadata: map[string]string{
					"Architecture": "amd64",
					"_pool_path":   "pool/main/a/acme/acme_1.0_amd64.deb",
				},
			},
			body: "deb-bytes",
			local: map[string]string{
				"apt-repo/pool/main/a/acme/acme_1.0_amd64.deb": "deb-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.AptArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/apt/pool/main/a/acme/acme_1.0_amd64.deb",
		},
		{
			typ:  manifest.TypePypi,
			pkg:  "examplesdk",
			ve:   manifest.VersionEntry{Version: "1.35.0"},
			body: "wheel-bytes",
			local: map[string]string{
				"wheels/examplesdk-1.35.0-py3-none-any.whl": "wheel-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				dir, prefix := builder.PypiArtifactDir(bcfg, store)
				return syncDirUpload(t, dst, dir, prefix)
			},
			url:          "/pypi/wheels/examplesdk-1.35.0-py3-none-any.whl",
			noVersionKey: true,
		},
		{
			// The defect this test was written for: the uploader wrote the
			// encoded module path, the Go client asks for the real one.
			typ:  manifest.TypeGomod,
			pkg:  "example.com/example-corp/widget-sdk",
			ve:   manifest.VersionEntry{Version: "v1.30.0"},
			body: "zip-bytes",
			local: map[string]string{
				"gomod/example.com--example-corp--widget-sdk/@v/v1.30.0.zip":  "zip-bytes",
				"gomod/example.com--example-corp--widget-sdk/@v/v1.30.0.info": "info-sibling",
				"gomod/example.com--example-corp--widget-sdk/@v/v1.30.0.mod":  "mod-sibling",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.GomodArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/go/example.com/example-corp/widget-sdk/@v/v1.30.0.zip",
		},
		{
			typ:  manifest.TypeHelm,
			pkg:  "ingress-nginx",
			ve:   manifest.VersionEntry{Version: "4.11.0"},
			body: "chart-bytes",
			local: map[string]string{
				"charts/ingress-nginx/4.11.0/ingress-nginx-4.11.0.tgz": "chart-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.HelmArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/helm/charts/ingress-nginx-4.11.0.tgz",
		},
		{
			// Scoped npm: the wire filename and the stored filename differ.
			typ:  manifest.TypeNpm,
			pkg:  "@example-corp/widget-cli",
			ve:   manifest.VersionEntry{Version: "1.5.0"},
			body: "tarball-bytes",
			local: map[string]string{
				"npm/@example-corp--widget-cli/1.5.0/@example-corp--widget-cli-1.5.0.tgz": "tarball-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.NpmArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/npm/@example-corp/widget-cli/-/widget-cli-1.5.0.tgz",
		},
		{
			typ:  manifest.TypeCargo,
			pkg:  "serde",
			ve:   manifest.VersionEntry{Version: "1.0.200"},
			body: "crate-bytes",
			local: map[string]string{
				"cargo/serde/1.0.200/serde-1.0.200.crate": "crate-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.CargoArtifactPaths(bcfg, store, ""), dst, t)
			},
			url: "/cargo/serde/1.0.200/download",
		},
		{
			// A mirrored repository: the name is the repository directory and
			// the version is the ABI, so the local tree, the object key and
			// the route are all the path a pkg client composes. The package
			// under All/Hashed carries the "~" and "$" the real catalogue
			// does, which is what makes this a test of the key scheme rather
			// than of a fixture.
			typ:  manifest.TypeFreeBSD,
			pkg:  "latest",
			ve:   manifest.VersionEntry{Version: "FreeBSD:14:amd64"},
			body: fbTarArchive(t, "packagesite.yaml", `{"name":"zogftw","version":"2025.02.23_1","repopath":"All/Hashed/zogftw-2025.02.23_1~2$snx.pkg"}`+"\n"),
			local: map[string]string{
				"freebsd/FreeBSD:14:amd64/latest/packagesite.pkg": fbTarArchive(t, "packagesite.yaml",
					`{"name":"zogftw","version":"2025.02.23_1","repopath":"All/Hashed/zogftw-2025.02.23_1~2$snx.pkg"}`+"\n"),
				"freebsd/FreeBSD:14:amd64/latest/data.pkg": fbTarArchive(t, "data",
					`{"packages":[{"name":"zogftw","version":"2025.02.23_1","repopath":"All/Hashed/zogftw-2025.02.23_1~2$snx.pkg"}]}`),
				"freebsd/FreeBSD:14:amd64/latest/meta.conf":                                "packing_format = \"tar\";\n",
				"freebsd/FreeBSD:14:amd64/latest/All/Hashed/zogftw-2025.02.23_1~2$snx.pkg": "one mirrored package",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				paths, release, err := builder.FreeBSDArtifactPaths(bcfg, store, "")
				if err != nil {
					t.Fatalf("enumerate freebsd artifacts: %v", err)
				}
				defer release()
				return artifactPathUpload(paths, dst, t)
			},
			url: "/freebsd/FreeBSD:14:amd64/latest/packagesite.pkg",
		},
		{
			// DIST_SUBDIR in the name is the hazard: the key, the DISTDIR
			// path and the route all have to keep it, or the server's
			// distinfo lookup finds no digest for the file it was handed.
			typ:  manifest.TypeDistfiles,
			pkg:  "pcpustat/1.6.tar.bz2",
			body: "distfile-bytes",
			local: map[string]string{
				"distfiles/pcpustat/1.6.tar.bz2": "distfile-bytes",
			},
			upload: func(t *testing.T, bcfg *builder.Config, store *manifest.Store, dst storage.ObjectStore) []string {
				return artifactPathUpload(builder.DistfilesArtifactPaths(bcfg, store, ""), dst, t)
			},
			configure: func(t *testing.T, cfg *config.Config) {
				tree := t.TempDir()
				sum := sha256.Sum256([]byte("distfile-bytes"))
				writeFile(t, tree, "Mk/bsd.licenses.db.mk", "")
				writeFile(t, tree, "sysutils/pcpustat/Makefile", "PORTNAME=\tpcpustat\nDIST_SUBDIR=\tpcpustat\n")
				writeFile(t, tree, "sysutils/pcpustat/distinfo", fmt.Sprintf(
					"SHA256 (pcpustat/1.6.tar.bz2) = %x\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", sum, len("distfile-bytes")))
				cfg.DistfilesPortsTree = tree
			},
			url: "/distfiles/pcpustat/1.6.tar.bz2",
		},
	}
}

func TestObjectKeysAgreeAcrossUploaderServerInventoryAndDelete(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range objectKeyCases(t) {
		seen[c.typ] = true
		t.Run(c.typ, func(t *testing.T) {
			ctx := t.Context()
			buildRoot := t.TempDir()
			store := manifest.NewLocalStore(t.TempDir())
			if err := store.AddVersion(ctx, c.typ, c.pkg, c.ve); err != nil {
				t.Fatalf("seed manifest: %v", err)
			}
			for rel, body := range c.local {
				writeFile(t, buildRoot, rel, body)
			}

			// 1. The uploader. Everything below compares against what this
			// wrote; nothing here asserts a literal key.
			mem := storage.NewMemory()
			bcfg := &builder.Config{BuildRoot: buildRoot, ManifestDir: "manifests"}
			written := c.upload(t, bcfg, store, mem)
			primary := primaryKeyFor(t, mem, c.body, written)

			// 2. The server handler, reached over the wire the way a client of
			// this ecosystem reaches it.
			cfg := &config.Config{StorageBackend: "local", ManifestDir: "manifests", AptCodename: "noble"}
			if c.configure != nil {
				c.configure(t, cfg)
			}
			stores := storage.NewSingle(mem)
			ts := httptest.NewServer(server.New(cfg, store, stores, ":0", nil).Handler())
			t.Cleanup(ts.Close)
			assertServes(t, ts.URL+c.url, c.body)

			pm, err := store.GetPackage(ctx, c.typ, c.pkg)
			if err != nil || pm == nil {
				t.Fatalf("get %s/%s: %v", c.typ, c.pkg, err)
			}

			// 3. inventory, which 'build status' and 'pkg move' resolve through.
			keys, invErr := inventory.ArtifactKeys(ctx, mem, pm, pm.Versions[0])

			// 4. The delete path.
			removed, delErr := deleteEntryObjects(ctx, stores, store, c.typ, c.pkg, io.Discard)

			if c.noVersionKey {
				if !errors.Is(invErr, manifest.ErrPypiNoObjectKey) {
					t.Errorf("inventory resolved %v (err %v); want the no-per-version-key sentinel", keys, invErr)
				}
				if !errors.Is(delErr, manifest.ErrPypiNoObjectKey) {
					t.Errorf("delete resolved %v (err %v); want the no-per-version-key sentinel", removed, delErr)
				}
				return
			}

			if invErr != nil {
				t.Fatalf("inventory: %v", invErr)
			}
			if len(keys) == 0 || keys[0] != primary {
				t.Errorf("inventory resolves %v, uploader wrote %q", keys, primary)
			}
			if delErr != nil {
				t.Fatalf("delete: %v", delErr)
			}
			if !contains(removed, primary) {
				t.Errorf("delete removed %v, uploader wrote %q", removed, primary)
			}
			if info, err := mem.Head(ctx, primary); err != nil || info.Exists {
				t.Errorf("%q still on the backend after delete (err %v)", primary, err)
			}
		})
	}
	for _, typ := range manifest.AllTypes {
		if !seen[typ] {
			t.Errorf("no case for type %q; every type has to be here or the next drift goes unnoticed", typ)
		}
	}
}

// primaryKeyFor picks the uploaded key holding the artifact body. The uploader
// also writes regenerable siblings — a packument, an index.yaml, a module's
// .info and .mod — and the body is what distinguishes the artifact from them.
func primaryKeyFor(t *testing.T, mem *storage.Memory, body string, written []string) string {
	t.Helper()
	if len(written) == 0 {
		t.Fatal("uploader wrote nothing; the local artifact is not where the builder looks")
	}
	var match []string
	for _, key := range written {
		data, err := mem.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		if string(data) == body {
			match = append(match, key)
		}
	}
	if len(match) == 0 {
		t.Fatalf("none of the uploaded keys %v holds the artifact body", written)
	}
	return match[0]
}

func assertServes(t *testing.T, url, want string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // httptest URL built in this test
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 — the handler resolved a key the uploader never wrote: %s",
			url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if string(body) != want {
		t.Errorf("GET %s served %q, want %q", url, string(body), want)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
