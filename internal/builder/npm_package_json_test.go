package builder

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// npmTGZ packs entries into a gzipped tar the way npm publishes one: every
// path under a single package/ root. entries maps a path relative to that root
// to its content.
func npmTGZ(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// npmPackageTGZ is the common case: one package.json at the published root.
func npmPackageTGZ(t *testing.T, packageJSON string) []byte {
	t.Helper()
	return npmTGZ(t, map[string]string{"package/package.json": packageJSON})
}

func writeTGZ(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pkg-1.0.0.tgz")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}
	return path
}

func TestReadNpmPackageJSONReadsTheRootPackageJSON(t *testing.T) {
	path := writeTGZ(t, npmPackageTGZ(t, `{"name":"color-convert","version":"2.0.1",
		"dependencies":{"color-name":"~1.1.4","ansi-styles":"^4.0.0"},
		"devDependencies":{"xo":"^0.24.0"}}`))

	pj, err := readNpmPackageJSON(path)
	deps := pj.Dependencies
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("deps = %+v, want the two runtime dependencies", deps)
	}
	// Sorted by name, so a re-fetch of unchanged bytes rewrites nothing.
	if deps[0].Name != "ansi-styles" || deps[1].Name != "color-name" {
		t.Errorf("deps = %+v, want ansi-styles then color-name", deps)
	}
	if deps[1].Req != "~1.1.4" {
		t.Errorf("color-name req = %q, want ~1.1.4", deps[1].Req)
	}
	for _, d := range deps {
		if d.Name == "xo" {
			t.Error("a devDependency reached the record; npm does not install one for a consumer")
		}
	}
}

// A package declaring none is not the same as a tarball carrying no
// package.json: the first is a leaf, the second is an archive nobody can read
// a declaration out of. Both record nothing, and only the second is a sentinel.
func TestReadNpmPackageJSONDistinguishesItsFailures(t *testing.T) {
	cases := []struct {
		name    string
		body    []byte
		want    error
		wantLen int
	}{
		{
			name: "a leaf package",
			body: npmPackageTGZ(t, `{"name":"color-name","version":"1.1.4"}`),
		},
		{
			name: "no package.json at the root",
			body: npmTGZ(t, map[string]string{"package/index.js": "module.exports = 1\n"}),
			want: errNpmPackageJSONMissing,
		},
		{
			name: "a bundled dependency's package.json is not the archive's",
			body: npmTGZ(t, map[string]string{
				"package/node_modules/dep/package.json": `{"dependencies":{"leftover":"1.0.0"}}`,
			}),
			want: errNpmPackageJSONMissing,
		},
		{
			name: "package.json is not JSON",
			body: npmPackageTGZ(t, "this is not json"),
			want: errNpmPackageJSONUnparseable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pj, err := readNpmPackageJSON(writeTGZ(t, tc.body))
			deps := pj.Dependencies
			if tc.want == nil {
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				if len(deps) != tc.wantLen {
					t.Errorf("deps = %+v, want none", deps)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A tarball that is not an archive at all fails rather than reading as a leaf.
// Read leniently it would record no dependencies for a truncated download and
// publish a package whose install cannot work, which is the shape of failure
// this whole path exists to end.
func TestReadNpmPackageJSONRefusesBytesThatAreNotATarball(t *testing.T) {
	if _, err := readNpmPackageJSON(writeTGZ(t, []byte("not a tarball"))); err == nil {
		t.Error("bytes that are not a gzip stream read as a package with no dependencies")
	}
}

// The ceiling is on the read, not on a length the archive declares. A tar
// header is attacker-controlled, so a member claiming to be small and
// streaming forever has to stop at the cap.
func TestReadNpmPackageJSONStopsAtTheByteCeiling(t *testing.T) {
	padding := make([]byte, npmPackageJSONMaxBytes+1)
	for i := range padding {
		padding[i] = 'x'
	}
	body := `{"name":"huge","_pad":"` + string(padding) + `"}`

	_, err := readNpmPackageJSON(writeTGZ(t, npmPackageTGZ(t, body)))
	if !errors.Is(err, errNpmPackageJSONUnparseable) {
		t.Errorf("err = %v, want %v for a package.json over the ceiling", err, errNpmPackageJSONUnparseable)
	}
}

// npm links executables from the packument's bin, so the read has to turn both
// package.json spellings into the one map the packument publishes. The string
// form names its command after the unscoped basename, as npm does: a scoped
// package with "bin": "./cli.js" installs a command called "cli", not "@acme/cli".
func TestReadNpmPackageJSONRecordsBin(t *testing.T) {
	cases := []struct {
		name        string
		packageJSON string
		want        map[string]string
		wantDropped int
	}{
		{
			name:        "the string form",
			packageJSON: `{"name":"@acme/cli","version":"1.0.0","bin":"./bin/cli.cjs"}`,
			want:        map[string]string{"cli": "./bin/cli.cjs"},
		},
		{
			name:        "the object form, kept as written",
			packageJSON: `{"name":"prettier","version":"3.9.9","bin":{"prettier":"./bin/prettier.cjs","pretty":"bin/p.js"}}`,
			want:        map[string]string{"prettier": "./bin/prettier.cjs", "pretty": "bin/p.js"},
		},
		{
			name: "unsafe entries dropped, the rest kept",
			packageJSON: `{"name":"evil","version":"1.0.0","bin":{
				"ok":"./bin/ok.js",
				"../escape":"./bin/a.js",
				"win\\escape":"./bin/b.js",
				"abs":"/usr/bin/env",
				"winabs":"C:\\tools\\x.exe",
				"climb":"./bin/../../outside.js",
				"winclimb":"bin\\..\\..\\outside.js"}}`,
			want:        map[string]string{"ok": "./bin/ok.js"},
			wantDropped: 6,
		},
		{
			name:        "a member that is not a string",
			packageJSON: `{"name":"odd","version":"1.0.0","bin":{"ok":"./ok.js","num":7}}`,
			want:        map[string]string{"ok": "./ok.js"},
			wantDropped: 1,
		},
		{
			name:        "a bin that is neither form",
			packageJSON: `{"name":"odd","version":"1.0.0","bin":["./ok.js"],"dependencies":{"a":"1"}}`,
			wantDropped: 1,
		},
		{
			name:        "no bin",
			packageJSON: `{"name":"left-pad","version":"1.3.0"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pj, err := readNpmPackageJSON(writeTGZ(t, npmPackageTGZ(t, tc.packageJSON)))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(pj.Bin) != len(tc.want) {
				t.Errorf("bin = %v, want %v", pj.Bin, tc.want)
			}
			for cmd, path := range tc.want {
				if pj.Bin[cmd] != path {
					t.Errorf("bin[%q] = %q, want %q", cmd, pj.Bin[cmd], path)
				}
			}
			if len(pj.DroppedBin) != tc.wantDropped {
				t.Errorf("dropped = %q, want %d entries", pj.DroppedBin, tc.wantDropped)
			}
		})
	}
}
