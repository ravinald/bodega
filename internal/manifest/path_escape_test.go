package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageNamesCannotTraverse is half the answer to CodeQL's
// go/path-injection on LocalBackend.Read, Write and Delete. A package name
// arrives in a request body and reaches a filesystem path, so the taint is
// real; two separate guards stand between them and this pins the first.
//
// SafeName collapses "/" to "--", so a name contributes exactly one path
// segment no matter what it contains. That is what makes a traversal
// unconstructible from a name: "../../etc/passwd" becomes the single segment
// "..--..--etc--passwd" before any path is built. The assertion is on the key
// rather than on where a write landed, because a write test passes whether the
// guard is present or absent and proves nothing about either.
func TestPackageNamesCannotTraverse(t *testing.T) {
	// "." and ".." are absent on purpose: they are the one shape SafeName does
	// not neutralize, and TestDotNamesAreRefusedBeforeTheyCollide below covers
	// them instead. They are refused at admission rather than encoded here, so
	// the keys they would derive are unchanged and this test's contract does
	// not reach them.
	hostile := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"....//....//etc/passwd",
		"a/../../../b",
		"../ESCAPED",
		"~/.ssh/authorized_keys",
		"..\\..\\windows",
		"....",
		"../..",
	}
	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			key := manifestPath(TypeApt, name)

			// The key must be exactly type/segment/manifest.json: three parts,
			// with the name occupying one of them.
			parts := strings.Split(key, "/")
			if len(parts) != 3 {
				t.Fatalf("manifestPath(%q) produced %d segments (%q); a name must never add a path level",
					name, len(parts), key)
			}
			if parts[0] != TypeApt || parts[2] != "manifest.json" {
				t.Fatalf("manifestPath(%q) = %q, which is not type/name/manifest.json", name, key)
			}
			// filepath.Clean is what a path escape would exploit. After it, the
			// key must still sit under the type directory.
			if cleaned := filepath.Clean(key); !strings.HasPrefix(cleaned, TypeApt+"/") {
				t.Errorf("manifestPath(%q) = %q cleans to %q, escaping the %s directory",
					name, key, cleaned, TypeApt)
			}
		})
	}
}

// TestSafePathRefusesWhatItClaimsTo covers the guard's own contract, including
// the NUL byte that filepath.Clean does not touch.
func TestSafePathRefusesWhatItClaimsTo(t *testing.T) {
	b := &LocalBackend{Dir: t.TempDir()}
	for _, tc := range []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"ordinary key", "apt/hello/manifest.json", false},
		{"parent escape", "../passwd", true},
		{"deep escape", "apt/../../../../etc/passwd", true},
		{"absolute", "/etc/passwd", true},
		{"NUL byte", "apt/hel\x00lo", true},
		{"empty", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.safePath(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("safePath(%q) was allowed", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("safePath(%q) refused a legitimate key: %v", tc.input, err)
			}
		})
	}
}

// TestDotNamesAreRefusedBeforeTheyCollide replaces the test that recorded issue
// #160 as unfixed. The key derivation is deliberately unchanged — ".." still
// cleans to the manifest root and still collides across types — so the guard
// has to be that no write path accepts the name. SavePackage is the one every
// writer reaches, including 'bodega pkg create', which does not go through
// admit.
//
// The containment boundary stays pinned too: this was never a traversal, and a
// future encoding change must not make it one.
func TestDotNamesAreRefusedBeforeTheyCollide(t *testing.T) {
	for _, name := range []string{".", ".."} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePackageName(name); err == nil {
				t.Errorf("ValidatePackageName(%q) allowed a name that resolves as path syntax", name)
			}

			store := NewLocalStore(t.TempDir())
			pm := &PackageManifest{Name: name, Type: TypeApt, Versions: []VersionEntry{{Version: "1.0"}}}
			if err := store.SavePackage(t.Context(), pm); err == nil {
				t.Errorf("SavePackage wrote %s/%q, which cleans to %q", TypeApt, name, filepath.Clean(manifestPath(TypeApt, name)))
			}
		})
	}

	// Contained, not a traversal: the key a refused name would have produced
	// still resolves under the manifest root.
	root := t.TempDir()
	b := &LocalBackend{Dir: root}
	resolved, err := b.safePath(manifestPath(TypeApt, ".."))
	if err != nil {
		t.Fatalf("safePath refused a key it currently allows: %v", err)
	}
	if rel, relErr := filepath.Rel(root, resolved); relErr != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("a dot name reached above the manifest root (%q), which would make this a traversal", resolved)
	}
}

// TestBinaryFilenameIsRefusedWhereverItReachesAKey covers the consumers of a
// binary filename outside the builder, for a manifest that predates the check:
// the object key a delete, move or repair derives, and the stored name a
// download alias resolves to. Each would otherwise hand the storage layer a
// key whose ".." lands on another package's object.
func TestBinaryFilenameIsRefusedWhereverItReachesAKey(t *testing.T) {
	const hostile = "../../other/1.0.0/other.bin"
	pm := &PackageManifest{Type: TypeBinary, Name: "tool", Versions: []VersionEntry{
		{Version: "1.0.0", URL: "https://example.invalid/tool.bin", Filename: hostile},
	}}

	if err := ValidateBinaryFilenames(pm); err == nil {
		t.Errorf("ValidateBinaryFilenames passed %q", hostile)
	}
	if err := NewLocalStore(t.TempDir()).SavePackage(t.Context(), pm); err == nil {
		t.Errorf("SavePackage wrote a binary filename of %q", hostile)
	}
	if keys, err := ArtifactKeys(pm, pm.Versions[0]); err == nil {
		t.Errorf("ArtifactKeys derived %q from filename %q", keys, hostile)
	}

	key := []byte("pepper")
	alias := pm.binaryAliasName(key, pm.Versions[0])
	if stored, _, ok := pm.BinaryStoredFilename(key, "1.0.0", alias); ok {
		t.Errorf("alias %q resolved to stored name %q", alias, stored)
	}

	for _, ok := range []string{"", "tool.bin", "..tool", "tool..", "~/tool", "~/0123abcd/tool.bin"} {
		if err := ValidateBinaryFilename(ok); err != nil {
			t.Errorf("ValidateBinaryFilename(%q) refused a confined relative path: %v", ok, err)
		}
	}
	for _, bad := range []string{".", "..", "../x", "a/../../x", "/etc/passwd", "a//b", "a/./b", "a/", `..\x`, "a\x00b"} {
		if err := ValidateBinaryFilename(bad); err == nil {
			t.Errorf("ValidateBinaryFilename(%q) passed", bad)
		}
	}
}

// TestValidateDebGlobConfinesToTheBuildModeRoot pins the per-mode root: a git
// source build globs inside its clone, an apt-get source build inside the
// shared sources directory one level above its tree.
func TestValidateDebGlobConfinesToTheBuildModeRoot(t *testing.T) {
	git := func(g string) VersionEntry {
		return VersionEntry{Version: "1.0", URL: "https://example.invalid/x.git", BuildCmd: "make deb", DebGlob: g}
	}
	src := func(g string) VersionEntry {
		return VersionEntry{Version: "1.0", BuildCmd: "dpkg-buildpackage -us -uc", DebGlob: g}
	}
	for _, tc := range []struct {
		name string
		ve   VersionEntry
		ok   bool
	}{
		{"git empty", git(""), true},
		{"git *.deb", git("*.deb"), true},
		{"git build/*.deb", git("build/*.deb"), true},
		{"git out/foo_*.deb", git("out/foo_*.deb"), true},
		{"source ../*.deb", src("../*.deb"), true},
		{"source ../efs-utils_*.deb", src("../efs-utils_*.deb"), true},
		{"git ../*.deb", git("../*.deb"), false},
		{"git ..", git(".."), false},
		{"source ../../*.deb", src("../../*.deb"), false},
		{"source a/../../x.deb", src("a/../../x.deb"), false},
		{"git /abs/*.deb", git("/abs/*.deb"), false},
		{"source /abs/*.deb", src("/abs/*.deb"), false},
		{"git ./x.deb", git("./x.deb"), false},
		{"git a//b.deb", git("a//b.deb"), false},
		{`git a\b.deb`, git(`a\b.deb`), false},
		{"git NUL", git("a\x00.deb"), false},
		{"git [", git("["), false},
		{"no build_cmd", VersionEntry{Version: "1.0", URL: "https://example.invalid/x.deb", DebGlob: "*.deb"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDebGlob(tc.ve)
			if tc.ok && err != nil {
				t.Errorf("ValidateDebGlob(%q) refused: %v", tc.ve.DebGlob, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ValidateDebGlob(%q) passed", tc.ve.DebGlob)
				}
				if !strings.Contains(err.Error(), "deb_glob") || !strings.Contains(err.Error(), "published") {
					t.Errorf("error %q does not name the field and why it matters", err)
				}
			}
		})
	}
}

func TestSavePackageRefusesEscapingDebGlob(t *testing.T) {
	pm := &PackageManifest{Type: TypeApt, Name: "widget", Versions: []VersionEntry{
		{Version: "1.0", URL: "https://example.invalid/widget.git", BuildCmd: "make deb", DebGlob: "../../*.deb"},
	}}
	err := NewLocalStore(t.TempDir()).SavePackage(t.Context(), pm)
	if err == nil {
		t.Fatal("SavePackage wrote a git source entry with deb_glob ../../*.deb")
	}
	if !strings.Contains(err.Error(), "widget@1.0") {
		t.Errorf("error %q does not name the version", err)
	}
}
