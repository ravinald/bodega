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
