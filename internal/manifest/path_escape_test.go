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
	// not neutralize, and TestDotNamesLandOutsideTheirType below records what
	// they do instead. Issue #160 carries the fix.
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

// TestDotNamesLandOutsideTheirType records the gap TestPackageNamesCannotTraverse
// is scoped around. A name of exactly "." or ".." survives SafeName, so it
// stays a path segment that Clean then resolves: ".." reaches the manifest
// root, where every type collides on one file.
//
// The test asserts the current behavior rather than the desired behavior, so
// it stays green until issue #160 lands and fails loudly when it does. It also
// pins the boundary that keeps this a layout bug rather than a traversal:
// nothing reaches above the manifest root.
func TestDotNamesLandOutsideTheirType(t *testing.T) {
	root := t.TempDir()
	b := &LocalBackend{Dir: root}

	aptKey := manifestPath(TypeApt, "..")
	npmKey := manifestPath(TypeNpm, "..")
	if filepath.Clean(aptKey) != filepath.Clean(npmKey) {
		t.Fatalf("issue #160 appears fixed: %q and %q no longer collide. "+
			"Update this test and TestPackageNamesCannotTraverse's exclusion list.", aptKey, npmKey)
	}

	if err := b.Write(t.Context(), aptKey, []byte(`{"name":"apt"}`)); err != nil {
		t.Fatalf("write apt: %v", err)
	}
	if err := b.Write(t.Context(), npmKey, []byte(`{"name":"npm"}`)); err != nil {
		t.Fatalf("write npm: %v", err)
	}
	got, err := b.Read(t.Context(), aptKey)
	if err != nil {
		t.Fatalf("read apt: %v", err)
	}
	if string(got) != `{"name":"npm"}` {
		t.Errorf("the collision changed shape: reading the apt key returned %s", got)
	}

	// The boundary that matters: contained, not a traversal.
	resolved, err := b.safePath(aptKey)
	if err != nil {
		t.Fatalf("safePath refused a key it currently allows: %v", err)
	}
	if rel, relErr := filepath.Rel(root, resolved); relErr != nil || strings.HasPrefix(rel, "..") {
		t.Errorf("a dot name reached above the manifest root (%q), which would make this a traversal", resolved)
	}
}
