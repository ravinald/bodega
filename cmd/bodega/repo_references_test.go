package main

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

// The internal docs tree is absent from a clone, so a source comment citing a
// file there sends the only reader who follows it to nothing. B35 swept docs/
// and README.md; 600ab31 removed the last two Go citations while closing
// something else, which is why #257 was already fixed by the time anyone
// looked.
//
// This is the grep that issue carried, run as a test so the next one does not
// depend on somebody remembering to run it. The needle is assembled from two
// pieces so this file is not its own first hit.
func TestNoSourceFileCitesAnUntrackedDoc(t *testing.T) {
	// os.Root rather than filepath.WalkDir: the walk and the read are then
	// scoped to one tree and cannot follow a symlink out of it.
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatalf("open repo root: %v", err)
	}
	defer func() { _ = root.Close() }()

	needle := "docs-" + "internal"

	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", needle, "dist", "vendor", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, readErr := fs.ReadFile(root.FS(), path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, needle) {
				t.Errorf("%s:%d cites %s, which a clone does not have; point at docs/ instead:\n  %s",
					path, i+1, needle, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
