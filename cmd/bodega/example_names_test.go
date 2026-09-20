package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"testing"
)

// Every name in an example is fictional unless something on the wire has to
// resolve to it. Registry hosts, tool names, and real go.mod dependencies are
// real because a reader who copies them needs them to work; a vendor named as
// sample data is a company singled out for nothing.
//
// Each needle is assembled from two pieces so this file is not its own first
// hit, the same trick repo_references_test.go uses.
var retiredNames = []string{
	"bit" + "warden",
	"shai" + "-hulud",
	"check" + "marx",
	"socket" + ".dev",
	"net" + "box",
	"hashi" + "corp",
	"terra" + "form",
	"aws" + "cli",
	"bo" + "to3",
	"@aws" + "-sdk",
	"oak" + ".cow.org",
	"bodega" + ".cow.org",
	"an" + "gus",
}

// Captured or generated content carries upstream's names, not ours: go.sum and
// the hostpkg fixtures are recordings, and manifests/ is a running instance's
// own output. Asking git which files it tracks separates all of that from
// authored content without a skip list that has to be maintained by hand.
func trackedFiles(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", "../..", "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var keep []string
	for _, p := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		switch {
		case p == "go.mod", p == "go.sum", p == "LICENSE":
		case strings.HasPrefix(p, "internal/hostpkg/testdata/"),
			strings.HasPrefix(p, "internal/policy/testdata/"):
		case strings.HasSuffix(p, ".go"), strings.HasSuffix(p, ".md"),
			strings.HasSuffix(p, ".sh"), strings.HasSuffix(p, ".yaml"),
			strings.HasSuffix(p, ".yml"), strings.HasSuffix(p, ".json"):
			keep = append(keep, p)
		}
	}
	return keep
}

func walkAuthored(t *testing.T, visit func(path string, body string)) {
	t.Helper()
	// os.Root rather than a bare open: every read is scoped to one tree and
	// cannot follow a symlink out of it.
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatalf("open repo root: %v", err)
	}
	defer func() { _ = root.Close() }()

	for _, p := range trackedFiles(t) {
		body, readErr := fs.ReadFile(root.FS(), p)
		if readErr != nil {
			t.Fatalf("read %s: %v", p, readErr)
		}
		visit(p, string(body))
	}
}

func TestNoRetiredVendorNameSurvivesInAnExample(t *testing.T) {
	walkAuthored(t, func(p, body string) {
		lower := strings.ToLower(body)
		for _, needle := range retiredNames {
			if !strings.Contains(lower, needle) {
				continue
			}
			for i, line := range strings.Split(body, "\n") {
				if strings.Contains(strings.ToLower(line), needle) {
					t.Errorf("%s:%d names %q, which examples no longer use; pick a fictional name:\n  %s",
						p, i+1, needle, strings.TrimSpace(line))
				}
			}
		}
	})
}

var (
	mdLink = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)\)`)
	// The README's header mark is an <img>, which no Markdown link syntax
	// covers and which fails as a broken-image icon on the page every reader
	// sees first.
	htmlImg = regexp.MustCompile(`<img[^>]+src="([^"]+)"`)
)

// Nothing in .github/workflows/ci.yml checks markdown links, so a directory
// rename leaves every link into it resolving to nothing and every gate green.
func TestEveryRelativeDocLinkResolves(t *testing.T) {
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatalf("open repo root: %v", err)
	}
	defer func() { _ = root.Close() }()

	walkAuthored(t, func(p, body string) {
		if !strings.HasSuffix(p, ".md") {
			return
		}
		refs := mdLink.FindAllStringSubmatch(body, -1)
		refs = append(refs, htmlImg.FindAllStringSubmatch(body, -1)...)
		for _, m := range refs {
			target := m[1]
			if i := strings.IndexByte(target, '#'); i >= 0 {
				target = target[:i]
			}
			if target == "" || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			resolved := path.Join(path.Dir(p), target)
			if _, statErr := fs.Stat(root.FS(), resolved); statErr != nil {
				t.Errorf("%s links to %q, which resolves to %q and does not exist", p, m[1], resolved)
			}
		}
	})
}
