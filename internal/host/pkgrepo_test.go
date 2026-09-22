package host_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

const goodConf = `FreeBSD: { enabled: no }

bodega-latest: {
  url: "https://bodega.internal/freebsd/${ABI}/latest",
  mirror_type: "none",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}`

func TestWritePkgRepoLandsTheFileAndCreatesItsDirectory(t *testing.T) {
	root := t.TempDir()
	wrote, err := host.WritePkgRepo(root, pkgrepos.ClientConfPath, goodConf)
	if err != nil {
		t.Fatalf("WritePkgRepo: %v", err)
	}
	want := filepath.Join(root, pkgrepos.ClientConfPath)
	if len(wrote) != 1 || wrote[0] != want {
		t.Fatalf("wrote %v, want [%s]", wrote, want)
	}
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != goodConf+"\n" {
		t.Errorf("file = %q, want the conf with one trailing newline", got)
	}
	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// pkg reads this as a user that is not always root, and it holds no
	// secret.
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", info.Mode().Perm())
	}
}

// A second run replaces rather than appends. Two definitions of one tag in
// one file is the state that makes "which repository is this host reading"
// unanswerable from the file.
func TestWritePkgRepoReplacesRatherThanAppends(t *testing.T) {
	root := t.TempDir()
	if _, err := host.WritePkgRepo(root, pkgrepos.ClientConfPath, goodConf); err != nil {
		t.Fatalf("first write: %v", err)
	}
	second := strings.Replace(goodConf, "bodega-latest", "bodega-quarterly", 1)
	if _, err := host.WritePkgRepo(root, pkgrepos.ClientConfPath, second); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, pkgrepos.ClientConfPath))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Contains(string(got), "bodega-latest") {
		t.Errorf("the first run's definition survived the second:\n%s", got)
	}
}

// A conf that disables nothing is refused. Installed, it leaves the host
// fetching from pkg.FreeBSD.org beside bodega, and nothing in "pkg update"
// output reports that: the operator believes the host is isolated.
func TestWritePkgRepoRefusesAConfThatDisablesNothing(t *testing.T) {
	root := t.TempDir()
	stanzaOnly := strings.SplitN(goodConf, "\n\n", 2)[1]
	if _, err := host.WritePkgRepo(root, pkgrepos.ClientConfPath, stanzaOnly); err == nil {
		t.Fatal("wrote a conf with no upstream override, leaving the host reading both repositories")
	}
	if _, err := os.Stat(filepath.Join(root, pkgrepos.ClientConfPath)); !os.IsNotExist(err) {
		t.Error("the refused conf still landed on disk")
	}
}

func TestWritePkgRepoRefusesAnEmptyConf(t *testing.T) {
	if _, err := host.WritePkgRepo(t.TempDir(), pkgrepos.ClientConfPath, "  \n"); err == nil {
		t.Fatal("wrote an empty pkg repository file")
	}
}
