package builder

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// countingBuildEntry is a git source-build entry whose build_cmd appends its
// version to counter and leaves a .deb in the clone.
func countingBuildEntry(upstream, ref, version, counter string) manifest.VersionEntry {
	return manifest.VersionEntry{
		Version:  version,
		URL:      upstream,
		Ref:      ref,
		BuildCmd: "echo " + version + " >> '" + counter + "' && touch widget_" + version + "_all.deb",
	}
}

func readCounter(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return strings.Fields(string(b))
}

func TestBuildAptSkipsBuiltVersion(t *testing.T) {
	upstream, release, _ := aptRefUpstream(t)
	counter := filepath.Join(t.TempDir(), "builds")
	pm := &manifest.PackageManifest{Type: manifest.TypeApt, Name: "widget", Versions: []manifest.VersionEntry{
		countingBuildEntry(upstream, release, "0.1.1", counter),
	}}
	cfg, store, _ := pinEnv(t, pm)
	var out bytes.Buffer
	cfg.Stdout = &out

	if s := FetchApt(cfg, store, "widget"); s.Failures != 0 {
		t.Fatalf("fetch failed: %+v\n%s", s.Results, out.String())
	}
	if s := BuildApt(cfg, store, "widget"); s.Failures != 0 || s.Total != 1 {
		t.Fatalf("first build: %+v\n%s", s, out.String())
	}

	out.Reset()
	s := BuildApt(cfg, store, "widget")
	if got := readCounter(t, counter); len(got) != 1 {
		t.Errorf("build_cmd ran %d times, want 1: a built version was rebuilt", len(got))
	}
	if s.Total != 0 || s.Failures != 0 {
		t.Errorf("second build summary Total=%d Failures=%d, want 0 and 0", s.Total, s.Failures)
	}
	second := out.String()
	for _, want := range []string{"0.1.1", "already built", "build fetch apt widget force"} {
		if !strings.Contains(second, want) {
			t.Errorf("second build output does not say %q:\n%s", want, second)
		}
	}
	if strings.Contains(second, ">>> [apt] build") {
		t.Errorf("second build printed a build header for a skipped version:\n%s", second)
	}

	cfg.Force = true
	s = BuildApt(cfg, store, "widget")
	if got := readCounter(t, counter); len(got) != 2 {
		t.Errorf("build_cmd ran %d times after a forced build, want 2", len(got))
	}
	if s.Total != 1 {
		t.Errorf("forced build summary Total=%d, want 1", s.Total)
	}
}

func TestBuildAptBuildsOnlyUnbuiltVersion(t *testing.T) {
	upstream, release, _ := aptRefUpstream(t)
	counter := filepath.Join(t.TempDir(), "builds")
	v1 := countingBuildEntry(upstream, release, "1.0", counter)
	pm := &manifest.PackageManifest{Type: manifest.TypeApt, Name: "widget", Versions: []manifest.VersionEntry{v1}}
	cfg, store, _ := pinEnv(t, pm)
	var out bytes.Buffer
	cfg.Stdout = &out

	if s := FetchApt(cfg, store, "widget"); s.Failures != 0 {
		t.Fatalf("fetch 1.0 failed: %+v\n%s", s.Results, out.String())
	}
	if s := BuildApt(cfg, store, "widget"); s.Failures != 0 {
		t.Fatalf("build 1.0 failed: %+v\n%s", s.Results, out.String())
	}

	saved, err := store.GetPackage(t.Context(), manifest.TypeApt, "widget")
	if err != nil || saved == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	saved.Versions = append(saved.Versions, countingBuildEntry(upstream, release, "2.0", counter))
	if err := store.SavePackage(t.Context(), saved); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if s := FetchApt(cfg, store, "widget"); s.Failures != 0 {
		t.Fatalf("fetch 2.0 failed: %+v\n%s", s.Results, out.String())
	}
	if s := BuildApt(cfg, store, "widget"); s.Failures != 0 {
		t.Fatalf("build after adding 2.0 failed: %+v\n%s", s.Results, out.String())
	}

	if got := strings.Join(readCounter(t, counter), ","); got != "1.0,2.0" {
		t.Errorf("build_cmd ran for %s, want 1.0,2.0", got)
	}
}
