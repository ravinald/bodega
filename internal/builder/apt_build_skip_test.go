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

// aptSourceShims puts apt-get and dpkg-source stand-ins on PATH. dpkg-source
// refuses an existing target, as the real one does ("unpack target exists").
func aptSourceShims(t *testing.T) {
	t.Helper()
	shims := t.TempDir()
	for name, body := range map[string]string{
		"apt-get":     "#!/bin/sh\nexit 0\n",
		"dpkg-source": "#!/bin/sh\n[ -f \"$2\" ] || exit 1\n[ -e \"$3\" ] && exit 1\nmkdir -p \"$3\"\n",
	} {
		if err := os.WriteFile(filepath.Join(shims, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", shims+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestForcedFetchRebuildsAptSourceEntry(t *testing.T) {
	aptSourceShims(t)
	counter := filepath.Join(t.TempDir(), "builds")
	ve := manifest.VersionEntry{Version: "2.0", BuildCmd: "echo 2.0 >> '" + counter + "' && touch ../efs-utils_2.0_all.deb"}
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{Type: manifest.TypeApt, Name: "efs-utils", Versions: []manifest.VersionEntry{ve}})
	var out bytes.Buffer
	cfg.Stdout = &out
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	siblings := []string{"efs-utils_1.0_all.deb", "efs-utils-extra_2.0_all.deb"}
	for _, f := range append([]string{"efs-utils_2.0.dsc"}, siblings...) {
		touchFile(t, filepath.Join(d.sources, f))
	}

	if s := FetchApt(cfg, store, "efs-utils"); s.Failures != 0 {
		t.Fatalf("fetch failed: %+v\n%s", s.Results, out.String())
	}
	if s := BuildApt(cfg, store, "efs-utils"); s.Failures != 0 || s.Total != 1 {
		t.Fatalf("first build: %+v\n%s", s, out.String())
	}

	cfg.Force = true
	if s := FetchApt(cfg, store, "efs-utils"); s.Failures != 0 {
		t.Fatalf("forced fetch failed: %+v\n%s", s.Results, out.String())
	}
	cfg.Force = false
	if s := BuildApt(cfg, store, "efs-utils"); s.Failures != 0 || s.Total != 1 {
		t.Fatalf("build after forced fetch: %+v\n%s", s, out.String())
	}
	if got := readCounter(t, counter); len(got) != 2 {
		t.Errorf("build_cmd ran %d times, want 2: the forced fetch left the version built\n%s", len(got), out.String())
	}
	for _, f := range siblings {
		if !fileExists(filepath.Join(d.sources, f)) {
			t.Errorf("forced fetch of efs-utils 2.0 removed %s", f)
		}
	}
}

func TestForcedFetchAptSourceReportsRemovalFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on")
	}
	aptSourceShims(t)
	ve := manifest.VersionEntry{Version: "2.0", BuildCmd: "touch ../efs-utils_2.0_all.deb"}
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{Type: manifest.TypeApt, Name: "efs-utils", Versions: []manifest.VersionEntry{ve}})
	var out bytes.Buffer
	cfg.Stdout = &out
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	touchFile(t, filepath.Join(d.sources, "efs-utils_2.0.dsc"))
	if s := FetchApt(cfg, store, "efs-utils"); s.Failures != 0 {
		t.Fatalf("fetch failed: %+v\n%s", s.Results, out.String())
	}
	if s := BuildApt(cfg, store, "efs-utils"); s.Failures != 0 {
		t.Fatalf("build failed: %+v\n%s", s.Results, out.String())
	}

	if err := os.Chmod(d.sources, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d.sources, 0o700) })
	cfg.Force = true
	s := FetchApt(cfg, store, "efs-utils")
	if s.Failures != 1 || len(s.Results) != 1 || s.Results[0].Err == nil {
		t.Fatalf("forced fetch did not fail: %+v\n%s", s.Results, out.String())
	}
	if err := s.Results[0].Err.Error(); !strings.Contains(err, "remove old build") || !strings.Contains(err, "efs-utils_2.0_all.deb") {
		t.Errorf("error %q does not name the .deb it could not remove", err)
	}
}
