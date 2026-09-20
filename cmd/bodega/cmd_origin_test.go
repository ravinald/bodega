package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/manifest"
)

// pipList is what `pip list --format=json` reports on a host with two packages.
const pipList = `[{"name": "requests", "version": "2.31.0"}, {"name": "urllib3", "version": "2.2.1"}]`

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// runConvert converts an inventory to a file and decodes the result.
func runConvert(t *testing.T, input string, args ...string) []manifest.PackageManifest {
	t.Helper()
	out := filepath.Join(t.TempDir(), "catalog.json")
	cmd := newConvertCmd(&globalFlags{})
	cmd.SetArgs(append([]string{"pypi", input, "-o", out}, args...))
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pkg convert: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read converted catalog: %v", err)
	}
	var pms []manifest.PackageManifest
	if err := json.Unmarshal(blob, &pms); err != nil {
		t.Fatalf("decode converted catalog: %v", err)
	}
	return pms
}

func runImport(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newImportCmd(&globalFlags{})
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.Execute()
}

// originOf reads the origins the store holds for one version.
func originOf(t *testing.T, env *discoverEnv, name, version string) []string {
	t.Helper()
	pm := env.readManifest(t, manifest.TypePypi, name)
	if pm == nil {
		t.Fatalf("pypi/%s is not in the store", name)
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return admit.Origins(ve)
		}
	}
	t.Fatalf("pypi/%s has no version %s", name, version)
	return nil
}

// Convert runs on the host being cataloged, so the hostname is the answer
// without anyone passing it. A catalog assembled from four hosts is only
// attributable if the unflagged run records where it ran.
func TestConvertStampsThisHostByDefault(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Skipf("this machine has no readable hostname: %v", err)
	}
	for _, pm := range runConvert(t, writeTemp(t, "pip.json", pipList)) {
		if got := admit.Origins(pm.Versions[0]); len(got) != 1 || got[0] != host {
			t.Errorf("pypi/%s origins = %v, want [%s]", pm.Name, got, host)
		}
	}
}

func TestConvertOriginFlagNamesAnotherHost(t *testing.T) {
	for _, pm := range runConvert(t, writeTemp(t, "pip.json", pipList), "--origin", "db01") {
		if got := admit.Origins(pm.Versions[0]); len(got) != 1 || got[0] != "db01" {
			t.Errorf("pypi/%s origins = %v, want [db01]", pm.Name, got)
		}
	}
}

// An inventory captured by hand carries no origin. --origin is how it gets one
// without a re-convert on the machine it came from.
func TestImportOriginStampsAPayloadCarryingNone(t *testing.T) {
	env := newDiscoverEnv(t)
	catalog := writeTemp(t, "catalog.json",
		`[{"config_version":1,"name":"requests","type":"pypi","versions":[{"version":"2.31.0"}]}]`)

	if err := runImport(t, "--origin", "db01", catalog); err != nil {
		t.Fatalf("pkg import --origin: %v", err)
	}
	if got := originOf(t, env, "requests", "2.31.0"); len(got) != 1 || got[0] != "db01" {
		t.Errorf("origins = %v, want [db01]", got)
	}
}

func TestImportOriginRefusesAPayloadThatDisagrees(t *testing.T) {
	env := newDiscoverEnv(t)
	catalog := writeTemp(t, "catalog.json", `[{"config_version":1,"name":"requests","type":"pypi",`+
		`"versions":[{"version":"2.31.0","metadata":{"_origin":"db02"}}]}]`)

	err := runImport(t, "--origin", "db01", catalog)
	if err == nil {
		t.Fatal("a flag contradicting the payload must fail, not pick a winner")
	}
	for _, want := range []string{"db01", "db02"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %q, got: %v", want, err)
		}
	}
	if pm := env.readManifest(t, manifest.TypePypi, "requests"); pm != nil {
		t.Error("the refused import wrote to the store anyway")
	}
}

// The reason the field is a list: a package on db01 and db02 came from both,
// and a merge that replaced would leave the catalog claiming only the last
// host to report it.
func TestImportMergeAccumulatesOrigins(t *testing.T) {
	env := newDiscoverEnv(t)
	catalogFrom := func(host string) string {
		return fmt.Sprintf(`[{"config_version":1,"name":"requests","type":"pypi",`+
			`"versions":[{"version":"2.31.0","metadata":{"_origin":%q}}]}]`, host)
	}

	if err := runImport(t, writeTemp(t, "db01.json", catalogFrom("db01"))); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if err := runImport(t, "--merge", writeTemp(t, "db02.json", catalogFrom("db02"))); err != nil {
		t.Fatalf("merge import: %v", err)
	}

	got := originOf(t, env, "requests", "2.31.0")
	if len(got) != 2 || got[0] != "db01" || got[1] != "db02" {
		t.Errorf("origins = %v, want [db01 db02]", got)
	}
}

// An export that drops the origin makes the catalog un-migratable: the field
// survives one instance and dies at the boundary between two.
func TestExportThenImportPreservesOrigins(t *testing.T) {
	source := newDiscoverEnv(t)
	catalog := writeTemp(t, "catalog.json", `[{"config_version":1,"name":"requests","type":"pypi",`+
		`"versions":[{"version":"2.31.0","metadata":{"_origin":"db01,db02"}}]}]`)
	if err := runImport(t, catalog); err != nil {
		t.Fatalf("seed import: %v", err)
	}
	if got := originOf(t, source, "requests", "2.31.0"); len(got) != 2 {
		t.Fatalf("seeded origins = %v, want two", got)
	}

	exported := captureStdout(t, func() {
		cmd := newExportCmd(&globalFlags{})
		cmd.SetArgs([]string{"pypi", "requests"})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err != nil {
			t.Errorf("pkg export: %v", err)
		}
	})

	// A second scratch install, so the assertion is on what crossed the file
	// rather than on what the first store still holds.
	target := newDiscoverEnv(t)
	if err := runImport(t, writeTemp(t, "exported.json", exported)); err != nil {
		t.Fatalf("import of the export: %v", err)
	}
	got := originOf(t, target, "requests", "2.31.0")
	if len(got) != 2 || got[0] != "db01" || got[1] != "db02" {
		t.Errorf("origins after a round trip = %v, want [db01 db02]", got)
	}
}
