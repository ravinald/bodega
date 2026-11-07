package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/host"
)

func writeLock(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "composer.lock")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const bodegaLock = `{
  "packages": [
    {"name": "psr/log", "dist": {"type": "zip", "url": "https://bodega.internal/composer/dist/psr/log/3.0.2/f16e1d5.zip"}},
    {"name": "local/path", "dist": {"type": "path", "url": ""}}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "dist": {"type": "zip", "url": "https://bodega.internal:443/composer/dist/phpunit/phpunit/11.0.0/abc.zip"}}
  ]
}`

func TestComposerLockAllAtBodegaIsOK(t *testing.T) {
	f, err := checkComposerLock(writeLock(t, bodegaLock), "https://bodega.internal")
	if err != nil {
		t.Fatal(err)
	}
	if f.Check != "composer-lock" || f.Status != host.StatusOK {
		t.Fatalf("finding = %+v, want an OK composer-lock row", f)
	}
	if !strings.Contains(f.Detail, "all 2 dist.url entries") {
		t.Errorf("detail = %q, want the two dist URLs counted", f.Detail)
	}
}

func TestComposerLockMixedHostsWarnsWithCounts(t *testing.T) {
	path := writeLock(t, `{
  "packages": [
    {"name": "symfony/console", "dist": {"url": "https://api.github.com/repos/symfony/console/zipball/aaa"}},
    {"name": "symfony/string", "dist": {"url": "https://api.github.com/repos/symfony/string/zipball/bbb"}},
    {"name": "psr/log", "dist": {"url": "https://bodega.internal/composer/dist/psr/log/3.0.2/f16e1d5.zip"}}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "dist": {"url": "https://api.github.com/repos/sebastianbergmann/phpunit/zipball/ccc"}},
    {"name": "acme/tool", "dist": {"url": "https://bodega.internal.evil.example/composer/dist/acme/tool/1.0.0/d.zip"}}
  ]
}`)
	f, err := checkComposerLock(path, "https://bodega.internal/")
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != host.StatusWarn {
		t.Fatalf("status = %s, want WARN: %+v", f.Status, f)
	}
	for _, want := range []string{"4 of 5 packages", "api.github.com (3)", "bodega.internal.evil.example (1)", path} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not name %q", f.Detail, want)
		}
	}
	if strings.Contains(f.Detail, "bodega.internal (") {
		t.Errorf("detail %q counts bodega itself as foreign", f.Detail)
	}
	if !strings.Contains(f.Remediation, "composer update --lock") {
		t.Errorf("remediation %q does not name composer update --lock", f.Remediation)
	}
}

func TestComposerLockNotJSONNamesThePath(t *testing.T) {
	path := writeLock(t, "<<<<<<< HEAD\n")
	_, err := checkComposerLock(path, "https://bodega.internal")
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want an error naming %s", err, path)
	}
}

// The flag reaches the report: doctor prints the row, and the remedy.
func TestDoctorComposerLockFlagPrintsTheRow(t *testing.T) {
	prevExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = prevExit })
	path := writeLock(t, `{"packages":[{"name":"a/b","dist":{"url":"https://api.github.com/repos/a/b/zipball/1"}}]}`)

	out, err := runDoctor(t, "--url", "https://bodega.internal", "--composer-lock", path)
	if err != nil {
		t.Fatalf("doctor = %v:\n%s", err, out)
	}
	var row string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "composer-lock") {
			row = line
		}
	}
	if !strings.Contains(row, "WARN") || !strings.Contains(row, "api.github.com (1)") {
		t.Errorf("composer-lock row = %q:\n%s", row, out)
	}
	if !strings.Contains(out, "composer update --lock") {
		t.Errorf("the remediation does not name composer update --lock:\n%s", out)
	}

	out, _ = runDoctor(t, "--url", "https://bodega.internal")
	if strings.Contains(out, "composer-lock") {
		t.Errorf("doctor without --composer-lock printed a composer-lock row:\n%s", out)
	}
}

// The lock bypass and its one-time fix are in the Composer section an
// operator configuring Composer reads, beside the doctor paragraph.
func TestUsageDocumentsComposerLock(t *testing.T) {
	usage := readDoc(t, "usage.md")
	start := strings.Index(usage, "**Composer** (`config.json`")
	end := strings.Index(usage, "bodega serves a Composer v2 repository under `/composer/`")
	if start < 0 || end < start {
		t.Fatal("the Composer client section moved")
	}
	section := usage[start:end]
	for _, want := range []string{
		"`composer install` fetches each archive from the `dist.url` the lock records and never consults the global repository",
		"a lock written against Packagist downloads from `api.github.com`",
		"`composer update --lock`",
		"keeps every locked version and rewrites each `dist.url` to bodega",
		"The rewritten `composer.lock` is the change to review and commit",
		"doctor reads no project unless `--composer-lock <path>`",
		"`composer-lock` row",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the Composer section of docs/usage.md does not say %q", want)
		}
	}
}
