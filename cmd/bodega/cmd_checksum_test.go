package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// checksumEnv is a scratch install holding one audit DB the CLI resolves
// through $BODEGA_CONFIG_FILE.
func checksumEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	body := `{"storage_backend":"local","storage_path":"` + dir + `","manifest_dir":"` + dir +
		`","audit_db":"` + dbPath + `","log_dir":"` + dir + `","allow_plaintext":true,"apt_codename":"noble"}`
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	return dbPath
}

func runChecksum(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newChecksumCmd(&globalFlags{})
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return out.String(), err
}

// `checksum clear` is the documented way out of a checksum mismatch, and it
// used to print "Cleared all checksums for apt/nginx" over a DELETE that
// matched nothing. An operator reading that goes looking for a second cause
// while the stale digest is still in the table.
func TestChecksumClearReportsWhatItDeleted(t *testing.T) {
	dbPath := checksumEnv(t)
	ctx := context.Background()

	// The key a mirrored pool fetch writes, filed the way verifyProxyChecksum
	// now files it.
	key := manifest.AptKey("pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb")
	typ, name, version := manifest.ParseKey(key)
	if typ != manifest.TypeApt || name != "nginx" {
		t.Fatalf("ParseKey(%q) = (%q, %q, %q); the fixture no longer stands for a mirrored .deb", key, typ, name, version)
	}

	db, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if err := db.StoreChecksum(ctx, key, typ, name, version, "sha256", "deadbeef", "computed"); err != nil {
		t.Fatalf("store checksum: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close audit db: %v", err)
	}

	out, err := runChecksum(t, "clear", "apt", "nginx")
	if err != nil {
		t.Fatalf("checksum clear apt nginx: %v", err)
	}
	if !strings.Contains(out, "Cleared 1 checksum(s) for apt/nginx") {
		t.Errorf("output does not name the row count:\n%s", out)
	}
	// What the clear does to the apt index, said before it is done: the row is
	// the mirrored-pool record, and an operator chasing a 502 reads this
	// paragraph rather than the exclusion section of usage.md (#225).
	if !strings.Contains(out, "the digest goes, the row stays") {
		t.Errorf("clear does not say what it leaves behind for apt:\n%s", out)
	}

	// Second run: the digest is already gone, and saying "Cleared 1" again
	// would send an operator whose 502 persists looking in the wrong place.
	out, err = runChecksum(t, "clear", "apt", "nginx")
	if err != nil {
		t.Fatalf("second checksum clear: %v", err)
	}
	if !strings.Contains(out, "nothing was cleared") {
		t.Errorf("a clear with no digest to remove still reported success:\n%s", out)
	}
	if strings.Contains(out, "Cleared 1") {
		t.Errorf("a clear with no digest to remove reported one:\n%s", out)
	}

	// A name nothing recorded is a different answer from a name already
	// cleared, because the next step differs: check the spelling, or stop
	// blaming the checksum.
	out, err = runChecksum(t, "clear", "apt", "ngnix")
	if err != nil {
		t.Fatalf("misspelled checksum clear: %v", err)
	}
	if !strings.Contains(out, "No cached checksums matched apt/ngnix") {
		t.Errorf("a name nothing recorded reads the same as one already cleared:\n%s", out)
	}
}

// archivePins stores one digest for apt/nginx in the default archive and one
// in each of two named archives, at one pool path, and returns the three keys.
func archivePins(t *testing.T, dbPath string) (def, ubuntu, debian string) {
	t.Helper()
	const rel = "pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb"
	def, ubuntu, debian = manifest.AptKey(rel), manifest.AptArchiveKey("ubuntu", rel), manifest.AptArchiveKey("debian", rel)
	db, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	for key, digest := range map[string]string{def: "d0", ubuntu: "d1", debian: "d2"} {
		typ, name, version := manifest.ParseKey(key)
		if err := db.StoreChecksum(context.Background(), key, typ, name, version, "sha256", digest, "computed"); err != nil {
			t.Fatalf("store checksum for %s: %v", key, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close audit db: %v", err)
	}
	return def, ubuntu, debian
}

// pinValues reads back the digest each key holds.
func pinValues(t *testing.T, dbPath string) map[string]string {
	t.Helper()
	db, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer db.Close()
	rows, err := db.ListChecksums(context.Background(), manifest.TypeApt, "nginx")
	if err != nil {
		t.Fatalf("list checksums: %v", err)
	}
	out := map[string]string{}
	for _, cs := range rows {
		out[cs.ObjectKey] = cs.Value
	}
	return out
}

// TestChecksumClearArchive: one pool path in two archives is two pins, and an
// operator whose Debian archive republished must be able to drop that pin
// without unpinning Ubuntu's build of the same filename.
func TestChecksumClearArchive(t *testing.T) {
	dbPath := checksumEnv(t)
	def, ubuntu, debian := archivePins(t, dbPath)

	out, err := runChecksum(t, "list", "--type", "apt", "--name", "nginx")
	if err != nil {
		t.Fatalf("checksum list: %v", err)
	}
	if !strings.Contains(out, "ARCHIVE") {
		t.Errorf("list has no ARCHIVE column:\n%s", out)
	}
	for digest, archive := range map[string]string{"d0": "-", "d1": "ubuntu", "d2": "debian"} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if strings.Contains(line, " "+digest+" ") && len(f) > 0 && f[len(f)-1] == archive {
				found = true
			}
		}
		if !found {
			t.Errorf("list does not show digest %s under archive %q:\n%s", digest, archive, out)
		}
	}

	out, err = runChecksum(t, "clear", "apt", "nginx", "--archive", "debian")
	if err != nil {
		t.Fatalf("clear --archive debian: %v", err)
	}
	if !strings.Contains(out, "Cleared 1 checksum(s) for apt/nginx in archive debian") {
		t.Errorf("output does not name the archive and the count:\n%s", out)
	}
	if got := pinValues(t, dbPath); got[debian] != "" || got[ubuntu] != "d1" || got[def] != "d0" {
		t.Errorf("after clear --archive debian the pins are %v, want only the debian one blank", got)
	}

	// Asked again, and asked of an archive that holds no pin: neither may
	// read as a clear.
	if out, err = runChecksum(t, "clear", "apt", "nginx", "--archive", "debian"); err != nil || !strings.Contains(out, "nothing was cleared") {
		t.Errorf("second clear --archive debian = %v:\n%s\nwant it to say nothing was cleared", err, out)
	}
	_, err = runChecksum(t, "clear", "apt", "nginx", "--archive", "fedora")
	if err == nil || !strings.Contains(err.Error(), `in archive "fedora"`) || !strings.Contains(err.Error(), "ubuntu") {
		t.Errorf("clear --archive fedora = %v, want a refusal naming the archives that do hold one", err)
	}
	if _, err = runChecksum(t, "clear", "npm", "lodash", "--archive", "debian"); err == nil || !strings.Contains(err.Error(), "apt only") {
		t.Errorf("clear npm --archive = %v, want a refusal: only apt has archives", err)
	}
	if got := pinValues(t, dbPath); got[ubuntu] != "d1" || got[def] != "d0" {
		t.Errorf("the refused clears changed the pins: %v", got)
	}
}

// TestChecksumClearEveryArchive: without --archive the package's pins go in
// every archive, as they did before archives existed, and the output says how
// many went from each.
func TestChecksumClearEveryArchive(t *testing.T) {
	dbPath := checksumEnv(t)
	archivePins(t, dbPath)

	out, err := runChecksum(t, "clear", "apt", "nginx")
	if err != nil {
		t.Fatalf("checksum clear apt nginx: %v", err)
	}
	for _, want := range []string{
		"Cleared 3 checksum(s) for apt/nginx",
		"default archive: 1",
		"archive debian: 1",
		"archive ubuntu: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for key, value := range pinValues(t, dbPath) {
		if value != "" {
			t.Errorf("pin on %s = %q after a clear with no --archive, want blank", key, value)
		}
	}
}

func TestReviewF119ChecksumVersionCountsEveryArchive(t *testing.T) {
	dbPath := checksumEnv(t)
	archivePins(t, dbPath)

	out, err := runChecksum(t, "clear", "apt", "nginx", "--version", "1.24.0-2ubuntu7.1")
	if err != nil {
		t.Fatalf("checksum clear --version: %v", err)
	}
	for _, want := range []string{
		"default archive: 1",
		"archive debian: 1",
		"archive ubuntu: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("version-scoped clear lacks %q:\n%s", want, out)
		}
	}
	for key, value := range pinValues(t, dbPath) {
		if value != "" {
			t.Errorf("pin on %s = %q after clear, want blank", key, value)
		}
	}
}
