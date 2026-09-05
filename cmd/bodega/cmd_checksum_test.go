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

	// Second run: the same command over an empty match has to say so.
	out, err = runChecksum(t, "clear", "apt", "nginx")
	if err != nil {
		t.Fatalf("second checksum clear: %v", err)
	}
	if !strings.Contains(out, "nothing was cleared") {
		t.Errorf("a clear that matched nothing still reported success:\n%s", out)
	}
	if strings.Contains(out, "Cleared 1") {
		t.Errorf("a clear that matched nothing reported a deletion:\n%s", out)
	}
}
