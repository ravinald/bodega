package builder

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// admissionConfig is a builder Config with an audit store whose npm OSV gate
// blocks, pointed at a database naming minimist 1.2.0 or, with synced false,
// at one never synced, which makes the gate warn. The age gate a fresh store
// seeds is removed so nothing here reaches the public registry.
func admissionConfig(t *testing.T, synced bool) (*Config, *bytes.Buffer) {
	t.Helper()
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	if _, err := adb.DeleteAgePolicy(t.Context(), manifest.TypeNpm); err != nil {
		t.Fatalf("delete seeded age policy: %v", err)
	}
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
	dir := t.TempDir()
	if synced {
		export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			f, _ := zw.Create("GHSA-test-0001.json")
			_ = json.NewEncoder(f).Encode(map[string]any{
				"id": "GHSA-test-0001",
				"affected": []map[string]any{{
					"package":  map[string]string{"name": "minimist", "ecosystem": "npm"},
					"versions": []string{"1.2.0"},
				}},
			})
			_ = zw.Close()
			_, _ = w.Write(buf.Bytes())
		}))
		t.Cleanup(export.Close)
		db := policy.NewOSVDatabase(dir)
		db.ExportBase = export.URL
		if _, err := db.Sync(t.Context(), "npm"); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}
	out := &bytes.Buffer{}
	c := &Config{AuditDB: adb, Stdout: out, policyChecker: policy.NewChecker(adb), app: &config.Config{OSVDBDir: dir}}
	return c, out
}

func onlyAdmission(t *testing.T, c *Config, typ, name, version string) audit.Admission {
	t.Helper()
	rows, err := c.AuditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: typ, PkgName: name, PkgVersion: version})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one admission row for %s/%s@%s, got %d: %+v", typ, name, version, len(rows), rows)
	}
	return rows[0]
}

// TestEnforcePolicyRecordsTheAdmission is the builder's leg of the matrix: a
// fetch is admitted under import's checks, its row cites the policy digest,
// and the digest pin that follows gives the row its object key.
func TestEnforcePolicyRecordsTheAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		synced   bool
		version  string
		decision string
		osv      string
	}{
		{"clean_pass", true, "1.2.8", audit.AdmissionAdmitted, audit.CheckPass},
		{"warn", false, "1.2.8", audit.AdmissionAdmitted, audit.CheckWarn},
		{"block", true, "1.2.0", audit.AdmissionPolicyBlocked, audit.CheckBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, out := admissionConfig(t, tc.synced)
			err := c.EnforcePolicy(t.Context(), manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: tc.version})
			if blocked := err != nil; blocked != (tc.decision == audit.AdmissionPolicyBlocked) {
				t.Fatalf("EnforcePolicy = %v for a %s", err, tc.name)
			}
			row := onlyAdmission(t, c, manifest.TypeNpm, "minimist", tc.version)
			digest, derr := policy.Digest(t.Context(), c.AuditDB)
			if derr != nil {
				t.Fatalf("Digest: %v", derr)
			}
			if row.Decision != tc.decision || row.PolicyDigest != digest {
				t.Errorf("row = decision %q digest %q, want %q and %q", row.Decision, row.PolicyDigest, tc.decision, digest)
			}
			var osv audit.AdmissionCheck
			for _, ck := range row.Checks {
				if ck.Check == audit.CheckOSV {
					osv = ck
				}
			}
			if osv.Status != tc.osv {
				t.Errorf("osv = %+v, want %s", osv, tc.osv)
			}
			if tc.name == "warn" && !strings.Contains(out.String(), "osv:") {
				t.Errorf("a warn was not printed: %q", out.String())
			}
			if err != nil {
				return
			}
			key := manifest.NpmTarballKey("minimist", tc.version)
			cs := &manifest.Checksum{Algorithm: "sha256", Value: strings.Repeat("a", 64)}
			if err := c.pinArtifactDigest(t.Context(), key, manifest.TypeNpm, "minimist", tc.version, cs); err != nil {
				t.Fatalf("pinArtifactDigest: %v", err)
			}
			if got := onlyAdmission(t, c, manifest.TypeNpm, "minimist", tc.version).ObjectKey; got != key {
				t.Errorf("object_key = %q after the pin, want %q", got, key)
			}
			if strings.Contains(out.String(), "WARNING") {
				t.Errorf("a pin with a decision behind it warned: %q", out.String())
			}
		})
	}
}

// TestPinWithNoAdmissionWarns is the pypi closure case: a wheel pip pulled in
// transitively was never admitted by version, so its pin writes a row that
// says not_evaluated and says so on the build's output.
func TestPinWithNoAdmissionWarns(t *testing.T) {
	c, out := admissionConfig(t, true)
	key := "pypi/wheels/idna-3.7-py3-none-any.whl"
	cs := &manifest.Checksum{Algorithm: "sha256", Value: strings.Repeat("b", 64)}
	if err := c.pinArtifactDigest(t.Context(), key, manifest.TypePypi, "idna", "3.7", cs); err != nil {
		t.Fatalf("pinArtifactDigest: %v", err)
	}
	row := onlyAdmission(t, c, manifest.TypePypi, "idna", "3.7")
	if row.ObjectKey != key || row.Evaluated() || row.PolicyDigest != "" {
		t.Errorf("unadmitted pin row = %+v, want the key and nothing evaluated", row)
	}
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), key) || !strings.Contains(out.String(), "idna") {
		t.Errorf("the WARNING does not name the package and key: %q", out.String())
	}
	// The next build verifies against the pin, finds that row and stays quiet.
	out.Reset()
	if err := c.pinArtifactDigest(t.Context(), key, manifest.TypePypi, "idna", "3.7", cs); err != nil {
		t.Fatalf("second pin: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a repeat pin warned again: %q", out.String())
	}
}
