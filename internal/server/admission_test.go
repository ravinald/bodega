package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The admission matrix on the server's three surfaces: POST /api/v1/packages,
// POST /api/v1/packages/import and a proxy fill. Each drives a clean pass, a
// warn and a block through the npm OSV gate, offline: a synced database that
// names minimist 1.2.0 passes 1.2.8 and blocks 1.2.0, and an osv_db_dir that
// was never synced makes the gate warn.

// syncedOSVDir syncs an npm OSV database naming minimist 1.2.0 and returns
// its directory.
func syncedOSVDir(t *testing.T) string {
	t.Helper()
	rec := map[string]any{
		"id": "GHSA-test-0001",
		"affected": []map[string]any{{
			"package":  map[string]string{"name": "minimist", "ecosystem": "npm"},
			"versions": []string{"1.2.0"},
		}},
	}
	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create("GHSA-test-0001.json")
		_ = json.NewEncoder(f).Encode(rec)
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(export.Close)
	dir := t.TempDir()
	db := policy.NewOSVDatabase(dir)
	db.ExportBase = export.URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	return dir
}

// gateNpmOSV sets the npm OSV gate to block on s, and points it at a synced
// database or, with synced false, at one that never was. The age gate a fresh
// store seeds is removed: it dates versions against the public registry.
func gateNpmOSV(t *testing.T, s *Server, synced bool) {
	t.Helper()
	if _, err := s.auditDB.DeleteAgePolicy(t.Context(), manifest.TypeNpm); err != nil {
		t.Fatalf("delete seeded age policy: %v", err)
	}
	if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
	if synced {
		s.cfg.OSVDBDir = syncedOSVDir(t)
	} else {
		s.cfg.OSVDBDir = t.TempDir()
	}
}

type admissionCase struct {
	name     string
	synced   bool
	version  string
	decision string
	osv      string
}

var admissionCases = []admissionCase{
	{"clean_pass", true, "1.2.8", audit.AdmissionAdmitted, audit.CheckPass},
	{"warn", false, "1.2.8", audit.AdmissionAdmitted, audit.CheckWarn},
	{"block", true, "1.2.0", audit.AdmissionPolicyBlocked, audit.CheckBlock},
}

// assertAdmission reads the one row for minimist@version and holds it to the
// case, the policy digest in force and the identity the request carried.
func assertAdmission(t *testing.T, s *Server, tc admissionCase, identity string) audit.Admission {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: tc.version})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one admission row for minimist@%s, got %d: %+v", tc.version, len(rows), rows)
	}
	r := rows[0]
	digest, err := policy.Digest(t.Context(), s.auditDB)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if r.Decision != tc.decision || r.PolicyDigest != digest || r.Identity != identity {
		t.Errorf("row = decision %q digest %q identity %q; want %q, %q, %q", r.Decision, r.PolicyDigest, r.Identity, tc.decision, digest, identity)
	}
	i := slices.IndexFunc(r.Checks, func(c audit.AdmissionCheck) bool { return c.Check == audit.CheckOSV })
	if i < 0 || r.Checks[i].Status != tc.osv || r.Checks[i].Action != policy.ActionBlock {
		t.Errorf("osv check = %+v, want status %s under action block", r.Checks, tc.osv)
	}
	return r
}

// withIdentity is a request IdentityMiddleware resolved to id.
func withIdentity(r *http.Request, id string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey, identityMatch{Identity: id}))
}

func TestCreateEntryRecordsTheAdmission(t *testing.T) {
	want := map[string]int{"clean_pass": http.StatusCreated, "warn": http.StatusCreated, "block": http.StatusForbidden}
	for _, tc := range admissionCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscoveryServer(t)
			gateNpmOSV(t, s, tc.synced)
			body := `{"name":"minimist","versions":[{"version":"` + tc.version + `"}]}`
			r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm", strings.NewReader(body))
			r.SetPathValue("type", manifest.TypeNpm)
			w := httptest.NewRecorder()
			s.handleCreateEntry(w, withIdentity(r, "build-07"))
			if w.Code != want[tc.name] {
				t.Fatalf("status = %d (%s), want %d", w.Code, w.Body.String(), want[tc.name])
			}
			assertAdmission(t, s, tc, "build-07")
		})
	}
}

func TestBulkImportRecordsTheAdmission(t *testing.T) {
	want := map[string]ImportOutcome{"clean_pass": ImportImported, "warn": ImportImported, "block": ImportPolicyBlocked}
	for _, tc := range admissionCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscoveryServer(t)
			gateNpmOSV(t, s, tc.synced)
			body := `[{"config_version":1,"name":"minimist","type":"npm","versions":[{"version":"` + tc.version + `"}]}]`
			r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/import", strings.NewReader(body))
			w := httptest.NewRecorder()
			s.handleBulkImport(w, withIdentity(r, "build-08"))
			var resp ImportResponse
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if len(resp.Results) != 1 || resp.Results[0].Outcome != want[tc.name] {
				t.Fatalf("results = %+v, want one %s", resp.Results, want[tc.name])
			}
			assertAdmission(t, s, tc, "build-08")
		})
	}
}

// TestProxyFillRecordsTheAdmission is requirement 4: a proxied version is
// held to import's per-version checks before the fetch, refused with the
// allow-list's status, and its row gains the object key once the digest is
// pinned.
func TestProxyFillRecordsTheAdmission(t *testing.T) {
	for _, tc := range admissionCases {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyingServer(t)
			gateNpmOSV(t, s, tc.synced)
			tarball := "/minimist/-/minimist-" + tc.version + ".tgz"
			up := newRecordingUpstream(t)
			up.route(tarball, "tarball bytes "+tc.version)
			s.cfg.NpmUpstream = up.ts.URL

			status, body := getStatusAndBody(t, s, "/npm"+tarball)
			row := assertAdmission(t, s, tc, "")
			key := manifest.NpmTarballKey("minimist", tc.version)
			if tc.decision == audit.AdmissionPolicyBlocked {
				if status != http.StatusForbidden || strings.TrimSpace(body) != "upstream blocked by osv policy" {
					t.Errorf("refusal = %d %q, want 403 naming the osv policy", status, body)
				}
				if slices.Contains(up.paths(), tarball) {
					t.Errorf("a refused version was fetched from upstream: %v", up.paths())
				}
				if row.ObjectKey != "" {
					t.Errorf("a refused version's row carries object key %q", row.ObjectKey)
				}
				return
			}
			if status != http.StatusOK {
				t.Fatalf("status = %d (%q), want 200", status, body)
			}
			if row.ObjectKey != key {
				t.Errorf("object_key = %q after the pin, want %q", row.ObjectKey, key)
			}
		})
	}
}

// An allow-list refusal on a proxy fill leaves a decision too, and a cache
// hit afterwards does not write another: only a fill is an admission.
func TestProxyFillRecordsAnAllowListRefusal(t *testing.T) {
	s := proxyingServer(t)
	gateNpmOSV(t, s, true)
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	s.policy.Invalidate()
	up := newRecordingUpstream(t)
	s.cfg.NpmUpstream = up.ts.URL

	status, body := getStatusAndBody(t, s, "/npm/minimist/-/minimist-1.2.8.tgz")
	if status != http.StatusForbidden || strings.TrimSpace(body) != "upstream blocked by allow-list" {
		t.Fatalf("refusal = %d %q, want the allow-list's 403", status, body)
	}
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgName: "minimist"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("Admissions = %d rows, %v; want 1", len(rows), err)
	}
	if rows[0].Decision != audit.AdmissionPolicyBlocked || rows[0].Checks[0].Status != audit.CheckBlock {
		t.Errorf("allow-list refusal row = %+v", rows[0])
	}
}
