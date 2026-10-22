package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The OSV gate on mirrored apt, against a fixture archive mirroring resolute
// and its security pocket and a stand-in OSV export carrying one advisory
// against php8.5 in Ubuntu:26.04:LTS: 8.5.4-0ubuntu1 is inside its range and
// 8.5.4-0ubuntu2 is the fix. The advisory names the source package, and the
// .deb is php8.5-fpm, so a gate asking under the binary name finds nothing.

const (
	mirrorOSVAdvisory = "USN-9999-1"
	mirrorOSVAdvised  = "pool/universe/p/php8.5/php8.5-fpm_8.5.4-0ubuntu1_amd64.deb"
	mirrorOSVFixed    = "pool/universe/p/php8.5/php8.5-fpm_8.5.4-0ubuntu2_amd64.deb"
)

// mirrorOSVServer mirrors resolute and resolute-security from one fixture
// archive and sets the apt OSV action. synced false leaves osv_db_dir empty,
// which is a release nobody ran 'policy osv sync' for.
func mirrorOSVServer(t *testing.T, action string, synced bool) (*Server, *bytes.Buffer) {
	t.Helper()
	archive := newFixtureArchive(t, map[string]string{
		mirrorOSVAdvised: "advised deb",
		mirrorOSVFixed:   "fixed deb",
	})
	s := mirrorServer(t, archive)
	list := []config.AptUpstream{{URL: archive.URL()}}
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{"resolute": list, "resolute-security": list}
	s.cfg.OSVDBDir = t.TempDir()
	if synced {
		syncMirrorOSV(t, s.cfg.OSVDBDir)
	}
	if action != "" {
		if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeApt, Action: action}); err != nil {
			t.Fatalf("set osv policy: %v", err)
		}
	}
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return s, &logs
}

// syncMirrorOSV writes the resolute index out of a stand-in for OSV's
// aggregate Ubuntu archive, which is the archive sync reads.
func syncMirrorOSV(t *testing.T, dir string) {
	t.Helper()
	rec := map[string]any{
		"id":       mirrorOSVAdvisory,
		"modified": "2026-10-22T00:00:00Z",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Ubuntu:26.04:LTS", "name": "php8.5"},
			"ranges": []any{map[string]any{"type": "ECOSYSTEM", "events": []any{
				map[string]any{"introduced": "0"}, map[string]any{"fixed": "8.5.4-0ubuntu2"},
			}}},
		}},
	}
	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create(mirrorOSVAdvisory + ".json")
		_ = json.NewEncoder(f).Encode(rec)
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(export.Close)
	db := policy.NewOSVDatabase(dir)
	db.ExportBase = export.URL
	if _, err := db.Sync(t.Context(), "Ubuntu:26.04:LTS"); err != nil {
		t.Fatalf("sync Ubuntu:26.04:LTS: %v", err)
	}
}

func mirrorOSVGet(t *testing.T, s *Server, poolPath string) (int, string) {
	t.Helper()
	code, body := mirrorGet(t, s, "/apt/"+poolPath)
	return code, string(body)
}

// policyRows is the policy_warn and policy_violation cache rows for one
// version, the rows that carry the advisory beside the admission.
func policyRows(t *testing.T, s *Server, version string) []audit.StoredEvent {
	t.Helper()
	var out []audit.StoredEvent
	for _, r := range cacheRows(t, s) {
		if r.PkgVersion == version && (r.Status == "policy_warn" || r.Status == audit.CachePolicyViolation) {
			out = append(out, r)
		}
	}
	return out
}

// osvCheckOf is the OSV entry of the one admission row for php8.5-fpm@version.
func osvCheckOf(t *testing.T, s *Server, version string) audit.AdmissionCheck {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeApt, PkgName: "php8.5-fpm", PkgVersion: version})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("no admission row for php8.5-fpm@%s", version)
	}
	r := rows[len(rows)-1]
	i := slices.IndexFunc(r.Checks, func(c audit.AdmissionCheck) bool { return c.Check == audit.CheckOSV })
	if i < 0 {
		t.Fatalf("admission row names no OSV check: %+v", r.Checks)
	}
	return r.Checks[i]
}

func TestAptMirrorOSV_BlockRefusesTheAdvisedVersionAndServesTheFix(t *testing.T) {
	s, _ := mirrorOSVServer(t, policy.ActionBlock, true)

	code, body := mirrorOSVGet(t, s, mirrorOSVAdvised)
	if code != http.StatusForbidden {
		t.Fatalf("advised version = %d, want 403 (%s)", code, body)
	}
	if !strings.Contains(body, mirrorOSVAdvisory) {
		t.Errorf("the refusal must name the advisory: %q", body)
	}
	rows := policyRows(t, s, "8.5.4-0ubuntu1")
	if len(rows) != 1 || rows[0].Status != audit.CachePolicyViolation || !strings.Contains(rows[0].Details, mirrorOSVAdvisory) {
		t.Errorf("want one policy_violation row naming %s, got %+v", mirrorOSVAdvisory, rows)
	}
	if c := osvCheckOf(t, s, "8.5.4-0ubuntu1"); c.Status != audit.CheckBlock || !strings.Contains(c.Detail, "Ubuntu:26.04:LTS") {
		t.Errorf("the admission must record the block against resolute's release: %+v", c)
	}

	if code, body := mirrorOSVGet(t, s, mirrorOSVFixed); code != http.StatusOK || body != "fixed deb" {
		t.Errorf("fixed version = %d %q, want 200 and the archive's bytes", code, body)
	}
	if rows := policyRows(t, s, "8.5.4-0ubuntu2"); len(rows) != 0 {
		t.Errorf("a clean version wrote policy rows: %+v", rows)
	}
}

// TestAptMirrorOSV_BlockRefusesAVersionAlreadyCached is the live run's shape:
// the vulnerable build reached the cache before the gate was turned on, and a
// gate that runs on the miss alone serves it from the cache forever, since a
// mirrored .deb has no manifest entry for rescan to revisit.
func TestAptMirrorOSV_BlockRefusesAVersionAlreadyCached(t *testing.T) {
	s, _ := mirrorOSVServer(t, "", true)
	if code, body := mirrorOSVGet(t, s, mirrorOSVAdvised); code != http.StatusOK {
		t.Fatalf("with no apt policy the fetch is ungated; got %d (%s)", code, body)
	}
	if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeApt, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}

	code, body := mirrorOSVGet(t, s, mirrorOSVAdvised)
	if code != http.StatusForbidden || !strings.Contains(body, mirrorOSVAdvisory) {
		t.Fatalf("cached advised version = %d %q, want 403 naming %s", code, body, mirrorOSVAdvisory)
	}
	if rows := policyRows(t, s, "8.5.4-0ubuntu1"); len(rows) != 1 || rows[0].Status != audit.CachePolicyViolation {
		t.Errorf("want one policy_violation row for the cached refusal, got %+v", rows)
	}
}

func TestAptMirrorOSV_WarnServesBothAndRecordsTheAdvised(t *testing.T) {
	s, _ := mirrorOSVServer(t, policy.ActionWarn, true)

	if code, body := mirrorOSVGet(t, s, mirrorOSVAdvised); code != http.StatusOK || body != "advised deb" {
		t.Fatalf("advised version under warn = %d %q, want 200", code, body)
	}
	if code, body := mirrorOSVGet(t, s, mirrorOSVFixed); code != http.StatusOK || body != "fixed deb" {
		t.Fatalf("fixed version under warn = %d %q, want 200", code, body)
	}
	// Again, out of the cache: the hit is gated too, and writes its own row.
	if code, _ := mirrorOSVGet(t, s, mirrorOSVAdvised); code != http.StatusOK {
		t.Fatalf("cached advised version under warn = %d, want 200", code)
	}

	rows := policyRows(t, s, "8.5.4-0ubuntu1")
	if len(rows) != 2 {
		t.Fatalf("want a policy_warn row for the miss and the hit, got %+v", rows)
	}
	for _, r := range rows {
		if r.Status != "policy_warn" || !strings.Contains(r.Details, mirrorOSVAdvisory) {
			t.Errorf("row = %+v, want policy_warn naming %s", r, mirrorOSVAdvisory)
		}
	}
	if c := osvCheckOf(t, s, "8.5.4-0ubuntu1"); c.Status != audit.CheckWarn {
		t.Errorf("osv check = %+v, want warn", c)
	}
	if rows := policyRows(t, s, "8.5.4-0ubuntu2"); len(rows) != 0 {
		t.Errorf("a clean version wrote policy rows: %+v", rows)
	}
}

// TestAptMirrorOSV_UnsyncedReleaseIsServedAndReported is requirement 3: a
// release with no index is served, the row says the check did not run and
// why, and the log names the release once however many fetches hit it.
func TestAptMirrorOSV_UnsyncedReleaseIsServedAndReported(t *testing.T) {
	s, logs := mirrorOSVServer(t, policy.ActionBlock, false)

	for _, p := range []string{mirrorOSVAdvised, mirrorOSVFixed, mirrorOSVAdvised} {
		if code, body := mirrorOSVGet(t, s, p); code != http.StatusOK {
			t.Fatalf("%s with no synced export = %d (%s), want 200", p, code, body)
		}
	}
	c := osvCheckOf(t, s, "8.5.4-0ubuntu1")
	if c.Status != audit.CheckNotEvaluated || !strings.Contains(c.Detail, "Ubuntu:26.04:LTS") {
		t.Errorf("osv check = %+v, want not_evaluated naming the release", c)
	}
	if rows := policyRows(t, s, "8.5.4-0ubuntu1"); len(rows) != 0 {
		t.Errorf("an unchecked fetch is not a finding, got rows %+v", rows)
	}
	if n := strings.Count(logs.String(), "served unchecked by the OSV gate"); n != 1 {
		t.Errorf("unchecked log lines = %d, want 1:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "Ubuntu:26.04:LTS") {
		t.Errorf("the log must name the release:\n%s", logs.String())
	}
}

// TestAptMirrorOSV_TwoMirroredReleasesAreNotGuessed pins the refusal to place
// a pool path: noble and resolute share a pool, and a noble revision checked
// against resolute's ranges sits below every resolute fix.
func TestAptMirrorOSV_TwoMirroredReleasesAreNotGuessed(t *testing.T) {
	s, _ := mirrorOSVServer(t, policy.ActionBlock, true)
	list := s.cfg.AptUpstreams["resolute"]
	s.cfg.AptUpstreams["noble"] = list

	if code, body := mirrorOSVGet(t, s, mirrorOSVAdvised); code != http.StatusOK {
		t.Fatalf("an unplaceable .deb is served unchecked, not refused; got %d (%s)", code, body)
	}
	if c := osvCheckOf(t, s, "8.5.4-0ubuntu1"); c.Status != audit.CheckNotEvaluated || !strings.Contains(c.Detail, "2 releases") {
		t.Errorf("osv check = %+v, want not_evaluated naming the two releases", c)
	}
}
