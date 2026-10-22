package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
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
	// mirrorOSVUnlisted is in the pool and in no Packages paragraph.
	mirrorOSVUnlisted = "pool/universe/p/php8.5/php8.5-fpm_8.5.4-0ubuntu3_amd64.deb"
)

// mirrorOSVDeb is one pool object and the Packages paragraph naming it.
type mirrorOSVDeb struct {
	pool, pkg, source, version, body string
}

// mirrorOSVDists publishes one codename's Release and a universe/binary-amd64
// Packages listing debs, compressed and digested as an archive publishes it.
func mirrorOSVDists(codename string, debs ...mirrorOSVDeb) map[string]string {
	var packages strings.Builder
	for _, d := range debs {
		sum := sha256.Sum256([]byte(d.body))
		fmt.Fprintf(&packages, "Package: %s\nSource: %s\nVersion: %s\nArchitecture: amd64\nFilename: %s\nSize: %d\nSHA256: %s\n\n",
			d.pkg, d.source, d.version, d.pool, len(d.body), hex.EncodeToString(sum[:]))
	}
	rest := "universe/binary-amd64/Packages.gz"
	gz := gzipFixture(packages.String())
	sum := sha256.Sum256(gz)
	release := strings.Join([]string{
		"Origin: Ubuntu", "Codename: " + codename, "Components: universe", "Architectures: amd64", "SHA256:",
		fmt.Sprintf(" %s %d %s", hex.EncodeToString(sum[:]), len(gz), rest), "",
	}, "\n")
	out := map[string]string{"dists/" + codename + "/Release": release, "dists/" + codename + "/" + rest: string(gz)}
	for _, d := range debs {
		out[d.pool] = d.body
	}
	return out
}

// mirrorOSVServer mirrors resolute and resolute-security from one fixture
// archive and sets the apt OSV action. synced false leaves osv_db_dir empty,
// which is a release nobody ran 'policy osv sync' for.
func mirrorOSVServer(t *testing.T, action string, synced bool) (*Server, *bytes.Buffer) {
	t.Helper()
	objects := mirrorOSVDists("resolute",
		mirrorOSVDeb{mirrorOSVAdvised, "php8.5-fpm", "php8.5", "8.5.4-0ubuntu1", "advised deb"})
	maps.Copy(objects, mirrorOSVDists("resolute-security",
		mirrorOSVDeb{mirrorOSVFixed, "php8.5-fpm", "php8.5", "8.5.4-0ubuntu2", "fixed deb"}))
	objects[mirrorOSVUnlisted] = "unlisted deb"
	s, logs := mirrorOSVServerFor(t, objects, action, "resolute", "resolute-security")
	s.cfg.OSVDBDir = t.TempDir()
	if synced {
		syncMirrorOSV(t, s.cfg.OSVDBDir, "Ubuntu:26.04:LTS", "php8.5", "8.5.4-0ubuntu2")
	}
	return s, logs
}

// mirrorOSVServerFor mirrors codenames from one archive serving objects, with
// the apt OSV action set unless action is empty.
func mirrorOSVServerFor(t *testing.T, objects map[string]string, action string, codenames ...string) (*Server, *bytes.Buffer) {
	t.Helper()
	archive := newFixtureArchive(t, objects)
	s := mirrorServer(t, archive)
	list := []config.AptUpstream{{URL: archive.URL()}}
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{}
	for _, c := range codenames {
		s.cfg.AptUpstreams[c] = list
	}
	s.cfg.OSVDBDir = t.TempDir()
	if action != "" {
		if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeApt, Action: action}); err != nil {
			t.Fatalf("set osv policy: %v", err)
		}
	}
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return s, &logs
}

// syncMirrorOSV writes one release's index out of a stand-in for OSV's
// aggregate archive, carrying mirrorOSVAdvisory against source below fixed.
func syncMirrorOSV(t *testing.T, dir, ecosystem, source, fixed string) {
	t.Helper()
	rec := map[string]any{
		"id":       mirrorOSVAdvisory,
		"modified": "2026-10-22T00:00:00Z",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": ecosystem, "name": source},
			"ranges": []any{map[string]any{"type": "ECOSYSTEM", "events": []any{
				map[string]any{"introduced": "0"}, map[string]any{"fixed": fixed},
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
	if _, err := db.Sync(t.Context(), ecosystem); err != nil {
		t.Fatalf("sync %s: %v", ecosystem, err)
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

// osvCheckOf is the OSV entry of the latest admission row for php8.5-fpm@version.
func osvCheckOf(t *testing.T, s *Server, version string) audit.AdmissionCheck {
	t.Helper()
	return osvCheckFor(t, s, "php8.5-fpm", version)
}

func osvCheckFor(t *testing.T, s *Server, name, version string) audit.AdmissionCheck {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeApt, PkgName: name, PkgVersion: version})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("no admission row for %s@%s", name, version)
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

// The pool drops the epoch openssh carries, and OSV's range keeps it: the
// gate has to compare the Packages paragraph's version, not the filename's,
// or the patched build sorts below the fix and is refused.
func TestAptMirrorOSV_EpochComesFromThePackagesParagraph(t *testing.T) {
	const (
		patched = "pool/main/o/openssh/openssh-server_9.6p1-3ubuntu13.20_amd64.deb"
		advised = "pool/main/o/openssh/openssh-server_9.6p1-3ubuntu13.2_amd64.deb"
	)
	objects := mirrorOSVDists("noble",
		mirrorOSVDeb{advised, "openssh-server", "openssh", "1:9.6p1-3ubuntu13.2", "advised deb"})
	maps.Copy(objects, mirrorOSVDists("noble-security",
		mirrorOSVDeb{patched, "openssh-server", "openssh", "1:9.6p1-3ubuntu13.20", "patched deb"}))
	s, _ := mirrorOSVServerFor(t, objects, policy.ActionBlock, "noble", "noble-security")
	syncMirrorOSV(t, s.cfg.OSVDBDir, "Ubuntu:24.04:LTS", "openssh", "1:9.6p1-3ubuntu13.3")

	if code, body := mirrorOSVGet(t, s, patched); code != http.StatusOK || body != "patched deb" {
		t.Fatalf("patched 1:9.6p1-3ubuntu13.20 against a fix at 1:9.6p1-3ubuntu13.3 = %d %q, want 200", code, body)
	}
	for _, r := range cacheRows(t, s) {
		if r.Status == "policy_warn" || r.Status == audit.CachePolicyViolation {
			t.Errorf("the patched build wrote a policy row: %+v", r)
		}
	}
	if c := osvCheckFor(t, s, "openssh-server", "9.6p1-3ubuntu13.20"); c.Status == audit.CheckBlock || c.Status == audit.CheckWarn {
		t.Errorf("osv check on the patched build = %+v, want clean", c)
	}

	code, body := mirrorOSVGet(t, s, advised)
	if code != http.StatusForbidden || !strings.Contains(body, mirrorOSVAdvisory) {
		t.Fatalf("advised 1:9.6p1-3ubuntu13.2 = %d %q, want 403 naming %s", code, body, mirrorOSVAdvisory)
	}
}

// A pool path no mirrored paragraph names is served unchecked rather than
// judged from its filename, which has no epoch to compare.
func TestAptMirrorOSV_PathNoParagraphNamesIsNotEvaluated(t *testing.T) {
	s, _ := mirrorOSVServer(t, policy.ActionBlock, true)

	if code, body := mirrorOSVGet(t, s, mirrorOSVUnlisted); code != http.StatusOK || body != "unlisted deb" {
		t.Fatalf("unlisted path = %d %q, want 200", code, body)
	}
	c := osvCheckOf(t, s, "8.5.4-0ubuntu3")
	if c.Status != audit.CheckNotEvaluated || !strings.Contains(c.Detail, "no Packages paragraph") {
		t.Errorf("osv check = %+v, want not_evaluated naming the missing paragraph", c)
	}
	if rows := policyRows(t, s, "8.5.4-0ubuntu3"); len(rows) != 0 {
		t.Errorf("an unchecked fetch is not a finding, got rows %+v", rows)
	}
}

func TestAptSourceVersion(t *testing.T) {
	for _, tc := range []struct{ source, version, want string }{
		{"openssh", "1:9.6p1-3ubuntu13.20", "1:9.6p1-3ubuntu13.20"},
		{"", "2.6.1-2", "2.6.1-2"},
		{"glib2.0 (2.80.0-6ubuntu3)", "2.80.0-6ubuntu3+b1", "2.80.0-6ubuntu3"},
		{"broken (", "1.0-1", "1.0-1"},
	} {
		if got := aptSourceVersion(map[string]string{"Source": tc.source, "Version": tc.version}); got != tc.want {
			t.Errorf("aptSourceVersion(%q, %q) = %q, want %q", tc.source, tc.version, got, tc.want)
		}
	}
}
