package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pins"
	"github.com/ravinald/bodega/internal/policy"
)

// adminServer is a server whose admin surface the test client can reach. The
// pins endpoint sits behind the same gate as the audit trail and the token
// list, so a test that skipped it would assert nothing about the one control
// this endpoint has.
func adminServer(t *testing.T) *Server {
	t.Helper()
	s := proxyingServer(t)
	var nets []*net.IPNet
	for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		nets = append(nets, n)
	}
	s.adminNets = nets
	s.refreshACLs(context.Background())
	return s
}

// The endpoint exists so a vulnerability management tool can read what a class
// of host is deliberately not patching. It has to carry the decision and the
// advisories together: either half alone is what the operator already had from
// apt-mark or from a scanner.
func TestAPIProfilePinsCarriesTheDecisionAndTheAdvisories(t *testing.T) {
	s := adminServer(t)
	ctx := context.Background()
	if err := s.store.AddVersion(ctx, manifest.TypePypi, "django", manifest.VersionEntry{
		Version: "4.2.11",
		Metadata: map[string]string{
			policy.OSVMetaVulns:     "GHSA-aaaa-bbbb-cccc",
			policy.OSVMetaSeverity:  `{"GHSA-aaaa-bbbb-cccc":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`,
			policy.OSVMetaCheckedAt: "2026-09-08T10:00:00Z",
		},
	}); err != nil {
		t.Fatalf("seed django: %v", err)
	}
	// Listed and not pinned: the report is about pins, and an entry that
	// defers to its type's default is not a decision to stop taking updates.
	if err := s.store.AddVersion(ctx, manifest.TypePypi, "requests",
		manifest.VersionEntry{Version: "2.31.0"}); err != nil {
		t.Fatalf("seed requests: %v", err)
	}
	bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{
			{
				Type: manifest.TypePypi, Name: "django",
				Constraint: manifest.ConstraintExact, Version: "4.2.11",
				Reason: "5 drops the middleware", ReviewAfter: "2020-01-01", Actor: "ravi",
			},
			{Type: manifest.TypePypi, Name: "requests"},
		})

	status, body := getWithToken(t, s, "", "/api/v1/profiles/web/pins")
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/profiles/web/pins = %d: %s", status, body)
	}
	var got struct {
		Profile string     `json:"profile"`
		Pins    []pins.Pin `json:"pins"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Profile != "web" {
		t.Errorf("the response names profile %q, want web", got.Profile)
	}
	if len(got.Pins) != 1 {
		t.Fatalf("pins = %d, want 1 (an unpinned entry is not a pin): %s", len(got.Pins), body)
	}
	p := got.Pins[0]
	if p.Name != "django" || p.Version != "4.2.11" {
		t.Errorf("the pin names %s at %s, want django at 4.2.11", p.Name, p.Version)
	}
	if p.Reason != "5 drops the middleware" || p.Actor != "ravi" {
		t.Errorf("the decision did not survive: reason=%q actor=%q", p.Reason, p.Actor)
	}
	if !p.Stale || p.OverdueDays <= 0 {
		t.Errorf("a pin due in 2020 reports stale=%v overdue=%d", p.Stale, p.OverdueDays)
	}
	if p.OSV.State != pins.OSVFlagged || len(p.OSV.Vulns) != 1 {
		t.Errorf("the advisory half is missing: %+v", p.OSV)
	}
	if len(p.OSV.Severity["GHSA-aaaa-bbbb-cccc"]) != 1 {
		t.Errorf("the severity B34 recorded is absent: %+v", p.OSV.Severity)
	}
	if p.OSV.Checked == nil {
		t.Error("the refresh date is absent, so nobody can tell how current the answer is")
	}

	stale := func(path string) []pins.Pin {
		t.Helper()
		status, body := getWithToken(t, s, "", path)
		if status != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, status, body)
		}
		var r struct {
			Pins []pins.Pin `json:"pins"`
		}
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return r.Pins
	}
	if n := len(stale("/api/v1/profiles/web/pins?stale=true")); n != 1 {
		t.Errorf("?stale=true returned %d pins, want the one that is overdue", n)
	}

	if status, _ := getWithToken(t, s, "", "/api/v1/profiles/nosuch/pins"); status != http.StatusNotFound {
		t.Errorf("an unknown profile answered %d, want 404", status)
	}
}

// A profile with no pins answers with an empty array rather than null. A
// client reading this to decide what a host class is not patching has to tell
// "no pins" from a field it failed to parse, and null reads as the second.
func TestAPIProfilePinsAnswersAnEmptyArray(t *testing.T) {
	s := adminServer(t)
	bindProfile(t, s, "clean", "clean01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})

	status, body := getWithToken(t, s, "", "/api/v1/profiles/clean/pins")
	if status != http.StatusOK {
		t.Fatalf("GET = %d: %s", status, body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if string(raw["pins"]) != "[]" {
		t.Errorf("pins = %s, want []", raw["pins"])
	}
}

// The pin report is the list of versions a class of host is deliberately not
// patching, with the advisories against them. A caller outside
// admin_permit_cidr gets none of it.
func TestAPIProfilePinsIsAdminGated(t *testing.T) {
	s := proxyingServer(t)
	bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "django",
			Constraint: manifest.ConstraintExact, Version: "4.2.11", Reason: "5 drops the middleware",
		}})

	status, body := getWithToken(t, s, "", "/api/v1/profiles/web/pins")
	if status != http.StatusForbidden {
		t.Fatalf("an unprivileged caller read the pin report: %d %s", status, body)
	}
	if strings.Contains(body, "django") {
		t.Errorf("the refusal leaks the pinned package:\n%s", body)
	}
}

// Index generation checks feasibility and reports. It must not extend the pin
// across the closure: each package pinned drags its own dependencies in, and a
// host would stop receiving security updates for all of them with nobody
// having decided that it should.
func TestIndexGenerationReportsPinConflictsAndExtendsNothing(t *testing.T) {
	s := adminServer(t)
	ctx := context.Background()
	for _, v := range []struct{ name, version string }{
		{"postgresql-14", "14.9"}, {"libpq5", "15.1"},
	} {
		if err := s.store.AddVersion(ctx, manifest.TypeApt, v.name,
			manifest.VersionEntry{Version: v.version}); err != nil {
			t.Fatalf("seed %s: %v", v.name, err)
		}
	}
	s.store.AddEdge(manifest.DepEdge{
		Parent: "apt/postgresql-14", Child: "apt/libpq5@14.9", RawSpec: "libpq5 (= 14.9)",
	})
	if err := s.store.SaveGraph(ctx); err != nil {
		t.Fatalf("save graph: %v", err)
	}
	// postgresql-14 is held at 14.9, which needs libpq5 14.9, and the profile
	// holds libpq5 at 15.1. That is the pin apt discovers during an upgrade.
	bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{
			{
				Type: manifest.TypeApt, Name: "postgresql-14",
				Constraint: manifest.ConstraintExact, Version: "14.9", Reason: "15 breaks the config",
			},
			{
				Type: manifest.TypeApt, Name: "libpq5",
				Constraint: manifest.ConstraintExact, Version: "15.1", Reason: "tracking the distro",
			},
		})

	var logged strings.Builder
	s.logger = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Through the index build rather than the pass alone: a feasibility check
	// nothing calls is a check that reports at no moment an operator has.
	if _, err := s.buildAptSnapshot(ctx); err != nil {
		t.Fatalf("build apt snapshot: %v", err)
	}

	if !strings.Contains(logged.String(), "apt/libpq5") {
		t.Errorf("index generation did not report the pin its own closure contradicts:\n%s", logged.String())
	}
	if !strings.Contains(logged.String(), "--strict-closure") {
		t.Errorf("the report does not name the deliberate way to extend a pin:\n%s", logged.String())
	}

	d, err := s.auditDB.GetProfile(ctx, "db")
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if len(d.Entries) != 2 {
		t.Errorf("index generation wrote %d entries, want the 2 an operator authored: %+v", len(d.Entries), d.Entries)
	}
	for _, e := range d.Entries {
		if e.Name == "libpq5" && e.Version != "15.1" {
			t.Errorf("index generation moved a pin an operator set: libpq5 at %s", e.Version)
		}
	}
}
