package server

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgsign"
	"github.com/ravinald/bodega/internal/policy"
)

// The advisory gate on a FreeBSD package fetch, against a mirrored latest/
// listing openssl at an affected build and at its fix, and a VuXML feed
// carrying one entry whose fix is the port revision.
const (
	fbsdOSVVid      = "9c4a8b1e-6b31-11ef-a6d3-a0369f7c1e01"
	fbsdOSVTopic    = "OpenSSL -- denial of service in X.509 name checks"
	fbsdOSVAffected = "All/Hashed/openssl-3.0.15,1~aaa111.pkg"
	fbsdOSVFixed    = "All/Hashed/openssl-3.0.15_1,1~bbb222.pkg"
)

const fbsdOSVFeed = `<?xml version="1.0" encoding="utf-8"?>
<vuxml xmlns="http://www.vuxml.org/apps/vuxml-1">
  <vuln vid="` + fbsdOSVVid + `">
    <topic>` + fbsdOSVTopic + `</topic>
    <affects><package><name>openssl</name><range><lt>3.0.15_1,1</lt></range></package></affects>
    <description><body xmlns="http://www.w3.org/1999/xhtml"><p>Fixed in the port.</p></body></description>
    <references><cvename>CVE-2024-6119</cvename></references>
    <dates><discovery>2024-09-03</discovery><entry>2024-09-04</entry></dates>
  </vuln>
</vuxml>
`

// fbsdOSVServer mirrors the repository, syncs the feed into osv_db_dir and
// sets the freebsd OSV action.
func fbsdOSVServer(t *testing.T, action string) *Server {
	t.Helper()
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	catalog, err := s.freeBSDArchive(freeBSDCatalogDoc, []byte(strings.Join([]string{
		`{"name":"openssl","origin":"security/openssl","version":"3.0.15,1","repopath":"` + fbsdOSVAffected + `"}`,
		`{"name":"openssl","origin":"security/openssl","version":"3.0.15_1,1","repopath":"` + fbsdOSVFixed + `"}`,
	}, "\n")+"\n"), upstreamPkgKey(t))
	if err != nil {
		t.Fatalf("build the published catalogue: %v", err)
	}
	mirrored(t, s, "latest", map[string]string{
		manifest.FreeBSDCatalogFile: string(catalog),
		fbsdOSVAffected:             "affected pkg",
		fbsdOSVFixed:                "fixed pkg",
	})

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fbsdOSVFeed))
	}))
	t.Cleanup(feed.Close)
	s.cfg.OSVDBDir = t.TempDir()
	db := policy.NewOSVDatabase(s.cfg.OSVDBDir)
	db.VuXMLURL = feed.URL + "/vuln.xml"
	if _, err := db.Sync(t.Context(), policy.VuXMLEcosystem); err != nil {
		t.Fatalf("sync VuXML: %v", err)
	}
	if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeFreeBSD, Action: action}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
	return s
}

func fbsdOSVCheck(t *testing.T, s *Server, version string) audit.AdmissionCheck {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeFreeBSD, PkgName: "openssl", PkgVersion: version})
	if err != nil || len(rows) == 0 {
		t.Fatalf("no admission row for openssl@%s (%v)", version, err)
	}
	r := rows[len(rows)-1]
	i := slices.IndexFunc(r.Checks, func(c audit.AdmissionCheck) bool { return c.Check == audit.CheckOSV })
	if i < 0 {
		t.Fatalf("admission row names no OSV check: %+v", r.Checks)
	}
	return r.Checks[i]
}

func namesAdvisory(s string) bool {
	return strings.Contains(s, fbsdOSVVid) && strings.Contains(s, fbsdOSVTopic)
}

func TestFreeBSDOSV_BlockRefusesTheAffectedVersionAndServesTheFix(t *testing.T) {
	s := fbsdOSVServer(t, policy.ActionBlock)

	code, body := getStatusAndBody(t, s, freeBSDURL("latest", fbsdOSVAffected))
	if code != http.StatusForbidden || !namesAdvisory(body) {
		t.Fatalf("affected version = %d %q, want 403 naming %s and its topic", code, body, fbsdOSVVid)
	}
	// The .sig beside it is the same package.
	if code, _ := getStatusAndBody(t, s, freeBSDURL("latest", fbsdOSVAffected+".sig")); code != http.StatusForbidden {
		t.Errorf("the affected version's .sig = %d, want 403", code)
	}
	rows := policyRows(t, s, "3.0.15,1")
	if len(rows) == 0 || rows[0].Status != audit.CachePolicyViolation || !namesAdvisory(rows[0].Details) {
		t.Errorf("want a policy_violation row naming %s and its topic, got %+v", fbsdOSVVid, rows)
	}
	if c := fbsdOSVCheck(t, s, "3.0.15,1"); c.Status != audit.CheckBlock || !namesAdvisory(c.Detail) {
		t.Errorf("admission OSV check = %+v, want block naming the vid and topic", c)
	}

	if code, body := getStatusAndBody(t, s, freeBSDURL("latest", fbsdOSVFixed)); code != http.StatusOK || body != "fixed pkg" {
		t.Errorf("fixed version = %d %q, want 200 and the stored bytes", code, body)
	}
	if rows := policyRows(t, s, "3.0.15_1,1"); len(rows) != 0 {
		t.Errorf("the fixed version wrote policy rows: %+v", rows)
	}
}

func TestFreeBSDOSV_WarnServesAndRecordsTheAffectedVersion(t *testing.T) {
	s := fbsdOSVServer(t, policy.ActionWarn)

	if code, body := getStatusAndBody(t, s, freeBSDURL("latest", fbsdOSVAffected)); code != http.StatusOK || body != "affected pkg" {
		t.Fatalf("affected version under warn = %d %q, want 200", code, body)
	}
	if code, _ := getStatusAndBody(t, s, freeBSDURL("latest", fbsdOSVFixed)); code != http.StatusOK {
		t.Fatalf("fixed version under warn = %d, want 200", code)
	}
	rows := policyRows(t, s, "3.0.15,1")
	if len(rows) != 1 || rows[0].Status != "policy_warn" || !namesAdvisory(rows[0].Details) {
		t.Errorf("want one policy_warn row naming %s and its topic, got %+v", fbsdOSVVid, rows)
	}
	if c := fbsdOSVCheck(t, s, "3.0.15,1"); c.Status != audit.CheckWarn {
		t.Errorf("admission OSV check = %+v, want warn", c)
	}
	if rows := policyRows(t, s, "3.0.15_1,1"); len(rows) != 0 {
		t.Errorf("the fixed version wrote policy rows: %+v", rows)
	}
}

// With no freebsd OSV action the object gate reads no catalogue for an
// unbound host and serves the affected version as before.
func TestFreeBSDOSV_UnsetActionLeavesTheFetchUngated(t *testing.T) {
	s := fbsdOSVServer(t, policy.ActionBlock)
	if _, err := s.auditDB.DeleteOSVPolicy(t.Context(), manifest.TypeFreeBSD); err != nil {
		t.Fatalf("delete osv policy: %v", err)
	}
	if code, _ := getStatusAndBody(t, s, freeBSDURL("latest", fbsdOSVAffected)); code != http.StatusOK {
		t.Errorf("affected version with no action = %d, want 200", code)
	}
	if rows := policyRows(t, s, "3.0.15,1"); len(rows) != 0 {
		t.Errorf("an ungated fetch wrote policy rows: %+v", rows)
	}
}
