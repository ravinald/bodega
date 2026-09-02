package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// TestSplitNamespace covers the traversal cases at the splitter, which is
// where they have to be refused: two handlers call this, and a check written
// at each call site is a check one of them will forget.
func TestSplitNamespace(t *testing.T) {
	for _, tc := range []struct {
		path, ns, rest string
		ok             bool
	}{
		{"github/torvalds/linux.git", "github", "torvalds/linux.git", true},
		{"github/torvalds/linux.git/info/refs", "github", "torvalds/linux.git/info/refs", true},
		{"github", "github", "", true},
		{"github/", "github", "", true},
		{"", "", "", false},
		{"/github/repo", "", "", false},
		{"../etc/passwd", "", "", false},
		{"github/../../etc/passwd", "", "", false},
		{"github/..%2f..%2fetc", "", "", false},
		{"github/./repo", "", "", false},
		{".", "", "", false},
	} {
		ns, rest, ok := splitNamespace(tc.path)
		if ok != tc.ok || ns != tc.ns || rest != tc.rest {
			t.Errorf("splitNamespace(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.path, ns, rest, ok, tc.ns, tc.rest, tc.ok)
		}
	}
}

// waitForNoNamespace polls until at least want no_namespace rows are visible.
// The recorder writes off the request goroutine, so absence and presence both
// need a window.
func waitForNoNamespace(t *testing.T, s *Server) []audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []audit.DiscoveryRow
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{
			Decision: audit.DecisionNoNamespace,
		})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) > 0 {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no no_namespace rows after 3s")
	return nil
}

// A request under /git/ naming a namespace no config covers is a request for a
// key nobody added. It 404s, and the row is what tells the operator which key
// to add.
func TestGitNamespaceRecordsNoNamespace(t *testing.T) {
	s := newDiscoveryServer(t)
	s.cfg.GitUpstreams = map[string]config.GitUpstream{
		"corp": {URL: "https://git.corp.example/", Mode: config.GitModeCatalog},
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/gitlab/team/tool.git/info/refs") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET unknown namespace = %d, want 404", resp.StatusCode)
	}

	rows := waitForNoNamespace(t, s)
	if len(rows) != 1 {
		t.Fatalf("no_namespace rows = %d, want 1 (%+v)", len(rows), rows)
	}
	if rows[0].PkgName != "gitlab" || rows[0].PatternHint != "gitlab" {
		t.Errorf("row = pkg_name %q, pattern_hint %q, want both %q — the actionable unit is the git_upstreams key",
			rows[0].PkgName, rows[0].PatternHint, "gitlab")
	}
	if rows[0].RegistryType != "git" {
		t.Errorf("registry_type = %q, want %q", rows[0].RegistryType, "git")
	}
}

// A configured namespace records nothing: the config already names it, so the
// discovery log has nothing to tell the operator. It still 404s here — the
// smart-HTTP proxy that would serve it is a separate change.
func TestGitNamespaceConfiguredRecordsNothing(t *testing.T) {
	s := newDiscoveryServer(t)
	s.cfg.GitUpstreams = map[string]config.GitUpstream{
		"corp": {URL: "https://git.corp.example/", Mode: config.GitModeOpen},
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/corp/team/tool.git/info/refs") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET configured namespace = %d, want 404", resp.StatusCode)
	}

	time.Sleep(250 * time.Millisecond)
	rows, err := s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{
		Decision: audit.DecisionNoNamespace,
	})
	if err != nil {
		t.Fatalf("list discovery: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("no_namespace rows = %d, want 0 for a namespace the config names (%+v)", len(rows), rows)
	}
}

// A traversal never reaches the namespace lookup, so it is a bad request
// rather than a miss worth recording.
func TestGitNamespaceRejectsTraversal(t *testing.T) {
	s := newDiscoveryServer(t)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/gitlab/..%2f..%2fetc/passwd") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET traversal = %d, want 400", resp.StatusCode)
	}
}

// The bundle route is the shipped one and the namespaced pattern must not take
// its paths. /git/{name}/{file} is the more specific pattern, so a two-segment
// request still reaches handleGitBundle: it answers 404 on a filename that
// names no ref, and leaves no no_namespace row behind.
func TestGitBundleRouteStillWins(t *testing.T) {
	s := newDiscoveryServer(t)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/gitlab/not-a-bundle") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET bundle path = %d, want 404", resp.StatusCode)
	}

	time.Sleep(250 * time.Millisecond)
	rows, err := s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{
		Decision: audit.DecisionNoNamespace,
	})
	if err != nil {
		t.Fatalf("list discovery: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("no_namespace rows = %d, want 0; the bundle route was rerouted through the namespace handler (%+v)", len(rows), rows)
	}
}
