package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The upstream hosts are .invalid (RFC 6761), which no resolver answers. That
// makes "the fetch was attempted" observable as a 502 without the test leaving
// the machine, and keeps the assertion the same on a host with no network.
const (
	hashicorpURL  = "https://releases.hashicorp.invalid/"
	terraformRest = "terraform/1.7.5/terraform_1.7.5_linux_amd64.zip"
	terraformPkg  = "hashicorp/" + terraformRest
	terraformKey  = manifest.BinaryPrefix + terraformPkg
	terraformURL  = hashicorpURL + terraformRest
)

// binaryServer builds a discovery server with one open and one catalog
// namespace, at the given discover_mode.
//
// The mode is written onto the field the handlers read rather than onto the
// config, because newServer only constructs a recorder for a non-empty mode
// and the off case has to prove the mode guard suppresses the row on its own,
// not merely that a nil recorder swallows it.
func binaryServer(t *testing.T, mode string) *Server {
	t.Helper()
	s := newDiscoveryServer(t)
	s.discoverMode = mode
	s.cfg.BinaryUpstreams = map[string]config.BinaryUpstream{
		"hashicorp": {URL: hashicorpURL, Mode: config.UpstreamModeOpen},
		"vendor":    {URL: "https://dl.vendor.invalid/", Mode: config.UpstreamModeCatalog},
	}
	return s
}

// getBinary drives one request through the full mux and returns its status.
func getBinary(t *testing.T, s *Server, path string) int {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + path) //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// seedBinaryPolicy inserts one binary allow-list rule and drops the checker's
// cache so the next request sees it.
func seedBinaryPolicy(t *testing.T, s *Server, pattern string) {
	t.Helper()
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "test-" + pattern,
		RegistryType: manifest.TypeBinary,
		RuleKind:     policy.KindPrefix,
		Pattern:      pattern,
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()
}

// waitForBinaryRows polls until want rows with the given decision are visible.
// The recorder writes off the request goroutine, so presence needs a window.
func waitForBinaryRows(t *testing.T, s *Server, decision string, want int) []audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []audit.DiscoveryRow
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{Decision: decision})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) >= want {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s rows = %d after 3s, want %d (%+v)", decision, len(rows), want, rows)
	return nil
}

// assertNoRows gives the asynchronous recorder a window and then asserts it
// wrote nothing. Absence is only meaningful after that wait.
func assertNoRows(t *testing.T, s *Server) {
	t.Helper()
	time.Sleep(250 * time.Millisecond)
	rows, err := s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{})
	if err != nil {
		t.Fatalf("list discovery: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("discovery rows = %d, want 0 (%+v)", len(rows), rows)
	}
}

// The case every existing operator is in: an install that upgrades and adds no
// binary_upstreams keeps serving the storage tree the uploader wrote, on the
// same un-namespaced path, with no discovery row.
func TestBinaryEmptyUpstreamsServesStorage(t *testing.T) {
	s := binaryServer(t, "observe")
	s.cfg.BinaryUpstreams = nil

	key := manifest.BinaryKey("mytool", "1.0.0", "mytool_linux_amd64")
	if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), key, []byte("ELF")); err != nil {
		t.Fatalf("seed storage: %v", err)
	}

	if got := getBinary(t, s, "/binaries/mytool/1.0.0/mytool_linux_amd64"); got != http.StatusOK {
		t.Errorf("GET legacy binary = %d, want 200 — an upgrade that adds no config must not change what already serves", got)
	}
	assertNoRows(t, s)
}

// A path whose first segment names no key, once any key exists, is a loud miss
// rather than a fall-through to a storage read that would also miss. The row
// names the key the operator meant to add.
func TestBinaryUnregisteredNamespaceRecordsNoNamespace(t *testing.T) {
	s := binaryServer(t, "observe")

	if got := getBinary(t, s, "/binaries/mytool/1.0.0/mytool_linux_amd64"); got != http.StatusNotFound {
		t.Errorf("GET unregistered namespace = %d, want 404", got)
	}

	rows := waitForBinaryRows(t, s, audit.DecisionNoNamespace, 1)
	if rows[0].PkgName != "mytool" || rows[0].PatternHint != "mytool" {
		t.Errorf("row = pkg_name %q, pattern_hint %q, want both %q — the actionable unit is the binary_upstreams key",
			rows[0].PkgName, rows[0].PatternHint, "mytool")
	}
	if rows[0].RegistryType != manifest.TypeBinary {
		t.Errorf("registry_type = %q, want %q", rows[0].RegistryType, manifest.TypeBinary)
	}
}

// An open namespace routes through proxyOrCache, which serves an already-cached
// object without reaching upstream. Both halves matter: the 200 proves the
// composed key is the one the cache write used, and the absent row proves a
// hit records nothing (see #127).
func TestBinaryOpenServesFromCache(t *testing.T) {
	s := binaryServer(t, "observe")
	if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), terraformKey, []byte("zip")); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	if got := getBinary(t, s, "/binaries/"+terraformPkg); got != http.StatusOK {
		t.Errorf("GET cached open-mode binary = %d, want 200", got)
	}
	assertNoRows(t, s)
}

// The open half of the behavior matrix. Each row crosses discover_mode with a
// policy state and pins the decision recorded and the status returned.
//
// A miss reaches fetchUpstream, whose host does not resolve, so "the fetch was
// attempted" reads as 502. That is the assertion separating learn from observe:
// both record, only learn proceeds past the deny.
func TestBinaryOpenMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       string
		rule       string
		wantStatus int
		wantRow    string
	}{
		{"off, no rules", "", "", http.StatusBadGateway, ""},
		{"off, deny", "", "https://elsewhere.example/", http.StatusForbidden, ""},
		{"observe, no rules", "observe", "", http.StatusBadGateway, audit.DecisionNoPolicy},
		{"observe, allow", "observe", "https://releases.hashicorp.invalid/terraform/", http.StatusBadGateway, audit.DecisionAllowed},
		{"observe, deny", "observe", "https://elsewhere.example/", http.StatusForbidden, audit.DecisionDenied},
		{"learn, no rules", "learn", "", http.StatusBadGateway, audit.DecisionNoPolicy},
		{"learn, deny bypassed", "learn", "https://elsewhere.example/", http.StatusBadGateway, audit.DecisionWouldDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := binaryServer(t, tc.mode)
			if tc.rule != "" {
				seedBinaryPolicy(t, s, tc.rule)
			}

			if got := getBinary(t, s, "/binaries/"+terraformPkg); got != tc.wantStatus {
				t.Errorf("status = %d, want %d", got, tc.wantStatus)
			}
			if tc.wantRow == "" {
				assertNoRows(t, s)
				return
			}

			rows := waitForBinaryRows(t, s, tc.wantRow, 1)
			if rows[0].PkgName != terraformPkg {
				t.Errorf("pkg_name = %q, want %q — the promote target is <namespace>/<rest>", rows[0].PkgName, terraformPkg)
			}
			if rows[0].UpstreamURL != terraformURL {
				t.Errorf("upstream_url = %q, want %q", rows[0].UpstreamURL, terraformURL)
			}
			// SuggestPattern has to produce a promotable prefix for the
			// namespaced shape. A "" would fall back to the policy candidate —
			// the full URL — which buckets every version of every binary
			// separately and makes 'discover list binary' unreadable.
			if want := "https://releases.hashicorp.invalid/terraform/"; rows[0].PatternHint != want {
				t.Errorf("pattern_hint = %q, want %q", rows[0].PatternHint, want)
			}
		})
	}
}

// The catalog half. A path no manifest entry names 404s without a fetch, at
// every discover_mode; only the row differs.
func TestBinaryCatalogMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, mode, wantRow string
	}{
		{"off", "", ""},
		{"observe", "observe", audit.DecisionNoManifest},
		{"learn", "learn", audit.DecisionNoManifest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := binaryServer(t, tc.mode)

			// 404 rather than 502 is the assertion that the pre-check ran
			// before proxyOrCache: a check made after the fetch would have
			// reached the upstream catalog mode exists to never reach.
			if got := getBinary(t, s, "/binaries/vendor/tool/2.0/tool.tar.gz"); got != http.StatusNotFound {
				t.Errorf("status = %d, want 404 — an uncataloged path must not reach upstream", got)
			}
			if tc.wantRow == "" {
				assertNoRows(t, s)
				return
			}

			rows := waitForBinaryRows(t, s, tc.wantRow, 1)
			if rows[0].PkgName != "vendor/tool/2.0/tool.tar.gz" {
				t.Errorf("pkg_name = %q, want %q", rows[0].PkgName, "vendor/tool/2.0/tool.tar.gz")
			}
			if want := "https://dl.vendor.invalid/tool/2.0/tool.tar.gz"; rows[0].UpstreamURL != want {
				t.Errorf("upstream_url = %q, want %q — promote needs a fetchable URL", rows[0].UpstreamURL, want)
			}
		})
	}
}

// A cataloged path proceeds. The manifest entry is the gate, so once it exists
// the request resolves exactly as an open-mode one does.
func TestBinaryCatalogHitProceeds(t *testing.T) {
	s := binaryServer(t, "observe")
	pkg := "vendor/tool/2.0/tool.tar.gz"
	if err := s.store.AddVersion(t.Context(), manifest.TypeBinary, pkg, manifest.VersionEntry{
		Version: "2.0",
		URL:     "https://dl.vendor.invalid/tool/2.0/tool.tar.gz",
		Mode:    manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), manifest.BinaryPrefix+pkg, []byte("tgz")); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	if got := getBinary(t, s, "/binaries/"+pkg); got != http.StatusOK {
		t.Errorf("GET cataloged binary = %d, want 200", got)
	}
	assertNoRows(t, s)
}
