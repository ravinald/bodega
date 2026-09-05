package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// TestStaleServeCountsTheRequest is issue #207. Discovery counts requests, not
// cache misses, and three branches of proxyOrResolve answered from the cached
// object without recording anything. Two of them fire during an upstream
// outage, so request_count and last_client went quiet for the window an
// operator is most likely to be reading them.
func TestStaleServeCountsTheRequest(t *testing.T) {
	const pkg = "leftpad"
	key := manifest.NpmTarballKey(pkg, "1.2.0")

	dead := func(context.Context) (string, error) {
		// Loopback, which upstreamGuard refuses: openUpstream fails without a
		// listener to depend on.
		return "http://127.0.0.1:1/leftpad.tgz", nil
	}

	for _, tc := range []struct {
		name       string
		resolve    upstreamResolver
		forceProxy bool
	}{
		{"cache disabled, object exists", nil, false},
		{"upstream resolution failed", func(context.Context) (string, error) {
			return "", errors.New("registry unreachable")
		}, true},
		// Below the allow-list gate, which already recorded this request. The
		// case is here to hold the count at one: #207 read the branch as
		// recording nothing, and a second write would make one client fetch
		// bump request_count twice.
		{"upstream fetch failed", dead, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscoveryServer(t)
			// A metadata TTL a seeded object is already past. Left at zero,
			// isCacheStale calls everything fresh and the request takes the
			// hit branch B16 already recorded.
			s.cache = CacheConfig{MetadataTTL: time.Nanosecond}
			store := storage.NewMemory()
			store.Seed(key, "cached-tarball")

			req := httptest.NewRequest(http.MethodGet, "/npm/"+pkg+"/-/"+pkg+"-1.2.0.tgz", nil)
			req.RemoteAddr = "127.0.0.1:33333"
			rec := httptest.NewRecorder()
			// immutable=false against an expired TTL: the object is present
			// and stale, which is what puts every one of these branches on the
			// serve-from-cache side.
			s.proxyOrResolve(rec, req, store, key, tc.resolve, "", manifest.TypeNpm, pkg, pkg, false, tc.forceProxy)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
			}
			if rec.Body.String() != "cached-tarball" {
				t.Fatalf("body = %q, want the stale cached copy", rec.Body.String())
			}

			row := waitForOneDiscoveryRow(t, s, manifest.TypeNpm)
			if row.PkgName != pkg {
				t.Errorf("pkg_name = %q, want %q", row.PkgName, pkg)
			}
			if row.Decision != audit.DecisionNoPolicy {
				t.Errorf("decision = %q, want %q", row.Decision, audit.DecisionNoPolicy)
			}
			if row.RequestCount != 1 {
				t.Errorf("request_count = %d, want 1", row.RequestCount)
			}
			if row.LastClient != "127.0.0.1" {
				t.Errorf("last_client = %q, want the caller that asked", row.LastClient)
			}
		})
	}
}

// waitForOneDiscoveryRow polls for exactly one row of the given type. The
// recorder writes off the request goroutine, so presence needs a window.
func waitForOneDiscoveryRow(t *testing.T, s *Server, regType string) audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []audit.DiscoveryRow
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: regType})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) == 1 {
			return rows[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("discovery rows = %d after 3s, want 1 (%+v)", len(rows), rows)
	return audit.DiscoveryRow{}
}
