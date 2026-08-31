package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// newACLServer builds a Server with a real audit DB behind it. The chain under
// test is the one Start would run, built once.
func newACLServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg.AptCodename = "noble"
	cfg.LogDir = dir
	cfg.AuditDB = filepath.Join(dir, "audit.db")
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil {
		t.Fatal("audit DB not opened; the test would assert nothing")
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	return s
}

func getStatus(t *testing.T, h http.Handler, remote string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// The point of the whole item: a list changed in the database reaches a server
// that is already running, through the chain it built at startup. A unit test
// on ParseDenyList would pass against the frozen tree this replaces.
func TestDenyListIsLiveOnOneHandler(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{DenyList: []string{"198.51.100.0/24"}})
	h := s.handler() // built once, exactly as Start does

	if got := getStatus(t, h, "203.0.113.5:1234"); got != http.StatusOK {
		t.Fatalf("before the change, 203.0.113.5 = %d, want 200", got)
	}

	if _, err := s.auditDB.AddACL(ctx, audit.ACLEntry{
		List: audit.ACLDeny, CIDR: "203.0.113.0/24", Actor: "ravi",
	}); err != nil {
		t.Fatalf("add deny entry: %v", err)
	}
	s.refreshACLs(ctx) // what SIGHUP does; the cache TTL gets there on its own

	if got := getStatus(t, h, "203.0.113.5:1234"); got != http.StatusForbidden {
		t.Fatalf("after the change, 203.0.113.5 = %d, want 403: the same handler is still serving the startup list", got)
	}

	if _, err := s.auditDB.RemoveACL(ctx, audit.ACLDeny, "203.0.113.0/24"); err != nil {
		t.Fatalf("remove deny entry: %v", err)
	}
	s.refreshACLs(ctx)
	if got := getStatus(t, h, "203.0.113.5:1234"); got != http.StatusOK {
		t.Fatalf("after the removal, 203.0.113.5 = %d, want 200", got)
	}
}

// The cache is the mechanism, so it has to work without a signal. Ageing the
// stamp is how a test reaches 30 seconds later.
func TestACLCacheExpiryPicksUpChange(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{DenyList: []string{"198.51.100.0/24"}})
	h := s.handler()

	if got := getStatus(t, h, "203.0.113.5:1234"); got != http.StatusOK {
		t.Fatalf("before the change = %d, want 200", got)
	}
	if _, err := s.auditDB.AddACL(ctx, audit.ACLEntry{List: audit.ACLDeny, CIDR: "203.0.113.0/24"}); err != nil {
		t.Fatalf("add deny entry: %v", err)
	}
	if got := getStatus(t, h, "203.0.113.5:1234"); got != http.StatusOK {
		t.Fatalf("inside the cache TTL = %d, want the cached 200", got)
	}
	s.aclAt.Store(0) // the cache has aged out
	if got := getStatus(t, h, "203.0.113.5:1234"); got != http.StatusForbidden {
		t.Fatalf("after the TTL = %d, want 403 with no signal sent", got)
	}
}

// Widening the admin list turns on the Bearer requirement. Captured at chain
// build time, that test would leave a widened server admitting unauthenticated
// mutations until it restarted.
func TestAdminWideningTurnsOnTokenRequirementLive(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{AdminPermitCIDR: []string{"127.0.0.0/8"}})
	h := s.handler()

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/apt", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := post(); got == http.StatusUnauthorized {
		t.Fatalf("localhost-only mutation = 401, want the request to pass the auth gate")
	}

	if _, err := s.auditDB.AddACL(ctx, audit.ACLEntry{List: audit.ACLAdmin, CIDR: "10.0.0.0/8"}); err != nil {
		t.Fatalf("widen admin list: %v", err)
	}
	s.refreshACLs(ctx)

	if got := post(); got != http.StatusUnauthorized {
		t.Fatalf("mutation after widening = %d, want 401: the token requirement did not follow the list", got)
	}
}

// trusted_proxies keeps its tri-state through the database. Only the middle
// case can be got wrong silently, which is why it is asserted on the composed
// path rather than on the resolver.
func TestTrustedProxiesTriStateThroughDB(t *testing.T) {
	ctx := context.Background()

	// Absent from config and database: the built-in RFC 1918 default applies,
	// so a header from a private peer is believed.
	s := newACLServer(t, &config.Config{AdminPermitCIDR: []string{"127.0.0.0/8"}})
	if owned, _ := s.auditDB.ACLSeeded(ctx, audit.ACLProxies); owned {
		t.Fatal("an absent trusted_proxies was written into the database, freezing the built-in default")
	}
	if got := s.trustedNetsFunc()(); got != nil {
		t.Fatalf("absent trusted_proxies resolved to %v, want nil (ask for the default)", got)
	}

	// Explicitly empty in the database: trust nobody.
	if _, err := s.auditDB.SeedACL(ctx, audit.ACLProxies, nil, "ravi"); err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	s.refreshACLs(ctx)
	got := s.trustedNetsFunc()()
	if got == nil {
		t.Fatal("an empty trusted_proxies read back as unset; the RFC 1918 default was handed back")
	}
	if len(got) != 0 {
		t.Fatalf("empty trusted_proxies resolved to %v, want an empty set", got)
	}

	// Populated.
	if _, err := s.auditDB.AddACL(ctx, audit.ACLEntry{List: audit.ACLProxies, CIDR: "127.0.0.1/32"}); err != nil {
		t.Fatalf("add proxy: %v", err)
	}
	s.refreshACLs(ctx)
	if got := s.trustedNetsFunc()(); len(got) != 1 || got[0].String() != "127.0.0.1/32" {
		t.Fatalf("populated trusted_proxies resolved to %v, want [127.0.0.1/32]", got)
	}
}

// An operator's config file values have to reach the store on first start,
// not be ignored while the server runs on defaults.
func TestConfigListsSeedOnFirstStart(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{
		AdminPermitCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"},
		DenyList:        []string{"203.0.113.0/24"},
		TrustedProxies:  []string{},
	})
	for _, tc := range []struct {
		list string
		want int
	}{
		{audit.ACLAdmin, 2},
		{audit.ACLDeny, 1},
		{audit.ACLProxies, 0},
	} {
		owned, err := s.auditDB.ACLSeeded(ctx, tc.list)
		if err != nil || !owned {
			t.Fatalf("%s owned = %v, %v; want the config value copied in on first start", tc.list, owned, err)
		}
		cidrs, err := s.auditDB.ACLCIDRs(ctx, tc.list)
		if err != nil {
			t.Fatalf("%s: %v", tc.list, err)
		}
		if len(cidrs) != tc.want {
			t.Errorf("%s entries = %v, want %d", tc.list, cidrs, tc.want)
		}
	}
}

// After the copy the database decides alone. A server restarted against an
// edited config file must not have the file's value quietly re-applied.
func TestDatabaseWinsOverConfigFileAfterSeed(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{DenyList: []string{"203.0.113.0/24"}})
	if _, err := s.auditDB.RemoveACL(ctx, audit.ACLDeny, "203.0.113.0/24"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// A second start against the same database and the same config file.
	s.seedACLs(ctx)
	s.refreshACLs(ctx)
	if got := s.aclNow().deny; len(got) != 0 {
		t.Fatalf("deny list = %v after a restart, want empty: the config file was re-applied over an operator's removal", got)
	}
}
