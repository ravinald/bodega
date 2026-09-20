package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// An empty (non-nil) trusted set is an operator disabling header trust, not an
// operator saying nothing. The distinction is the whole point of the config
// being tri-state: read as "unset" it would hand the RFC1918 default back to a
// deployment that removed it, and on a shared network that is an unauthenticated
// mutation path through MutationAuthMiddleware.
func TestRealIPEmptyTrustedSetTrustsNoHeader(t *testing.T) {
	var gotIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ClientIP(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := RealIPMiddleware(StaticNets([]*net.IPNet{}))(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.4.5.6:1234"
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotIP != "10.4.5.6" {
		t.Errorf("ClientIP = %q, want 10.4.5.6 (the peer, not the header)", gotIP)
	}
}

// requestScheme must answer to the same set RealIPMiddleware resolved against.
// Reading the built-in default instead would believe X-Forwarded-Proto from a
// peer the operator deliberately excluded.
func TestRequestSchemeHonorsConfiguredTrustedSet(t *testing.T) {
	_, lb, _ := net.ParseCIDR("10.9.0.0/16")

	var scheme string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme = requestScheme(r)
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name string
		peer string
		nets []*net.IPNet
		want string
	}{
		{"named proxy is believed", "10.9.1.1:5000", []*net.IPNet{lb}, "https"},
		{"unnamed RFC1918 peer is not", "10.4.5.6:5000", []*net.IPNet{lb}, "http"},
		{"empty set believes nobody", "10.9.1.1:5000", []*net.IPNet{}, "http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme = ""
			handler := RealIPMiddleware(StaticNets(tc.nets))(inner)
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Forwarded-Proto", "https")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if scheme != tc.want {
				t.Errorf("requestScheme = %q, want %q", scheme, tc.want)
			}
		})
	}
}

// A handler reached without RealIPMiddleware in front still needs a defensible
// answer, so the fallback is the built-in default rather than an empty set that
// would silently stop honoring a legitimate proxy.
func TestTrustedNetsForFallsBackToDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	if got := len(trustedNetsFor(req)); got != len(defaultTrustedNets()) {
		t.Errorf("trustedNetsFor without middleware returned %d nets, want the default %d",
			got, len(defaultTrustedNets()))
	}
}

// The composed path is the one that matters. RealIPMiddleware resolving an
// address correctly proves nothing on its own: the defect this guards is a
// stranger reaching MutationAuthMiddleware as 127.0.0.1, which needs both
// middlewares and the real chain between them.
func TestSpoofedRealIPAgainstMutationGate(t *testing.T) {
	cases := []struct {
		name     string
		trusted  []string
		peer     string
		wantCode int
	}{
		{
			// The built-in default trusts all of RFC 1918, so a peer anywhere
			// on a shared private network is believed. Asserted rather than
			// fixed here: it is the documented default, and the cost of it is
			// exactly why trusted_proxies exists.
			name:     "default trusts any RFC1918 peer",
			trusted:  nil,
			peer:     "10.4.5.6:41000",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "empty list refuses the spoof",
			trusted:  []string{},
			peer:     "10.4.5.6:41000",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "unnamed peer refused when a proxy is named",
			trusted:  []string{"10.9.0.0/16"},
			peer:     "10.4.5.6:41000",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "named proxy is still believed",
			trusted:  []string{"10.9.0.0/16"},
			peer:     "10.9.1.1:41000",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{
				AptCodename:     "noble",
				LogDir:          dir,
				AuditDB:         filepath.Join(dir, "audit.db"),
				AdminPermitCIDR: []string{"127.0.0.0/8"},
				TrustedProxies:  tc.trusted,
			}
			s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
				slog.New(slog.NewTextHandler(io.Discard, nil)))
			if s.auditDB != nil {
				t.Cleanup(func() { _ = s.auditDB.Close() })
			}

			req := httptest.NewRequest("DELETE", "/api/v1/packages/apt/nothing-here", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Real-IP", "127.0.0.1")
			rec := httptest.NewRecorder()
			s.handler().ServeHTTP(rec, req)

			// 404 means the gate passed and only routing stopped it; 403 means
			// the gate refused. Distinguishing the two is the whole assertion.
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}
