package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

//nolint:gosec // G101: test fixtures, not credentials.
const (
	invPepper   = "inventory-test-pepper"
	invToken    = "bodega_ak_inventory"
	fullToken   = "bodega_ak_full"
	outsideAddr = "198.51.100.7:40000"
	adminAddr   = "10.0.0.5:40000"
)

const cdxDoc = `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-10-08T10:00:00Z"},
"components":[{"name":"curl","version":"8.5.0-2ubuntu10","purl":"pkg:deb/ubuntu/curl@8.5.0-2ubuntu10?arch=amd64"}]}`

// newInventoryServer builds a server with admin_permit_cidr on 10.0.0.0/8,
// so tokens are required there, and two CycloneDX instances: "hosts"
// enabled with a small body cap and "off" disabled. It mints one inventory
// token bound to web-01 and one full token.
func newInventoryServer(t *testing.T, adminCIDR []string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		StoragePath:     dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: adminCIDR,
		AllowPlaintext:  true,
		InventorySources: map[string]config.InventorySource{
			"hosts": {"type": "cyclonedx", "enabled": true, "max_body_bytes": float64(4096)},
			"off":   {"type": "cyclonedx", "enabled": false},
		},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil || s.inventory == nil {
		t.Fatalf("server built without audit db or inventory frame (inventoryErr=%v)", s.inventoryErr)
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	s.pepper = invPepper
	ctx := context.Background()
	if err := s.auditDB.InsertScopedToken(ctx, "inv1", "web-01", audit.HashToken(invToken, invPepper), "", audit.ScopeInventory, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.InsertToken(ctx, "full1", "admin", audit.HashToken(fullToken, invPepper), "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{Kind: audit.BindToken, Key: "inv1", Identity: "web-01"}); err != nil {
		t.Fatal(err)
	}
	s.refreshIdentities(ctx)
	return s
}

func send(s *Server, method, path, remote, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec
}

// A host outside admin_permit_cidr reaches the route its source registered,
// and the report lands under the identity its token is bound to.
func TestInventoryPushReachesRegisteredRouteFromOutsideAdminCIDR(t *testing.T) {
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	rec := send(s, http.MethodPost, "/api/v1/inventory/sources/hosts/bom", outsideAddr, invToken, cdxDoc)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s; want 202", rec.Code, rec.Body)
	}
	reports, err := s.auditDB.InventoryReports(context.Background(), "hosts")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Identity != "web-01" || reports[0].ExternalID != "web-01" {
		t.Fatalf("reports = %+v, want one for web-01", reports)
	}
	if c := reports[0].Components; len(c) != 1 || c[0].Ecosystem != manifest.TypeApt || c[0].Name != "curl" {
		t.Errorf("components = %+v, want curl as apt", c)
	}
	// The source vouched for the host, so it wrote the mapping itself.
	if id, _ := s.auditDB.InventoryHostIdentity(context.Background(), "hosts", "web-01"); id != "web-01" {
		t.Errorf("mapping = %q, want web-01", id)
	}
}

// The exemption is the registered route and nothing near it.
func TestInventoryExemptionCoversNoOtherPost(t *testing.T) {
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	for _, path := range []string{
		"/api/v1/packages/apt",                    // an ordinary mutation
		"/api/v1/tokens",                          // token minting
		"/api/v1/inventory/sources/nope/bom",      // no such instance
		"/api/v1/inventory/sources/off/bom",       // configured, disabled
		"/api/v1/inventory/sources/hosts/other",   // instance exists, route does not
		"/api/v1/inventory/sources/hosts/bom/x",   // a path below the route
		"/api/v1/inventory/sources/hosts",         // the instance itself
		"/api/v1/inventory/sources/hosts/../bom",  // traversal spelling
		"/api/v1/inventory/sources/hosts/bom?x=y", // query does not change the path, so this one is exempt
	} {
		rec := send(s, http.MethodPost, path, outsideAddr, invToken, cdxDoc)
		exempt := path == "/api/v1/inventory/sources/hosts/bom?x=y"
		if exempt {
			if rec.Code != http.StatusAccepted {
				t.Errorf("POST %s: status = %d, want 202", path, rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s from outside admin_permit_cidr: status = %d, want 403", path, rec.Code)
		}
	}
	// DELETE and PATCH on the push path are not registered routes either.
	for _, m := range []string{http.MethodDelete, http.MethodPatch} {
		if rec := send(s, m, "/api/v1/inventory/sources/hosts/bom", outsideAddr, invToken, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s on the push route: status = %d, want 403", m, rec.Code)
		}
	}
}

// An inventory token reaches nothing but the push routes, whether or not
// the server requires tokens, and the refusal names the scope and route.
func TestInventoryTokenRefusedOnOtherMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		admin  []string
		remote string
	}{
		{"token required", []string{"10.0.0.0/8"}, adminAddr},
		{"localhost only", []string{"127.0.0.0/8"}, "127.0.0.1:40000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newInventoryServer(t, tc.admin)
			rec := send(s, http.MethodPost, "/api/v1/tokens", tc.remote, invToken, `{"label":"x"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `"inventory"`) || !strings.Contains(body, "/api/v1/tokens") {
				t.Errorf("refusal %q does not name the scope and the route", body)
			}
			rows, _ := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
			if len(rows) != 1 || rows[0].Status != audit.DenialTokenScope {
				t.Errorf("denials = %+v, want one %s", rows, audit.DenialTokenScope)
			}
			// A full token on the same route still works.
			if rec := send(s, http.MethodPost, "/api/v1/tokens", tc.remote, fullToken, `{"label":"x"}`); rec.Code != http.StatusCreated {
				t.Errorf("full token: status = %d, want 201", rec.Code)
			}
		})
	}
}

func TestInventoryPushRefusesFullAndMissingTokens(t *testing.T) {
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/hosts/bom", outsideAddr, fullToken, cdxDoc); rec.Code != http.StatusForbidden {
		t.Errorf("full token: status = %d, want 403", rec.Code)
	}
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/hosts/bom", outsideAddr, "", cdxDoc); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/hosts/bom", outsideAddr, "bodega_ak_nope", cdxDoc); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown token: status = %d, want 401", rec.Code)
	}
	if reports, _ := s.auditDB.InventoryReports(context.Background(), ""); len(reports) != 0 {
		t.Errorf("refused pushes stored %d reports", len(reports))
	}
}

func TestInventoryPushBodyCap(t *testing.T) {
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	big := cdxDoc + strings.Repeat(" ", 5000)
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/hosts/bom", outsideAddr, invToken, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	// Without a Content-Length the cap still holds while reading.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/sources/hosts/bom", io.MultiReader(bytes.NewReader([]byte(big))))
	req.ContentLength = -1
	req.RemoteAddr = outsideAddr
	req.Header.Set("Authorization", "Bearer "+invToken)
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked: status = %d, want 413", rec.Code)
	}
}

func TestInventoryConfigErrorRefusesStart(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		LogDir: dir, StoragePath: dir, AuditDB: filepath.Join(dir, "audit.db"), AllowPlaintext: true,
		InventorySources: map[string]config.InventorySource{"x": {"type": "nope"}},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0", nil)
	t.Cleanup(func() { _ = s.auditDB.Close() })
	err := s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "inventory_sources.x.type") {
		t.Errorf("Start = %v, want the inventory_sources error", err)
	}
}

// A pushed report is classified on arrival, and GET /api/v1/inventory/{identity}
// returns the host's classified set to an admin address and refuses any other.
func TestInventoryReportRouteServesTheClassifiedHost(t *testing.T) {
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	if err := s.auditDB.Record(context.Background(), audit.Event{EventType: audit.EventServeFetch, PkgType: "apt",
		PkgName: "pool/main/c/curl/curl_8.5.0-2ubuntu10_amd64.deb", Identity: "web-01",
		ObjectKey: "packages/apt/pool/main/c/curl/curl_8.5.0-2ubuntu10_amd64.deb", Status: "success"}); err != nil {
		t.Fatal(err)
	}
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/hosts/bom", outsideAddr, invToken, cdxDoc); rec.Code != http.StatusAccepted {
		t.Fatalf("push status = %d, body %s", rec.Code, rec.Body)
	}

	if rec := send(s, http.MethodGet, "/api/v1/inventory/web-01", outsideAddr, "", ""); rec.Code != http.StatusForbidden {
		t.Errorf("from outside admin_permit_cidr: status = %d, want 403", rec.Code)
	}
	rec := send(s, http.MethodGet, "/api/v1/inventory/web-01", adminAddr, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s; want 200", rec.Code, rec.Body)
	}
	var got struct {
		Identity   string `json:"identity"`
		Alert      bool   `json:"alert"`
		Components []struct {
			Name    string   `json:"name"`
			Class   string   `json:"class"`
			Sources []string `json:"sources"`
		} `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Identity != "web-01" || got.Alert || len(got.Components) != 1 ||
		got.Components[0].Class != "served" || got.Components[0].Sources[0] != "hosts" {
		t.Errorf("report = %s, want curl served through hosts and no alert", rec.Body)
	}
	if rec := send(s, http.MethodGet, "/api/v1/inventory/nobody", adminAddr, "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unmapped identity: status = %d, want 404", rec.Code)
	}
}
