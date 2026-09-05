package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// TestPolicyRefusalSurvivesAClientHangUp is issue #208. The allow-list verdict
// ran on r.Context(), which net/http cancels the moment the client closes the
// connection. On a cold rule cache the verdict is a database read, so a
// hang-up made it fail, the handler answered 500 and returned above the deny
// branch, and neither the 403 nor the policy_violation row happened.
//
// The two conditions have to hold together: a warm cache answers from memory
// and never notices the cancellation, and a canceled context against a warm
// cache still refuses correctly. Firing a request and not reading the response
// is ordinary scanner behavior, which is what put the loss on the callers the
// row exists to name.
func TestPolicyRefusalSurvivesAClientHangUp(t *testing.T) {
	s := newDiscoveryServer(t)

	// Proxy mode, so the tarball request reaches the allow-list rather than
	// being served or 404'd out of storage.
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{
		Version: "1.2.0",
		Mode:    manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	// One rule for npm that names a different package: rules exist, none
	// matches, so the candidate is a violation.
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "npm-allow-elsewhere",
		RegistryType: manifest.TypeNpm,
		RuleKind:     policy.KindPackage,
		Pattern:      "rightpad",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	// Cold: the next verdict loads from the database instead of the 30s
	// read-through cache, which is the only state in which the cancellation
	// can reach the query.
	s.policy.Invalidate()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", nil).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:33333"
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}

	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query audit db: %v", err)
	}
	var found int
	for _, row := range rows {
		if row.Status == "policy_violation" && row.PkgName == "leftpad" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("policy_violation rows for leftpad = %d, want 1 (%+v)", found, rows)
	}
}
