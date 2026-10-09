package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory/osquery"
	"github.com/ravinald/bodega/internal/manifest"
)

var osquerySources = map[string]config.InventorySource{
	"osq":     {"type": "osquery", "enabled": true, "mode": "server", "interval": "30m"},
	"osq-b":   {"type": "osquery", "enabled": true, "mode": "shipper"},
	"osq-off": {"type": "osquery", "enabled": false, "mode": "server"},
}

func addEnrollSecret(t *testing.T, s *Server, instance, identity string) string {
	t.Helper()
	secret := "bodega_es_" + instance + identity
	if err := s.auditDB.InsertOsquerySecret(context.Background(), audit.OsquerySecret{
		ID: instance + "-" + identity, Source: instance, Label: identity, Identity: identity,
	}, audit.HashToken(secret, s.pepper)); err != nil {
		t.Fatal(err)
	}
	return secret
}

// Requirement 6, and requirement 3's link to it: the plan names each enabled
// osquery instance with the trees the host's profile declares, and the
// config endpoint schedules those same trees for a node of that identity.
func TestOsqueryPlanSection(t *testing.T) {
	s := hostedServer(t)
	f := clientProfile(t, s)
	if s.pepper == "" {
		t.Fatal("the fixture server loaded no pepper, so no enroll secret can verify")
	}
	s.cfg.InventorySources = osquerySources
	s.cfg.OsqueryScanDirs = config.OsqueryScanDirs{
		Default:  config.OsqueryDirs{Python: []string{"/usr/lib/python3/dist-packages"}},
		Profiles: map[string]config.OsqueryDirs{"web": {NPM: []string{"/srv/b", "/srv/a"}}},
	}
	s.setupInventory()
	if s.inventoryErr != nil {
		t.Fatal(s.inventoryErr)
	}

	code, body := clientGet(t, s, f.token, "/client/plan?os=linux&codename=noble")
	if code != http.StatusOK {
		t.Fatalf("plan = %d %s", code, body)
	}
	var plan clientPlan
	if err := json.Unmarshal([]byte(body), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Osquery) != 2 {
		t.Fatalf("osquery section = %+v, want the two enabled instances", plan.Osquery)
	}
	a, b := plan.Osquery[0], plan.Osquery[1]
	if a.Instance != "osq" || a.Mode != osquery.ModeServer || b.Instance != "osq-b" || b.Mode != osquery.ModeShipper {
		t.Errorf("instances = %+v / %+v", a, b)
	}
	if !strings.HasSuffix(a.Endpoint, "/api/v1/inventory/sources/osq") || !strings.HasPrefix(a.Endpoint, "http") {
		t.Errorf("endpoint = %q, want the instance's route base", a.Endpoint)
	}
	if a.Interval != 1800 || b.Interval != 3600 {
		t.Errorf("intervals = %d / %d, want 1800 and the 3600 default", a.Interval, b.Interval)
	}
	if !reflect.DeepEqual(a.NPMDirs, []string{"/srv/a", "/srv/b"}) || len(a.PythonDirs) != 0 || a.PythonDirs == nil {
		t.Errorf("dirs = python %v npm %v; want the profile's entry, sorted, replacing the default", a.PythonDirs, a.NPMDirs)
	}
	if _, txt := clientGet(t, s, f.token, "/client/plan.txt?os=linux&codename=noble"); strings.Contains(txt, "osquery") {
		t.Errorf("plan.txt grew an osquery record:\n%s", txt)
	}

	secret := addEnrollSecret(t, s, "osq", "web-host")
	rec := send(s, http.MethodPost, a.Endpoint[strings.Index(a.Endpoint, "/api/"):]+"/enroll", outsideAddr, "", `{"enroll_secret":"`+secret+`"}`)
	var enrolled struct {
		NodeKey string `json:"node_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil || enrolled.NodeKey == "" {
		t.Fatalf("enroll = %d %s", rec.Code, rec.Body)
	}
	rec = send(s, http.MethodPost, "/api/v1/inventory/sources/osq/config", outsideAddr, "", `{"node_key":"`+enrolled.NodeKey+`"}`)
	if !strings.Contains(rec.Body.String(), `npm_packages WHERE directory IN ('/srv/a', '/srv/b')`) ||
		strings.Contains(rec.Body.String(), "python_packages") {
		t.Errorf("config does not schedule the plan's trees: %s", rec.Body)
	}

	// A host with no profile reads the server-wide default.
	if got := s.osqueryDirsForIdentity("nobody"); !reflect.DeepEqual(got.Python, []string{"/usr/lib/python3/dist-packages"}) || got.NPM != nil {
		t.Errorf("default dirs = %+v", got)
	}
}

// The osquery routes are exempt from the admin gate like every registered
// push route, and a refused enroll lands as a denied row naming the check.
func TestOsqueryRoutesFromOutsideAdminCIDR(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename: "noble", LogDir: dir, StoragePath: dir, AuditDB: filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{"10.0.0.0/8"}, AllowPlaintext: true, InventorySources: osquerySources,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil || s.inventory == nil {
		t.Fatalf("no audit db or frame (inventoryErr=%v)", s.inventoryErr)
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	s.pepper = invPepper
	ctx := context.Background()
	if err := s.auditDB.InsertScopedToken(ctx, "inv1", "shipper", audit.HashToken(invToken, invPepper), "", audit.ScopeInventory, nil); err != nil {
		t.Fatal(err)
	}

	secret := addEnrollSecret(t, s, "osq", "web-01")
	rec := send(s, http.MethodPost, "/api/v1/inventory/sources/osq/enroll", outsideAddr, "", `{"enroll_secret":"`+secret+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"node_key"`) {
		t.Fatalf("enroll from outside the admin CIDR = %d %s", rec.Code, rec.Body)
	}

	rec = send(s, http.MethodPost, "/api/v1/inventory/sources/osq/enroll", outsideAddr, "", `{"enroll_secret":"bodega_es_forged"}`)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"node_invalid":true}` {
		t.Errorf("forged secret = %d %s", rec.Code, rec.Body)
	}
	rows, err := s.auditDB.Query(ctx, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	denied := false
	for _, r := range rows {
		if r.EventType == audit.EventDenied && strings.Contains(r.Details, "unknown or revoked secret") && strings.Contains(r.Details, `"instance":"osq"`) {
			denied = true
		}
	}
	if !denied {
		t.Errorf("no denied row names the failed check: %+v", rows)
	}

	line := `{"name":"bodega_packages_linux","hostIdentifier":"db-01","unixTime":1791500000,"action":"snapshot","snapshot":[{"ecosystem":"apt","name":"curl","version":"8.5.0"}]}` + "\n"
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/osq-b/results", outsideAddr, invToken, line); rec.Code != http.StatusAccepted {
		t.Errorf("results from outside the admin CIDR = %d %s", rec.Code, rec.Body)
	}
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/osq-off/enroll", outsideAddr, "", `{"enroll_secret":"`+secret+`"}`); rec.Code != http.StatusForbidden {
		t.Errorf("a disabled instance's enroll = %d, want the admin gate's 403", rec.Code)
	}
	if rec := send(s, http.MethodPost, "/api/v1/inventory/sources/osq/results", outsideAddr, invToken, line); rec.Code != http.StatusForbidden {
		t.Errorf("results on a server-mode instance = %d, want the admin gate's 403", rec.Code)
	}
}

// Requirement 7: the shipper is served, and its digest is published in
// /api/v1/status and in docs/usage.md, each matching the served bytes.
func TestOsqueryShipScriptDigestIsPublished(t *testing.T) {
	s := hostedServer(t)
	f := clientProfile(t, s)

	code, body := clientGet(t, s, f.token, "/client/osquery-ship.sh")
	if code != http.StatusOK || body != string(osqueryShipScript) || !strings.HasPrefix(body, "#!/bin/sh\n") {
		t.Fatalf("GET /client/osquery-ship.sh = %d:\n%.200s", code, body)
	}
	sum := sha256.Sum256([]byte(body))
	served := hex.EncodeToString(sum[:])

	_, status := clientGet(t, s, f.token, "/api/v1/status")
	var st statusResponse
	if err := json.Unmarshal([]byte(status), &st); err != nil {
		t.Fatal(err)
	}
	if st.OsqueryShipSHA256 != served || st.ClientSetupSHA256 == "" {
		t.Errorf("status osquery_ship_sha256 = %q, want %s beside client_setup_sha256", st.OsqueryShipSHA256, served)
	}
	usage, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(usage), "SHA-256 `"+served+"`") {
		t.Errorf("docs/usage.md does not publish the shipper's digest. Write it as SHA-256 `%s`", served)
	}
	if code, _ := clientGet(t, s, "", "/client/osquery-ship.sh"); code != http.StatusForbidden {
		t.Errorf("unidentified host got the shipper: %d", code)
	}
}
