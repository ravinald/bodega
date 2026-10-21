package admit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/integration/socket"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The socket type's verdict lands in the admission row: its score and alerts
// in the detail whatever the outcome, a failing alert under the default warn
// admitting with a warning, and a 500 refusing under block.
func TestAdmitRecordsSocketVerdict(t *testing.T) {
	answer := map[string]string{
		"zq-socket-clean": `{"inputPurl":"pkg:cargo/zq-socket-clean@1.0.0","name":"zq-socket-clean","version":"1.0.0","score":{"overall":0.9},"alerts":[{"key":"a","type":"installScripts","severity":"low"}]}`,
		"zq-socket-bad":   `{"inputPurl":"pkg:cargo/zq-socket-bad@1.0.0","name":"zq-socket-bad","version":"1.0.0","score":{"overall":0.4},"alerts":[{"key":"b","type":"malware","severity":"critical"}]}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		for name, line := range answer {
			if strings.Contains(string(body), "pkg:cargo/"+name+"@1.0.0") {
				_, _ = w.Write([]byte(line + "\n"))
				return
			}
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := socket.BaseURL
	socket.BaseURL = srv.URL + "/v0/"
	t.Cleanup(func() { socket.BaseURL = old })
	t.Setenv(integration.SecretEnv("socket-admit", "api_token"), "test-token")

	f := newAdmissionFixture(t)
	ctx := t.Context()
	cfg := *f.unsynced
	cfg.Integrations = map[string]config.Integration{"socket-admit": {"type": socket.Type, "enabled": true}}

	res := Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, crate("zq-socket-clean"), "ravi")
	c := checkOf(t, cargoRow(t, f, "zq-socket-clean"), "integration:socket-admit")
	if res.Decision != Admitted || c.Status != audit.CheckPass || c.Action != policy.ActionWarn ||
		!strings.Contains(c.Detail, "score 90/100; alerts: installScripts (low)") {
		t.Errorf("clean: %v, %+v", res.Decision, c)
	}

	res = Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, crate("zq-socket-bad"), "ravi")
	c = checkOf(t, cargoRow(t, f, "zq-socket-bad"), "integration:socket-admit")
	if res.Decision != Admitted || c.Status != audit.CheckWarn || !strings.Contains(c.Detail, "critical alert malware") ||
		!strings.Contains(strings.Join(res.Warnings, "\n"), "integration:socket-admit") {
		t.Errorf("alert under warn: %v %v, %+v", res.Decision, res.Warnings, c)
	}

	if err := f.adb.SetIntegrationPolicy(ctx, audit.IntegrationPolicy{Instance: "socket-admit", Ecosystem: manifest.TypeCargo, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	res = Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, crate("zq-socket-outage"), "ravi")
	c = checkOf(t, cargoRow(t, f, "zq-socket-outage"), "integration:socket-admit")
	if res.Decision != PolicyBlocked || res.Check != "integration:socket-admit" || c.Status != audit.CheckBlock ||
		!strings.Contains(c.Detail, "500") || strings.Contains(c.Detail, "test-token") {
		t.Errorf("500 under block: %v %q, %+v", res.Decision, res.Check, c)
	}
}

// One admission of a 7-version manifest asks Socket once, for all 7 purls:
// 100 quota units. F40's per-version path sent 7 requests, 700 units, which
// is past a free token's 500-unit hour. A second admission inside cache_ttl
// asks nothing, and one adding 3 versions to 2 cached ones asks about the 3.
func TestAdmitBatchesSocketLookups(t *testing.T) {
	var mu sync.Mutex
	var sent [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Components []struct{ PURL string } `json:"components"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var purls []string
		for _, c := range req.Components {
			purls = append(purls, c.PURL)
			fmt.Fprintf(w, `{"inputPurl":%q,"score":{"overall":0.77},"alerts":[]}`+"\n", c.PURL)
		}
		mu.Lock()
		sent = append(sent, purls)
		mu.Unlock()
	}))
	defer srv.Close()
	old := socket.BaseURL
	socket.BaseURL = srv.URL + "/v0/"
	t.Cleanup(func() { socket.BaseURL = old })
	t.Setenv(integration.SecretEnv("socket-batch", "api_token"), "test-token")
	requests := func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return append([][]string(nil), sent...)
	}

	f := newAdmissionFixture(t)
	ctx := t.Context()
	cfg := *f.unsynced
	cfg.Integrations = map[string]config.Integration{"socket-batch": {"type": socket.Type, "enabled": true}}
	versions := func(vs ...string) *manifest.PackageManifest {
		pm := &manifest.PackageManifest{Type: manifest.TypeCargo, Name: "zq-socket-batch"}
		for _, v := range vs {
			pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: v})
		}
		return pm
	}
	seven := []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"}

	if res := Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, versions(seven...), "ravi"); res.Decision != Admitted {
		t.Fatalf("admit: %v %s", res.Decision, res.Reason)
	}
	if reqs := requests(); len(reqs) != 1 || len(reqs[0]) != 7 {
		t.Fatalf("requests %v, want 1 carrying 7 purls", reqs)
	}
	for _, v := range seven {
		rows, err := f.adb.Admissions(ctx, audit.AdmissionFilter{PkgType: manifest.TypeCargo, PkgName: "zq-socket-batch", PkgVersion: v})
		if err != nil || len(rows) == 0 {
			t.Fatalf("Admissions(%s) = %d rows, %v", v, len(rows), err)
		}
		if c := checkOf(t, rows[0], "integration:socket-batch"); c.Status != audit.CheckPass || !strings.Contains(c.Detail, "score 77/100") {
			t.Errorf("%s: %+v", v, c)
		}
	}

	Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, versions(seven...), "ravi")
	if reqs := requests(); len(reqs) != 1 {
		t.Errorf("a second admission inside cache_ttl sent %d more requests", len(reqs)-1)
	}

	Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, versions("1.0.0", "1.0.1", "2.0.0", "2.0.1", "2.0.2"), "ravi")
	reqs := requests()
	if len(reqs) != 2 || strings.Join(reqs[1], " ") != "pkg:cargo/zq-socket-batch@2.0.0 pkg:cargo/zq-socket-batch@2.0.1 pkg:cargo/zq-socket-batch@2.0.2" {
		t.Errorf("requests %v, want a second carrying the 3 uncached purls", reqs)
	}
}
