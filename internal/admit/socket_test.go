package admit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
		"zq-socket-clean": `{"name":"zq-socket-clean","version":"1.0.0","score":{"overall":0.9},"alerts":[{"key":"a","type":"installScripts","severity":"low"}]}`,
		"zq-socket-bad":   `{"name":"zq-socket-bad","version":"1.0.0","score":{"overall":0.4},"alerts":[{"key":"b","type":"malware","severity":"critical"}]}`,
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
