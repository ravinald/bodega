package socket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const sentinel = "sktsec_test_token_value"

// stub is Socket's /purl endpoint, answering status and body, and recording
// what it was sent.
type stub struct {
	*httptest.Server
	hits    atomic.Int64
	gotAuth atomic.Value
	gotPURL atomic.Value

	mu               sync.Mutex
	status           int
	retryAfter, body string
}

func newStub(t *testing.T, status int, body string) *stub {
	t.Helper()
	s := &stub{status: status, body: body}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v0/purl" || r.URL.Query().Get("alerts") != "true" {
			t.Errorf("request %s %s", r.Method, r.URL)
		}
		s.gotAuth.Store(r.Header.Get("Authorization"))
		var req struct {
			Components []struct{ PURL string } `json:"components"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.Components) == 1 {
			s.gotPURL.Store(req.Components[0].PURL)
		}
		s.mu.Lock()
		status, retry, body := s.status, s.retryAfter, s.body
		s.mu.Unlock()
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	old := BaseURL
	BaseURL = s.URL + "/v0/"
	t.Cleanup(func() { BaseURL = old; s.Close() })
	return s
}

func (s *stub) set(status int, retryAfter, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.retryAfter, s.body = status, retryAfter, body
}

func row(score float64, alerts ...string) string {
	var as []map[string]string
	for _, a := range alerts {
		typ, sev, _ := strings.Cut(a, ":")
		as = append(as, map[string]string{"key": "k-" + typ, "type": typ, "severity": sev, "category": "supplyChainRisk"})
	}
	b, _ := json.Marshal(map[string]any{"type": "npm", "name": "left-pad", "version": "1.3.0",
		"score": map[string]float64{"overall": score}, "alerts": as})
	return string(b) + "\n"
}

func checkerFor(t *testing.T, kv ...any) *checker {
	t.Helper()
	t.Setenv(integration.SecretEnv("socket", "api_token"), sentinel)
	e := config.Integration{"type": Type, "enabled": true}
	for i := 0; i+1 < len(kv); i += 2 {
		e[kv[i].(string)] = kv[i+1]
	}
	inst, err := integration.ValidateInstance("socket", e)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newChecker(inst)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*checker)
}

var leftPad = integration.Query{Ecosystem: manifest.TypeNpm, Name: "left-pad", Version: "1.3.0"}

func TestDescriptor(t *testing.T) {
	d, ok := integration.Lookup(Type)
	if !ok {
		t.Fatal("socket is not registered")
	}
	if d.Cost != integration.CostFreeTier || d.DefaultAction != policy.ActionWarn ||
		d.DataSent != "The package's purl (name and version) is sent to api.socket.dev." {
		t.Errorf("descriptor: cost %s, action %s, sends %q", d.Cost, d.DefaultAction, d.DataSent)
	}
	if strings.Join(d.Ecosystems, ",") != "npm,pypi,gomod,cargo" {
		t.Errorf("ecosystems %v", d.Ecosystems)
	}
	if f, _ := d.Field("api_token"); !f.Secret {
		t.Error("api_token is not secret")
	}
	if f, _ := d.Field("fail_alert_severity"); f.Default != "critical" {
		t.Errorf("fail_alert_severity default %q", f.Default)
	}
	if f, _ := d.Field("min_score"); f.Default != "" {
		t.Errorf("min_score default %q, want no floor", f.Default)
	}
	// An enabled instance with no token is refused at load; a literal one in
	// the file is refused naming the command that moves it.
	if _, err := integration.ValidateInstance("socket", config.Integration{"type": Type, "enabled": true}); err == nil ||
		!strings.Contains(err.Error(), "bodega integration secret socket api_token") {
		t.Errorf("no token: %v", err)
	}
	if _, err := integration.ValidateInstance("socket", config.Integration{"type": Type, "api_token": "x"}); err == nil {
		t.Error("a literal token was accepted")
	}
	for _, bad := range []any{float64(-1), float64(101)} {
		if _, err := integration.ValidateInstance("socket", config.Integration{"type": Type, "min_score": bad}); err == nil {
			t.Errorf("min_score %v accepted", bad)
		}
	}
}

// A clean row passes and records its score and alerts; the token goes as a
// bearer token and the purl is the only thing sent.
func TestPass(t *testing.T) {
	s := newStub(t, http.StatusOK, row(0.82, "installScripts:low", "networkAccess:middle"))
	a, err := checkerFor(t).Lookup(t.Context(), leftPad)
	if err != nil {
		t.Fatal(err)
	}
	if a.Flagged || a.Reason != "score 82/100; alerts: installScripts (low), networkAccess (middle)" {
		t.Errorf("answer %+v", a)
	}
	if s.gotAuth.Load() != "Bearer "+sentinel || s.gotPURL.Load() != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("sent auth %v, purl %v", s.gotAuth.Load(), s.gotPURL.Load())
	}
}

// An alert at or above fail_alert_severity fails; one below it does not.
func TestAlert(t *testing.T) {
	newStub(t, http.StatusOK, row(0.9, "malware:critical", "shellAccess:high"))
	a, err := checkerFor(t).Lookup(t.Context(), leftPad)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Flagged || !strings.Contains(a.Reason, "critical alert malware") || strings.Contains(a.Reason, "high alert") ||
		!strings.Contains(a.Reason, "shellAccess (high)") {
		t.Errorf("default floor: %+v", a)
	}
	a, _ = checkerFor(t, "fail_alert_severity", "high").Lookup(t.Context(), leftPad)
	if !a.Flagged || !strings.Contains(a.Reason, "high alert shellAccess") {
		t.Errorf("high floor: %+v", a)
	}
	newStub(t, http.StatusOK, row(0.9, "shellAccess:high"))
	if a, _ := checkerFor(t).Lookup(t.Context(), leftPad); a.Flagged {
		t.Errorf("a high alert failed under the critical default: %+v", a)
	}
}

// A score below min_score fails; with no min_score no score does.
func TestLowScore(t *testing.T) {
	newStub(t, http.StatusOK, row(0.31))
	a, err := checkerFor(t, "min_score", float64(50)).Lookup(t.Context(), leftPad)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Flagged || !strings.Contains(a.Reason, "score 31 is below min_score 50") {
		t.Errorf("answer %+v", a)
	}
	if a, _ := checkerFor(t).Lookup(t.Context(), leftPad); a.Flagged {
		t.Errorf("no floor, yet flagged: %+v", a)
	}
}

// A 429 is an error, and no query is sent until its Retry-After has passed.
func TestRateLimitHonorsRetryAfter(t *testing.T) {
	s := newStub(t, http.StatusTooManyRequests, `{"error":{"message":"rate limited"}}`)
	s.set(http.StatusTooManyRequests, "120", `{"error":{"message":"rate limited"}}`)
	c := checkerFor(t)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	if _, err := c.Lookup(t.Context(), leftPad); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("429: %v", err)
	}
	s.set(http.StatusOK, "", row(0.9))
	now = now.Add(119 * time.Second)
	if _, err := c.Lookup(t.Context(), leftPad); err == nil || !strings.Contains(err.Error(), "Retry-After") {
		t.Errorf("inside the wait: %v", err)
	}
	if s.hits.Load() != 1 {
		t.Errorf("%d requests inside the wait, want 1", s.hits.Load())
	}
	now = now.Add(time.Second)
	if a, err := c.Lookup(t.Context(), leftPad); err != nil || a.Flagged {
		t.Errorf("after the wait: %+v, %v", a, err)
	}
}

func TestRetryAfterForms(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for h, want := range map[string]time.Duration{
		"":          defaultRetryAfter,
		"30":        30 * time.Second,
		"999999999": maxRetryAfter,
		"-5":        0,
		"soon":      defaultRetryAfter,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second,
	} {
		if got := retryAfter(h, now); got != want {
			t.Errorf("retryAfter(%q) = %s, want %s", h, got, want)
		}
	}
}

// A 5xx, a malformed body and a synthetic notFound row are each an error,
// never a pass, and no error carries the token.
func TestErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"500":         {http.StatusInternalServerError, "oops", "500"},
		"401":         {http.StatusUnauthorized, `{"error":{"message":"bad token"}}`, "401"},
		"not json":    {http.StatusOK, "<html>", "newline-delimited JSON"},
		"empty":       {http.StatusOK, "", "no package row"},
		"notFound":    {http.StatusOK, row(0, "notFound:low"), "could not resolve"},
		"pendingScan": {http.StatusOK, row(0, "pendingScan:low"), "not finished analyzing"},
	} {
		t.Run(name, func(t *testing.T) {
			newStub(t, tc.status, tc.body)
			_, err := checkerFor(t).Lookup(t.Context(), leftPad)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Errorf("the error carries the token: %v", err)
			}
		})
	}
	t.Run("network", func(t *testing.T) {
		s := newStub(t, http.StatusOK, row(0.9))
		s.Close()
		if _, err := checkerFor(t).Lookup(t.Context(), leftPad); err == nil || strings.Contains(err.Error(), sentinel) {
			t.Errorf("err = %v", err)
		}
	})
}

// Through the frame, a second admission of the same purl inside cache_ttl
// sends no second query.
func TestFrameCachesAnswers(t *testing.T) {
	s := newStub(t, http.StatusOK, row(0.9))
	t.Setenv(integration.SecretEnv("socket-cache", "api_token"), sentinel)
	checks := integration.Checks(map[string]config.Integration{"socket-cache": {"type": Type, "enabled": true}}, nil)
	if len(checks) != 1 {
		t.Fatalf("%d checks", len(checks))
	}
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad"}
	ve := &manifest.VersionEntry{Version: "1.3.0"}
	for range 3 {
		if r := checks[0].Check(t.Context(), pm, ve); r.Action != policy.ActionPass || !strings.Contains(r.Reason, "score 90/100") {
			t.Fatalf("result %+v", r)
		}
	}
	if s.hits.Load() != 1 {
		t.Errorf("%d queries for one purl, want 1", s.hits.Load())
	}
}
