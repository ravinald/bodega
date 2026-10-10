package cyclonedx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
)

const doc16 = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {"timestamp": "2026-10-08T10:00:00Z", "component": {"name": "web-01", "type": "operating-system"}},
  "components": [
    {"name": "curl", "version": "8.5.0", "purl": "pkg:deb/ubuntu/curl@8.5.0?arch=amd64&repository_url=http://archive.ubuntu.com/ubuntu",
     "hashes": [{"alg": "SHA-1", "content": "AA"}, {"alg": "SHA-256", "content": "BEEF"}]},
    {"name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3",
     "evidence": {"occurrences": [{"location": "/usr/lib/python3/dist-packages/requests"}]},
     "components": [{"name": "urllib3", "version": "2.2.2", "purl": "pkg:pypi/urllib3@2.2.2"}]},
    {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
     "externalReferences": [{"type": "distribution", "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}]},
    {"name": "spring-core", "version": "6.1.0", "purl": "pkg:maven/org.springframework/spring-core@6.1.0"},
    {"name": "mystery"}
  ]
}`

func TestNormalizeMapsTheCommonModel(t *testing.T) {
	b, err := (&Source{}).Normalize([]byte(doc16), "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Reports) != 1 || len(b.Attempts) != 0 {
		t.Fatalf("batch = %+v, want one report", b)
	}
	r := b.Reports[0]
	if r.ExternalID != "web-01" || !r.ObservedAt.Equal(time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("report header = %+v", r)
	}
	got := map[string]inventory.Component{}
	for _, c := range r.Components {
		got[c.Name] = c
	}
	if len(got) != 6 {
		t.Fatalf("components = %d (%v), want 6 with the nested urllib3 and without the metadata subject", len(got), r.Components)
	}
	for name, eco := range map[string]string{
		"curl": "apt", "requests": "pypi", "urllib3": "pypi", "lodash": "npm",
		"spring-core": inventory.EcosystemOther, "mystery": inventory.EcosystemOther,
	} {
		if got[name].Ecosystem != eco {
			t.Errorf("%s ecosystem = %q, want %q", name, got[name].Ecosystem, eco)
		}
	}
	if c := got["curl"]; c.DigestAlgorithm != "sha256" || c.DigestValue != "beef" || c.Origin != "http://archive.ubuntu.com/ubuntu" {
		t.Errorf("curl = %+v, want the SHA-256 digest and the repository_url origin", c)
	}
	if got["requests"].Path != "/usr/lib/python3/dist-packages/requests" {
		t.Errorf("requests path = %q", got["requests"].Path)
	}
	if got["lodash"].Origin != "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" {
		t.Errorf("lodash origin = %q, want the distribution reference", got["lodash"].Origin)
	}
	for _, c := range r.Components {
		if !inventory.ValidEcosystem(c.Ecosystem) {
			t.Errorf("%s carries %q, outside the common model", c.Name, c.Ecosystem)
		}
	}
}

func TestNormalizeAcceptsOnly15And16(t *testing.T) {
	for v, ok := range map[string]bool{"1.5": true, "1.6": true, "1.4": false, "2.0": false, "": false} {
		doc := `{"bomFormat":"CycloneDX","specVersion":"` + v + `","components":[]}`
		_, err := (&Source{}).Normalize([]byte(doc), "h")
		if (err == nil) != ok {
			t.Errorf("specVersion %q: err = %v, want accepted=%v", v, err, ok)
		}
	}
	for _, bad := range []string{`{"bomFormat":"SPDX","specVersion":"1.6"}`, `not json`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"yesterday"}}`} {
		if _, err := (&Source{}).Normalize([]byte(bad), "h"); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestSettings(t *testing.T) {
	insts, err := inventory.Configure(map[string]config.InventorySource{"h": {"type": TypeName, "enabled": true}})
	if err != nil {
		t.Fatal(err)
	}
	push := insts[0].Source.(inventory.PushSource)
	if rt := push.Routes(); len(rt) != 1 || rt[0].Path != RoutePath || rt[0].MaxBody != 32<<20 {
		t.Errorf("routes = %+v, want POST bom capped at 32 MiB", rt)
	}
	if insts[0].Interval != inventory.DefaultPushInterval {
		t.Errorf("interval = %s, want the push default %s", insts[0].Interval, inventory.DefaultPushInterval)
	}
	weekly, err := inventory.Configure(map[string]config.InventorySource{"h": {"type": TypeName, "interval": "168h"}})
	if err != nil || weekly[0].Interval != 168*time.Hour {
		t.Errorf("interval 168h: err = %v, instance = %+v; a push host's expected cadence is configurable", err, weekly)
	}
	for raw, want := range map[string]config.InventorySource{
		"inventory_sources.h.max_body_bytes": {"type": TypeName, "max_body_bytes": float64(-1)},
		"inventory_sources.h.interval":       {"type": TypeName, "interval": "soon"},
		"inventory_sources.h.url":            {"type": TypeName, "url": "https://x"},
	} {
		if _, err := inventory.Configure(map[string]config.InventorySource{"h": want}); err == nil || !strings.Contains(err.Error(), raw) {
			t.Errorf("err = %v, want one naming %s", err, raw)
		}
	}
}

type stubCreds struct {
	tok inventory.Token
	err error
}

func (s stubCreds) Token(*http.Request) (inventory.Token, error) { return s.tok, s.err }

func TestAuthenticate(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, inventory.RoutePrefix+"h/bom", nil)
	for _, tc := range []struct {
		name   string
		tok    inventory.Token
		status int
	}{
		{"full scope", inventory.Token{ID: "t", Scope: audit.ScopeFull, Identity: "web-01"}, http.StatusForbidden},
		{"no binding", inventory.Token{ID: "t", Scope: audit.ScopeInventory}, http.StatusForbidden},
		{"inventory and bound", inventory.Token{ID: "t", Scope: audit.ScopeInventory, Identity: "web-01"}, 0},
	} {
		p, err := (&Source{}).Authenticate(req, stubCreds{tok: tc.tok})
		if tc.status == 0 {
			if err != nil || p.ExternalID != "web-01" || p.Identity != "web-01" {
				t.Errorf("%s: principal %+v, err %v", tc.name, p, err)
			}
			continue
		}
		ae, ok := err.(*inventory.AuthError)
		if !ok || ae.Status != tc.status {
			t.Errorf("%s: err = %v, want status %d", tc.name, err, tc.status)
		}
	}
}
