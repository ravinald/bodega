package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/idp"
	"github.com/ravinald/bodega/internal/idp/idptest"
)

// bodega login runs the device flow against the provider the server names,
// trades the ID token at the server's exchange, and stores the result 0600.
func TestLoginDeviceFlowStoresToken(t *testing.T) {
	is := idptest.New(t)
	is.DeviceIDToken = is.Token(t, map[string]any{"aud": "bodega-cli", "sub": "alice"})

	var exchanged string
	expires := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/providers":
			_ = json.NewEncoder(w).Encode([]idp.ProviderInfo{{
				Name: "okta", Issuer: is.URL, ClientID: "bodega-cli",
				DeviceAuthURL: is.URL + "/device", TokenURL: is.URL + "/token",
			}})
		case "/api/v1/auth/exchange":
			var body struct {
				IDToken string `json:"id_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			exchanged = body.IDToken
			_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:gosec // G101: a fake exchange response, not a credential
				"token": "bodega_ak_login", "id": "abc", "scopes": "read,admin",
				"expires_at": expires.Format(time.RFC3339), "subject": "alice", "issuer": is.URL,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var out strings.Builder
	f := loginFlow{
		server: srv.URL, allowPlaintext: true,
		credPath: filepath.Join(t.TempDir(), "bodega", "credentials.json"),
		out:      &out,
	}
	if err := f.run(context.Background()); err != nil {
		t.Fatalf("login: %v", err)
	}
	if exchanged != is.DeviceIDToken {
		t.Error("the server was not handed the ID token the device flow returned")
	}
	if !strings.Contains(out.String(), "ABCD-EFGH") || !strings.Contains(out.String(), is.URL+"/activate") {
		t.Errorf("the prompt does not show the code and URL:\n%s", out.String())
	}
	fi, err := os.Stat(f.credPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	cred, ok := config.LoadLoginCredential(f.credPath, srv.URL, time.Now())
	if !ok || cred.Token != "bodega_ak_login" || cred.Subject != "alice" || !cred.ExpiresAt.Equal(expires) {
		t.Errorf("stored = %+v, %v", cred, ok)
	}
}

func TestLoginRefusesAmbiguousOrMissingProvider(t *testing.T) {
	providers := []idp.ProviderInfo{{Name: "a"}, {Name: "b"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providers)
	}))
	defer srv.Close()
	f := loginFlow{server: srv.URL, allowPlaintext: true, out: &strings.Builder{}}
	if err := f.run(context.Background()); err == nil || !strings.Contains(err.Error(), "--provider") {
		t.Errorf("two providers, none chosen: %v", err)
	}
	f.provider = "c"
	if err := f.run(context.Background()); err == nil || !strings.Contains(err.Error(), "offers a, b") {
		t.Errorf("unknown provider: %v", err)
	}
	providers = nil
	f.provider = ""
	if err := f.run(context.Background()); err == nil || !strings.Contains(err.Error(), "no device sign-in") {
		t.Errorf("no providers: %v", err)
	}
}
