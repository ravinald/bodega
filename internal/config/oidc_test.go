package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

func TestLoadValidatesOIDCProviders(t *testing.T) {
	const rule = `"rules":[{"claims":{"repository":"acme/app"},"scopes":"read,write:npm"}]`
	cases := []struct{ body, err string }{
		{`{"oidc_providers":[{"issuer":"https://token.actions.githubusercontent.com","audience":"https://bodega",` + rule + `}],"oidc_token_ttl":"5m"}`, ""},
		{`{"oidc_providers":[{"issuer":"http://127.0.0.1:9999","client_id":"cli",` + rule + `}]}`, ""},
		{`{"oidc_token_ttl":"soon"}`, `invalid oidc_token_ttl "soon"`},
		{`{"oidc_providers":[{"issuer":"http://idp.example","audience":"a",` + rule + `}]}`, "must be https"},
		{`{"oidc_providers":[{"issuer":"https://idp.example",` + rule + `}]}`, "set audience"},
		{`{"oidc_providers":[{"issuer":"https://idp.example","audience":"a","rules":[]}]}`, "no rules"},
		{`{"oidc_providers":[{"issuer":"https://idp.example","audience":"a","rules":[{"claims":{},"scopes":"read"}]}]}`, "no claims to match"},
		{`{"oidc_providers":[{"issuer":"https://idp.example","audience":"a","rules":[{"claims":{"sub":"*"},"scopes":"read"}]}]}`, "matches anything"},
		{`{"oidc_providers":[{"issuer":"https://idp.example","audience":"a","rules":[{"claims":{"sub":"x"},"scopes":"root"}]}]}`, "unknown scope"},
		{`{"oidc_providers":[{"issuer":"https://idp.example","audience":"a","rules":[{"claims":{"sub":"x"},"scopes":"inventory"}]}]}`, "cannot grant inventory"},
		{`{"oidc_providers":[{"issuer":"https://idp.example","audience":"a",` + rule + `},{"issuer":"https://idp.example","audience":"b",` + rule + `}]}`, "configured twice"},
	}
	for _, tc := range cases {
		writeConfig(t, tc.body)
		_, err := config.Load(t.TempDir(), "", "", "", false, false)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: %v", tc.body, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: err = %v, want one containing %q", tc.body, err, tc.err)
		}
	}
}

func TestResolveOIDCTokenTTL(t *testing.T) {
	if got := (&config.Config{}).ResolveOIDCTokenTTL(); got != 15*time.Minute {
		t.Errorf("default = %s, want 15m", got)
	}
	if got := (&config.Config{OIDCTokenTTL: "5m"}).ResolveOIDCTokenTTL(); got != 5*time.Minute {
		t.Errorf("5m = %s", got)
	}
}

// The credentials file is 0600 in a 0700 directory, a wider file is narrowed
// on the next save, and an expired credential is not used.
func TestLoginCredentialStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bodega", "credentials.json")
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if err := config.SaveLoginCredential(path, "https://bodega.example/", config.LoginCredential{Token: "t1", ExpiresAt: exp, Subject: "alice"}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v; want %v", p, fi.Mode().Perm(), err, want)
		}
	}
	got, ok := config.LoadLoginCredential(path, "https://bodega.example", time.Now())
	if !ok || got.Token != "t1" || !got.ExpiresAt.Equal(exp) || got.Subject != "alice" {
		t.Errorf("load = %+v, %v", got, ok)
	}
	if _, ok := config.LoadLoginCredential(path, "https://bodega.example", exp.Add(time.Second)); ok {
		t.Error("an expired credential was returned")
	}
	if _, ok := config.LoadLoginCredential(path, "https://other.example", time.Now()); ok {
		t.Error("a credential was returned for another server")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveLoginCredential(path, "https://other.example", config.LoginCredential{Token: "t2", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode after re-save = %v, want 0600", fi.Mode().Perm())
	}
	if got, ok := config.LoadLoginCredential(path, "https://bodega.example", time.Now()); !ok || got.Token != "t1" {
		t.Error("saving a second server dropped the first")
	}
}

func TestResolveTokenForPrefersEnvThenLoginThenFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	cfg := &config.Config{Token: "from-file"}
	t.Setenv(config.EnvToken, "")
	if got := cfg.ResolveTokenFor("https://bodega.example"); got != "from-file" {
		t.Errorf("no login: %q, want the config file's token", got)
	}
	path, err := config.LoginCredentialsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveLoginCredential(path, "https://bodega.example", config.LoginCredential{Token: "from-login", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolveTokenFor("https://bodega.example"); got != "from-login" {
		t.Errorf("after login: %q, want the login token", got)
	}
	t.Setenv(config.EnvToken, "from-env")
	if got := cfg.ResolveTokenFor("https://bodega.example"); got != "from-env" {
		t.Errorf("with $BODEGA_TOKEN: %q", got)
	}
}
