package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/server"
)

// TestClientRefusesPlaintext covers the combination that leaks a credential.
// A bearer token on an unencrypted link is readable by anything on the path,
// so the client fails rather than warning.
func TestClientRefusesPlaintext(t *testing.T) {
	for _, tc := range []struct {
		name, url, token string
		allow            bool
		wantErr          string
	}{
		{name: "token over http", url: "http://bodega.example", token: "bodega_ak_secret", wantErr: "bearer token"},
		{name: "http with no token", url: "http://bodega.example", wantErr: "plaintext"},
		{name: "no host", url: "https://", wantErr: "names no host"},
		{name: "wrong scheme", url: "ftp://bodega.example", wantErr: "not http or https"},
		{name: "https is fine", url: "https://bodega.example", token: "bodega_ak_secret"},
		{name: "http with the override", url: "http://bodega.example", token: "bodega_ak_secret", allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.url, tc.token, tc.allow)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				if c.Token != tc.token {
					t.Errorf("token not carried")
				}
				return
			}
			if err == nil {
				t.Fatalf("NewClient accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestClientSendsBearerToken pins the header the mutation gate reads. Without
// it a push against a server whose admin list reaches past localhost gets 401
// with nothing naming why.
func TestClientSendsBearerToken(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(server.ImportResponse{Imported: 1, Results: []server.ImportResult{}})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "bodega_ak_secret", false)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.HTTP = srv.Client()

	if _, err := c.Import(nil, true); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if gotAuth != "Bearer bodega_ak_secret" {
		t.Errorf("Authorization = %q, want a Bearer credential", gotAuth)
	}
	if gotQuery != "merge=true" {
		t.Errorf("query = %q, want merge=true", gotQuery)
	}
}

// TestClientReportsTheServersReason keeps a refusal readable. A bare status
// line leaves whoever is debugging at 03:00 with nothing to act on.
func TestClientReportsTheServersReason(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"Unauthorized"}`)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "", true)
	c.HTTP = srv.Client()
	_, err := c.Import(nil, false)
	if err == nil {
		t.Fatal("a 401 was reported as success")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error = %q, want both the status and the server's reason", err)
	}
}

// TestRemoteImportOpensNoLocalStore is the axis that matters for --server,
// and it is not the same as "the import returned 200". The host running
// 'pkg convert' has no manifest directory, no bucket and no audit database;
// requiring any of them there is exactly what the flag exists to avoid.
//
// It runs the real command rather than calling importToServer, because the
// guarantee lives in where RunE branches: reaching loadStore at all is the
// failure. The config below names paths under /nonexistent, so anything that
// opens the store errors instead of quietly creating a default.
func TestRemoteImportOpensNoLocalStore(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(server.ImportResponse{
			Imported: len(got),
			Results:  []server.ImportResult{{Type: "apt", Name: "hello", Outcome: server.ImportImported}},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	catalog := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(catalog,
		[]byte(`[{"config_version":1,"name":"hello","type":"apt","versions":[{"version":"2.10","source_name":"hello"}]}]`),
		0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(
		`{"manifest_dir":"/nonexistent/f7/manifests","storage_path":"/nonexistent/f7/storage","bucket":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	cmd := newImportCmd(&globalFlags{})
	cmd.SetArgs([]string{"--server", srv.URL, "--allow-plaintext", catalog})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("a remote import reached for the local store: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("server received %d manifests, want 1", len(got))
	}
	if got[0]["name"] != "hello" {
		t.Errorf("manifest arrived as %v", got[0])
	}
	if intent, ok := reloadIntent(cmd); !ok || intent != reloadQuiet {
		t.Errorf("reload intent = %q (declared %v); a remote import has no local server to signal", intent, ok)
	}
}

// TestLocalImportStillOpensTheStore is the other half. Without it the test
// above passes just as well on a verb that never touches the store at all,
// and the local path is the one every existing workflow uses.
func TestLocalImportStillOpensTheStore(t *testing.T) {
	dir := t.TempDir()
	catalog := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(catalog,
		[]byte(`[{"config_version":1,"name":"hello","type":"apt","versions":[{"version":"2.10","source_name":"hello"}]}]`),
		0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(
		`{"manifest_dir":"/nonexistent/f7/manifests","storage_path":"/nonexistent/f7/storage","bucket":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	cmd := newImportCmd(&globalFlags{})
	cmd.SetArgs([]string{catalog})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("a local import succeeded against a manifest directory that cannot exist, " +
			"so the test above proves nothing about --server")
	}
}

// TestRemoteImportFailsWhenNothingLands keeps a wholly refused push from
// exiting 0. A catalog that landed nothing is not a successful import.
func TestRemoteImportFailsWhenNothingLands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(server.ImportResponse{
			Skipped: 1,
			Results: []server.ImportResult{{
				Type: "apt", Name: "hello",
				Outcome: server.ImportConflict, Reason: "package already exists",
			}},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	catalog := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(catalog,
		[]byte(`[{"config_version":1,"name":"hello","type":"apt","versions":[{"version":"2.10"}]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importToServer(srv.URL, "", true, false, []string{catalog}); err == nil {
		t.Fatal("a push where every package was refused reported success")
	}
}
