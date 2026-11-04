package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestPolicyProvenanceSetAndList(t *testing.T) {
	adbPath := admissionInstall(t, false)
	if out, err := runRoot(t, "policy", "provenance", "set", "npm", "block"); err != nil || !strings.Contains(out, "npm upstream provenance policy: block") {
		t.Fatalf("set: %v\n%s", err, out)
	}
	out, err := runRoot(t, "policy", "provenance", "set", "cargo", "block")
	if err != nil || !strings.Contains(out, "block refuses all of them") {
		t.Errorf("block on an uncovered ecosystem should say what it does: %v\n%s", err, out)
	}
	out, err = runRoot(t, "policy", "provenance", "set", "pypi", "block")
	if err != nil || strings.Contains(out, "records unavailable") {
		t.Errorf("block on pypi, which the check verifies, printed the uncovered note: %v\n%s", err, out)
	}
	if _, err := runRoot(t, "policy", "provenance", "set", "npm", "allow"); err == nil {
		t.Error("an action outside warn|block|ignore was accepted")
	}
	if _, err := runRoot(t, "policy", "provenance", "set", "quicklisp", "warn"); err == nil {
		t.Error("an unknown ecosystem was accepted")
	}
	out, err = runRoot(t, "policy", "provenance", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"npm", "block", "cargo", "warn (default)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not show %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "helm" && !strings.Contains(line, "warn (default)  yes") {
			t.Errorf("helm is verified by the check, but list says:\n%s", line)
		}
		if len(f) >= 3 && f[0] == "pypi" && f[2] != "yes" {
			t.Errorf("pypi VERIFIES = %q, want yes:\n%s", f[2], out)
		}
	}

	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	if p, err := adb.GetProvenancePolicy(context.Background(), "npm"); err != nil || p.Action != "block" || p.Actor == "" {
		t.Errorf("stored policy = %+v, %v", p, err)
	}
}

// reset clears the pin and records who did it and what the pin held.
func TestPkgTrustShowAndReset(t *testing.T) {
	adbPath := admissionInstall(t, false)
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adb.PinProvenance(context.Background(), audit.ProvenancePin{PkgType: "npm", PkgName: "sigstore",
		SourceRepositoryURI: "https://github.com/sigstore/sigstore-js", BuilderID: "https://github.com/actions/runner/github-hosted",
		PinnedVersion: "3.0.0"}); err != nil {
		t.Fatal(err)
	}
	_ = adb.Close()

	out, err := runRoot(t, "pkg", "trust", "show", "npm", "sigstore")
	if err != nil || !strings.Contains(out, "https://github.com/sigstore/sigstore-js") || !strings.Contains(out, "3.0.0") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if out, err = runRoot(t, "pkg", "trust", "reset", "npm", "sigstore"); err != nil || !strings.Contains(out, "Cleared the pin") {
		t.Fatalf("reset: %v\n%s", err, out)
	}
	if out, _ = runRoot(t, "pkg", "trust", "show", "npm", "sigstore"); !strings.Contains(out, "has no pin") {
		t.Errorf("show after reset:\n%s", out)
	}

	adb, err = audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	events, err := adb.Query(context.Background(), audit.Filter{EventType: audit.EventPolicy, PkgType: "npm", PkgName: "sigstore"})
	if err != nil || len(events) != 1 {
		t.Fatalf("reset events = %+v, %v", events, err)
	}
	var details map[string]string
	_ = json.Unmarshal([]byte(events[0].Details), &details)
	if events[0].Actor == "" || details["op"] != "trust_reset" || details["source_repository_uri"] != "https://github.com/sigstore/sigstore-js" {
		t.Errorf("reset event = %+v", events[0])
	}
}

func TestServeRefusesAnUnusableTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "trusted_root.json")
	if err := os.WriteFile(junk, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "absent.json"), "unparsable": junk} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"storage_backend": "local", "storage_path": filepath.Join(dir, "storage"),
				"manifest_dir": filepath.Join(dir, "manifests"), "log_dir": dir, "allow_plaintext": true,
				"listen_addr": "127.0.0.1:0", "sigstore_trusted_root": path,
			})
			cfgPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(config.EnvConfigFile, cfgPath)
			_, err := runRoot(t, "serve", "--quiet")
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "sigstore_trusted_root") {
				t.Errorf("serve with %s trusted root: %v", name, err)
			}
		})
	}
}

// A keyring serve cannot read would leave every .prov under its prefix
// unknown at admission, so serve refuses to start on it, naming the file.
func TestServeRefusesAnUnreadableHelmKeyring(t *testing.T) {
	dir := t.TempDir()
	keyring := filepath.Join(dir, "charts.gpg")
	body, _ := json.Marshal(map[string]any{
		"storage_backend": "local", "storage_path": filepath.Join(dir, "storage"),
		"manifest_dir": filepath.Join(dir, "manifests"), "log_dir": dir, "allow_plaintext": true,
		"listen_addr": "127.0.0.1:0", "helm_keyrings": map[string]string{"https://charts.example.com/": keyring},
	})
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	_, err := runRoot(t, "serve", "--quiet")
	if err == nil || !strings.Contains(err.Error(), keyring) || !strings.Contains(err.Error(), "helm_keyrings") {
		t.Errorf("serve with an unreadable helm keyring: %v", err)
	}
}

func TestReviewHelmProxyAdmissionChecksProvenance(t *testing.T) {
	dir := t.TempDir()
	oldPepper := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{filepath.Join(dir, "pepper")}
	t.Cleanup(func() { audit.DefaultPepperPaths = oldPepper })
	var provGets atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".prov") {
			provGets.Add(1)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("chart bytes"))
	}))
	t.Cleanup(up.Close)
	cfg := &config.Config{LogDir: dir, StoragePath: dir, AuditDB: filepath.Join(dir, "audit.db"), AllowPlaintext: true, ProxyCacheEnabled: true}
	db, err := audit.Open(cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.SetProvenancePolicy(t.Context(), audit.ProvenancePolicy{Ecosystem: manifest.TypeHelm, Action: "block", Actor: "review"}); err != nil {
		t.Fatal(err)
	}
	store := manifest.NewLocalStore(filepath.Join(dir, "manifests"))
	pm := &manifest.PackageManifest{ConfigVersion: manifest.CurrentConfigVersion, Type: manifest.TypeHelm, Name: "podinfo", Versions: []manifest.VersionEntry{{Version: "6.7.0", URL: up.URL + "/charts", Mode: manifest.ModeProxy}}}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatal(err)
	}
	s := server.New(cfg, store, storage.NewSingle(storage.NewMemory()), "127.0.0.1:0", nil)
	req := httptest.NewRequest(http.MethodGet, "http://bodega.local/helm/charts/podinfo-6.7.0.tgz", nil)
	req.RemoteAddr = "127.0.0.1:33333"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	rows, err := db.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeHelm, PkgName: "podinfo"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("admissions: %d, %v; HTTP %d", len(rows), err, rec.Code)
	}
	for _, c := range rows[0].Checks {
		if c.Check != audit.CheckUpstreamProvenance {
			continue
		}
		if c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceUnavailable || provGets.Load() != 1 || rec.Code != http.StatusForbidden {
			t.Fatalf("proxy admission: status=%s provenance=%+v detail=%q .prov GETs=%d HTTP=%d; want unavailable/block after reading .prov", c.Status, c.Provenance, c.Detail, provGets.Load(), rec.Code)
		}
		return
	}
	t.Fatal("proxy admission recorded no upstream_provenance check")
}

// docParagraph is the line of a docs page that starts with prefix, the unit a
// requirement on that page's prose is checked against: these pages hold one
// paragraph, table row or list item per line.
func docParagraph(t *testing.T, page, prefix string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", page))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("docs/%s has no line starting %q; the paragraph moved", page, prefix)
	return ""
}

func docSpan(t *testing.T, page, from, to string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", page))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("docs/%s has no %q", page, from)
	}
	s = s[i:]
	if j := strings.Index(s[len(from):], to); j >= 0 {
		s = s[:len(from)+j]
	}
	return s
}

func requireAll(t *testing.T, where, text string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("%s does not say %q", where, w)
		}
	}
}

// docs/usage.md describes the helm check where it describes current behavior:
// the per-type table, the uncovered ecosystems, the unavailable and unknown
// cases, the helm_keyrings key and the Helm-specific fields.
func TestUsageDocDescribesHelmProvenance(t *testing.T) {
	requireAll(t, "the per-type table's helm row", docParagraph(t, "usage.md", "| `helm` from a classic chart repository"),
		".prov", "helm_keyrings", "sha256")
	uncovered := docParagraph(t, "usage.md", "**Ecosystems not covered.**")
	if strings.Contains(uncovered, "`helm`,") {
		t.Errorf("the uncovered ecosystems still list helm: %s", uncovered)
	}
	requireAll(t, "the uncovered ecosystems", uncovered, "over OCI", "`unavailable`")
	requireAll(t, "the unavailable/unknown paragraph", docParagraph(t, "usage.md", "`unavailable` is the registry's answer"),
		"For helm, a `.prov` that answers 404 is `unavailable`", "`unknown`", "no_keyring", "a keyring that cannot be loaded")
	keyrings := docParagraph(t, "usage.md", "The longest prefix that a chart URL starts with wins")
	requireAll(t, "the helm_keyrings paragraph", keyrings,
		"ends in `/`", "evil.net", "chmod go-w", "private key material", "gpg --export", "`bodega serve` loads every keyring before it binds and refuses to start")
	requireAll(t, "the helm_keyrings key", docParagraph(t, "usage.md", "`helm_keyrings` maps"),
		"config-file key only", "no CLI flag")
	requireAll(t, "the full config listing", docSpan(t, "usage.md", `  "sigstore_trusted_root": "",`, "\n}"), `"helm_keyrings"`)
	requireAll(t, "Helm-specific fields", docSpan(t, "usage.md", "### Helm-specific fields", "\n### "),
		"`.prov` file beside the chart URL", "verified at admission", "a proxy fill refuses")
}

// docs/threat-model.md no longer lists helm among the types with no verified
// publisher statement, and says what the helm check does and does not stop;
// docs/design.md names the .prov among the admission checks.
func TestThreatModelDocDescribesHelmProvenance(t *testing.T) {
	everywhere := docSpan(t, "threat-model.md", "- **A compromised maintainer account publishing outside CI, everywhere", "\n- **")
	if strings.Contains(everywhere, "helm") {
		t.Errorf("the threat model still lists helm among the types with no verified publisher statement:\n%s", everywhere)
	}
	requireAll(t, "the threat model's helm item", docSpan(t, "threat-model.md", "- **Helm charts, past the keyring.**", "\n- **"),
		"did not configure records `invalid`", "drops its `.prov` records `unavailable`", "only `block`",
		"only as good as how the operator", "served over OCI is not checked")
	requireAll(t, "docs/design.md's admission checks", docParagraph(t, "design.md", "Every path runs the same admission checks"),
		"Helm chart's `.prov`", "helm_keyrings")
}

// docs/slsa.md's Level 2 row names the .prov check, and the publisher
// signature gap no longer names Helm or #275 but still names OCI charts.
func TestSLSADocDescribesHelmProvenance(t *testing.T) {
	requireAll(t, "the L2 publisher signature row", docParagraph(t, "slsa.md", "| L2: a publisher signature"),
		"Helm `.prov` files", "operator-configured keyring")
	gap := docParagraph(t, "slsa.md", "- **Publisher signatures are verified for")
	requireAll(t, "the publisher signatures gap", gap,
		"**Publisher signatures are verified for npm, PyPI, GitHub releases and classic Helm charts only.**", "served over OCI")
	for _, stale := range []string{"#275", "Helm `.prov` files are", "and Helm `.prov` files"} {
		if strings.Contains(gap, stale) {
			t.Errorf("the publisher signatures gap still says %q: %s", stale, gap)
		}
	}
}
