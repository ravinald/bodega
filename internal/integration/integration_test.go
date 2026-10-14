package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// probeLookups counts every Lookup the double answers, for the cache test.
var probeLookups atomic.Int64

// double answers from its own "verdict" setting.
type double struct{ inst *Instance }

func (d double) Lookup(ctx context.Context, q Query) (Answer, error) {
	probeLookups.Add(1)
	switch d.inst.String("verdict") {
	case "flagged":
		return Answer{Flagged: true, Reason: q.Name + " is bad", Quota: "41 of 50 left"}, nil
	case "error":
		return Answer{}, errors.New("503 Service Unavailable")
	case "slow":
		<-ctx.Done()
		return Answer{}, ctx.Err()
	}
	return Answer{}, nil
}

func init() {
	Register(Descriptor{
		Type: "every-kind", DisplayName: "Every kind", VendorURL: "https://example.test/", Cost: CostFreeTier,
		Ecosystems: []string{manifest.TypeCargo}, DataSent: "The purl of every version asked about.",
		DefaultAction: policy.ActionWarn,
		Fields: []Field{
			{Key: "label", Label: "Label", Kind: KindString},
			{Key: "limit", Label: "Limit", Kind: KindInt, Default: "10", Min: 1, Max: 100},
			{Key: "window", Label: "Window", Kind: KindDuration, Default: "1h", MinDuration: time.Minute, MaxDuration: 24 * time.Hour},
			{Key: "strict", Label: "Strict", Kind: KindBool, Default: "false"},
			{Key: "verdict", Label: "Verdict", Kind: KindEnum, Default: "clean", Options: []string{"clean", "flagged", "error", "slow"}},
			{Key: "endpoint", Label: "Endpoint", Kind: KindURL, Default: "https://api.example.test/"},
			{Key: "api_token", Label: "API token", Kind: KindString, Secret: true, Required: true},
		},
		Probe: Query{Ecosystem: manifest.TypeCargo, Name: "serde", Version: "1.0.0"},
		New:   func(inst *Instance) (Checker, error) { return double{inst}, nil },
	})
}

func entry(kv ...any) config.Integration {
	e := config.Integration{"type": "every-kind"}
	for i := 0; i+1 < len(kv); i += 2 {
		e[kv[i].(string)] = kv[i+1]
	}
	return e
}

// The validator refuses every wrong kind and out-of-range value with the
// instance, the key and what it wanted, accepts the right ones, and fills
// defaults.
func TestValidateInstanceEveryKind(t *testing.T) {
	inst, err := ValidateInstance("vendor", entry("label", "x", "limit", 5.0, "window", "2h", "strict", true,
		"verdict", "flagged", "endpoint", "http://mirror.internal/v1"))
	if err != nil {
		t.Fatalf("valid entry refused: %v", err)
	}
	if inst.String("label") != "x" || inst.Int("limit") != 5 || inst.Duration("window") != 2*time.Hour ||
		!inst.Bool("strict") || inst.String("verdict") != "flagged" || inst.Enabled {
		t.Errorf("parsed %+v", inst.values)
	}
	inst, err = ValidateInstance("vendor", entry())
	if err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	if inst.Int("limit") != 10 || inst.Duration("window") != time.Hour || inst.Duration(KeyCacheTTL) != time.Hour ||
		inst.Duration(KeyTimeout) != 10*time.Second || inst.String("endpoint") != "https://api.example.test/" {
		t.Errorf("defaults %+v", inst.values)
	}

	bad := map[string]struct {
		e    config.Integration
		want string
	}{
		"string_as_number":     {entry("label", 3.0), `integrations.vendor.label: want a string, got 3`},
		"int_as_string":        {entry("limit", "5"), `integrations.vendor.limit: want a whole number from 1 to 100, got "5"`},
		"int_fraction":         {entry("limit", 2.5), `integrations.vendor.limit: want a whole number`},
		"int_out_of_range":     {entry("limit", 101.0), `got 101`},
		"duration_unparsable":  {entry("window", "soon"), `integrations.vendor.window: want a duration`},
		"duration_below_floor": {entry("window", "30s"), `from 1m to 1d, got "30s"`},
		"bool_as_string":       {entry("strict", "yes"), `integrations.vendor.strict: want true or false, got "yes"`},
		"enum_unknown":         {entry("verdict", "maybe"), `want one of clean, flagged, error, slow, got "maybe"`},
		"url_scheme":           {entry("endpoint", "ftp://x/"), `integrations.vendor.endpoint: want an http or https URL`},
		"url_userinfo":         {entry("endpoint", "https://u:p@x/"), `want an http or https URL with no user, password or fragment`},
		"enabled_not_bool":     {entry("enabled", "true"), `integrations.vendor.enabled: want true or false`},
		"unknown_key":          {entry("colour", "red"), `integrations.vendor.colour: unknown key for type every-kind (accepted: type, enabled, label`},
		"literal_secret": {entry("api_token", "sk-live-123"),
			"integrations.vendor.api_token: a secret is never written in the config file; remove the key and run: bodega integration secret vendor api_token"},
		"relative_secret_file": {entry("api_token_file", "token.txt"), `integrations.vendor.api_token_file: want an absolute path`},
		"cache_ttl_too_long":   {entry(KeyCacheTTL, "30d"), `integrations.vendor.cache_ttl: want a duration`},
		"unknown_type":         {config.Integration{"type": "nope"}, `integrations.vendor.type: unknown integration type "nope" (registered: `},
		"no_type":              {config.Integration{"enabled": true}, `integrations.vendor.type: required`},
	}
	for name, c := range bad {
		_, err := ValidateInstance("vendor", c.e)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "sk-live-123") {
			t.Errorf("%s: the error repeats the secret: %v", name, err)
		}
	}
	if _, err := ValidateInstance("Vendor.Prod", entry()); err == nil || !strings.Contains(err.Error(), "integrations.Vendor.Prod: an instance name") {
		t.Errorf("bad instance name: %v", err)
	}
}

// A disabled instance is held to every rule an enabled one is, except that
// its required secret need not exist yet.
func TestValidateDisabledSameRules(t *testing.T) {
	t.Setenv(CredentialsEnv, "")
	if _, err := ValidateInstance("vendor", entry("enabled", false, "limit", 0.0)); err == nil {
		t.Error("a disabled instance with an out-of-range value was accepted")
	}
	if _, err := ValidateInstance("vendor", entry("enabled", false)); err != nil {
		t.Errorf("a disabled instance without its secret was refused: %v", err)
	}
	_, err := ValidateInstance("vendor", entry("enabled", true))
	if err == nil || !strings.Contains(err.Error(), "integrations.vendor.api_token: no secret found: run `bodega integration secret vendor api_token`") {
		t.Errorf("enabled without a secret: %v", err)
	}
}

// Secrets are read from $CREDENTIALS_DIRECTORY, then the environment, then
// <key>_file, and the first found wins.
func TestSecretLookupOrder(t *testing.T) {
	creds := t.TempDir()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inst, err := ValidateInstance("socket-prod", entry("api_token_file", file))
	if err != nil {
		t.Fatal(err)
	}
	if SecretEnv("socket-prod", "api_token") != "BODEGA_SOCKET_PROD_API_TOKEN" {
		t.Fatalf("SecretEnv = %s", SecretEnv("socket-prod", "api_token"))
	}
	read := func() (string, string) {
		t.Helper()
		v, src, err := inst.Secret("api_token")
		if err != nil {
			t.Fatalf("Secret: %v", err)
		}
		return v, src
	}

	t.Setenv(CredentialsEnv, "")
	t.Setenv("BODEGA_SOCKET_PROD_API_TOKEN", "")
	if v, src := read(); v != "from-file" || src != SourceFile+" "+file {
		t.Errorf("file only: %q from %q", v, src)
	}
	t.Setenv("BODEGA_SOCKET_PROD_API_TOKEN", "from-env")
	if v, src := read(); v != "from-env" || src != SourceEnv {
		t.Errorf("env over file: %q from %q", v, src)
	}
	if err := os.WriteFile(filepath.Join(creds, "socket-prod.api_token"), []byte("from-creds\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CredentialsEnv, creds)
	if v, src := read(); v != "from-creds" || src != SourceCredentials {
		t.Errorf("credentials over env: %q from %q", v, src)
	}
	// A relative CREDENTIALS_DIRECTORY is not systemd's, and is skipped.
	t.Setenv(CredentialsEnv, "relative/dir")
	if v, _ := read(); v != "from-env" {
		t.Errorf("relative credentials dir was read: %q", v)
	}

	t.Setenv(CredentialsEnv, "")
	t.Setenv("BODEGA_SOCKET_PROD_API_TOKEN", "")
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inst.Secret("api_token"); err == nil || !strings.Contains(err.Error(), "readable beyond its owner") {
		t.Errorf("world-readable secret file: %v", err)
	}
}

func TestWriteSecretMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvConfigFile, filepath.Join(dir, "config.json"))
	inst, err := ValidateInstance("vendor", entry())
	if err != nil {
		t.Fatal(err)
	}
	path, err := WriteSecret(inst, "api_token", strings.NewReader("sk-123\n"))
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "credentials", "vendor.api_token") {
		t.Errorf("path = %s", path)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stat %s: %v %v", path, info.Mode(), err)
	}
	if _, err := WriteSecret(inst, "label", strings.NewReader("x")); err == nil {
		t.Error("a non-secret field was written as a secret")
	}
}

func TestRedact(t *testing.T) {
	got := Redact(config.Integration{"type": "every-kind", "api_token": "sk", "label": "x"})
	if got["api_token"] != Redacted || got["label"] != "x" {
		t.Errorf("declared secret: %v", got)
	}
	got = Redact(config.Integration{"type": "unregistered", "auth_token": "sk", "url": "u"})
	if got["auth_token"] != Redacted || got["url"] != "u" {
		t.Errorf("unregistered type: %v", got)
	}
}

func TestRegisterPanics(t *testing.T) {
	base := func() Descriptor {
		return Descriptor{Type: "panics", DisplayName: "p", Cost: CostFree, DataSent: "nothing",
			DefaultAction: policy.ActionWarn, New: func(*Instance) (Checker, error) { return nil, nil }}
	}
	cases := map[string]func(*Descriptor){
		"duplicate":        func(d *Descriptor) { d.Type = "every-kind" },
		"field_no_kind":    func(d *Descriptor) { d.Fields = []Field{{Key: "x"}} },
		"field_reserved":   func(d *Descriptor) { d.Fields = []Field{{Key: "enabled", Kind: KindBool}} },
		"enum_no_options":  func(d *Descriptor) { d.Fields = []Field{{Key: "x", Kind: KindEnum}} },
		"bad_default":      func(d *Descriptor) { d.Fields = []Field{{Key: "x", Kind: KindInt, Default: "ten"}} },
		"no_data_sentence": func(d *Descriptor) { d.DataSent = "" },
		"bad_action":       func(d *Descriptor) { d.DefaultAction = "pass" },
	}
	for name, edit := range cases {
		d := base()
		edit(&d)
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: Register did not panic", name)
				}
			}()
			Register(d)
		}()
	}
}

type memStore struct {
	actions map[string]string
	errs    map[string]string
	broken  bool
}

func (m *memStore) GetIntegrationPolicy(_ context.Context, inst, eco string) (audit.IntegrationPolicy, error) {
	if m.broken {
		return audit.IntegrationPolicy{}, errors.New("database is locked")
	}
	a, ok := m.actions[inst+"/"+eco]
	if !ok {
		return audit.IntegrationPolicy{}, audit.ErrIntegrationPolicyNotFound
	}
	return audit.IntegrationPolicy{Instance: inst, Ecosystem: eco, Action: a}, nil
}

func (m *memStore) RecordIntegrationError(_ context.Context, inst, msg string) error {
	if m.errs == nil {
		m.errs = map[string]string{}
	}
	m.errs[inst] = msg
	return nil
}

func crate(name string) (*manifest.PackageManifest, *manifest.VersionEntry) {
	pm := &manifest.PackageManifest{Type: manifest.TypeCargo, Name: name, Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}
	return pm, &pm.Versions[0]
}

// The action is the policy row, or the descriptor default without one, or
// block when the store cannot say; an error takes it and is recorded.
func TestCheckActionsAndErrors(t *testing.T) {
	t.Setenv("BODEGA_ACT_API_TOKEN", "sk")
	store := &memStore{actions: map[string]string{}}
	raw := map[string]config.Integration{
		"act":  entry("enabled", true, "verdict", "error"),
		"idle": entry("enabled", false, "verdict", "flagged"),
	}
	checks := Checks(raw, store)
	if len(checks) != 1 || checks[0].CheckName() != "integration:act" {
		t.Fatalf("Checks = %d, want the enabled instance only", len(checks))
	}
	pm, ve := crate("serde")
	ctx := context.Background()
	if r := checks[0].Check(ctx, pm, ve); r.Action != policy.ActionWarn || !strings.HasPrefix(r.Reason, "error: ") ||
		r.Details["outcome"] != "error" {
		t.Errorf("default action: %+v", r)
	}
	if !strings.Contains(store.errs["act"], "503") {
		t.Errorf("last error not recorded: %v", store.errs)
	}
	store.actions["act/cargo"] = policy.ActionBlock
	if r := checks[0].Check(ctx, pm, ve); r.Action != policy.ActionBlock {
		t.Errorf("block row: %+v", r)
	}
	store.broken = true
	if a := checks[0].ActionFor(ctx, manifest.TypeCargo); a != policy.ActionBlock {
		t.Errorf("unreadable policy reads as %s, want block", a)
	}
	store.broken = false

	npm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "x", Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}
	if r := checks[0].Check(ctx, npm, &npm.Versions[0]); r.Action != policy.ActionNotEvaluated {
		t.Errorf("uncovered ecosystem: %+v", r)
	}
	star := &manifest.PackageManifest{Type: manifest.TypeCargo, Name: "x", Versions: []manifest.VersionEntry{{Version: "*"}}}
	if r := checks[0].Check(ctx, star, &star.Versions[0]); r.Action != policy.ActionNotEvaluated {
		t.Errorf("unpinned version: %+v", r)
	}
}

// A timeout is an error under the action, not a pass.
func TestCheckTimeout(t *testing.T) {
	t.Setenv("BODEGA_SLOW_API_TOKEN", "sk")
	c := Build("slow", entry("enabled", true, "verdict", "slow", KeyTimeout, "1s"), nil)
	pm, ve := crate("serde")
	start := time.Now()
	r := c.Check(context.Background(), pm, ve)
	if r.Action != policy.ActionWarn || !strings.Contains(r.Reason, "deadline exceeded") {
		t.Errorf("timeout: %+v", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("timeout took %s", time.Since(start))
	}
}

// An answer is reused for cache_ttl, across calls to Checks with an
// unchanged entry, and asked again once it expires or the entry changes.
func TestCheckCachesPerPURL(t *testing.T) {
	t.Setenv("BODEGA_CACHED_API_TOKEN", "sk")
	raw := map[string]config.Integration{"cached": entry("enabled", true, "verdict", "flagged", KeyCacheTTL, "1m")}
	pm, ve := crate("serde")
	ctx := context.Background()
	before := probeLookups.Load()
	c := Checks(raw, nil)[0]
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Check(ctx, pm, ve)
	Checks(raw, nil)[0].Check(ctx, pm, ve)
	if n := probeLookups.Load() - before; n != 1 {
		t.Errorf("two checks of one purl made %d lookups, want 1", n)
	}
	other, ove := crate("tokio")
	c.Check(ctx, other, ove)
	if n := probeLookups.Load() - before; n != 2 {
		t.Errorf("a second purl made %d lookups in total, want 2", n)
	}
	now = now.Add(2 * time.Minute)
	c.Check(ctx, pm, ve)
	if n := probeLookups.Load() - before; n != 3 {
		t.Errorf("after the TTL: %d lookups, want 3", n)
	}
	raw["cached"]["label"] = "changed"
	Checks(raw, nil)[0].Check(ctx, pm, ve)
	if n := probeLookups.Load() - before; n != 4 {
		t.Errorf("a changed entry reused the old cache: %d lookups, want 4", n)
	}
}

// An entry that stops validating becomes a check that records the reason as
// an error under the type's default action, never one that stops running.
func TestChecksInvalidEntryFailsClosed(t *testing.T) {
	t.Setenv("BODEGA_BROKEN_API_TOKEN", "")
	t.Setenv(CredentialsEnv, "")
	c := Checks(map[string]config.Integration{"broken": entry("enabled", true)}, nil)
	if len(c) != 1 {
		t.Fatalf("Checks = %d", len(c))
	}
	pm, ve := crate("serde")
	if r := c[0].Check(context.Background(), pm, ve); r.Action != policy.ActionWarn || !strings.Contains(r.Reason, "no secret found") {
		t.Errorf("invalid entry: %+v", r)
	}
}

func TestRunTest(t *testing.T) {
	t.Setenv("BODEGA_PROBE_API_TOKEN", "sk")
	var out strings.Builder
	if err := RunTest(context.Background(), &out, "probe", entry("verdict", "flagged"), nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"query:   pkg:cargo/serde@1.0.0", "latency: ", "answer:  flagged (serde is bad)", "quota:   41 of 50 left"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	store := &memStore{}
	out.Reset()
	if err := RunTest(context.Background(), &out, "probe", entry("verdict", "error"), store); err == nil {
		t.Error("an erroring probe returned nil")
	}
	if store.errs["probe"] == "" {
		t.Error("a failed test was not recorded as the last error")
	}
}

// Load refuses an integrations block the validator refuses, naming the
// instance and key, and accepts a disabled valid one.
func TestConfigLoadValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv(config.EnvConfigFile, path)
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	load := func() error {
		_, err := config.Load(filepath.Join(dir, "m"), "", "", dir, true, false)
		return err
	}
	write(`{"integrations": {"vendor": {"type": "every-kind", "api_token": "sk-live"}}}`)
	if err := load(); err == nil || !strings.Contains(err.Error(), "integrations.vendor.api_token: a secret is never written") {
		t.Errorf("literal secret: %v", err)
	}
	write(`{"integrations": {"vendor": {"type": "every-kind", "limit": 500}}}`)
	if err := load(); err == nil || !strings.Contains(err.Error(), "integrations.vendor.limit") {
		t.Errorf("out of range: %v", err)
	}
	write(`{"integrations": {"vendor": {"type": "every-kind", "enabled": false}}}`)
	if err := load(); err != nil {
		t.Errorf("valid disabled entry: %v", err)
	}
}
