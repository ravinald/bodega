package clientconf

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

var ociUpstreams = map[string]string{ //nolint:gosec // G101: a fixture credential, asserted absent from what clients get
	"docker.io": "https://registry-1.docker.io",
	"ghcr.io":   "https://robot:s3cret@ghcr.io",
	"quay.io":   "https://quay.io",
}

func ociFile(t *testing.T, files []OCIFile, path string) OCIFile {
	t.Helper()
	for _, f := range files {
		if f.Path(OSLinux) == path {
			return f
		}
	}
	t.Fatalf("no oci file at %s", path)
	return OCIFile{}
}

// F99 R1, R2: each runtime's file for an https and a plaintext base, with
// the insecure setting on the second alone.
func TestOCIClientRendersEachRuntimeForBothSchemes(t *testing.T) {
	cases := []struct {
		base                                 string
		daemon, hosts, config, registriesCnf string
		insecureNote                         bool
	}{
		{
			base:   "https://bodega.internal",
			daemon: "{\n  \"registry-mirrors\": [\n    \"https://bodega.internal/\"\n  ]\n}\n",
			hosts:  "server = \"https://ghcr.io\"\n\n[host.\"https://bodega.internal\"]\n  capabilities = [\"pull\", \"resolve\"]\n",
			config: "version = 2\n\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n",
			registriesCnf: "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"bodega.internal/docker.io\"\n\n" +
				"[[registry]]\nprefix = \"ghcr.io\"\nlocation = \"ghcr.io\"\n\n[[registry.mirror]]\nlocation = \"bodega.internal/ghcr.io\"\n\n" +
				"[[registry]]\nprefix = \"quay.io\"\nlocation = \"quay.io\"\n\n[[registry.mirror]]\nlocation = \"bodega.internal/quay.io\"\n",
		},
		{
			base:   "http://bodega.internal:8080/",
			daemon: "{\n  \"registry-mirrors\": [\n    \"http://bodega.internal:8080/\"\n  ],\n  \"insecure-registries\": [\n    \"bodega.internal:8080\"\n  ]\n}\n",
			hosts:  "server = \"https://ghcr.io\"\n\n[host.\"http://bodega.internal:8080\"]\n  capabilities = [\"pull\", \"resolve\"]\n  skip_verify = true\n",
			config: "version = 2\n\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n",
			registriesCnf: "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"bodega.internal:8080/docker.io\"\ninsecure = true\n\n" +
				"[[registry]]\nprefix = \"ghcr.io\"\nlocation = \"ghcr.io\"\n\n[[registry.mirror]]\nlocation = \"bodega.internal:8080/ghcr.io\"\ninsecure = true\n\n" +
				"[[registry]]\nprefix = \"quay.io\"\nlocation = \"quay.io\"\n\n[[registry.mirror]]\nlocation = \"bodega.internal:8080/quay.io\"\ninsecure = true\n",
			insecureNote: true,
		},
	}
	for _, c := range cases {
		files := OCIClient(c.base, ociUpstreams)
		if len(files) != 6 {
			t.Fatalf("%s: %d files, want daemon.json, three hosts.toml, config.toml and the drop-in", c.base, len(files))
		}
		daemon := ociFile(t, files, DockerDaemonPath)
		if daemon.Content != c.daemon || daemon.Runtime != RuntimeDocker || daemon.Key != "" {
			t.Errorf("%s daemon.json = %q (runtime %s, key %q), want %q", c.base, daemon.Content, daemon.Runtime, daemon.Key, c.daemon)
		}
		notes := strings.Join(daemon.Notes, ". ")
		if !strings.Contains(notes, "covers Docker Hub only") || !strings.Contains(notes, "ghcr.io or quay.io") ||
			!strings.Contains(notes, "/etc/containerd/certs.d/<registry>/hosts.toml") || !strings.Contains(notes, RegistriesConfDropIn) {
			t.Errorf("%s daemon.json notes do not name the Docker Hub limit and the other files: %q", c.base, notes)
		}
		if got := strings.Contains(notes, "insecure-registries"); got != c.insecureNote {
			t.Errorf("%s daemon.json notes mention insecure-registries = %v, want %v", c.base, got, c.insecureNote)
		}
		hosts := ociFile(t, files, "/etc/containerd/certs.d/ghcr.io/hosts.toml")
		if hosts.Content != c.hosts || hosts.Key != OCIHostsFileKey("ghcr.io") {
			t.Errorf("%s ghcr.io hosts.toml = %q (key %q), want %q", c.base, hosts.Content, hosts.Key, c.hosts)
		}
		if strings.Contains(hosts.Content, "s3cret") {
			t.Errorf("hosts.toml carries bodega's upstream credential: %q", hosts.Content)
		}
		cfg := ociFile(t, files, ContainerdConfigPath)
		if cfg.Content != c.config || cfg.Runtime != RuntimeContainerd {
			t.Errorf("%s config.toml = %q, want %q", c.base, cfg.Content, c.config)
		}
		if got := strings.Contains(strings.Join(cfg.Notes, ". "), "skip_verify"); got != c.insecureNote {
			t.Errorf("%s config.toml notes mention skip_verify = %v, want %v", c.base, got, c.insecureNote)
		}
		drop := ociFile(t, files, RegistriesConfDropIn)
		if drop.Content != c.registriesCnf || drop.Runtime != RuntimePodman {
			t.Errorf("%s drop-in = %q, want %q", c.base, drop.Content, c.registriesCnf)
		}
		if got := strings.Contains(strings.Join(drop.Notes, ". "), "insecure = true"); got != c.insecureNote {
			t.Errorf("%s drop-in notes mention insecure = %v, want %v", c.base, got, c.insecureNote)
		}
		for _, f := range files {
			if OCIRuntimeOf(f.Path(OSLinux)) != f.Runtime {
				t.Errorf("OCIRuntimeOf(%s) = %q, want %q", f.Path(OSLinux), OCIRuntimeOf(f.Path(OSLinux)), f.Runtime)
			}
			if f.Key != "" && !OCIFileKeyValid(f.Key) {
				t.Errorf("key %q does not validate", f.Key)
			}
		}
	}
}

// F99 R3: daemon.json keeps its other keys and their order, registry-mirrors
// is replaced, and insecure-registries keeps the entries it had.
func TestMergeDockerDaemonKeepsOtherKeys(t *testing.T) {
	existing := []byte(`{"log-driver":"journald","registry-mirrors":["https://mirror.gcr.io"],"insecure-registries":["10.0.0.5:5000"],"live-restore":true}`)
	planned := []byte(DockerDaemon("http://bodega.internal:8080", nil).Content)
	got, err := MergeDockerDaemon(existing, planned)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"log-driver\": \"journald\",\n  \"registry-mirrors\": [\n    \"http://bodega.internal:8080/\"\n  ],\n" +
		"  \"insecure-registries\": [\n    \"10.0.0.5:5000\",\n    \"bodega.internal:8080\"\n  ],\n  \"live-restore\": true\n}\n"
	if string(got) != want {
		t.Errorf("merge =\n%s\nwant\n%s", got, want)
	}
	again, err := MergeDockerDaemon(got, planned)
	if err != nil || string(again) != string(got) {
		t.Errorf("a second merge changed the file (%v):\n%s", err, again)
	}
	if empty, _ := MergeDockerDaemon(nil, planned); string(empty) != string(planned) {
		t.Errorf("an absent daemon.json got %q, want the plan", empty)
	}
	if _, err := MergeDockerDaemon([]byte(`["not an object"]`), planned); err == nil || !strings.Contains(err.Error(), "Nothing was written") {
		t.Errorf("a non-object daemon.json = %v, want a refusal", err)
	}
}

// F99 R1, R3: config_path is added where no line sets it, in the table the
// file's version names, and a set one is left alone.
func TestMergeContainerdConfigSetsConfigPathOnlyWhenUnset(t *testing.T) {
	planned := []byte(ContainerdConfig("https://bodega.internal").Content)
	setting := `  config_path = "/etc/containerd/certs.d"`
	cases := []struct {
		name, existing, want string
	}{
		{"absent", "", string(planned)},
		{"set", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/srv/certs\"\n", ""},
		{"set single-quoted", "version = 2\n[plugins.'io.containerd.grpc.v1.cri'.registry]\n  config_path = '/srv/certs'\n", ""},
		{"set empty", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"\"\n",
			"version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n" + setting + "\n"},
		{"v2 table present", "# ops\nversion = 2\n[plugins.'io.containerd.grpc.v1.cri'.registry]  # mirrors\n  [plugins.\"io.containerd.grpc.v1.cri\".registry.headers]\n",
			"# ops\nversion = 2\n[plugins.'io.containerd.grpc.v1.cri'.registry]  # mirrors\n" + setting + "\n  [plugins.\"io.containerd.grpc.v1.cri\".registry.headers]\n"},
		{"v2 table absent", "version = 2\nroot = \"/var/lib/containerd\"\n",
			"version = 2\nroot = \"/var/lib/containerd\"\n\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n" + setting + "\n"},
		{"v3", "version = 3\n", "version = 3\n\n[plugins.\"io.containerd.cri.v1.images\".registry]\n" + setting + "\n"},
		{"docker's v1", "disabled_plugins = [\"cri\"]\n", "disabled_plugins = [\"cri\"]\n\n[plugins.cri.registry]\n" + setting + "\n"},
	}
	for _, c := range cases {
		got, err := MergeContainerdConfig([]byte(c.existing), planned)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		want := c.want
		if want == "" {
			want = c.existing
		}
		if string(got) != want {
			t.Errorf("%s: merge =\n%s\nwant\n%s", c.name, got, want)
		}
		if again, _ := MergeContainerdConfig(got, planned); string(again) != string(got) {
			t.Errorf("%s: a second merge changed the file:\n%s", c.name, again)
		}
	}
	if _, err := MergeContainerdConfig([]byte("version = 9\n"), planned); err == nil {
		t.Error("an unknown config version was edited, want a refusal")
	}
}

// F99 R1, R3: the merge edits the key containerd reads, whatever spelling
// the file gives it, keeps the line's comment and every other key, and
// refuses a form it cannot edit, or one containerd would refuse beside
// config_path, rather than write it.
func TestMergeContainerdConfigEditsTheEffectiveKey(t *testing.T) {
	planned := []byte(ContainerdConfig("https://bodega.internal").Content)
	cri := "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n"
	cases := []struct {
		name, existing, want string
	}{
		{"quoted key", cri + `"config_path" = ""` + "\n", cri + `"config_path" = "/etc/containerd/certs.d"` + "\n"},
		{"literal key", cri + `'config_path' = ''` + "\n", cri + `'config_path' = "/etc/containerd/certs.d"` + "\n"},
		{"quoted comment", cri + `config_path = "" # example "/srv/x"` + "\n", cri + `config_path = "/etc/containerd/certs.d" # example "/srv/x"` + "\n"},
		{"dotted from the plugin table", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\"]\n  registry.config_path = \"\"\n",
			"version = 2\n[plugins.\"io.containerd.grpc.v1.cri\"]\n  registry.config_path = \"/etc/containerd/certs.d\"\n"},
		{"another plugin's config_path", "version = 2\n[plugins.\"io.containerd.other.v1\".registry]\n  config_path = \"\"\n",
			"version = 2\n[plugins.\"io.containerd.other.v1\".registry]\n  config_path = \"\"\n\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n"},
		{"another plugin's config_path set", "version = 2\n[plugins.\"io.containerd.other.v1\".registry]\n  config_path = \"/srv/other\"\n" + cri[len("version = 2\n"):] + "  config_path = \"\"\n",
			"version = 2\n[plugins.\"io.containerd.other.v1\".registry]\n  config_path = \"/srv/other\"\n" + cri[len("version = 2\n"):] + "  config_path = \"/etc/containerd/certs.d\"\n"},
		{"header inside a multi-line string", "version = 2\nnote = \"\"\"\n" + cri[len("version = 2\n"):] + "config_path = \"\"\n\"\"\"\n",
			"version = 2\nnote = \"\"\"\n" + cri[len("version = 2\n"):] + "config_path = \"\"\n\"\"\"\n\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n"},
		{"empty mirrors table", cri + "[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors]\n",
			cri + "  config_path = \"/etc/containerd/certs.d\"\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors]\n"},
	}
	for _, c := range cases {
		got, err := MergeContainerdConfig([]byte(c.existing), planned)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s: merge =\n%s\nwant\n%s", c.name, got, c.want)
		}
		if r, err := ReadContainerdConfig(got); err != nil || r.ConfigPath != ContainerdCertsDir {
			t.Errorf("%s: the merged file reads back as %+v, %v", c.name, r, err)
		}
		if again, err := MergeContainerdConfig(got, planned); err != nil || string(again) != string(got) {
			t.Errorf("%s: a second merge = %v, changed:\n%s", c.name, err, again)
		}
	}
	refused := []struct{ name, existing, says string }{
		{"inline table", "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\"]\n  registry = { config_path = \"\" }\n", "by hand"},
		{"multi-line value", cri + "config_path = \"\"\"\n\"\"\"\n", "by hand"},
		{"legacy mirrors", cri + "[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"docker.io\"]\n  endpoint = [\"https://m.internal\"]\n", "sets mirrors"},
		{"legacy tls", cri + "[plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"m.internal\".tls]\n  insecure_skip_verify = true\n", ".tls"},
		{"duplicate key", cri + "config_path = \"\"\n\"config_path\" = \"\"\n", "cannot load"},
		{"not TOML", "version = 2\n[plugins\n", "cannot load"},
		{"non-string config_path", cri + "config_path = 3\n", "not a string"},
	}
	for _, c := range refused {
		got, err := MergeContainerdConfig([]byte(c.existing), planned)
		if err == nil || !strings.Contains(err.Error(), c.says) || !strings.Contains(err.Error(), "Nothing was written") {
			t.Errorf("%s: merge = %v\n%s\nwant a refusal saying %q", c.name, err, got, c.says)
		}
	}
}

// F99 R3: every oci file applied through NewChange, then planned again,
// changes nothing, and the merged daemon.json keeps the operator's key.
func TestOCIApplyTwiceChangesNothing(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "etc/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "etc/docker/daemon.json"), []byte(`{"data-root":"/srv/docker"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "etc/containerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "etc/containerd/config.toml"), []byte("disabled_plugins = [\"cri\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changes := func() []Change {
		var out []Change
		for _, f := range OCIClient("http://bodega.internal:8080", ociUpstreams) {
			sum := sha256.Sum256([]byte(f.Content))
			rec := PlanRecord{System: manifest.TypeOCI, Action: PlanInstall, Path: "~" + f.Path(OSLinux), SHA256: hex.EncodeToString(sum[:])}
			c, err := NewChange(rec, []byte(f.Content), home)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return out
	}
	if _, err := Apply(changes(), ".bak"); err != nil {
		t.Fatal(err)
	}
	for _, c := range changes() {
		if !c.Unchanged() {
			t.Errorf("second plan would change %s:\n%s", c.Target, c.New)
		}
	}
	daemon, _ := os.ReadFile(filepath.Join(home, "etc/docker/daemon.json"))
	if !strings.Contains(string(daemon), `"data-root": "/srv/docker"`) || !strings.Contains(string(daemon), "registry-mirrors") {
		t.Errorf("daemon.json after apply = %s", daemon)
	}
}

// F99 R3, R4: the config_path edit is planned only where containerd would
// read it: an import whose CRI table supersedes the main file's, one that
// fails to load, or a versionless one containerd 2.x migrates into the CRI
// plugin's table refuses the change rather than present it as effective.
func TestNewChangeRefusesAContainerdEditAnImportSupersedes(t *testing.T) {
	f := ContainerdConfig("https://bodega.internal")
	sum := sha256.Sum256([]byte(f.Content))
	rec := PlanRecord{System: manifest.TypeOCI, Action: PlanInstall, Path: "~" + f.Path(OSLinux), SHA256: hex.EncodeToString(sum[:])}
	cri := "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n"
	main := "version = 2\nimports = [\"conf.d/*.toml\"]\n"
	cases := []struct {
		name, imported, refusal string
	}{
		{"import sets another path", cri + "config_path = \"/srv/direct\"\n", "sets config_path = \"/srv/direct\""},
		{"import sets an empty path", cri + "config_path = \"\"\n", "sets config_path = \"\""},
		{"import carries the table without config_path", cri + "max_concurrent_downloads = 3\n", "doctor cannot tell"},
		{"import names certs.d", cri + "config_path = \"/srv/a:/etc/containerd/certs.d\"\n", ""},
		{"import of another plugin", "version = 2\n[plugins.\"io.containerd.grpc.v1.other\"]\nx = 1\n", ""},
		{"versionless import names the short CRI id", "[plugins.cri.registry]\nconfig_path = \"/srv/direct\"\n", "it sets no version and holds [plugins.cri]"},
		{"versionless import names a version 3 table", "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/srv/direct\"\n", "holds [plugins.\"io.containerd.cri.v1.images\"]"},
		{"versionless import in the main file's own names", cri[len("version = 2\n"):] + "config_path = \"/srv/direct\"\n", "sets config_path = \"/srv/direct\""},
		{"versionless import of another plugin", "[plugins.cgroups]\nno_prometheus = true\n", ""},
		{"no import matches the glob", "", ""},
	}
	for _, c := range cases {
		home := t.TempDir()
		dir := filepath.Join(home, "etc/containerd/conf.d")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "etc/containerd/config.toml"), []byte(main), 0o644); err != nil {
			t.Fatal(err)
		}
		if c.imported != "" {
			if err := os.WriteFile(filepath.Join(dir, "runtime.toml"), []byte(c.imported), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		ch, err := NewChange(rec, []byte(f.Content), home)
		switch {
		case c.refusal == "" && err != nil:
			t.Errorf("%s: %v, want the edit planned", c.name, err)
		case c.refusal == "" && !strings.Contains(string(ch.New), "config_path = \"/etc/containerd/certs.d\""):
			t.Errorf("%s: planned\n%s\nwant config_path set", c.name, ch.New)
		case c.refusal != "" && (err == nil || !strings.Contains(err.Error(), c.refusal)):
			t.Errorf("%s: %v, want a refusal saying %q", c.name, err, c.refusal)
		}
	}

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "etc/containerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "etc/containerd/config.toml"), []byte("version = 2\nimports = [\"missing.toml\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChange(rec, []byte(f.Content), home); err == nil || !strings.Contains(err.Error(), "missing.toml, which could not be read") {
		t.Errorf("missing import: %v, want a refusal naming it", err)
	}
}

// TestContainerdConfigLoadsWithContainerdsTOML holds ReadContainerdConfig to
// the grammar of go-toml v2.2.4, which containerd v2.2.0 loads config.toml
// with: TOML 1.1 syntax a later parser accepts is a file containerd does not
// start with, in the main file and in one it imports.
func TestContainerdConfigLoadsWithContainerdsTOML(t *testing.T) {
	const registry = "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n config_path = \"/etc/containerd/certs.d\"\n"
	if r, err := ReadContainerdConfig([]byte(registry + " audit = { a = \"b\" }\n")); err != nil || r.ConfigPath != ContainerdCertsDir {
		t.Fatalf("control = %+v, %v; want config_path read", r, err)
	}
	for name, tail := range map[string]string{
		"trailing comma in an inline table":     " audit = { a = \"b\", }\n",
		"newline in an inline table":            " audit = { a = \"b\",\n c = \"d\" }\n",
		"newline before an inline table closes": " audit = { a = \"b\"\n }\n",
	} {
		if r, err := ReadContainerdConfig([]byte(registry + tail)); err == nil {
			t.Errorf("%s: read %+v; containerd refuses to load this file", name, r)
		}
		home := t.TempDir()
		dir := filepath.Join(home, "etc/containerd")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "extra.toml"), []byte(registry+tail), 0o644); err != nil {
			t.Fatal(err)
		}
		if r, err := ResolveContainerdConfig(home, "/etc/containerd/config.toml", []byte("version = 2\nimports = [\"extra.toml\"]\n")); err == nil {
			t.Errorf("%s in an imported file: read %+v; containerd refuses to load it", name, r)
		}
	}
}

// TestContainerdHostsFileLoadsAsContainerd holds ParseContainerdHostsFile to
// what containerd v2.2.0's ConfigureHosts answered for each of these files:
// the endpoints it resolved in order, or that it discarded the file. The
// TOML 1.1 cases are ones the go-toml release the module graph resolves
// accepts and the v2.2.4 containerd parses with rejects. A host
// written as an inline table or a dotted key is one containerd never lists,
// because it orders hosts by their table headers.
func TestContainerdHostsFileLoadsAsContainerd(t *testing.T) {
	const host = "[host.\"https://bodega.internal:8443\"]\n"
	const bodega = "https://bodega.internal:8443/v2"
	for _, tc := range []struct {
		name, body string
		// want is the endpoints in order, the top-level server last and ""
		// where the file names none; nil is a file containerd discards.
		want []string
	}{
		{"control", "server = \"https://registry-1.docker.io\"\n" + host + " capabilities = [\"pull\", \"resolve\"]\n skip_verify = false\n", []string{bodega, "https://registry-1.docker.io/v2"}},
		{"skip_verify array", host + " skip_verify = [\"x\"]\n", nil},
		{"skip_verify string at the top level", "skip_verify = \"no\"\n" + host, nil},
		{"ca integer", host + " ca = 3\n", nil},
		{"ca date", host + " ca = 1979-05-27\n", nil},
		{"ca mixed list", host + " ca = [\"a\", 3]\n", nil},
		{"ca list", host + " ca = [\"a\", \"/b\"]\n", []string{bodega, ""}},
		{"ca twice", host + " ca = \"a\"\n ca = \"b\"\n", nil},
		{"client pair", host + " client = [[\"a\", \"b\"]]\n", []string{bodega, ""}},
		{"client short pair", host + " client = [[\"a\"]]\n", nil},
		{"client integer", host + " client = 5\n", nil},
		{"client integer list", host + " client = [5]\n", nil},
		{"capability case", host + " capabilities = [\"Pull\"]\n", []string{bodega, ""}},
		{"capability unknown", host + " capabilities = [\"bogus\"]\n", nil},
		{"capabilities string", host + " capabilities = \"pull\"\n", nil},
		{"capabilities empty", host + " capabilities = []\n", []string{bodega, ""}},
		{"header integer", host + " [host.\"https://bodega.internal:8443\".header]\n x = 5\n", nil},
		{"header mixed list", host + " [host.\"https://bodega.internal:8443\".header]\n x = [\"a\", 1]\n", nil},
		{"header list", host + " [host.\"https://bodega.internal:8443\".header]\n x = [\"a\", \"b\"]\n", []string{bodega, ""}},
		{"header string", host + " header = \"x\"\n", nil},
		{"override_path string", host + " override_path = \"yes\"\n", nil},
		{"dial_timeout unparsable", host + " dial_timeout = \"abc\"\n", nil},
		{"dial_timeout integer", host + " dial_timeout = 5\n", nil},
		{"dial_timeout", host + " dial_timeout = \"5s\"\n", []string{bodega, ""}},
		{"server integer", "server = 5\n" + host, nil},
		{"server unparsable", "server = \"http://%zz\"\n" + host, nil},
		{"host unparsable", "[host.\"http://%zz\"]\n", nil},
		{"host a string", "host = \"x\"\n", nil},
		{"syntax", host + " ca = \n", nil},
		{"unknown keys", "foo = 1\n" + host + " bar = [1]\n", []string{bodega, ""}},
		{"host without a scheme", "[host.\"bodega.internal:8443\"]\n", []string{bodega, ""}},
		{"host with a path", "[host.\"https://bodega.internal:8443/a/b/\"]\n", []string{"https://bodega.internal:8443/a/b/v2", ""}},
		{"host with an overridden path", "[host.\"https://bodega.internal:8443/a/b/\"]\n override_path = true\n", []string{"https://bodega.internal:8443/a/b", ""}},
		{"host reopened", "[host.\"https://a\"]\n[host.\"https://b\"]\n[host.\"https://a\".header]\n x = \"1\"\n", []string{"https://a/v2", "https://b/v2", "https://a/v2", ""}},
		{"host as an inline table", "host = { \"https://bodega.internal:8443\" = { capabilities = [\"pull\"] } }\n", []string{""}},
		{"TOML 1.1 trailing comma in an inline table", host + " header = { X-Audit = \"value\", }\n", nil},
		{"TOML 1.1 newline in an inline table", host + " header = { X-Audit = \"value\",\n X-Other = \"value\" }\n", nil},
		{"TOML 1.1 newline before an inline table closes", host + " header = { X-Audit = \"value\"\n }\n", nil},
		{"inline table header", host + " header = { X-Audit = \"value\" }\n", []string{bodega, ""}},
		{"host as a dotted key", "host.\"https://bodega.internal:8443\".capabilities = [\"pull\"]\n", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseContainerdHostsFile("/etc/containerd/certs.d/docker.io", []byte(tc.body))
			if tc.want == nil {
				if err == nil {
					t.Fatalf("loaded %+v; containerd discards this file", f.Hosts)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused (%v); containerd loads this file", err)
			}
			var got []string
			for _, h := range f.Hosts {
				endpoint := ""
				if h.Host != "" {
					endpoint = h.Scheme + "://" + h.Host + h.Path
				}
				got = append(got, endpoint)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("endpoints = %q, want %q", got, tc.want)
			}
			if last := f.Hosts[len(f.Hosts)-1]; !last.Server {
				t.Errorf("the last entry is %+v, not the top-level server", last)
			}
		})
	}
	f, err := ParseContainerdHostsFile("/etc/containerd/certs.d/docker.io", []byte(host+" ca = [\"a\", \"/b\"]\n capabilities = [\"resolve\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h := f.Hosts[0]; !slices.Equal(h.CA, []string{"/etc/containerd/certs.d/docker.io/a", "/b"}) || h.Pull {
		t.Errorf("host = %+v; want ca resolved against the file's directory and no pull", h)
	}
}

// TestContainerdConfigLoadsAsContainerdDoes holds the config.toml reader to
// what containerd v2.2.0's config.LoadConfig answered for each of these
// files, run from a scratch module against that release: it decodes the
// whole server configuration with its field types, a key it does not know is
// a warning, and a plugin named without its URI past version 1 is refused
// once the files have merged.
func TestContainerdConfigLoadsAsContainerdDoes(t *testing.T) {
	for _, c := range []struct {
		name, body string
		loads      bool
	}{
		{"valid", "version = 2\nroot = \"/var/lib/containerd\"\n[grpc]\n  uid = 0\n[timeouts]\n  \"io.containerd.timeout.shim.cleanup\" = \"5s\"\n", true},
		{"unknown key", "version = 2\nnot_a_key = 17\n[grpc]\n  nope = true\n", true},
		{"root", "version = 2\nroot = 17\n", false},
		{"disabled_plugins", "version = 2\ndisabled_plugins = 17\n", false},
		{"grpc uid", "version = 2\n[grpc]\n  uid = \"0\"\n", false},
		{"timeouts", "version = 2\n[timeouts]\n  a = 5\n", false},
		{"proxy_plugins", "version = 2\n[proxy_plugins.x]\n  capabilities = \"pull\"\n", false},
		{"stream_processors", "version = 2\n[stream_processors.x]\n  args = [1]\n", false},
		{"metrics", "version = 2\n[metrics]\n  grpc_histogram = \"yes\"\n", false},
		{"imports", "version = 2\nimports = \"a.toml\"\n", false},
		{"plugins", "version = 2\nplugins = 17\n", false},
		{"oom_score", "version = 2\noom_score = 1.5\n", false},
		{"version string", "version = \"2\"\n", false},
		{"version 4", "version = 4\n", false},
		{"v2 short disabled", "version = 2\ndisabled_plugins = [\"cri\"]\n", false},
		{"v2 short required", "version = 2\nrequired_plugins = [\"cri\"]\n", false},
		{"v1 short disabled", "disabled_plugins = [\"cri\"]\n", true},
		{"v3 full disabled", "version = 3\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n", true},
	} {
		eff, err := ResolveContainerdConfig(t.TempDir(), ContainerdConfigPath, []byte(c.body))
		if loads := err == nil && eff.Invalid == ""; loads != c.loads {
			t.Errorf("%s: loads = %v (err %v, invalid %q), containerd says %v", c.name, loads, err, eff.Invalid, c.loads)
		}
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc/containerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/containerd/extra.toml"), []byte("version = 2\nstate = 17\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveContainerdConfig(dir, ContainerdConfigPath, []byte("version = 2\nimports = [\"extra.toml\"]\n")); err == nil || !strings.Contains(err.Error(), "extra.toml") {
		t.Errorf("an import with a wrong field type = %v, want an error naming it", err)
	}
}

// TestDockerDaemonLoadsAsDockerdDoes holds the daemon.json loader to moby
// v28.5.2's MergeDaemonConfigurations and Validate, read from that release's
// source: dockerd does not build on the hosts these tests run on, so the
// answers are the source's rather than a run's.
func TestDockerDaemonLoadsAsDockerdDoes(t *testing.T) {
	for _, c := range []struct {
		name, body string
		loads      bool
	}{
		{"empty", "", true},
		{"whitespace", " \n", true},
		{"empty object", "{}", true},
		{"utf-8 bom", "\xef\xbb\xbf{\"debug\":true}", true},
		{"utf-16le bom", "\xff\xfe{\x00}\x00", true},
		{"usual keys", `{"registry-mirrors":["https://bodega.internal"],"insecure-registries":["bodega.internal:8080"],"log-driver":"json-file","log-opts":{"max-size":"10m"},"live-restore":true,"default-ulimits":{"nofile":{"Name":"nofile","Hard":64000,"Soft":64000}},"runtimes":{"x":{"path":"/usr/bin/x"}},"default-address-pools":[{"base":"172.30.0.0/16","size":24}],"default-shm-size":"64M","dns":["192.0.2.1"],"features":{"containerd-snapshotter":true},"builder":{"gc":{"enabled":true,"policy":[{"keepStorage":"10GB","filter":["unused-for=2200h"]}]}},"proxies":{"http-proxy":"http://proxy.internal:3128"},"exec-opts":["native.cgroupdriver=systemd"],"hosts":["unix:///var/run/docker.sock","tcp://127.0.0.1:2376","fd://"]}`, true},
		{"deprecated key dockerd skips", `{"deprecated-key-path":"/x"}`, true},
		{"flag spelling of a tag dockerd never reads", `{"containerd-plugins-namespace":"x"}`, true},

		{"not json", "{", false},
		{"not an object", "[]", false},
		{"invalid utf-8", "{\"labels\":[\"a=\xff\"]}", false},
		{"log-driver type", `{"log-driver":17}`, false},
		{"registry-mirrors type", `{"registry-mirrors":"https://bodega.internal"}`, false},
		{"debug type", `{"debug":"yes"}`, false},
		{"dns address", `{"dns":["not-an-ip"]}`, false},
		{"shm size bare number", `{"default-shm-size":67108864}`, false},
		{"address pool base", `{"default-address-pools":[{"base":"172.30.0.0","size":24}]}`, false},
		{"builder gc policy type", `{"builder":{"gc":{"policy":"all"}}}`, false},
		{"proxies member type", `{"proxies":{"http-proxy":17}}`, false},
		{"unknown key", `{"registry-mirror":["https://bodega.internal"],"regsitry-mirrors":[]}`, false},
		{"unknown key in a group", `{"proxies":{"socks-proxy":"x"}}`, false},
		{"tag with no flag", `{"swarm-raft-heartbeat-tick":1}`, false},
		{"tag spelling dockerd has no flag for", `{"containerd-plugin-namespace":"x"}`, false},
		{"both host gateway keys", `{"host-gateway-ip":"192.0.2.1","host-gateway-ips":["192.0.2.1"]}`, false},
		{"log level", `{"log-level":"loud"}`, false},
		{"log format", `{"log-format":"xml"}`, false},
		{"mirror without scheme", `{"registry-mirrors":["bodega.internal"]}`, false},
		{"mirror with credentials", `{"registry-mirrors":["https://u:p@bodega.internal"]}`, false},
		{"label without =", `{"labels":["a"]}`, false},
		{"conflicting labels", `{"labels":["a=1","a=2"]}`, false},
		{"host proto", `{"hosts":["ssh://x"]}`, false},
		{"exec-opt", `{"exec-opts":["isolation=hyperv"]}`, false},
		{"ipc mode", `{"default-ipc-mode":"host"}`, false},
		{"cgroupns mode", `{"default-cgroupns-mode":"shared"}`, false},
		{"fixed-cidr-v6", `{"fixed-cidr-v6":"10.0.0.0/8"}`, false},
		{"negative mtu", `{"mtu":-1}`, false},
		{"api-cors-header", `{"api-cors-header":"*"}`, false},
		{"generic resource", `{"node-generic-resources":["gpu"]}`, false},
	} {
		d, err := ParseDockerDaemonFile([]byte(c.body))
		if (err == nil) != c.loads {
			t.Errorf("%s: err = %v, dockerd loads it = %v", c.name, err, c.loads)
		}
		if c.name == "usual keys" && (d == nil || len(d.Mirrors) != 1 || d.Mirrors[0] != "https://bodega.internal" || len(d.InsecureRegistries) != 1) {
			t.Errorf("%s: read %+v", c.name, d)
		}
	}
}

// A daemon.json dockerd refuses over a key the plan never sets is not merged
// into, and one it loads keeps that key.
func TestMergeDockerDaemonRefusesWhatDockerdRefuses(t *testing.T) {
	planned := DockerDaemon("https://bodega.internal", nil).Content
	if out, err := MergeDockerDaemon([]byte(`{"log-driver":17}`), []byte(planned)); err == nil || !strings.Contains(err.Error(), "log-driver") && !strings.Contains(err.Error(), "Type") {
		t.Errorf("merge into a file dockerd refuses = %q, %v; want a refusal naming the field", out, err)
	}
	out, err := MergeDockerDaemon([]byte(`{"log-driver":"journald"}`), []byte(planned))
	if err != nil || !strings.Contains(string(out), `"log-driver": "journald"`) || !strings.Contains(string(out), "bodega.internal") {
		t.Errorf("merge into a file dockerd loads = %q, %v", out, err)
	}
}

// F116 R1, R2: the CRI plugins' checks run on what config.toml and its
// imports add up to, as containerd v2.2.0 validates the merged configuration,
// whether or not an import matched a file and whichever file holds each key.
func TestContainerdValidatesWhatItsImportsAddUpTo(t *testing.T) {
	const registry = "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
	const runtime = "[plugins.\"io.containerd.cri.v1.runtime\".containerd"
	for name, tc := range map[string]struct {
		main    string
		imports map[string]string
		invalid string
	}{
		"no import, default runtime": {main: "version = 3\n" + registry},
		"pattern matching nothing still validates": {
			main:    "version = 3\nimports = [\"conf.d/*.toml\"]\n" + runtime + "]\ndefault_runtime_name = \"missing\"\n" + registry,
			invalid: "no corresponding runtime configured",
		},
		"the runtime the main file names is in an import": {
			main:    "version = 3\nimports = [\"conf.d/*.toml\"]\n" + runtime + "]\ndefault_runtime_name = \"nvidia\"\n" + registry,
			imports: map[string]string{"conf.d/nvidia.toml": "version = 3\n" + runtime + ".runtimes.nvidia]\nruntime_type = \"io.containerd.runc.v2\"\n"},
		},
		"an import names a runtime no file configures": {
			main:    "version = 3\nimports = [\"conf.d/*.toml\"]\n" + registry,
			imports: map[string]string{"conf.d/default.toml": "version = 3\n" + runtime + "]\ndefault_runtime_name = \"kata\"\n"},
			invalid: "no corresponding runtime configured",
		},
		"an import empties the name": {
			main:    "version = 3\nimports = [\"conf.d/*.toml\"]\n" + registry,
			imports: map[string]string{"conf.d/default.toml": "version = 3\n" + runtime + "]\ndefault_runtime_name = \"\"\n"},
			invalid: "`default_runtime_name` is empty",
		},
		"a nested import completes a runtime's fields": {
			main: "version = 3\nimports = [\"a.toml\"]\n" + runtime + ".runtimes.runc]\nprivileged_without_host_devices_all_devices_allowed = true\n" + registry,
			imports: map[string]string{
				"a.toml": "version = 3\nimports = [\"b.toml\"]\n",
				"b.toml": "version = 3\n" + runtime + ".runtimes.runc]\nprivileged_without_host_devices = true\n",
			},
		},
		"the fields stay incomplete across imports": {
			main:    "version = 3\nimports = [\"a.toml\"]\n" + runtime + ".runtimes.runc]\nprivileged_without_host_devices_all_devices_allowed = true\n" + registry,
			imports: map[string]string{"a.toml": "version = 3\n"},
			invalid: "requires `privileged_without_host_devices`",
		},
		"a version 2 table split over two files": {
			main:    "version = 2\nimports = [\"a.toml\"]\n[plugins.\"io.containerd.grpc.v1.cri\".containerd]\ndefault_runtime_name = \"nvidia\"\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n",
			imports: map[string]string{"a.toml": "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.nvidia]\nruntime_type = \"io.containerd.runc.v2\"\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"},
		},
		"an import disables what the main file requires": {
			main:    "version = 3\nimports = [\"a.toml\"]\nrequired_plugins = [\"io.containerd.internal.v1.opt\"]\n" + registry,
			imports: map[string]string{"a.toml": "version = 3\ndisabled_plugins = [\"io.containerd.internal.v1.opt\"]\n"},
			invalid: "required plugin io.containerd.internal.v1.opt not included",
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range tc.imports {
				file := filepath.Join(root, "etc/containerd", rel)
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			eff, err := ResolveContainerdConfig(root, ContainerdConfigPath, []byte(tc.main))
			if err != nil {
				t.Fatalf("ResolveContainerdConfig: %v", err)
			}
			if tc.invalid == "" && eff.Invalid != "" || tc.invalid != "" && !strings.Contains(eff.Invalid, tc.invalid) {
				t.Errorf("Invalid = %q; want one holding %q", eff.Invalid, tc.invalid)
			}
		})
	}
}

// F116 R1, R2: a disabled plugin is read for what it does to the CRI
// service at containerd v2.2.0, and one doctor does not follow is never
// read as harmless.
func TestContainerdDisabledPluginsAreNeverAssumedHarmless(t *testing.T) {
	for _, tc := range []struct {
		conf        string
		criDisabled bool
		invalid     string
	}{
		{conf: "disabled_plugins = [\"cri\"]\n", criDisabled: true},
		{conf: "version = 2\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n", criDisabled: true},
		{conf: "version = 3\ndisabled_plugins = [\"io.containerd.cri.v1.images\"]\n", criDisabled: true},
		{conf: "version = 3\ndisabled_plugins = [\"io.containerd.cri.v1.runtime\"]\n", invalid: "unable to load CRI runtime service plugin dependency"},
		{conf: "version = 3\ndisabled_plugins = [\"io.containerd.snapshotter.v1.overlayfs\"]\n", invalid: "a type containerd's CRI service requires"},
		{conf: "version = 3\ndisabled_plugins = [\"io.containerd.metadata.v1.bolt\"]\n", invalid: "a type containerd's CRI service requires"},
		{conf: "version = 3\ndisabled_plugins = [\"com.example.unknown.v1.thing\"]\n", invalid: "a type containerd's CRI service requires"},
		{conf: "disabled_plugins = [\"bolt\"]\n", invalid: "io.containerd.metadata.v1.bolt"},
		{conf: "disabled_plugins = [\"restart\", \"opt\", \"otlp\", \"introspection\"]\n"},
		{conf: "version = 3\ndisabled_plugins = [\"io.containerd.internal.v1.opt\", \"io.containerd.tracing.processor.v1.otlp\", \"io.containerd.grpc.v1.healthcheck\"]\n"},
		{conf: "version = 3\ndisabled_plugins = [\"io.containerd.internal.v1.opt\"]\nrequired_plugins = [\"io.containerd.internal.v1.opt\"]\n", invalid: "required plugin io.containerd.internal.v1.opt not included"},
	} {
		r, err := ReadContainerdConfig([]byte(tc.conf))
		if err != nil {
			t.Fatalf("%q: %v", tc.conf, err)
		}
		if r.CRIDisabled != tc.criDisabled || tc.invalid == "" && r.Invalid != "" || tc.invalid != "" && !strings.Contains(r.Invalid, tc.invalid) {
			t.Errorf("%q: CRIDisabled = %v, Invalid = %q; want %v and one holding %q", tc.conf, r.CRIDisabled, r.Invalid, tc.criDisabled, tc.invalid)
		}
	}
}

const containerdDefaultFixture = "testdata/containerd-v2.2.0-config-default.toml"

// F116 R1, R2: refusing what containerd cannot start on must not refuse a
// stock host. The fixture is what `containerd config default` prints from the
// v2.2.0 linux/arm64 release, and every plugin table in it is one the port
// decodes rather than passes over.
func TestContainerdConfigDefaultIsAccepted(t *testing.T) {
	data, err := os.ReadFile(containerdDefaultFixture)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := ResolveContainerdConfig(t.TempDir(), ContainerdConfigPath, data)
	if err != nil || eff.Invalid != "" || eff.CRIDisabled {
		t.Fatalf("refused the default config.toml: err=%v invalid=%q criDisabled=%v", err, eff.Invalid, eff.CRIDisabled)
	}
	if want := "/etc/containerd/certs.d:/etc/docker/certs.d"; eff.ConfigPath != want {
		t.Errorf("config_path = %q, want %q", eff.ConfigPath, want)
	}
	cfg, err := decodeContainerdConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	tables := 0
	for name := range cfg.Plugins {
		table, registered := containerdPlugins[name]
		if !registered {
			t.Errorf("the default config.toml holds [plugins.%q], which the port does not list as registered", name)
		}
		if table != nil {
			tables++
		}
	}
	// Every plugin that registers a Config prints its table in the default.
	for name, table := range containerdPlugins {
		if _, printed := cfg.Plugins[name]; table != nil && !printed {
			t.Errorf("the port decodes a table for %s, which the default config.toml does not hold", name)
		}
	}
	if tables != 23 {
		t.Errorf("the default config.toml holds %d tables the port decodes outside the CRI plugins, want 23", tables)
	}
}

// F116 R1, R2: the bound on what the port certifies is the whole composed
// document, not the tables some check happens to read. The stock config.toml
// with one key moved off its default, in each top-level section in turn, is
// refused by name unless containerdModeled lists that key: a listener
// address on a port that would bind is refused exactly as one that would not.
func TestContainerdDefaultWithOneUnlistedKeyIsRefused(t *testing.T) {
	stock, err := os.ReadFile(containerdDefaultFixture)
	if err != nil {
		t.Fatal(err)
	}
	const overlayfs = "[plugins.'io.containerd.snapshotter.v1.overlayfs']\n    root_path = "
	for _, tc := range []struct {
		name, old, new, imported string
		invalid                  string
	}{
		{name: "root", old: "root = '/var/lib/containerd'", new: "root = '/srv/containerd'", invalid: "config.toml sets root "},
		{name: "state", old: "state = '/run/containerd'", new: "state = '/srv/run'", invalid: "config.toml sets state "},
		{name: "temp", old: "temp = ''", new: "temp = '/srv/tmp'", invalid: "config.toml sets temp "},
		{name: "oom_score", old: "oom_score = 0", new: "oom_score = -999", invalid: "config.toml sets oom_score "},
		{name: "grpc", old: "[grpc]\n  address = '/run/containerd/containerd.sock'", new: "[grpc]\n  address = '/srv/run/containerd.sock'", invalid: "[grpc] sets address "},
		{name: "grpc tcp listener", old: "tcp_address = ''", new: "tcp_address = '127.0.0.1:5000'", invalid: "[grpc] sets tcp_address "},
		{name: "grpc message size", old: "max_recv_message_size = 16777216", new: "max_recv_message_size = 1024", invalid: "[grpc] sets max_recv_message_size "},
		{name: "ttrpc", old: "[ttrpc]\n  address = ''", new: "[ttrpc]\n  address = '/run/containerd/other.ttrpc'", invalid: "[ttrpc] sets address "},
		{name: "debug", old: "[debug]\n  address = ''", new: "[debug]\n  address = '/run/containerd/debug.sock'", invalid: "[debug] sets address "},
		{name: "metrics", old: "[metrics]\n  address = ''", new: "[metrics]\n  address = '127.0.0.1:1338'", invalid: "[metrics] sets address "},
		{name: "metrics histogram", old: "grpc_histogram = false", new: "grpc_histogram = true", invalid: "[metrics] sets grpc_histogram "},
		{name: "cgroup", old: "[cgroup]\n  path = ''", new: "[cgroup]\n  path = '/containerd'", invalid: "[cgroup] sets path "},
		{name: "timeouts", old: "'io.containerd.timeout.shim.load' = '5s'", new: "'io.containerd.timeout.shim.load' = '30s'", invalid: "[timeouts] sets io.containerd.timeout.shim.load "},
		{name: "timeouts key nothing registers", old: "[timeouts]\n", new: "[timeouts]\n  'io.containerd.timeout.other' = '5s'\n", invalid: "[timeouts] sets io.containerd.timeout.other "},
		{name: "stream_processors", old: "returns = 'application/vnd.oci.image.layer.v1.tar'\n    path = 'ctd-decoder'", new: "returns = 'application/vnd.oci.image.layer.v1.tar'\n    path = '/srv/decoder'", invalid: "[stream_processors] sets io.containerd.ocicrypt.decoder.v1.tar.path "},
		{name: "stream_processors entry", old: "[stream_processors]\n", new: "[stream_processors]\n  [stream_processors.other]\n", invalid: "[stream_processors] sets other "},
		{name: "proxy_plugins", old: "[cgroup]\n", new: "[proxy_plugins.stargz]\n  type = 'snapshot'\n  address = '/run/stargz.sock'\n  platform = 'linux/amd64'\n\n[cgroup]\n", invalid: "[proxy_plugins] sets stargz.platform "},
		{name: "plugins", old: overlayfs + "''", new: overlayfs + "'/srv/overlay'", invalid: "[plugins.\"io.containerd.snapshotter.v1.overlayfs\"] sets root_path "},
		{name: "plugins, a CRI table", old: "stream_server_port = '0'", new: "stream_server_port = '10010'", invalid: "[plugins.\"io.containerd.grpc.v1.cri\"] sets stream_server_port "},
		{name: "an import", imported: "version = 3\n[debug]\naddress = '/run/containerd/debug.sock'\n", invalid: "[debug] sets address "},

		{name: "a default spelled another way", old: "'io.containerd.timeout.cri.defercleanup' = '1m0s'", new: "'io.containerd.timeout.cri.defercleanup' = '60s'"},
		{name: "a listed key", old: "level = ''", new: "level = 'debug'"},
		{name: "a default an import spells out", imported: "version = 3\nroot = '/var/lib/containerd'\n[grpc]\ntcp_address = ''\nuid = 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(string(stock), tc.old) != 1 && tc.old != "" {
				t.Fatalf("the default config.toml holds %q %d times, want once", tc.old, strings.Count(string(stock), tc.old))
			}
			conf := string(stock)
			if tc.old != "" {
				conf = strings.Replace(conf, tc.old, tc.new, 1)
			}
			root := t.TempDir()
			if tc.imported != "" {
				// The stock imports list is /etc/containerd/conf.d/*.toml.
				file := filepath.Join(root, "etc/containerd/conf.d/10-site.toml")
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(tc.imported), 0600); err != nil {
					t.Fatal(err)
				}
			}
			eff, err := ResolveContainerdConfig(root, ContainerdConfigPath, []byte(conf))
			if err != nil {
				t.Fatal(err)
			}
			if tc.invalid == "" && eff.Invalid != "" {
				t.Errorf("refused a configuration that holds containerd's defaults or a key the port follows: %s", eff.Invalid)
			}
			if tc.invalid != "" && !strings.Contains(eff.Invalid, tc.invalid) {
				t.Errorf("Invalid = %q, want it to name %q", eff.Invalid, tc.invalid)
			}
		})
	}
}

// F116 R1, R2: containerd v2.2.0's New decodes the table of every plugin it
// registers and exits on a wrong type in any of them, so the port holds every
// one to its types: each field of each table, given a value of another type,
// is refused, and the same table under a disabled plugin is not.
func TestContainerdEveryPluginTableIsTyped(t *testing.T) {
	const registry = "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
	resolve := func(t *testing.T, conf string) ContainerdEffective {
		t.Helper()
		eff, err := ResolveContainerdConfig("", filepath.Join(t.TempDir(), "config.toml"), []byte(conf))
		if err != nil {
			t.Fatalf("%v\n%s", err, conf)
		}
		return eff
	}
	for name, table := range containerdPlugins {
		if table == nil {
			continue
		}
		typ := reflect.TypeOf(table()).Elem()
		wrong := []string{"plugins.\"" + name + "\" = 42\n"}
		for i := range typ.NumField() {
			f := typ.Field(i)
			value := "42"
			if k := f.Type.Kind(); k == reflect.Int || k == reflect.Float64 || k == reflect.Bool {
				value = "\"x\""
			}
			wrong = append(wrong, "[plugins.\""+name+"\"]\n"+f.Tag.Get("toml")+" = "+value+"\n")
		}
		for _, w := range wrong {
			if eff := resolve(t, "version = 3\n"+w+registry); eff.Invalid == "" {
				t.Errorf("accepted a table containerd does not start on:\n%s", w)
			}
			if eff := resolve(t, "version = 3\ndisabled_plugins = [\""+name+"\"]\n"+w+registry); strings.Contains(eff.Invalid, "does not decode its table") {
				t.Errorf("refused the table of a disabled plugin, which containerd never decodes: %s\n%s", eff.Invalid, w)
			}
		}
	}
}

// F116 R1, R2: the rest of what New reads before it serves anything, on the
// composed configuration. No containerd runs here: the cases are the errors
// and panics of cmd/containerd/server/server.go at v2.2.0.
func TestContainerdStartupChecks(t *testing.T) {
	const registry = "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
	for _, tc := range []struct {
		name, conf, imported string
		invalid              string
	}{
		{name: "no required plugin", conf: "version = 3\nrequired_plugins = []\n"},
		{name: "the CRI plugin required", conf: "version = 3\nrequired_plugins = [\"io.containerd.grpc.v1.cri\", \"io.containerd.cri.v1.images\"]\n"},
		{name: "a required plugin nothing registers", conf: "version = 3\nrequired_plugins = [\"io.containerd.audit.v1.missing\"]\n", invalid: "not included"},
		{name: "a required plugin an import names", conf: "version = 3\nimports = [\"extra.toml\"]\n", imported: "version = 3\nrequired_plugins = [\"io.containerd.audit.v1.missing\"]\n", invalid: "not included"},
		{name: "a required plugin under its version 2 name", conf: "version = 2\nrequired_plugins = [\"io.containerd.monitor.v1.cgroups\"]\n", invalid: "not included"},
		{name: "a required plugin whose start depends on the host", conf: "version = 3\nrequired_plugins = [\"io.containerd.snapshotter.v1.btrfs\"]\n", invalid: "doctor does not follow"},
		{name: "a required proxy plugin", conf: "version = 3\nrequired_plugins = [\"io.containerd.snapshotter.v1.stargz\"]\n[proxy_plugins.stargz]\ntype = \"snapshot\"\naddress = \"/run/stargz.sock\"\n", invalid: "doctor does not follow"},
		{name: "a proxy plugin", conf: "version = 3\n[proxy_plugins.stargz]\ntype = \"snapshot\"\naddress = \"/run/stargz.sock\"\n"},
		{name: "a proxy plugin of no type", conf: "version = 3\n[proxy_plugins.stargz]\ntype = \"snapshots\"\n", invalid: "no type for plugin"},
		{name: "a proxy plugin under a registered name", conf: "version = 3\n[proxy_plugins.overlayfs]\ntype = \"snapshot\"\n", invalid: "already registered"},
		{name: "a timeout", conf: "version = 3\n[timeouts]\n\"io.containerd.timeout.shim.load\" = \"5s\"\n"},
		{name: "a timeout with no unit", conf: "version = 3\n[timeouts]\n\"io.containerd.timeout.shim.load\" = \"5\"\n", invalid: "unable to parse 5 into a time duration"},
		{name: "a timeout an import replaces", conf: "version = 3\nimports = [\"extra.toml\"]\n[timeouts]\n\"io.containerd.timeout.shim.load\" = \"5\"\n", imported: "version = 3\n[timeouts]\n\"io.containerd.timeout.shim.load\" = \"5s\"\n"},
		{name: "a TLS pair for the TCP listener", conf: "version = 3\n[grpc]\ntcp_tls_cert = \"/etc/containerd/tls.crt\"\ntcp_tls_key = \"/etc/containerd/tls.key\"\n", invalid: "[grpc] sets tcp_tls_cert"},
		{name: "a table no plugin decodes", conf: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.stargz\"]\nroot_path = 42\n"},
		{name: "version 2 names", conf: "version = 2\n[plugins.\"io.containerd.monitor.v1.cgroups\"]\nno_prometheus = false\n[plugins.\"io.containerd.internal.v1.restart\"]\ninterval = \"10s\"\n[plugins.\"io.containerd.runtime.v2.task\"]\nplatforms = [\"linux/amd64\"]\nsched_core = false\n[plugins.\"io.containerd.runtime.v1.linux\"]\nshim = 42\n"},
		{name: "a version 2 table the cgroups plugin takes", conf: "version = 2\n[plugins.\"io.containerd.monitor.v1.cgroups\"]\nno_prometheus = \"no\"\n", invalid: "io.containerd.monitor.task.v1.cgroups does not decode its table"},
		{name: "a version 1 table the restart plugin takes", conf: "[plugins.restart]\ninterval = 10\n", invalid: "io.containerd.monitor.container.v1.restart does not decode its table"},
		{name: "a duration with no unit", conf: "version = 3\n[plugins.\"io.containerd.gc.v1.scheduler\"]\nschedule_delay = \"100\"\n", invalid: "io.containerd.gc.v1.scheduler does not decode its table"},
		{name: "a wrong type in an import", conf: "version = 3\nimports = [\"extra.toml\"]\n", imported: "version = 3\n[plugins.\"io.containerd.metadata.v1.bolt\"]\ncontent_sharing_policy = 42\n", invalid: "io.containerd.metadata.v1.bolt does not decode its table"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.imported != "" {
				if err := os.WriteFile(filepath.Join(dir, "extra.toml"), []byte(tc.imported), 0600); err != nil {
					t.Fatal(err)
				}
			}
			table := registry
			if !strings.Contains(tc.conf, "version = ") {
				table = "[plugins.cri.registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
			} else if strings.Contains(tc.conf, "version = 2") {
				table = "[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
			}
			eff, err := ResolveContainerdConfig("", filepath.Join(dir, "config.toml"), []byte(tc.conf+table))
			if err != nil {
				t.Fatal(err)
			}
			if tc.invalid == "" && eff.Invalid != "" {
				t.Errorf("refused a configuration containerd starts on: %s", eff.Invalid)
			}
			if tc.invalid != "" && !strings.Contains(eff.Invalid, tc.invalid) {
				t.Errorf("Invalid = %q, want it to name %q", eff.Invalid, tc.invalid)
			}
		})
	}
}

// A table that decodes is not one its plugin starts on. These are the values
// containerd v2.2.0's command and the plugins its CRI service starts through
// refuse after the decode, each beside a value of the same key they accept.
// No containerd runs here: the cases are the errors of
// cmd/containerd/command/main.go and each plugin's InitFn at that version.
func TestContainerdInitChecks(t *testing.T) {
	const (
		registry  = "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
		images    = "[plugins.\"io.containerd.cri.v1.images\"]\n"
		bolt      = "[plugins.\"io.containerd.metadata.v1.bolt\"]\n"
		transfer  = "[[plugins.\"io.containerd.transfer.v1.local\".unpack_config]]\n"
		devmapper = "[plugins.\"io.containerd.snapshotter.v1.devmapper\"]\n"
		stargz    = "[proxy_plugins.stargz]\ntype = \"snapshot\"\naddress = \"/run/stargz.sock\"\n"
	)
	for _, tc := range []struct {
		name, conf, imported string
		invalid              string
	}{
		{name: "a log level in upper case", conf: "version = 3\n[debug]\nlevel = \"WARNING\"\nformat = \"json\"\n"},
		{name: "an unknown log level", conf: "version = 3\n[debug]\nlevel = \"verbose\"\n", invalid: "not a valid logrus Level"},
		{name: "an unknown log level in an import", conf: "version = 3\nimports = [\"extra.toml\"]\n", imported: "version = 3\n[debug]\nlevel = \"verbose\"\n", invalid: "not a valid logrus Level"},
		{name: "an unknown log format", conf: "version = 3\n[debug]\nformat = \"logfmt\"\n", invalid: "unknown log format"},
		{name: "root and state apart", conf: "version = 3\nroot = \"/srv/containerd\"\nstate = \"/run/containerd\"\n", invalid: "config.toml sets root"},
		{name: "root and state the same", conf: "version = 3\nroot = \"/srv/containerd\"\nstate = \"/srv/containerd\"\n", invalid: "root and state must be different paths"},
		{name: "root at the default state", conf: "version = 3\nroot = \"/run/containerd\"\n", invalid: "root and state must be different paths"},

		{name: "the isolated policy", conf: "version = 3\n" + bolt + "content_sharing_policy = \"isolated\"\n"},
		{name: "an empty policy", conf: "version = 3\n" + bolt + "content_sharing_policy = \"\"\n"},
		{name: "an unknown policy", conf: "version = 3\n" + bolt + "content_sharing_policy = \"private\"\n", invalid: "unknown policy: private"},
		{name: "an unknown policy an import replaces", conf: "version = 3\nimports = [\"extra.toml\"]\n" + bolt + "content_sharing_policy = \"private\"\n", imported: "version = 3\n" + bolt + "content_sharing_policy = \"shared\"\n"},
		{name: "an unknown policy under its version 1 name", conf: "[plugins.bolt]\ncontent_sharing_policy = \"private\"\n", invalid: "unknown policy: private"},
		{name: "an unknown policy of a disabled plugin", conf: "version = 3\ndisabled_plugins = [\"io.containerd.metadata.v1.bolt\"]\n" + bolt + "content_sharing_policy = \"private\"\n", invalid: "doctor does not follow"},

		{name: "a built-in snapshotter", conf: "version = 3\n" + images + "snapshotter = \"native\"\n"},
		{name: "a proxy snapshotter", conf: "version = 3\n" + stargz + images + "snapshotter = \"stargz\"\n"},
		{name: "a snapshotter nothing provides", conf: "version = 3\n" + images + "snapshotter = \"stargz\"\n", invalid: "failed to find snapshotter \"stargz\""},
		{name: "an empty snapshotter", conf: "version = 3\n" + images + "snapshotter = \"\"\n", invalid: "failed to find snapshotter \"\""},
		{name: "a proxy of another type", conf: "version = 3\n[proxy_plugins.stargz]\ntype = \"diff\"\n" + images + "snapshotter = \"stargz\"\n", invalid: "failed to find snapshotter \"stargz\""},
		{name: "a proxy snapshotter an import declares", conf: "version = 3\nimports = [\"extra.toml\"]\n" + images + "snapshotter = \"stargz\"\n", imported: "version = 3\n" + stargz},
		{name: "a version 2 snapshotter nothing provides", conf: "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd]\nsnapshotter = \"stargz\"\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\nruntime_type = \"io.containerd.runc.v2\"\n", invalid: "failed to find snapshotter \"stargz\""},
		{name: "a runtime platform", conf: "version = 3\n" + images + "[plugins.\"io.containerd.cri.v1.images\".runtime_platforms.kata]\nplatform = \"linux/arm64/v8\"\nsnapshotter = \"anything\"\n"},
		{name: "a runtime platform with a wildcard", conf: "version = 3\n[plugins.\"io.containerd.cri.v1.images\".runtime_platforms.kata]\nplatform = \"linux/*\"\n", invalid: "wildcards not yet supported"},

		{name: "a task platform", conf: "version = 3\n[plugins.\"io.containerd.runtime.v2.task\"]\nplatforms = [\"linux/amd64\", \"arm64\"]\n"},
		{name: "a task platform nothing knows", conf: "version = 3\n[plugins.\"io.containerd.runtime.v2.task\"]\nplatforms = [\"linux/amd64\", \"beos\"]\n", invalid: "invalid platform beos"},
		{name: "a differ order", conf: "version = 3\n[proxy_plugins.zstd]\ntype = \"diff\"\n[plugins.\"io.containerd.service.v1.diff-service\"]\ndefault = [\"zstd\", \"walking\"]\n"},
		{name: "a differ order naming one the host may skip", conf: "version = 3\n[plugins.\"io.containerd.service.v1.diff-service\"]\ndefault = [\"erofs\", \"walking\"]\n", invalid: "mkfs.erofs is installed and has a tar mode, which depends on this host"},
		{name: "a differ order naming none", conf: "version = 3\n[plugins.\"io.containerd.service.v1.diff-service\"]\ndefault = [\"walking\", \"zstd\"]\n", invalid: "needed differ not loaded: zstd"},
		{name: "an unpack configuration", conf: "version = 3\n" + stargz + transfer + "platform = \"linux/amd64\"\nsnapshotter = \"stargz\"\ndiffer = \"walking\"\n"},
		{name: "an unpack platform that does not parse", conf: "version = 3\n" + transfer + "platform = \"\"\nsnapshotter = \"overlayfs\"\n", invalid: "platform configuration  invalid"},
		{name: "an unpack snapshotter nothing provides", conf: "version = 3\n" + transfer + "platform = \"linux\"\nsnapshotter = \"stargz\"\n", invalid: "snapshotter \"stargz\" not found"},
		{name: "an unpack differ nothing provides", conf: "version = 3\n" + transfer + "platform = \"linux\"\nsnapshotter = \"overlayfs\"\ndiffer = \"zstd\"\n", invalid: "failed to get instance for diff plugin \"zstd\""},
		{name: "an unpack configuration an import replaces", conf: "version = 3\nimports = [\"extra.toml\"]\n" + transfer + "platform = \"linux\"\nsnapshotter = \"stargz\"\n", imported: "version = 3\n" + transfer + "platform = \"linux\"\nsnapshotter = \"native\"\ndiffer = \"walking\"\n"},
		// With no differ named, containerd matches the entry's platform against
		// what each loaded diff plugin advertises on the host.
		{name: "an unpack configuration naming no differ", conf: "version = 3\n" + transfer + "platform = \"linux\"\nsnapshotter = \"native\"\n", invalid: "sets no differ"},
		{name: "an unpack configuration naming no differ in an import", conf: "version = 3\nimports = [\"extra.toml\"]\n", imported: "version = 3\n" + transfer + "platform = \"windows/amd64\"\nsnapshotter = \"native\"\n", invalid: "sets no differ"},
		// With no unpack_config at all the transfer plugin fills in the
		// default snapshotter and differ by name, and one set empty stays empty.
		{name: "the default unpack snapshotter disabled", conf: "version = 3\ndisabled_plugins = [\"io.containerd.snapshotter.v1.overlayfs\"]\n" + images + "snapshotter = \"native\"\n", invalid: "doctor does not follow whether the service starts without it"},
		{name: "the default unpack differ disabled", conf: "version = 3\ndisabled_plugins = [\"io.containerd.differ.v1.walking\"]\n[plugins.\"io.containerd.service.v1.diff-service\"]\ndefault = []\n", invalid: "doctor does not follow whether the service starts without it"},
		{name: "an empty unpack configuration", conf: "version = 3\n" + images + "snapshotter = \"native\"\n[plugins.\"io.containerd.transfer.v1.local\"]\nunpack_config = []\n"},

		{name: "an unpack differ the host may skip", conf: "version = 3\n" + transfer + "platform = \"linux\"\nsnapshotter = \"overlayfs\"\ndiffer = \"erofs\"\n", invalid: "depends on this host"},
		{name: "an unpack snapshotter containerd skips", conf: "version = 3\n" + transfer + "platform = \"linux\"\nsnapshotter = \"devmapper\"\n", invalid: "snapshotter \"devmapper\" not found: containerd skips plugin"},

		// A registered plugin is not one that loaded: containerd skips
		// devmapper with no pool_name, and blockfile with nothing to make its
		// scratch file from, and a consumer naming either finds none. Where
		// the host decides the skip, doctor does not.
		{name: "devmapper selected with no pool", conf: "version = 3\n" + images + "snapshotter = \"devmapper\"\n", invalid: "failed to find snapshotter \"devmapper\": containerd skips plugin io.containerd.snapshotter.v1.devmapper while its table sets no pool_name"},
		{name: "devmapper selected with an empty pool", conf: "version = 3\n" + images + "snapshotter = \"devmapper\"\n" + devmapper + "pool_name = \"\"\nbase_image_size = \"10GB\"\n", invalid: "failed to find snapshotter \"devmapper\""},
		{name: "devmapper selected with a pool", conf: "version = 3\n" + images + "snapshotter = \"devmapper\"\n" + devmapper + "pool_name = \"containerd-pool\"\nbase_image_size = \"10GB\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.devmapper\"] sets pool_name"},
		{name: "devmapper selected with a pool an import sets", conf: "version = 3\nimports = [\"extra.toml\"]\n" + images + "snapshotter = \"devmapper\"\n", imported: "version = 3\n" + devmapper + "pool_name = \"containerd-pool\"\nbase_image_size = \"10GB\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.devmapper\"] sets pool_name"},
		{name: "a version 2 devmapper with no pool", conf: "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".containerd]\nsnapshotter = \"devmapper\"\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\nruntime_type = \"io.containerd.runc.v2\"\n", invalid: "failed to find snapshotter \"devmapper\""},
		{name: "blockfile selected with a scratch file", conf: "version = 3\n" + images + "snapshotter = \"blockfile\"\n[plugins.\"io.containerd.snapshotter.v1.blockfile\"]\nscratch_file = \"/opt/containerd/blockfile\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.blockfile\"] sets scratch_file"},
		{name: "blockfile selected with nothing to recreate from", conf: "version = 3\n" + images + "snapshotter = \"blockfile\"\n[plugins.\"io.containerd.snapshotter.v1.blockfile\"]\nrecreate_scratch = true\n", invalid: "containerd skips plugin io.containerd.snapshotter.v1.blockfile"},
		{name: "blockfile selected as registered", conf: "version = 3\n" + images + "snapshotter = \"blockfile\"\n", invalid: "a scratch file exists under the blockfile snapshotter's root, which depends on this host"},
		{name: "zfs selected", conf: "version = 3\n" + images + "snapshotter = \"zfs\"\n", invalid: "depends on this host"},
		{name: "btrfs selected", conf: "version = 3\n" + images + "snapshotter = \"btrfs\"\n", invalid: "depends on this host"},
		{name: "zfs configured and not selected", conf: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.zfs\"]\nroot_path = \"/tank/containerd\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.zfs\"] sets root_path"},

		// GetSingle needs exactly one plugin of the type; GetByType takes all.
		{name: "a second content store", conf: "version = 3\n[proxy_plugins.remote]\ntype = \"content\"\naddress = \"/run/content.sock\"\n", invalid: "multiple plugins registered for io.containerd.content.v1 (content, remote)"},
		{name: "a second content store an import declares", conf: "version = 3\nimports = [\"extra.toml\"]\n", imported: "version = 3\n[proxy_plugins.remote]\ntype = \"io.containerd.content.v1\"\n", invalid: "multiple plugins registered for io.containerd.content.v1"},
		{name: "proxies of the collected types", conf: "version = 3\n" + stargz + "[proxy_plugins.zstd]\ntype = \"diff\"\n[proxy_plugins.kata]\ntype = \"sandbox\"\n"},

		{name: "devmapper with no pool", conf: "version = 3\n" + devmapper + "fs_type = \"zfs\"\n"},
		{name: "devmapper configured", conf: "version = 3\n" + devmapper + "pool_name = \"containerd-pool\"\nbase_image_size = \"10GB\"\nfs_type = \"xfs\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.devmapper\"] sets pool_name"},
		{name: "devmapper with no image size", conf: "version = 3\n" + devmapper + "pool_name = \"containerd-pool\"\n", invalid: "failed to parse base image size"},
		{name: "devmapper with an unknown filesystem", conf: "version = 3\n" + devmapper + "pool_name = \"containerd-pool\"\nbase_image_size = \"10GB\"\nfs_type = \"zfs\"\n", invalid: "unsupported Filesystem Type"},
		{name: "an erofs default size", conf: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.erofs\"]\ndefault_size = \"64 MiB\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.erofs\"] sets default_size"},

		// Past the keys above, a table of a plugin the CRI service starts
		// through is certified only at the values containerd registers.
		{name: "registered values written out", conf: "version = 3\n[plugins.\"io.containerd.gc.v1.scheduler\"]\npause_threshold = 0.02\nmutation_threshold = 100\nstartup_delay = \"100ms\"\nschedule_delay = \"0ms\"\n[plugins.\"io.containerd.snapshotter.v1.overlayfs\"]\nroot_path = \"\"\nmount_options = []\n[plugins.\"io.containerd.transfer.v1.local\"]\nmax_concurrent_downloads = 3\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\nrequired_plugins = []\n"},
		{name: "a garbage collector threshold", conf: "version = 3\n[plugins.\"io.containerd.gc.v1.scheduler\"]\npause_threshold = 0.5\n", invalid: "[plugins.\"io.containerd.gc.v1.scheduler\"] sets pause_threshold"},
		{name: "an overlayfs mount option", conf: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.overlayfs\"]\nmount_options = [\"volatile\"]\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.overlayfs\"] sets mount_options"},
		{name: "an overlayfs root in an import", conf: "version = 3\nimports = [\"extra.toml\"]\n", imported: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.overlayfs\"]\nroot_path = \"/srv/overlay\"\n", invalid: "[plugins.\"io.containerd.snapshotter.v1.overlayfs\"] sets root_path"},
		{name: "an overlayfs root an import resets", conf: "version = 3\nimports = [\"extra.toml\"]\n[plugins.\"io.containerd.snapshotter.v1.overlayfs\"]\nroot_path = \"/srv/overlay\"\n", imported: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.overlayfs\"]\nroot_path = \"\"\n"},
		{name: "a transfer registry path", conf: "version = 3\n[plugins.\"io.containerd.transfer.v1.local\"]\nconfig_path = \"/etc/containerd/other.d\"\n", invalid: "[plugins.\"io.containerd.transfer.v1.local\"] sets config_path"},
		{name: "an image verifier directory", conf: "version = 3\n[plugins.\"io.containerd.image-verifier.v1.bindir\"]\nbin_dir = \"/srv/verifiers\"\n", invalid: "[plugins.\"io.containerd.image-verifier.v1.bindir\"] sets bin_dir"},
		{name: "an NRI validator", conf: "version = 3\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\nenable = true\n", invalid: "[plugins.\"io.containerd.nri.v1.nri\"] sets default_validator"},
		{name: "a version 2 cgroups table", conf: "version = 2\n[plugins.\"io.containerd.monitor.v1.cgroups\"]\nno_prometheus = true\n", invalid: "[plugins.\"io.containerd.monitor.task.v1.cgroups\"] sets no_prometheus"},
		{name: "a table of a plugin the CRI service does not start through", conf: "version = 3\n[plugins.\"io.containerd.internal.v1.opt\"]\npath = \"/srv/opt\"\n[plugins.\"io.containerd.monitor.container.v1.restart\"]\ninterval = \"30s\"\n"},
		{name: "an erofs default size with no number", conf: "version = 3\n[plugins.\"io.containerd.snapshotter.v1.erofs\"]\ndefault_size = \"large\"\n", invalid: "failed to parse default_size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.imported != "" {
				if err := os.WriteFile(filepath.Join(dir, "extra.toml"), []byte(tc.imported), 0600); err != nil {
					t.Fatal(err)
				}
			}
			table := registry
			if !strings.Contains(tc.conf, "version = ") {
				table = "[plugins.cri.registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
			} else if strings.Contains(tc.conf, "version = 2") {
				table = "[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
			}
			eff, err := ResolveContainerdConfig("", filepath.Join(dir, "config.toml"), []byte(tc.conf+table))
			if err != nil {
				t.Fatal(err)
			}
			if tc.invalid == "" && eff.Invalid != "" {
				t.Errorf("refused a configuration containerd starts on: %s", eff.Invalid)
			}
			if tc.invalid != "" && !strings.Contains(eff.Invalid, tc.invalid) {
				t.Errorf("Invalid = %q, want it to name %q", eff.Invalid, tc.invalid)
			}
		})
	}
}

// The two parsers the init checks port answer as their sources do: Parse in
// github.com/containerd/platforms v1.0.0-rc.2 and RAMInBytes in
// github.com/docker/go-units v0.5.0, for whether a value parses at all.
func TestContainerdPlatformAndSizeParsers(t *testing.T) {
	for spec, ok := range map[string]bool{
		"linux": true, "macOS": true, "windows(10.0.17763)": true, "arm64": true, "x86_64": true, "armhf": true,
		"linux/amd64": true, "anything/atall": true, "linux/arm/v7": true, "linux/arm64/v8": true,
		"": false, "beos": false, "linux/": false, "/amd64": false, "linux/amd64/v1/extra": false,
		"linux/*": false, "lin ux/amd64": false, "linux(10)(11)": false, "linux/amd64(1)": false,
	} {
		if err := containerdPlatformError(spec); (err == nil) != ok {
			t.Errorf("platform %q: error %v, want it to parse: %v", spec, err, ok)
		}
	}
	for size, ok := range map[string]bool{
		"10": true, "10b": true, "10k": true, "10KB": true, "10KiB": true, "1.5g": true, "10 GB": true, "32": true, ".5m": true, "10 ": true,
		"": false, "large": false, "10x": false, "10kk": false, "10kbb": false, "10bb": false, "-1g": false, "10kib2x": false, "1.2.3g": false, "g": false,
	} {
		if err := containerdRAMSizeError(size); (err == nil) != ok {
			t.Errorf("size %q: error %v, want it to parse: %v", size, err, ok)
		}
	}
}

// The CRI plugins' own tables answer to the same bound as the tables of the
// plugins they start through: a key startup acts on holds what containerd
// v2.2.0 registers, in whichever file and format version sets it, and a key
// the port follows may hold anything its validator passes.
func TestContainerdCRITablesHoldDefaultsOrFollowedValues(t *testing.T) {
	const (
		v3 = "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
		v2 = "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
	)
	for name, tc := range map[string]struct {
		main, imported string
		// refused is the key the reason names, "" when the file is accepted.
		refused string
	}{
		"registry only":            {main: v3},
		"registry only, version 2": {main: v2},
		"systemd cgroup and a second runtime": {main: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\nSystemdCgroup = true\n" +
			"[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.kata]\nruntime_type = \"io.containerd.kata.v2\"\nsandboxer = \"shim\"\n"},
		"followed scalars": {main: v3 + "[plugins.\"io.containerd.grpc.v1.cri\"]\ndisable_tcp_service = false\nstream_idle_timeout = \"1h\"\n" +
			"[plugins.\"io.containerd.cri.v1.runtime\"]\nenable_cdi = false\nenable_selinux = true\nmax_container_log_line_size = -1\n"},
		"version 2 names the stock directories": {main: v2 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nsandbox_image = \"registry.k8s.io/pause:3.8\"\nstream_server_port = \"0\"\n" +
			"[plugins.\"io.containerd.grpc.v1.cri\".cni]\nbin_dir = \"/opt/cni/bin\"\nconf_dir = \"/etc/cni/net.d\"\nmax_conf_num = 1\n"},

		"stream address":       {main: v3 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nstream_server_address = \"\"\n", refused: "stream_server_address"},
		"stream port":          {main: v3 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nstream_server_port = \"10010\"\n", refused: "stream_server_port"},
		"self-signed streams":  {main: v3 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nenable_tls_streaming = true\n", refused: "enable_tls_streaming"},
		"cni conf dir":         {main: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".cni]\nconf_dir = \"/nonexistent\"\n", refused: "cni.conf_dir"},
		"cni bin dirs emptied": {main: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".cni]\nbin_dirs = []\n", refused: "cni.bin_dirs"},
		"cdi spec dirs":        {main: v3 + "[plugins.\"io.containerd.cri.v1.runtime\"]\ncdi_spec_dirs = [\"/x\"]\n", refused: "cdi_spec_dirs"},
		"a runtime's cni conf dir": {main: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.kata]\nruntime_type = \"io.containerd.kata.v2\"\ncni_conf_dir = \"/x\"\n",
			refused: "containerd.runtimes.kata.cni_conf_dir"},
		"a runtime's snapshotter": {main: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc]\nsnapshotter = \"native\"\n",
			refused: "containerd.runtimes.runc.snapshotter"},
		// time.NewTicker panics on it in the snapshot syncer.
		"stats period of zero": {main: v3 + "[plugins.\"io.containerd.cri.v1.images\"]\nstats_collect_period = 0\n", refused: "stats_collect_period"},
		"local pull":           {main: v3 + "[plugins.\"io.containerd.cri.v1.images\"]\nuse_local_image_pull = true\n", refused: "use_local_image_pull"},

		"version 2 stream port":  {main: v2 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nstream_server_port = \"65536\"\n", refused: "stream_server_port"},
		"version 2 bin_dir":      {main: v2 + "[plugins.\"io.containerd.grpc.v1.cri\".cni]\nbin_dir = \"/usr/lib/cni\"\n", refused: "cni.bin_dirs"},
		"version 2 stats period": {main: v2 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nstats_collect_period = 0\n", refused: "stats_collect_period"},
		"version 2 snapshot annotations": {main: v2 + "[plugins.\"io.containerd.grpc.v1.cri\".containerd]\ndisable_snapshot_annotations = false\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\nruntime_type = \"io.containerd.runc.v2\"\n",
			refused: "disable_snapshot_annotations"},

		"an import sets the port": {main: "imports = [\"conf.d/*.toml\"]\n" + v3,
			imported: "version = 3\n[plugins.\"io.containerd.grpc.v1.cri\"]\nstream_server_port = \"65536\"\n", refused: "stream_server_port"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "config.toml")
			if tc.imported != "" {
				if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "conf.d", "10-cri.toml"), []byte(tc.imported), 0600); err != nil {
					t.Fatal(err)
				}
			}
			eff, err := ResolveContainerdConfig("", file, []byte(tc.main))
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.refused == "" && (eff.Invalid != "" || eff.ConfigPath != "/etc/containerd/certs.d"):
				t.Errorf("refused a configuration containerd v2.2.0 starts on: config_path=%q invalid=%q", eff.ConfigPath, eff.Invalid)
			case tc.refused != "" && !strings.Contains(eff.Invalid, "sets "+tc.refused+" to a value other than"):
				t.Errorf("want a refusal naming %s, got invalid=%q", tc.refused, eff.Invalid)
			}
		})
	}
}
