package clientconf

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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
