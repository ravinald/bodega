package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/manifest"
)

// ociPlanServer answers /client/plan with the oci records a server renders
// for base, each path rooted under the caller's home, and serves each file
// at the URL its record names.
func ociPlanServer(t *testing.T, base string) *httptest.Server {
	t.Helper()
	files := clientconf.OCIClient(base, map[string]string{"docker.io": "https://registry-1.docker.io", "ghcr.io": "https://ghcr.io"})
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		var plan clientconf.Plan
		for _, f := range files {
			sum := sha256.Sum256([]byte(f.Content))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "docker-host", Match: "cidr:192.0.2.1/32", System: manifest.TypeOCI, Action: clientconf.PlanInstall,
				Path: "~" + f.Path(clientconf.OSLinux), URL: srv.URL + "/client/oci?file=" + f.Key,
				SHA256: hex.EncodeToString(sum[:]), Reason: strings.Join(f.Notes, ". "),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	mux.HandleFunc("GET /client/oci", func(w http.ResponseWriter, r *http.Request) {
		for _, f := range files {
			if f.Key == r.URL.Query().Get("file") {
				_, _ = io.WriteString(w, f.Content)
			}
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// stubRuntimes puts exactly the named commands on doctor's PATH.
func stubRuntimes(t *testing.T, bins ...string) {
	t.Helper()
	prev := doctorLookPath
	doctorLookPath = func(name string) (string, error) {
		for _, b := range bins {
			if b == name {
				return "/usr/bin/" + name, nil
			}
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { doctorLookPath = prev })
}

// F99 R1, R3: a Docker host with containerd and no podman gets daemon.json
// merged into its own, the containerd files, no drop-in, and the restarts
// printed; a second apply changes nothing.
func TestDoctorConfigureOCIKeepsPresentRuntimes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t, "dockerd", "containerd")
	srv := ociPlanServer(t, "http://bodega.internal:8080")
	daemon := filepath.Join(home, "etc/docker/daemon.json")
	if err := os.MkdirAll(filepath.Dir(daemon), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(daemon, []byte(`{"log-driver":"journald"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runDoctor(t, "--configure", "oci", "--url", srv.URL, "--allow-plaintext")
	if err != nil || !strings.Contains(out, "covers Docker Hub only") || !strings.Contains(out, "insecure-registries gains bodega.internal:8080") {
		t.Fatalf("dry run = %v:\n%s", err, out)
	}
	if strings.Contains(out, "podman and buildah") || strings.Contains(out, "systemctl restart") {
		t.Errorf("the dry run named podman's file or a restart:\n%s", out)
	}

	out, err = runDoctor(t, "--configure", "oci", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	for _, want := range []string{"systemctl restart docker", "systemctl restart containerd"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply did not print %q:\n%s", want, out)
		}
	}
	got, _ := os.ReadFile(daemon)
	if !strings.Contains(string(got), `"log-driver": "journald"`) || !strings.Contains(string(got), `"http://bodega.internal:8080/"`) {
		t.Errorf("daemon.json after --apply = %s", got)
	}
	for _, p := range []string{"etc/containerd/certs.d/docker.io/hosts.toml", "etc/containerd/certs.d/ghcr.io/hosts.toml", "etc/containerd/config.toml"} {
		if _, err := os.Stat(filepath.Join(home, p)); err != nil {
			t.Errorf("%s was not written: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, clientconf.RegistriesConfDropIn)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the registries.conf drop-in was written on a host with no podman: %v", err)
	}

	out, err = runDoctor(t, "--configure", "oci", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil || !strings.Contains(out, "Nothing to change") || strings.Contains(out, "systemctl restart") {
		t.Errorf("second --apply = %v:\n%s", err, out)
	}
}

// F99 R1: oci named on a host with no runtime is refused, naming what doctor
// looked for.
func TestDoctorConfigureOCIRefusesWithNoRuntime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stubRuntimes(t)
	srv := ociPlanServer(t, "https://bodega.internal")
	_, err := runDoctor(t, "--configure", "oci", "--url", srv.URL, "--allow-plaintext")
	if err == nil || !strings.Contains(err.Error(), "dockerd, containerd, podman, buildah, crio") {
		t.Errorf("--configure oci with no runtime = %v, want a refusal naming the commands", err)
	}
}

// F99 R4: bare doctor names a Docker with no mirror, and the command that
// configures it; a runtime that is not installed gets no row.
func TestDoctorReportsDockerWithNoMirror(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, clientconf.DockerDaemonPath), []byte(`{"log-driver":"journald"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stubRuntimes(t, "dockerd")
	prevRoot, prevExit := doctorOCIRoot, doctorExit
	doctorOCIRoot, doctorExit = root, func(int) {}
	t.Cleanup(func() { doctorOCIRoot, doctorExit = prevRoot, prevExit })

	out, err := runDoctor(t, "--url", "https://bodega.internal")
	if err != nil {
		t.Fatalf("doctor = %v:\n%s", err, out)
	}
	var row string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "oci-docker") {
			row = line
		}
	}
	if !strings.Contains(row, "WARN") || !strings.Contains(row, "sets no registry-mirrors") {
		t.Errorf("oci-docker row = %q:\n%s", row, out)
	}
	if !strings.Contains(out, "bodega doctor --configure oci --apply") {
		t.Errorf("the remediation does not name --configure oci:\n%s", out)
	}
	if strings.Contains(out, "oci-containerd") || strings.Contains(out, "oci-podman") {
		t.Errorf("a runtime not on PATH got a row:\n%s", out)
	}
}
