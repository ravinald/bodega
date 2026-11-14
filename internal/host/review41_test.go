package host

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/oracletest"
)

type review41Policy struct {
	check string
	path  string
	plain string
	mixed string
}

func review41HTTPPolicy(t *testing.T, mixed bool) {
	t.Helper()
	const plain = "http://bodega.internal:8443"
	for _, tc := range []review41Policy{
		{"npm-config", "home/.npmrc", "registry=" + plain + "/npm/\ncafile=CA\n", "registry=BASE/npm/\ncafile=CA\n@plain:registry=" + plain + "/npm/\n"},
		{"git-config", "home/.gitconfig", "[url \"" + plain + "/git/\"]\n insteadOf=https://github.com/\n[http]\n sslCAInfo=CA\n", "[url \"BASE/git/\"]\n insteadOf=https://github.com/\n[url \"" + plain + "/git/\"]\n insteadOf=https://gitlab.com/\n[http]\n sslCAInfo=CA\n"},
		{"goproxy-env", "home/.config/go/env", "GOPROXY=" + plain + "/go\n", "GOPROXY=BASE/go," + plain + "/go\n"},
		{"helm-repos", "home/.config/helm/repositories.yaml", "repositories:\n- name: plain\n  url: " + plain + "/helm\n  caFile: CA\n", "repositories:\n- name: plain\n  url: " + plain + "/helm\n  caFile: CA\n- name: secure\n  url: BASE/helm\n  caFile: CA\n"},
		{"apt-sources", "etc/apt/sources.list.d/corp.sources", "Types: deb\nURIs: " + plain + "/apt\nSuites: stable\nComponents: main\n", "Types: deb\nURIs: BASE/apt " + plain + "/apt\nSuites: stable\nComponents: main\n"},
		{"oci-docker", "etc/docker/daemon.json", `{"registry-mirrors":["` + plain + `"]}`, `{"registry-mirrors":["BASE","` + plain + `"]}`},
		{"oci-containerd", "etc/containerd/certs.d/docker.io/hosts.toml", "server=\"https://registry-1.docker.io\"\n[host.\"" + plain + "\"]\ncapabilities=[\"pull\",\"resolve\"]\n", "server=\"https://registry-1.docker.io\"\n[host.\"" + plain + "\"]\ncapabilities=[\"pull\",\"resolve\"]\n[host.\"BASE\"]\nca=\"CA\"\ncapabilities=[\"pull\",\"resolve\"]\n"},
	} {
		t.Run(tc.check, func(t *testing.T) {
			p, ca, base := auditTrust(t)
			p.ConfigDir = func() (string, error) { return filepath.Join(p.Home, ".config"), nil }
			body := tc.plain
			if mixed {
				body = tc.mixed
			}
			writeTrustFile(t, filepath.Join(p.Root, tc.path), strings.NewReplacer("BASE", base, "CA", ca).Replace(body))
			if tc.check == "oci-containerd" {
				writeTrustFile(t, filepath.Join(p.Root, clientconf.ContainerdConfigPath), "version=3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path=\"/etc/containerd/certs.d\"\n")
			}
			v := auditState(t, p, tc.check, base)
			if v.State != TrustUnchecked {
				t.Errorf("plaintext endpoint was certified from a separate HTTPS chain: %+v", v)
			}
			rows := p.Apply([]Finding{{Check: tc.check, Status: StatusOK}}, base)
			if rows[0].Status != StatusWarn || !strings.Contains(rows[0].Detail, "unchecked") {
				t.Errorf("ordinary row omits plaintext trust bypass: %+v", rows[0])
			}
		})
	}
}

func TestReview41PlainHTTPIsNotVerified(t *testing.T)            { review41HTTPPolicy(t, false) }
func TestReview41PlainHTTPBesideHTTPSIsNotVerified(t *testing.T) { review41HTTPPolicy(t, true) }

func TestReview41NativeHelmHTTPDoesNotVerify(t *testing.T) {
	helm := oracletest.Helm(t)
	home := t.TempDir()
	var plainRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != "http" || r.Host != "bodega.internal:8443" || r.TLS != nil {
			t.Errorf("unexpected request: %s %s TLS=%v", r.URL, r.Host, r.TLS)
		}
		plainRequests.Add(1)
		_, _ = w.Write([]byte("apiVersion: v1\nentries: {}\n"))
	}))
	defer proxy.Close()
	wrong, _ := trustFixture(t)
	ca := filepath.Join(home, "unrelated.pem")
	writeTrustFile(t, ca, string(wrong))
	file := filepath.Join(home, "repositories.yaml")
	writeTrustFile(t, file, "repositories:\n- name: plain\n  url: http://bodega.internal:8443/helm\n  caFile: "+ca+"\n")
	native := exec.Command(helm, "repo", "update", "plain", "--repository-config", file)
	native.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "HTTP_PROXY=" + proxy.URL, "http_proxy=" + proxy.URL, "NO_PROXY=", "no_proxy="}
	out, err := native.CombinedOutput()
	t.Logf("native HTTP with unrelated CA: err=%v requests=%d output=%s", err, plainRequests.Load(), out)
	if err != nil || plainRequests.Load() != 1 {
		t.Fatal("native HTTP did not exercise the unverified plaintext request")
	}
	var secureRequests atomic.Int32
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secureRequests.Add(1)
		_, _ = w.Write([]byte("apiVersion: v1\nentries: {}\n"))
	}))
	defer secure.Close()
	for _, right := range []bool{false, true} {
		if right {
			writeTrustFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw})))
		}
		writeTrustFile(t, file, "repositories:\n- name: secure\n  url: "+secure.URL+"/helm\n  caFile: "+ca+"\n")
		native = exec.Command(helm, "repo", "update", "secure", "--repository-config", file)
		native.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
		out, err = native.CombinedOutput()
		t.Logf("native HTTPS rightCA=%v: err=%v requests=%d output=%s", right, err, secureRequests.Load(), out)
		if !right && (!strings.Contains(string(out), "certificate signed by unknown authority") || secureRequests.Load() != 0) {
			t.Fatal("wrong CA control did not fail certificate verification")
		}
		if right && (err != nil || secureRequests.Load() != 1) {
			t.Fatal("right CA control failed")
		}
	}
	// The ordinary and selected verdict use an actual private root and leaf,
	// for a non-loopback endpoint, rather than an unconditional verifier.
	p, ca, base := auditTrust(t)
	p.System = func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }
	writeTrustFile(t, filepath.Join(p.Home, ".config/helm/repositories.yaml"), "repositories:\n- name: plain\n  url: http://bodega.internal:8443/helm\n  caFile: "+ca+"\n")
	if v := auditState(t, p, "helm-repos", base); v.State != TrustUnchecked {
		t.Errorf("native HTTP uses no certificate; doctor certifies HTTPS roots: %+v", v)
	}
}
