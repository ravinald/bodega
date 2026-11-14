package host

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/oracletest"
)

func TestReviewF116HelmAliasRetainsTrustObligation(t *testing.T) {
	for _, alias := range []string{"https://BODEGA.internal:8443/helm", "https://bodega.internal:08443/helm"} {
		t.Run(alias, func(t *testing.T) {
			p, _, base := auditTrust(t)
			p.System = func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }
			writeTrustFile(t, filepath.Join(p.Home, ".config/helm/repositories.yaml"), "apiVersion: \"\"\nrepositories:\n- name: corp\n  url: "+alias+"\n")
			if v := auditState(t, p, "helm-repos", base); v.State != TrustFailed {
				t.Errorf("equivalent Helm endpoint lost its failed trust obligation: %+v", v)
			}
			rows := p.Apply(p.Rows(base), base)
			if len(rows) != 1 || rows[0].Status != StatusWarn || !strings.Contains(rows[0].Remediation, "--ca-file") {
				t.Errorf("ordinary report omits untrusted Helm endpoint: %+v", rows)
			}
		})
	}
}

func TestReviewF116HelmAliasCannotBorrowAnotherStore(t *testing.T) {
	p, ca, base := auditTrust(t)
	wrong, _ := trustFixture(t)
	wrongPath := filepath.Join(p.Root, "unrelated.pem")
	writeTrustFile(t, wrongPath, string(wrong))
	writeTrustFile(t, filepath.Join(p.Home, ".config/helm/repositories.yaml"), "apiVersion: \"\"\nrepositories:\n- name: exact\n  url: "+base+"/helm\n  caFile: "+ca+"\n- name: alias\n  url: https://BODEGA.internal:8443/helm\n  caFile: "+wrongPath+"\n")
	if v := auditState(t, p, "helm-repos", base); v.State != TrustFailed {
		t.Errorf("Helm alias with unrelated caFile borrowed exact entry's trust: %+v", v)
	}
	rows := p.Apply(p.Rows(base), base)
	if len(rows) != 1 || rows[0].Status != StatusWarn || !strings.Contains(rows[0].Detail, wrongPath) {
		t.Errorf("ordinary Helm row certifies the unused store: %+v", rows)
	}
}

func TestReviewF116ContainerdAliasCannotBorrowAnotherStore(t *testing.T) {
	p, ca, base := auditTrust(t)
	p.System = func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }
	wrong, _ := trustFixture(t)
	wrongPath := filepath.Join(p.Root, "unrelated.pem")
	writeTrustFile(t, wrongPath, string(wrong))
	writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/certs.d/docker.io/hosts.toml"), "server=\"https://registry-1.docker.io\"\n[host.\""+base+"\"]\nca=\""+ca+"\"\ncapabilities=[\"pull\",\"resolve\"]\n")
	writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/certs.d/ghcr.io/hosts.toml"), "server=\"https://ghcr.io\"\n[host.\"https://BODEGA.internal:8443/v2\"]\nca=\""+wrongPath+"\"\ncapabilities=[\"pull\",\"resolve\"]\n")
	if v := auditState(t, p, "oci-containerd", base); v.State != TrustFailed {
		t.Errorf("containerd alias with unrelated ca borrowed another registry's trust: %+v", v)
	}
	row := p.Apply([]Finding{{Check: "oci-containerd", Status: StatusOK}}, base)[0]
	if row.Status != StatusWarn || !strings.Contains(row.Remediation, "--ca-file") {
		t.Errorf("ordinary containerd row certifies unrelated CA: %+v", row)
	}
}

func TestReviewF116HelmAliasMatchesNativeTLS(t *testing.T) {
	helm := oracletest.Helm(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("apiVersion: v1\nentries: {}\n"))
	}))
	defer srv.Close()
	home := t.TempDir()
	ca, wrong := filepath.Join(home, "good.pem"), filepath.Join(home, "wrong.pem")
	writeTrustFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	wrongPEM, _ := trustFixture(t)
	writeTrustFile(t, wrong, string(wrongPEM))
	u, _ := url.Parse(srv.URL)
	alias := "https://" + u.Hostname() + ":0" + u.Port()
	file := filepath.Join(home, ".config/helm/repositories.yaml")
	writeTrustFile(t, file, "apiVersion: \"\"\nrepositories:\n- name: exact\n  url: "+srv.URL+"/helm\n  caFile: "+ca+"\n- name: alias\n  url: "+alias+"/helm\n  caFile: "+wrong+"\n")
	for _, name := range []string{"exact", "alias"} {
		native := exec.Command(helm, "repo", "update", name, "--repository-config", file)
		native.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
		out, err := native.CombinedOutput()
		t.Logf("native %s: err=%v output=%s", name, err, out)
		if name == "exact" && err != nil {
			t.Fatal("good CA control failed")
		}
		if name == "alias" && !strings.Contains(string(out), "certificate signed by unknown authority") {
			t.Fatal("alias did not exercise TLS rejection")
		}
	}
	p := TrustProbe{Root: home, Home: home, GOOS: "linux", Getenv: func(string) string { return "" }, System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }}
	if v := auditState(t, p, "helm-repos", srv.URL); v.State != TrustFailed {
		t.Errorf("native Helm rejects alias TLS but doctor certifies it: %+v", v)
	}
}
