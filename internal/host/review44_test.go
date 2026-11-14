package host

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/oracletest"
)

func TestReview44PipFindLinksHTTPIsUnchecked(t *testing.T) {
	p, ca, base := auditTrust(t)
	file := filepath.Join(p.Home, ".config/pip/pip.conf")
	before := "[global]\nindex-url=" + base + "/pypi/simple/\ncert=" + ca + "\n"
	writeTrustFile(t, file, before)
	if v := auditState(t, p, "pip-config", base); v.State != TrustVerified {
		t.Fatalf("HTTPS control: %+v", v)
	}
	link := strings.Replace(strings.Replace(base, "https://", "http://", 1), "bodega.internal", "bodega%2einternal", 1) + "/review43_demo-1.0-py3-none-any.whl"
	writeTrustFile(t, file, before+"find-links="+link+"\n")
	v := auditState(t, p, "pip-config", base)
	t.Logf("find-links=%s selected verdict=%+v", link, v)
	if v.State != TrustUnchecked || !strings.Contains(v.Detail, "find-links") {
		t.Errorf("a direct HTTP wheel must keep its own unchecked obligation: %+v", v)
	}
	row := p.Apply([]Finding{checkPipConfig(p.Root, p.GOOS, p.Home)}, base)[0]
	t.Logf("ordinary row=%+v", row)
	if row.Status != StatusWarn || !strings.Contains(row.Detail, "unchecked") || !strings.Contains(row.Detail, "find-links") {
		t.Errorf("the HTTP wheel borrowed the HTTPS index verdict: %+v", row)
	}
}

func TestReview44PipFindLinksAloneKeepsTrustObligation(t *testing.T) {
	p, ca, base := auditTrust(t)
	file := filepath.Join(p.Home, ".config/pip/pip.conf")
	writeTrustFile(t, file, "[global]\nindex-url=https://elsewhere.example/simple/\ncert="+ca+"\nfind-links="+strings.Replace(strings.Replace(base, "https://", "http://", 1), "bodega.internal", "bodega%2einternal", 1)+"/review43_demo-1.0-py3-none-any.whl\n")
	v := auditState(t, p, "pip-config", base)
	if v.State != TrustUnchecked || !strings.Contains(v.Detail, "find-links") {
		t.Errorf("find-links is a request to bodega even when the index is elsewhere: %+v", v)
	}
}

func TestReview44NativePipFindLinksHTTPAndTLSControls(t *testing.T) {
	python := oracletest.Pip(t)
	var wheel bytes.Buffer
	zw := zip.NewWriter(&wheel)
	for name, contents := range map[string]string{
		"review43_demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: review43-demo\nVersion: 1.0\n",
		"review43_demo-1.0.dist-info/WHEEL":    "Wheel-Version: 1.0\nGenerator: review\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		"review43_demo-1.0.dist-info/RECORD":   "",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var plaintext, encrypted atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "no TLS route in this fixture", 502)
			return
		}
		if r.Host != "bodega.internal:8443" || r.URL.Scheme != "http" || r.TLS != nil {
			t.Errorf("unexpected route: %s %s", r.Method, r.URL)
		}
		plaintext.Add(1)
		_, _ = w.Write(wheel.Bytes())
	}))
	defer proxy.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".whl") {
			encrypted.Add(1)
			_, _ = w.Write(wheel.Bytes())
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()
	wrong, _ := trustFixture(t)
	right := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	for _, kind := range []string{"http", "https-wrong-ca", "https-right-ca"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			ca, cfg := filepath.Join(home, "ca.pem"), filepath.Join(home, "pip.conf")
			cert, base := wrong, srv.URL
			if kind == "https-right-ca" {
				cert = right
			}
			writeTrustFile(t, ca, string(cert))
			env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "PIP_CONFIG_FILE=" + cfg, "PIP_BREAK_SYSTEM_PACKAGES=true"}
			if kind == "http" {
				base = "http://bodega.internal:8443"
				env = append(env, "http_proxy="+proxy.URL, "https_proxy="+proxy.URL, "no_proxy=", "NO_PROXY=")
			}
			index := base
			if kind == "http" {
				index = "https://bodega.internal:8443"
			}
			writeTrustFile(t, cfg, "[global]\nindex-url="+index+"/pypi/simple/\nfind-links="+strings.Replace(base, "bodega.internal", "bodega%2einternal", 1)+"/review43_demo-1.0-py3-none-any.whl\ncert="+ca+"\nretries=0\ntimeout=3\ndisable-pip-version-check=true\n")
			plaintext.Store(0)
			encrypted.Store(0)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--no-deps", "review43-demo")
			cmd.Dir, cmd.Env = home, env
			out, err := cmd.CombinedOutput()
			t.Logf("%s: plain=%d TLS=%d err=%v\n%s", kind, plaintext.Load(), encrypted.Load(), err, out)
			if kind == "https-wrong-ca" {
				if err == nil || encrypted.Load() != 0 || !strings.Contains(string(out), "ssl-verification-failed") {
					t.Fatal("wrong-CA TLS control did not reject")
				}
				return
			}
			if err != nil || !strings.Contains(string(out), "Would install review43-demo-1.0") {
				t.Fatal("native pip did not accept the wheel")
			}
			if kind == "http" && plaintext.Load() == 0 {
				t.Fatal("HTTP fixture made no plaintext request")
			}
			if kind == "https-right-ca" && encrypted.Load() == 0 {
				t.Fatal("right-CA control made no TLS request")
			}
		})
	}
}
