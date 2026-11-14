package host

import (
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

func TestReview42NativeGitHTTP(t *testing.T) {
	git := oracletest.Git(t)
	home := t.TempDir()
	wrong, _ := trustFixture(t)
	ca := filepath.Join(home, "roots.pem")
	writeTrustFile(t, ca, string(wrong))
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != "http" || r.Host != "bodega.internal:8443" || r.TLS != nil {
			t.Errorf("unexpected request: %v %s TLS=%v", r.URL, r.Host, r.TLS)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
	}))
	defer proxy.Close()
	writeTrustFile(t, filepath.Join(home, ".gitconfig"), "[url \"http://bodega.internal:8443/git/\"]\n insteadOf = https://original.invalid/\n[http]\n sslCAInfo = "+ca+"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, "ls-remote", "https://original.invalid/repo")
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "http_proxy=" + proxy.URL, "HTTP_PROXY=" + proxy.URL, "no_proxy=", "NO_PROXY="}
	out, err := cmd.CombinedOutput()
	t.Logf("HTTP with unrelated CA: requests=%d err=%v output=%s", requests.Load(), err, out)
	if requests.Load() == 0 || err != nil {
		t.Fatal("native Git did not exercise successful plaintext rewrite")
	}
}

func TestReview42NativeGitHTTPSControls(t *testing.T) {
	git := oracletest.Git(t)
	home := t.TempDir()
	ca := filepath.Join(home, "roots.pem")
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
	}))
	defer server.Close()
	wrong, _ := trustFixture(t)
	for _, right := range []bool{false, true} {
		cert := wrong
		if right {
			cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		}
		writeTrustFile(t, ca, string(cert))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, git, "-c", "http.sslCAInfo="+ca, "ls-remote", server.URL+"/repo")
		cmd.Dir = home
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"}
		out, err := cmd.CombinedOutput()
		cancel()
		t.Logf("HTTPS rightCA=%v requests=%d err=%v output=%s", right, requests.Load(), err, out)
		if !right && (err == nil || requests.Load() != 0 || !strings.Contains(strings.ToLower(string(out)), "certificate")) {
			t.Fatal("wrong-CA control did not reject")
		}
		if right && (err != nil || requests.Load() == 0) {
			t.Fatal("right-CA control did not succeed")
		}
	}
}

func TestReview42NativePipWildcardHTTP(t *testing.T) {
	python := oracletest.Pip(t)
	home := t.TempDir()
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != "http" || r.Host != "bodega.internal:8443" || r.TLS != nil {
			t.Errorf("unexpected request: %v %s TLS=%v", r.URL, r.Host, r.TLS)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer proxy.Close()
	wrong, _ := trustFixture(t)
	ca := filepath.Join(home, "unrelated.pem")
	writeTrustFile(t, ca, string(wrong))
	file := filepath.Join(home, "pip.conf")
	for _, wildcard := range []bool{false, true} {
		body := "[global]\nindex-url=http://bodega.internal:8443/pypi/simple/\ncert=" + ca + "\nretries=0\ntimeout=5\ndisable-pip-version-check=true\n"
		if wildcard {
			body += "trusted-host=*\n"
		}
		writeTrustFile(t, file, body)
		requests.Store(0)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, python, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--no-deps", "review42-no-such-package")
		cmd.Dir = home
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "PIP_CONFIG_FILE=" + file, "PIP_BREAK_SYSTEM_PACKAGES=true", "http_proxy=" + proxy.URL, "HTTP_PROXY=" + proxy.URL, "no_proxy=", "NO_PROXY="}
		out, err := cmd.CombinedOutput()
		cancel()
		t.Logf("wildcard=%v HTTP requests=%d err=%v output=%s", wildcard, requests.Load(), err, out)
		if wildcard && requests.Load() == 0 {
			t.Fatal("wildcard did not permit plaintext request")
		}
		if !wildcard && requests.Load() != 0 {
			t.Fatal("control used plaintext without trusted-host")
		}
	}
}
