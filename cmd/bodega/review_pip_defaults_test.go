package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/oracletest"
)

type pipDefaultsAudit struct {
	base, defaults, explicit, config, home string
	chain                                  []*x509.Certificate //nolint:unused // kept as the reviewer supplied it; the fixture records the served chain.
}

func TestReviewPipExplicitCAKeepsNativeDefaultRoots(t *testing.T) {
	python := oracletest.Pip(t)
	home := t.TempDir()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("native TLS accepted"))
	}))
	defer server.Close()
	other := review42PlanServer(t, "pypi")
	f := pipDefaultsAudit{base: server.URL, defaults: filepath.Join(home, "defaults.pem"), explicit: filepath.Join(home, "explicit.pem"), config: filepath.Join(home, "pip.conf"), home: home}
	if err := os.WriteFile(f.defaults, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.explicit, other.pem, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                                             string
		legacy, explicitMatches, defaultsMatch, accepted bool
	}{
		{"default roots survive unrelated cert", false, false, true, true},
		{"legacy replaces defaults", true, false, true, false},
		{"legacy accepts explicit issuer", true, true, false, true},
		{"neither root matches", false, false, false, false},
	} {
		explicit, defaults := f.explicit, f.explicit
		if tc.explicitMatches {
			explicit = f.defaults
		}
		if tc.defaultsMatch {
			defaults = f.defaults
		}
		body := "[global]\nindex-url=" + f.base + "/simple/\ncert=" + explicit + "\nretries=0\ntimeout=3\ndisable-pip-version-check=true\n"
		if tc.legacy {
			body += "use-deprecated=legacy-certs\n"
		}
		if err := os.WriteFile(f.config, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, python, "-c", `
import sys
from pip._vendor import certifi
# Supply a temporary default bundle; the client and TLS implementation stay native.
certifi.where = lambda: sys.argv[2]
from pip._internal.commands import create_command
cmd = create_command("install")
options, _ = cmd.parse_args([])
assert options.cert == sys.argv[3], options.cert
try:
    with cmd._build_session(options) as session:
        response = session.get(sys.argv[1])
        response.raise_for_status()
        print(response.text)
except Exception as exc:
    print(type(exc).__name__ + ": " + str(exc))
    sys.exit(7)
`, f.base, defaults, explicit)
		cmd.Dir = home
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "PIP_CONFIG_FILE=" + f.config}
		out, err := cmd.CombinedOutput()
		cancel()
		t.Logf("%s: err=%v output=%s", tc.name, err, out)
		if tc.accepted && (err != nil || !strings.Contains(string(out), "native TLS accepted")) {
			t.Fatal("pip's default roots did not remain effective beside the explicit cert")
		}
		if !tc.accepted && (err == nil || !strings.Contains(string(out), "CERTIFICATE_VERIFY_FAILED") && !strings.Contains(string(out), "SSLVerificationError")) {
			t.Fatal("legacy replacement control did not reject the unrelated explicit CA")
		}
	}
}

func TestReviewPipExplicitCAReportKeepsKnownSystemTrust(t *testing.T) {
	f := review44PipSetup(t)
	other := review42PlanServer(t, "pypi")
	explicit := filepath.Join(f.home, "unrelated.pem")
	config := filepath.Join(f.home, ".config/pip/pip.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(explicit, other.pem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("[global]\nindex-url="+f.base+"/pypi/simple/\ncert="+explicit+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldProbe, oldExit := doctorTrustProbe, doctorExit
	ca, err := x509.ParseCertificate(mustPEMBlock(t, f.issuer))
	if err != nil {
		t.Fatal(err)
	}
	doctorTrustProbe = func() host.TrustProbe {
		p := oldProbe()
		p.System = func(chain []*x509.Certificate, name string) error {
			return host.VerifyServed(chain, name, []*x509.Certificate{ca})
		}
		p.Pip = func() (host.PipDefault, error) { return host.PipDefault{Version: "26.2.1", Truststore: true}, nil }
		return p
	}
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorTrustProbe, doctorExit = oldProbe, oldExit })
	out, err := runDoctor(t, "--url", f.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range strings.Split(out, "\n") {
		if !strings.HasPrefix(row, "pip-config ") {
			continue
		}
		t.Log(row)
		if strings.Contains(row, "WARN") || strings.Contains(row, "does not verify") {
			t.Errorf("pip verifies through the system store, but the ordinary row reports its explicit store as a failure: %s", row)
		}
		return
	}
	t.Fatal("ordinary doctor omitted pip-config")
}

func TestReviewPipExplicitCADoesNotProveDefaultRootsAbsent(t *testing.T) {
	f := review44PipSetup(t)
	other := review42PlanServer(t, "pypi")
	explicit := filepath.Join(f.home, "unrelated.pem")
	if err := os.WriteFile(explicit, other.pem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config, []byte("[global]\nindex-url="+f.base+"/pypi/simple/\ncert="+explicit+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	probe := doctorTrustProbe()
	ca, err := x509.ParseCertificate(mustPEMBlock(t, f.issuer))
	if err != nil {
		t.Fatal(err)
	}
	probe.System = func(chain []*x509.Certificate, name string) error {
		return host.VerifyServed(chain, name, []*x509.Certificate{ca})
	}
	verdicts, err := probe.Judge([]string{"pip-config"}, f.base)
	if err != nil || len(verdicts) != 1 {
		t.Fatalf("verdicts=%+v err=%v", verdicts, err)
	}
	t.Logf("unknown pip default policy: %+v", verdicts[0])
	if verdicts[0].State != host.TrustUnchecked {
		t.Errorf("with the pip default unknown and system roots valid, an unrelated explicit bundle cannot prove failure; want unchecked, got %+v", verdicts[0])
	}
}

func mustPEMBlock(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("missing PEM fixture")
	}
	return block.Bytes
}
