package host

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestReview42GitTransport(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			p, ca, base := auditTrust(t)
			p.LookupEnv = nil
			body := "[url \"" + strings.Replace(base, "https://", scheme+"://", 1) + "/git/\"]\n insteadOf=https://github.com/\n[http]\n sslCAInfo=" + ca + "\n"
			writeTrustFile(t, filepath.Join(p.Home, ".gitconfig"), body)
			v := auditState(t, p, "git-config", base)
			t.Logf("%s: %+v", body, v)
			if scheme == "http" && (v.State != TrustUnchecked || !strings.Contains(strings.ToLower(v.Detail), "http")) {
				t.Errorf("Git HTTP verified using HTTPS chain: %+v", v)
			}
			if scheme == "https" && v.State != TrustVerified {
				t.Fatalf("HTTPS control was not verified: %+v", v)
			}
		})
	}
}

func TestReview42PipWildcardPlaintext(t *testing.T) {
	p, ca, base := auditTrust(t)
	p.LookupEnv = nil
	body := "[global]\nindex-url=" + base + "/pypi/simple/\nextra-index-url=" + strings.Replace(base, "https://", "http://", 1) + "/plain/simple/\ntrusted-host=*\ncert=" + ca + "\n"
	writeTrustFile(t, filepath.Join(p.Home, ".config/pip/pip.conf"), body)
	v := auditState(t, p, "pip-config", base)
	t.Logf("%+v", v)
	if v.State != TrustUnchecked {
		t.Errorf("pip wildcard allows plaintext route: %+v", v)
	}
	rows := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)
	if rows[0].Status != StatusWarn {
		t.Errorf("ordinary row: %+v", rows[0])
	}
}

func TestReview42GitMixedTransport(t *testing.T) {
	p, ca, base := auditTrust(t)
	p.LookupEnv = nil
	plain := strings.Replace(base, "https://", "http://", 1)
	body := "[url \"" + base + "/git/\"]\n insteadOf=https://github.com/\n[url \"" + plain + "/git/\"]\n insteadOf=https://gitlab.com/\n[http]\n sslCAInfo=" + ca + "\n"
	writeTrustFile(t, filepath.Join(p.Home, ".gitconfig"), body)
	v := auditState(t, p, "git-config", base)
	if v.State != TrustUnchecked {
		t.Errorf("HTTP borrowed HTTPS verdict: %+v", v)
	}
}
