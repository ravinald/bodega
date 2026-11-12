package host

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// trustFixture is a CA, and the chain a bodega at bodega.internal:8443
// serves under it.
func trustFixture(t *testing.T) (caPEM []byte, chain []*x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "internal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bodega.internal"}, DNSNames: []string{"bodega.internal"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), []*x509.Certificate{leaf}
}

func writeTrustFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// F116 R2: a row whose client is configured for bodega warns when no store
// that client reads verifies bodega's chain, naming the store and --ca-file;
// a client whose own store holds the CA does not, and neither does a row
// whose client is not pointed at bodega.
func TestTrustProbeWarnsNamingTheStore(t *testing.T) {
	const base, hostport = "https://bodega.internal:8443", "bodega.internal:8443"
	caPEM, chain := trustFixture(t)
	root, home := t.TempDir(), t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	writeTrustFile(t, ca, string(caPEM))

	// pip is configured and names no CA; npm is configured and names it.
	writeTrustFile(t, filepath.Join(root, "etc/pip.conf"), "[global]\nindex-url = "+base+"/pypi/simple/\n")
	writeTrustFile(t, filepath.Join(root, home, ".npmrc"), "registry="+base+"/npm/\ncafile="+ca+"\n")
	writeTrustFile(t, filepath.Join(home, ".cargo/config.toml"), "[source.bodega]\nregistry = \"sparse+"+base+"/cargo/\"\n")
	writeTrustFile(t, filepath.Join(root, "etc/apt/sources.list.d/other.sources"), "URIs: https://mirror.example/ubuntu\n")
	writeTrustFile(t, filepath.Join(root, "etc/docker/daemon.json"), `{"registry-mirrors":["`+base+`"]}`)
	writeTrustFile(t, filepath.Join(root, "etc/docker/certs.d", hostport, "ca.crt"), string(caPEM))
	// cargo and podman are configured for bodega with no CA either reads;
	// their rows are not this probe's to judge.
	writeTrustFile(t, filepath.Join(root, "etc/containers/registries.conf.d/bodega.conf"), "[[registry]]\nprefix = \"docker.io\"\n[[registry.mirror]]\nlocation = \""+hostport+"\"\n")
	writeTrustFile(t, filepath.Join(root, "etc/containerd/certs.d/docker.io/hosts.toml"),
		"server = \"https://registry-1.docker.io\"\n\n[host.\""+base+"\"]\n  ca = \""+ca+"\"\n  capabilities = [\"pull\", \"resolve\"]\n")

	var dialed []string
	untrusted := x509.UnknownAuthorityError{}
	probe := TrustProbe{
		Root: root, Home: home, GOOS: "linux",
		Getenv:    func(string) string { return "" },
		ConfigDir: func() (string, error) { return filepath.Join(home, ".config"), nil },
		Chain: func(hp string) ([]*x509.Certificate, error) {
			dialed = append(dialed, hp)
			return chain, nil
		},
		System: func([]*x509.Certificate, string) error { return untrusted },
	}
	rows := []Finding{
		{Check: "pip-config", Status: StatusOK, Detail: "no pip config references public PyPI"},
		{Check: "npm-config", Status: StatusOK},
		{Check: "cargo-config", Status: StatusOK},
		{Check: "apt-sources", Status: StatusOK},
		{Check: "oci-docker", Status: StatusOK},
		{Check: "oci-containerd", Status: StatusOK},
		{Check: "oci-podman", Status: StatusOK},
		{Check: "goproxy-env", Status: StatusWarn, Detail: "GOPROXY unset"},
		{Check: "snapd", Status: StatusOK},
	}
	got := map[string]Finding{}
	for _, f := range probe.Apply(rows, base) {
		got[f.Check] = f
	}
	for check, want := range map[string]struct{ store, system string }{
		"pip-config": {"the system trust store, which pip reads while no cert setting names a bundle, does not verify", "--configure pypi --ca-file"},
	} {
		f := got[check]
		if f.Status != StatusWarn || !strings.Contains(f.Detail, want.store) || !strings.Contains(f.Detail, hostport) || !strings.Contains(f.Remediation, want.system) {
			t.Errorf("%s = %s %q, remediation %q; want a warning naming %q and %q", check, f.Status, f.Detail, f.Remediation, want.store, want.system)
		}
	}
	for _, check := range []string{"npm-config", "oci-docker", "oci-containerd", "apt-sources", "snapd", "cargo-config", "oci-podman"} {
		if f := got[check]; f.Status != StatusOK {
			t.Errorf("%s = %s %q, want it left OK", check, f.Status, f.Detail)
		}
	}
	if f := got["goproxy-env"]; f.Detail != "GOPROXY unset" {
		t.Errorf("a row with its own finding was rewritten: %q", f.Detail)
	}
	if len(dialed) != 1 || dialed[0] != hostport {
		t.Errorf("dialed %v, want %s once", dialed, hostport)
	}

	// The system store verifying settles every row here: npm's cafile is
	// the right CA, and each other client reads the system store, pip
	// because it says it does. A pip that cannot be asked is unchecked, and
	// TestTrustProbeAsksNodeAndPipForTheirDefaults holds that it warns.
	probe.System = func([]*x509.Certificate, string) error { return nil }
	probe.Pip = func() (PipDefault, error) { return PipDefault{Version: "26.2", Truststore: true}, nil }
	for _, f := range probe.Apply(rows, base) {
		if f.Check != "goproxy-env" && f.Status != StatusOK {
			t.Errorf("%s = %s with the system store verifying: %s", f.Check, f.Status, f.Detail)
		}
	}

	// A server that does not answer, or a plaintext base, measures nothing.
	probe.System = func([]*x509.Certificate, string) error { return untrusted }
	probe.Chain = func(string) ([]*x509.Certificate, error) { return nil, errors.New("connection refused") }
	for _, f := range probe.Apply(rows, base) {
		if f.Check == "pip-config" && f.Status != StatusOK {
			t.Errorf("pip-config = %s with bodega unreachable, want the row as the check wrote it", f.Status)
		}
	}
	dialed = nil
	probe.Chain = func(hp string) ([]*x509.Certificate, error) { dialed = append(dialed, hp); return chain, nil }
	probe.Apply(rows, "http://bodega.internal:8443")
	probe.Apply([]Finding{{Check: "apt-sources", Status: StatusOK}}, base)
	if len(dialed) != 0 {
		t.Errorf("dialed %v for a plaintext base and for a host with no client configured", dialed)
	}
}

func reviewTrust(t *testing.T) (TrustProbe, string, string) {
	t.Helper()
	pem, chain := trustFixture(t)
	root := t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	writeTrustFile(t, ca, string(pem))
	return TrustProbe{Root: root, Home: "/home/test", GOOS: "linux", Getenv: func(string) string { return "" },
		Chain:  func(string) ([]*x509.Certificate, error) { return chain, nil },
		System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} },
	}, ca, "https://bodega.internal:8443"
}

func TestReviewNpmExplicitCAOverridesSystem(t *testing.T) {
	p, _, base := reviewTrust(t)
	other, _ := trustFixture(t)
	wrong := filepath.Join(p.Root, "wrong-ca.pem")
	writeTrustFile(t, wrong, string(other))
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile="+wrong+"\n")
	p.System = func([]*x509.Certificate, string) error { return nil }
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Remediation, "--ca-file") {
		t.Fatalf("npm with an unrelated explicit cafile: %+v; want WARN and --ca-file", f)
	}
}

func TestReviewTrustResolvesConfigPrecedence(t *testing.T) {
	for _, kind := range []string{"npm", "pip"} {
		t.Run(kind, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			other, _ := trustFixture(t)
			wrong := filepath.Join(p.Root, "wrong-ca.pem")
			writeTrustFile(t, wrong, string(other))
			if kind == "npm" {
				writeTrustFile(t, filepath.Join(p.Root, "etc/npmrc"), "cafile="+ca+"\n")
				writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile="+wrong+"\n")
			} else {
				writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\ncert="+ca+"\n")
				writeTrustFile(t, filepath.Join(p.Root, p.Home, ".config/pip/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\ncert="+wrong+"\n")
			}
			f := p.Apply([]Finding{{Check: kind + "-config", Status: StatusOK}}, base)[0]
			if f.Status != StatusWarn {
				t.Fatalf("%s user CA overrides trusted global CA: got %+v; want WARN", kind, f)
			}
		})
	}
}

func TestReviewContainerdChecksEachRegistry(t *testing.T) {
	p, ca, base := reviewTrust(t)
	for _, registry := range []string{"docker.io", "ghcr.io"} {
		body := "server = \"https://" + registry + "\"\n[host.\"" + base + "\"]\ncapabilities=[\"pull\",\"resolve\"]\n"
		if registry == "docker.io" {
			body += "ca = \"" + ca + "\"\n"
		}
		writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/certs.d", registry, "hosts.toml"), body)
	}
	f := p.Apply([]Finding{{Check: "oci-containerd", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn {
		t.Fatalf("ghcr.io has no trusted CA: got %+v; want WARN", f)
	}
}

func TestReviewContainerdAcceptsCAArray(t *testing.T) {
	p, ca, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/certs.d/docker.io/hosts.toml"),
		"server=\"https://registry-1.docker.io\"\n[host.\""+base+"\"]\nca=[\""+ca+"\"]\ncapabilities=[\"pull\",\"resolve\"]\n")
	f := p.Apply([]Finding{{Check: "oci-containerd", Status: StatusOK}}, base)[0]
	if f.Status != StatusOK {
		t.Fatalf("valid containerd CA array: got %+v; want OK", f)
	}
}

func TestReviewTrustFindsDarwinPip(t *testing.T) {
	p, _, base := reviewTrust(t)
	p.GOOS = "darwin"
	writeTrustFile(t, filepath.Join(p.Root, "Library/Application Support/pip/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\n")
	f := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn {
		t.Fatalf("configured macOS pip with untrusted CA: got %+v; want WARN", f)
	}
}

func TestReviewContainerdUsesEffectiveConfigPath(t *testing.T) {
	p, ca, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/config.toml"),
		"version=2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path=\"/srv/certs\"\n")
	writeTrustFile(t, filepath.Join(p.Root, "srv/certs/docker.io/hosts.toml"),
		"server=\"https://registry-1.docker.io\"\n[host.\""+base+"\"]\nca=\""+ca+"\"\ncapabilities=[\"pull\",\"resolve\"]\n")
	var rows []Finding
	for _, f := range (OCIHost{Root: p.Root, LookPath: onlyRuntime("containerd")}).Check(base) {
		if f.Check == "oci-containerd" {
			rows = append(rows, f)
		}
	}
	if len(rows) != 1 || rows[0].Status != StatusOK {
		t.Fatalf("fixture not configured: %+v", rows)
	}
	f := p.Apply(rows, base)[0]
	if f.Status != StatusOK {
		t.Fatalf("trusted CA in effective /srv/certs: got %+v; want OK", f)
	}
}

func TestReviewTrustChecksConfiguredWarnRow(t *testing.T) {
	p, _, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\n@legacy:registry=https://registry.npmjs.org/\n")
	before := checkNpmConfig(p.Root, p.GOOS, p.Home)
	if before.Status != StatusWarn {
		t.Fatalf("fixture has no prior warning: %+v", before)
	}
	f := p.Apply([]Finding{before}, base)[0]
	if !strings.Contains(f.Remediation, "--ca-file") {
		t.Fatalf("configured npm has two problems but CA is unchecked: %+v", f)
	}
}

func TestAuditNpmBundledRootsAreNotSystemStore(t *testing.T) {
	p, _, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\n")
	p.Getenv = func(k string) string {
		if k == "NODE_OPTIONS" {
			return "--use-bundled-ca"
		}
		return ""
	}
	p.System = func([]*x509.Certificate, string) error { return nil }
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Remediation, "--ca-file") {
		t.Fatalf("private CA only in system store, Node uses bundled roots: %+v; want WARN and --ca-file", f)
	}
}

func TestAuditPipUsesExplicitConfigFile(t *testing.T) {
	p, ca, base := reviewTrust(t)
	config := filepath.Join(p.Root, "custom-pip.conf")
	writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\ncert="+ca+"\n")
	writeTrustFile(t, config, "[global]\ncert=/missing/ca.pem\n")
	p.Getenv = func(k string) string {
		if k == "PIP_CONFIG_FILE" {
			return config
		}
		return ""
	}
	f := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "/missing/ca.pem") {
		t.Fatalf("PIP_CONFIG_FILE overrides global cert: %+v; want WARN naming /missing/ca.pem", f)
	}
}

func TestAuditNpmCAArrayRetainsAllRoots(t *testing.T) {
	p, ca, base := reviewTrust(t)
	trusted, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := trustFixture(t)
	escape := func(b []byte) string {
		return "\"" + strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", `\n`) + "\""
	}
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\nca[]="+escape(trusted)+"\nca[]="+escape(other)+"\n")
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusOK {
		t.Fatalf("valid first CA in npm's ca[] array: %+v; want OK", f)
	}
}

// F116 R2: with no CA setting, npm and pip are judged against what Node and
// pip say they read. The system store settles the row only where the client
// reads it, and a client that cannot be asked leaves the row saying so.
func TestTrustProbeAsksNodeAndPipForTheirDefaults(t *testing.T) {
	trusted := func([]*x509.Certificate, string) error { return nil }
	certifi := func(t *testing.T, p TrustProbe, pem string) string {
		path := filepath.Join(p.Root, "site-packages/pip/_vendor/certifi/cacert.pem")
		writeTrustFile(t, path, pem)
		return path
	}
	for _, tc := range []struct {
		name, check string
		set         func(t *testing.T, p *TrustProbe, ca string)
		status      Status
		detail      string
	}{
		{"node lists its defaults and they hold the CA", "npm-config", func(t *testing.T, p *TrustProbe, ca string) {
			p.Node = func() (NodeRoots, error) { return NodeRoots{PEM: []string{ca}, Effective: true}, nil }
		}, StatusOK, ""},
		{"node lists its defaults without the CA, system store trusts it", "npm-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
			p.Node = func() (NodeRoots, error) { return NodeRoots{Effective: true}, nil }
		}, StatusWarn, "the CA certificates Node trusts by default"},
		{"node built on OpenSSL's store", "npm-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
			p.Node = func() (NodeRoots, error) { return NodeRoots{OpenSSLDefault: true}, nil }
		}, StatusOK, ""},
		{"node cannot be asked, system store trusts it", "npm-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
			p.Node = func() (NodeRoots, error) { return NodeRoots{}, errors.New("no node on PATH") }
		}, StatusWarn, "no node on PATH"},
		{"NODE_EXTRA_CA_CERTS holds the CA beside the bundled roots", "npm-config", func(t *testing.T, p *TrustProbe, _ string) {
			extra := filepath.Join(p.Root, "ca.pem")
			p.Getenv = func(k string) string {
				return map[string]string{"NODE_OPTIONS": "--use-bundled-ca", "NODE_EXTRA_CA_CERTS": extra}[k]
			}
		}, StatusOK, ""},
		{"an old pip reads certifi, system store trusts it", "pip-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
			bundle := certifi(t, *p, "")
			p.Pip = func() (PipDefault, error) { return PipDefault{Version: "23.3", Certifi: bundle}, nil }
		}, StatusWarn, "the certifi bundle pip 23.3 reads"},
		{"a pip on truststore", "pip-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
			bundle := certifi(t, *p, "")
			p.Pip = func() (PipDefault, error) { return PipDefault{Version: "26.2", Truststore: true, Certifi: bundle}, nil }
		}, StatusOK, ""},
		{"a pip on truststore told to use certifi", "pip-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
			bundle := certifi(t, *p, "")
			p.Getenv = func(k string) string { return map[string]string{"PIP_USE_DEPRECATED": "legacy-certs"}[k] }
			p.Pip = func() (PipDefault, error) { return PipDefault{Version: "26.2", Truststore: true, Certifi: bundle}, nil }
		}, StatusWarn, "the certifi bundle"},
		{"pip cannot be asked, system store trusts it", "pip-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.System = trusted
		}, StatusWarn, "unchecked"},
		{"pip loads no file under PIP_CONFIG_FILE=/dev/null", "pip-config", func(t *testing.T, p *TrustProbe, _ string) {
			p.Getenv = func(k string) string { return map[string]string{"PIP_CONFIG_FILE": os.DevNull}[k] }
		}, StatusWarn, "PIP_CONFIG_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, caFile, base := reviewTrust(t)
			ca, err := os.ReadFile(caFile)
			if err != nil {
				t.Fatal(err)
			}
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\n")
			writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\n")
			tc.set(t, &p, string(ca))
			f := p.Apply([]Finding{{Check: tc.check, Status: StatusOK}}, base)[0]
			if f.Status != tc.status || !strings.Contains(f.Detail, tc.detail) || (tc.detail == "" && f.Detail != "") {
				t.Errorf("%s = %s %q; want %s naming %q", tc.check, f.Status, f.Detail, tc.status, tc.detail)
			}
		})
	}
}

// F116 R2: a client that verifies through the system store is judged against
// the file its own setting names instead, where it names one.
func TestTrustProbeReadsTheStoreAClientIsPointedAt(t *testing.T) {
	trusted := func([]*x509.Certificate, string) error { return nil }
	for _, tc := range []struct {
		name, check string
		// set configures the client for bodega with a CA setting naming
		// file, and returns the probe to judge it with.
		set func(t *testing.T, p *TrustProbe, base, file string)
	}{
		{"apt Acquire::https::CAInfo", "apt-sources", func(t *testing.T, p *TrustProbe, base, file string) {
			writeTrustFile(t, filepath.Join(p.Root, "etc/apt/sources.list.d/bodega.sources"), "URIs: "+base+"/apt/\n")
			writeTrustFile(t, filepath.Join(p.Root, "etc/apt/apt.conf.d/99ca"), "Acquire::https::CAInfo \""+file+"\";\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The named file holds the CA and the system store does not.
			p, ca, base := reviewTrust(t)
			tc.set(t, &p, base, ca)
			if f := p.Apply([]Finding{{Check: tc.check, Status: StatusOK}}, base)[0]; f.Status != StatusOK {
				t.Errorf("the file the setting names holds the CA: %s %q; want OK", f.Status, f.Detail)
			}
			// The named file lacks it and the system store holds it.
			p, _, base = reviewTrust(t)
			other, _ := trustFixture(t)
			wrong := filepath.Join(p.Root, "wrong.pem")
			writeTrustFile(t, wrong, string(other))
			tc.set(t, &p, base, wrong)
			p.System = trusted
			f := p.Apply([]Finding{{Check: tc.check, Status: StatusOK}}, base)[0]
			if f.Status != StatusWarn || !strings.Contains(f.Detail, wrong) {
				t.Errorf("the system store holds the CA and the named file does not: %s %q; want %s", f.Status, f.Detail, StatusWarn)
			}
		})
	}
}

// F116 R2: doctor runs neither node nor pip to learn its default store, so
// a client left on that default is unchecked whatever the system store
// says, and verified only through an input doctor reads.
func TestDefaultStoresNobodyAnswersForAreUnchecked(t *testing.T) {
	for check, tc := range map[string]struct {
		config, body, key string
	}{
		"npm-config": {".npmrc", "registry=BASE/npm/\n", "NODE_EXTRA_CA_CERTS"},
		"pip-config": {".config/pip/pip.conf", "[global]\nindex-url = BASE/pypi/simple/\n", "PIP_CERT"},
	} {
		p, ca, base := reviewTrust(t)
		p.Node, p.Pip = AskNode, AskPip
		p.System = func([]*x509.Certificate, string) error { return nil }
		writeTrustFile(t, filepath.Join(p.Root, p.Home, tc.config), strings.ReplaceAll(tc.body, "BASE", base))
		f := p.Apply([]Finding{{Check: check, Status: StatusOK}}, base)[0]
		if f.Status != StatusWarn || !strings.Contains(f.Detail, "unchecked") {
			t.Errorf("%s on its default store, the system store verifying: %s %q; want WARN unchecked", check, f.Status, f.Detail)
		}
		p.Getenv = func(k string) string {
			if k == tc.key {
				return ca
			}
			return ""
		}
		p.System = func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }
		if f := p.Apply([]Finding{{Check: check, Status: StatusOK}}, base)[0]; f.Status != StatusOK {
			t.Errorf("%s with %s naming the CA: %s %q; want OK", check, tc.key, f.Status, f.Detail)
		}
	}
}

func TestIndependentPipConfigSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, setting string
		want          Status
	}{
		{"colon", "cert: /missing/private-ca.pem\n", StatusWarn},
		{"continued-non-cert", "cert=CA_PATH\nfind-links =\n  cert=/missing/not-a-setting.pem\n", StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			setting := strings.ReplaceAll(tc.setting, "CA_PATH", ca)
			writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\n"+setting)
			if tc.want == StatusWarn {
				p.System = func([]*x509.Certificate, string) error { return nil }
			}
			f := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)[0]
			if f.Status != tc.want {
				t.Fatalf("pip reads %q: got %+v; want %s", setting, f, tc.want)
			}
		})
	}
}

func TestIndependentAptEffectiveCA(t *testing.T) {
	for _, mode := range []string{"later-file", "other-host", "comment"} {
		t.Run(mode, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			writeTrustFile(t, filepath.Join(p.Root, "etc/apt/sources.list.d/bodega.sources"), "URIs: "+base+"/apt/\n")
			dir := filepath.Join(p.Root, "etc/apt/apt.conf.d")
			switch mode {
			case "later-file":
				writeTrustFile(t, filepath.Join(dir, "10ca"), "Acquire::https::CAInfo \""+ca+"\";\n")
				writeTrustFile(t, filepath.Join(dir, "90ca"), "Acquire::https::CAInfo \"/missing/effective-ca.pem\";\n")
			case "other-host":
				writeTrustFile(t, filepath.Join(dir, "10ca"), "Acquire::https::unrelated.example::CAInfo \""+ca+"\";\n")
			case "comment":
				writeTrustFile(t, filepath.Join(dir, "10ca"), "// Acquire::https::CAInfo \""+ca+"\";\n")
			}
			f := p.Apply([]Finding{{Check: "apt-sources", Status: StatusOK}}, base)[0]
			if f.Status != StatusWarn || !strings.Contains(f.Remediation, "--ca-file") {
				t.Fatalf("apt %s: got %+v; want WARN", mode, f)
			}
		})
	}
}

func TestIndependentNpmSelectedUserConfig(t *testing.T) {
	p, ca, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile="+ca+"\n")
	selected := filepath.Join(p.Root, "selected.npmrc")
	other, _ := trustFixture(t)
	wrong := filepath.Join(p.Root, "effective-ca.pem")
	writeTrustFile(t, wrong, string(other))
	writeTrustFile(t, selected, "registry="+base+"/npm/\ncafile="+wrong+"\n")
	p.Getenv = func(k string) string {
		if k == "NPM_CONFIG_USERCONFIG" {
			return selected
		}
		return ""
	}
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, wrong) {
		t.Fatalf("npm selected userconfig: got %+v; want WARN naming effective-ca.pem", f)
	}
}

func TestIndependentNpmCAFileIsNotAUnion(t *testing.T) {
	p, ca, base := reviewTrust(t)
	trusted, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := trustFixture(t)
	wrong := filepath.Join(p.Root, "other.pem")
	writeTrustFile(t, wrong, string(other))
	inline := "\"" + strings.ReplaceAll(strings.TrimSpace(string(trusted)), "\n", `\n`) + "\""
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\nca[]="+inline+"\ncafile="+wrong+"\n")
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn {
		t.Fatalf("npm cafile replaces inline ca: got %+v; want WARN", f)
	}
}

func TestIndependentPipRequestsBundlePrecedence(t *testing.T) {
	p, ca, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\ncert="+ca+"\n")
	p.Getenv = func(k string) string {
		if k == "REQUESTS_CA_BUNDLE" {
			return "/missing/requests-ca.pem"
		}
		return ""
	}
	f := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "/missing/requests-ca.pem") {
		t.Fatalf("requests overrides pip session.verify: got %+v; want WARN naming requests-ca.pem", f)
	}
}

// TestTrustFollowsEachClientsOwnPrecedence pins the cases beside the ones a
// review reported: the same grammar and precedence rules, read the other way.
func TestTrustFollowsEachClientsOwnPrecedence(t *testing.T) {
	inline := func(t *testing.T, ca string) string {
		data, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		return `"` + strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", `\n`) + `"`
	}
	apt := func(t *testing.T, p TrustProbe, base string, files map[string]string) {
		writeTrustFile(t, filepath.Join(p.Root, "etc/apt/sources.list.d/bodega.sources"), "URIs: "+base+"/apt/\n")
		for name, body := range files {
			writeTrustFile(t, filepath.Join(p.Root, "etc/apt", name), body)
		}
	}
	for _, tc := range []struct {
		name, check string
		setup       func(t *testing.T, p *TrustProbe, ca, base string)
		want        Status
	}{
		{"apt scoped to bodega's host, in nested braces, over a wrong global", "apt-sources", func(t *testing.T, p *TrustProbe, ca, base string) {
			apt(t, *p, base, map[string]string{
				"apt.conf.d/10global": "Acquire::https::CAInfo \"/missing/global.pem\";\n",
				"apt.conf.d/20host":   "/* ours */ Acquire { HTTPS { bodega.internal { cainfo \"" + ca + "\"; }; }; };\n",
			})
		}, StatusOK},
		{"apt.conf is read after apt.conf.d", "apt-sources", func(t *testing.T, p *TrustProbe, ca, base string) {
			apt(t, *p, base, map[string]string{"apt.conf.d/99ca": "Acquire::https::CAInfo \"" + ca + "\";\n", "apt.conf": "Acquire::https::CAInfo \"/missing/main.pem\";\n"})
		}, StatusWarn},
		{"apt skips a fragment whose name it does not load, and honors #clear", "apt-sources", func(t *testing.T, p *TrustProbe, ca, base string) {
			apt(t, *p, base, map[string]string{
				"apt.conf.d/10ca":           "Acquire::https::CAInfo \"" + ca + "\";\n",
				"apt.conf.d/50clear":        "#clear Acquire::https;\n",
				"apt.conf.d/90ca.dpkg-dist": "Acquire::https::CAInfo \"" + ca + "\";\n",
			})
		}, StatusWarn},
		{"npm ca[] after cafile in one file is unchecked, not resolved", "npm-config", func(t *testing.T, p *TrustProbe, ca, base string) {
			other, _ := trustFixture(t)
			wrong := filepath.Join(p.Root, "other.pem")
			writeTrustFile(t, wrong, string(other))
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile="+wrong+"\nca[]="+inline(t, ca)+"\n")
		}, StatusWarn},
		{"npm ca beside a cafile naming no file is unchecked", "npm-config", func(t *testing.T, p *TrustProbe, ca, base string) {
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\nca="+inline(t, ca)+"\ncafile=/missing/gone.pem\n")
		}, StatusWarn},
		{"npm inline ca in the global file under a per-user cafile", "npm-config", func(t *testing.T, p *TrustProbe, ca, base string) {
			other, _ := trustFixture(t)
			wrong := filepath.Join(p.Root, "other.pem")
			writeTrustFile(t, wrong, string(other))
			writeTrustFile(t, filepath.Join(p.Root, "etc/npmrc"), "ca="+inline(t, wrong)+"\n")
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile=\""+ca+"\"\n")
		}, StatusOK},
		{"npm cafile through a ${NAME} reference is unchecked", "npm-config", func(t *testing.T, p *TrustProbe, ca, base string) {
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile=${CA_DIR}/ca.pem\n")
			p.System = func([]*x509.Certificate, string) error { return nil }
		}, StatusWarn},
		{"npm environment cafile outranks the selected userconfig", "npm-config", func(t *testing.T, p *TrustProbe, ca, base string) {
			selected := filepath.Join(p.Root, "selected.npmrc")
			writeTrustFile(t, selected, "registry="+base+"/npm/\ncafile="+ca+"\n")
			other, _ := trustFixture(t)
			wrong := filepath.Join(p.Root, "other.pem")
			writeTrustFile(t, wrong, string(other))
			p.Getenv = func(k string) string {
				return map[string]string{"npm_config_userconfig": selected, "npm_config_cafile": wrong}[k]
			}
		}, StatusWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			tc.setup(t, &p, ca, base)
			f := p.Apply([]Finding{{Check: tc.check, Status: StatusOK}}, base)[0]
			if f.Status != tc.want || tc.want == StatusOK && f.Detail != "" {
				t.Fatalf("got %+v; want %s", f, tc.want)
			}
		})
	}
}

func TestStaffPipVirtualenvOverridesGlobalCA(t *testing.T) {
	p, ca, base := reviewTrust(t)
	writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\ncert="+ca+"\n")
	venv := filepath.Join(p.Root, "venv")
	writeTrustFile(t, filepath.Join(venv, "pip.conf"), "[global]\ncert=/missing/venv-ca.pem\n")
	p.Getenv = func(k string) string {
		if k == "VIRTUAL_ENV" {
			return venv
		}
		return ""
	}
	f := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "/missing/venv-ca.pem") {
		t.Fatalf("pip virtualenv overrides global cert: got %+v; want WARN naming venv-ca.pem", f)
	}
}

func TestStaffPipIgnoresConfigFilesFromOtherPlatforms(t *testing.T) {
	for _, tc := range []struct{ goos, unused string }{
		{"linux", "home/test/Library/Application Support/pip/pip.conf"},
		{"freebsd", "usr/local/etc/pip.conf"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			p.GOOS = tc.goos
			writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url="+base+"/pypi/simple/\ncert=/missing/effective-pip-ca.pem\n")
			writeTrustFile(t, filepath.Join(p.Root, tc.unused), "[global]\ncert="+ca+"\n")
			f := p.Apply([]Finding{{Check: "pip-config", Status: StatusOK}}, base)[0]
			if f.Status != StatusWarn || !strings.Contains(f.Detail, "/missing/effective-pip-ca.pem") {
				t.Fatalf("pip %s never loads %s: got %+v; want WARN for effective-pip-ca.pem", tc.goos, tc.unused, f)
			}
		})
	}
}

// F116 R1: git and helm, which have no row in the report, are judged after a
// CA install by the setting each one reads: git the sslCAInfo of the longest
// URL match, helm the caFile of bodega's repository entry.
func TestTrustProbeJudgesGitAndHelm(t *testing.T) {
	p, ca, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	gitconfig := filepath.Join(p.Home, ".gitconfig")
	repos := filepath.Join(p.Home, ".config/helm/repositories.yaml")
	rows := []Finding{{Check: "git-config", Status: StatusOK}, {Check: "helm-repos", Status: StatusOK}}
	rewrite := "[url \"" + base + "/git/gh/\"]\n\tinsteadOf = https://github.com/\n"
	scoped := "[http \"" + base + "/\"]\n\tsslCAInfo = " + ca + "\n"
	for _, tc := range []struct {
		name, git, helm string
		env             map[string]string
		warn            map[string]string
	}{
		{name: "not configured", git: scoped, helm: "repositories:\n  - name: corp\n    url: https://charts.example\n      caFile: /x\n"},
		{name: "own settings hold the CA", git: rewrite + scoped, helm: "repositories:\n  - name: bodega\n    url: " + base + "/helm\n    caFile: " + ca + "\n"},
		{name: "a longer section and a caFile name another store", git: rewrite + scoped + "[http \"" + base + "/git/gh/corp/\"]\n\tsslCAInfo = /missing/corp.pem\n",
			helm: "repositories:\n  - name: bodega\n    url: " + base + "/helm\n    caFile: /missing/helm.pem\n",
			warn: map[string]string{"git-config": "/missing/corp.pem", "helm-repos": "/missing/helm.pem"}},
		{name: "no setting leaves the system store", git: rewrite, helm: "repositories:\n  - name: bodega\n    url: " + base + "/helm\n",
			warn: map[string]string{"git-config": systemStoreName, "helm-repos": systemStoreName}},
		{name: "the environment outranks the file", git: rewrite + scoped, env: map[string]string{"GIT_SSL_CAINFO": "/missing/env.pem"},
			helm: "repositories: []\n", warn: map[string]string{"git-config": "GIT_SSL_CAINFO"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeTrustFile(t, gitconfig, tc.git)
			writeTrustFile(t, repos, tc.helm)
			p.Getenv = func(k string) string { return tc.env[k] }
			for _, f := range p.Apply(rows, base) {
				want, warns := tc.warn[f.Check]
				if warns != (f.Status == StatusWarn) || !strings.Contains(f.Detail, want) {
					t.Errorf("%s = %s %q; want a warning naming %q: %v", f.Check, f.Status, f.Detail, want, warns)
				}
			}
		})
	}
}

func TestFinalGitProbeAcceptsNativeSectionSyntax(t *testing.T) {
	p, ca, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	target := filepath.Join(p.Home, ".gitconfig")
	writeTrustFile(t, target, "[url \""+base+"/git/gh/\"]\n\tinsteadOf = https://github.com/\n[http \""+base+"/\"]\n\tsslCAInfo = "+ca+"\n[http \""+base+"/git/gh/\"] # corporate roots\n\tsslCAInfo = /missing/corporate.pem\n")
	out, err := exec.Command("git", "config", "--file", target, "--get-urlmatch", "http.sslCAInfo", base+"/git/gh/repo").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "/missing/corporate.pem" {
		t.Fatalf("native git: %v: %s", err, out)
	}
	f := p.Apply([]Finding{{Check: "git-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "/missing/corporate.pem") {
		t.Fatalf("native git reads /missing/corporate.pem; probe returned %+v", f)
	}
}

func TestFinalNpmRegistryEnvironmentStillChecksTrust(t *testing.T) {
	for _, key := range []string{"npm_config_registry", "NPM_CONFIG_REGISTRY"} {
		t.Run(key, func(t *testing.T) {
			p, _, base := reviewTrust(t)
			other, _ := trustFixture(t)
			wrong := filepath.Join(p.Root, "unrelated-ca.pem")
			writeTrustFile(t, wrong, string(other))
			p.Getenv = func(k string) string {
				switch k {
				case key:
					return base + "/npm/"
				case "NPM_CONFIG_CAFILE":
					return wrong
				}
				return ""
			}
			f := p.Apply([]Finding{checkNpmConfig(p.Root, p.GOOS, p.Home)}, base)[0]
			if f.Status != StatusWarn || !strings.Contains(f.Detail, wrong) || !strings.Contains(f.Remediation, "--ca-file") {
				t.Fatalf("npm's environment selects bodega and an unrelated CA; probe returned %+v", f)
			}
		})
	}
}

// F116 R2: a row whose client cannot be judged warns naming the input that
// stood in the way, and whether a client reaches bodega is read from its
// effective settings, not from the text of a file it may not load.
func TestTrustProbeJudgesEffectiveConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, check string
		set         func(t *testing.T, p *TrustProbe, base string)
		warn        string
	}{
		{"git header in a form the reader does not follow", "git-config", func(t *testing.T, p *TrustProbe, base string) {
			writeTrustFile(t, filepath.Join(p.Home, ".gitconfig"), "[url \""+base+"/git/gh/\"] insteadOf = https://github.com/\n")
		}, "insteadOf = https://github.com/"},
		{"git configured through the environment", "git-config", func(_ *testing.T, p *TrustProbe, _ string) {
			p.Getenv = func(k string) string { return map[string]string{"GIT_CONFIG_COUNT": "2"}[k] }
		}, "GIT_CONFIG_COUNT"},
		{"npm registry in a file the environment outranks", "npm-config", func(t *testing.T, p *TrustProbe, base string) {
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\n")
			p.Getenv = func(k string) string {
				return map[string]string{"npm_config_registry": "https://registry.corp.example/"}[k]
			}
		}, ""},
		{"npm registry named only in a comment", "npm-config", func(t *testing.T, p *TrustProbe, base string) {
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "; registry="+base+"/npm/\nregistry=https://registry.corp.example/\n")
		}, ""},
		{"npm scope sent to bodega", "npm-config", func(t *testing.T, p *TrustProbe, base string) {
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "@corp:registry="+base+"/npm/\n")
		}, "does not verify"},
		{"pip index named only in a comment", "pip-config", func(t *testing.T, p *TrustProbe, base string) {
			writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\n# index-url = "+base+"/pypi/simple/\nindex-url = https://pypi.corp.example/simple/\n")
		}, ""},
		{"pip index replaced by the environment", "pip-config", func(t *testing.T, p *TrustProbe, base string) {
			writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url = "+base+"/pypi/simple/\n")
			p.Getenv = func(k string) string {
				return map[string]string{"PIP_INDEX_URL": "https://pypi.corp.example/simple/"}[k]
			}
		}, ""},
		{"pip extra index from the environment alone", "pip-config", func(_ *testing.T, p *TrustProbe, base string) {
			p.Getenv = func(k string) string { return map[string]string{"PIP_EXTRA_INDEX_URL": base + "/pypi/simple/"}[k] }
		}, "does not verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, base := reviewTrust(t)
			if tc.check == "git-config" {
				p.Home = filepath.Join(p.Root, "home")
			}
			tc.set(t, &p, base)
			f := p.Apply([]Finding{{Check: tc.check, Status: StatusOK, Detail: "as the check wrote it"}}, base)[0]
			switch {
			case tc.warn == "" && (f.Status != StatusOK || f.Detail != "as the check wrote it"):
				t.Errorf("a client whose effective settings do not reach bodega was judged: %+v", f)
			case tc.warn != "" && (f.Status != StatusWarn || !strings.Contains(f.Detail, tc.warn) || !strings.Contains(f.Remediation, "--ca-file")):
				t.Errorf("row = %+v; want a warning naming %q and --ca-file", f, tc.warn)
			}
		})
	}
}

// F116 R1: Judge owes a verdict for every check it is handed, and tells a
// client that verifies from one that fails, one that could not be judged and
// one nothing points at bodega: only the first is a pass.
func TestJudgeTellsVerifiedFromEverythingElse(t *testing.T) {
	p, ca, base := reviewTrust(t)
	gitHome := filepath.Join(p.Root, "githome")
	writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), "registry="+base+"/npm/\ncafile="+ca+"\n")
	writeTrustFile(t, filepath.Join(p.Root, "etc/pip.conf"), "[global]\nindex-url = "+base+"/pypi/simple/\ncert = /missing/ca.pem\n")
	got, err := p.Judge([]string{"npm-config", "pip-config", "helm-repos", "no-such-check"}, base)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]TrustState{"npm-config": TrustVerified, "pip-config": TrustFailed, "helm-repos": TrustAbsent}
	if len(got) != len(want) {
		t.Fatalf("Judge returned %d verdicts for %d known checks: %+v", len(got), len(want), got)
	}
	for _, v := range got {
		if v.State != want[v.Check] || (v.State == TrustFailed) != strings.Contains(v.Detail, "/missing/ca.pem") {
			t.Errorf("%s = %+v; want state %d", v.Check, v, want[v.Check])
		}
	}
	p.Home = gitHome
	p.Getenv = func(k string) string { return map[string]string{"GIT_CONFIG_PARAMETERS": "'http.sslCAInfo=/x'"}[k] }
	got, err = p.Judge([]string{"git-config"}, base)
	if err != nil || len(got) != 1 || got[0].State != TrustUnchecked || !strings.Contains(got[0].Detail, "GIT_CONFIG_PARAMETERS") || got[0].System != "git" {
		t.Errorf("git configured by the environment = %+v, %v; want unchecked naming the variable", got, err)
	}
	p.Chain = func(string) ([]*x509.Certificate, error) { return nil, errors.New("connection refused") }
	if _, err := p.Judge([]string{"git-config"}, base); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("a server that does not answer = %v; want an error, not a set of passes", err)
	}
	if _, err := p.Judge([]string{"git-config"}, "http://bodega.internal"); err == nil {
		t.Error("a plaintext base was judged")
	}
}

func TestAudit6GitIncludeProbe(t *testing.T) {
	p, ca, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	target, included := filepath.Join(p.Home, ".gitconfig"), filepath.Join(p.Home, "corporate.gitconfig")
	writeTrustFile(t, included, "[http \""+base+"/git/gh/\"]\n\tsslCAInfo = /missing/corporate.pem\n")
	writeTrustFile(t, target, "[url \""+base+"/git/gh/\"]\n\tinsteadOf = https://github.com/\n[http \""+base+"/\"]\n\tsslCAInfo = "+ca+"\n[include]\n\tpath = "+included+"\n")
	out, err := exec.Command("git", "config", "--includes", "--file", target, "--get-urlmatch", "http.sslCAInfo", base+"/git/gh/repo").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "/missing/corporate.pem" {
		t.Fatalf("native git: %v: %s", err, out)
	}
	f := p.Apply([]Finding{{Check: "git-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || (!strings.Contains(f.Detail, "/missing/corporate.pem") && !strings.Contains(strings.ToLower(f.Detail), "include")) || !strings.Contains(f.Remediation, "--ca-file") {
		t.Fatalf("native git selects the included missing CA; probe returned %+v", f)
	}
}

func TestAudit7NpmInlinePolicyMustBeUnchecked(t *testing.T) {
	p, ca, base := reviewTrust(t)
	raw, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(p.Root, p.Home, ".npmrc")
	writeTrustFile(t, config, "registry="+base+"/npm/\ncafile="+ca+"\nca[]=\""+strings.ReplaceAll(strings.TrimSpace(string(raw)), "\n", `\n`)+"\"\n")
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "unchecked") || !strings.Contains(f.Detail, config) || !strings.Contains(f.Detail, "ca[]") || !strings.Contains(f.Remediation, "--ca-file") {
		t.Fatalf("operator requires an unchecked warning naming ca[] and its file; got %+v", f)
	}
}

func TestAudit7NpmCAFileCommentCannotRestoreDefaultRoots(t *testing.T) {
	nativeNpm(t)
	p, ca, base := reviewTrust(t)
	good, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := trustFixture(t)
	wrong := filepath.Join(p.Root, "corporate.pem")
	writeTrustFile(t, wrong, string(other))
	p.Getenv = func(key string) string {
		if key == "NODE_EXTRA_CA_CERTS" {
			return ca
		}
		return ""
	}
	p.Node = func() (NodeRoots, error) { return NodeRoots{PEM: []string{string(good)}, Effective: true}, nil }
	home := filepath.Join(p.Root, p.Home)
	config := filepath.Join(home, ".npmrc")
	writeTrustFile(t, config, "registry="+base+"/npm/\ncafile="+wrong+" # corporate bundle\n")
	cmd := exec.Command("npm", "config", "get", "cafile", "--userconfig", config, "--globalconfig", filepath.Join(p.Root, "global.npmrc"))
	cmd.Dir = home
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if !strings.HasPrefix(strings.ToLower(key), "npm_config_") && key != "HOME" && key != "NODE_OPTIONS" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+home)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != wrong {
		t.Fatalf("native npm cafile = %q, %v; want %s", out, err, wrong)
	}
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Remediation, "--ca-file") || (!strings.Contains(f.Detail, wrong) && !strings.Contains(f.Detail, "unchecked")) {
		t.Fatalf("native npm replaces default roots with %s; probe returned %+v", wrong, f)
	}
}

func TestAudit8NpmQuotedCAFileCannotRestoreDefaultRoots(t *testing.T) {
	nativeNpm(t)
	p, ca, base := reviewTrust(t)
	good, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := trustFixture(t)
	wrong := filepath.Join(p.Root, "corporate.pem")
	writeTrustFile(t, wrong, string(other))
	p.Node = func() (NodeRoots, error) { return NodeRoots{PEM: []string{string(good)}, Effective: true}, nil }
	home := filepath.Join(p.Root, p.Home)
	config := filepath.Join(home, ".npmrc")
	writeTrustFile(t, config, "registry="+base+"/npm/\n\"cafile\"="+wrong+"\n")
	cmd := exec.Command("npm", "config", "get", "cafile", "--userconfig", config, "--globalconfig", filepath.Join(p.Root, "global.npmrc"))
	cmd.Dir = home
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if !strings.HasPrefix(strings.ToLower(key), "npm_config_") && key != "HOME" && key != "NODE_OPTIONS" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+home)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != wrong {
		t.Fatalf("native npm cafile = %q, %v; want %s", out, err, wrong)
	}
	f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Remediation, "--ca-file") || (!strings.Contains(f.Detail, wrong) && !strings.Contains(f.Detail, "unchecked")) {
		t.Fatalf("native npm replaces default roots with quoted cafile %s; probe returned %+v", wrong, f)
	}
}

func TestAudit8NpmRegistryCommentStillOwesTrust(t *testing.T) {
	nativeNpm(t)
	p, _, base := reviewTrust(t)
	other, _ := trustFixture(t)
	wrong := filepath.Join(p.Root, "corporate.pem")
	writeTrustFile(t, wrong, string(other))
	home := filepath.Join(p.Root, p.Home)
	config := filepath.Join(home, ".npmrc")
	writeTrustFile(t, config, "registry="+base+" # internal registry\ncafile="+wrong+"\n")
	cmd := exec.Command("npm", "config", "get", "registry", "--userconfig", config, "--globalconfig", filepath.Join(p.Root, "global.npmrc"))
	cmd.Dir = home
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if !strings.HasPrefix(strings.ToLower(key), "npm_config_") && key != "HOME" && key != "NODE_OPTIONS" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+home)
	out, err := cmd.Output()
	if err != nil || strings.TrimRight(strings.TrimSpace(string(out)), "/") != base {
		t.Fatalf("native npm registry = %q, %v; want %s", out, err, base)
	}
	before := checkNpmConfig(p.Root, p.GOOS, p.Home)
	f := p.Apply([]Finding{before}, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Remediation, "--ca-file") || (!strings.Contains(f.Detail, wrong) && !strings.Contains(f.Detail, "unchecked")) {
		t.Fatalf("native npm reaches %s and its cafile lacks the issuer, but doctor left the row %+v", base, f)
	}
}

// TestNpmProbeReadsLinesAsNpmDecodesThem walks the npmrc forms the probe
// shares a decoder with the install for: a quoted or commented line names the
// option npm reads, and a line whose option cannot be told leaves the row
// unchecked whether or not another line names bodega.
func TestNpmProbeReadsLinesAsNpmDecodesThem(t *testing.T) {
	for _, tc := range []struct {
		name, rc string
		good     bool
		want     string
	}{
		{"quoted registry and cafile with the issuer", "\"registry\" = {base}/npm/ ; internal\n'cafile'={ca} # issuer\n", true, ""},
		{"ca list form holding the issuer after a plain ca", "registry={base}\nca=\"unrelated\"\n\"ca[]\"={inline}\n", true, ""},
		{"cafile under a section sets nothing", "registry={base}\n[corp]\ncafile={ca}\n", false, "Node"},
		{"registry in its list form", "registry[]={base}\n", false, "unchecked"},
		{"reference in a name on a host with no bodega registry", "//${HOST}/:_authToken=hunter2\n", false, "unchecked"},
		{"bracket line npm reads as an option", "registry={base}\n [corp]\ncafile={ca}\n", false, "unchecked"},
		{"cafile from a reference", "registry={base}\ncafile=${CORP_CA}\n", false, "unchecked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			issuer, err := os.ReadFile(ca)
			if err != nil {
				t.Fatal(err)
			}
			p.Node = func() (NodeRoots, error) { return NodeRoots{Effective: true}, nil }
			inline := `"` + strings.ReplaceAll(strings.TrimSpace(string(issuer)), "\n", `\n`) + `"`
			rc := strings.NewReplacer("{base}", base, "{ca}", ca, "{inline}", inline).Replace(tc.rc)
			writeTrustFile(t, filepath.Join(p.Root, p.Home, ".npmrc"), rc)
			f := p.Apply([]Finding{{Check: "npm-config", Status: StatusOK}}, base)[0]
			if tc.good {
				if f.Status != StatusOK {
					t.Fatalf("npm verifies bodega through this file; probe returned %+v", f)
				}
				return
			}
			if f.Status != StatusWarn || !strings.Contains(f.Detail, tc.want) || !strings.Contains(f.Remediation, "--ca-file") || strings.Contains(f.Detail, "hunter2") {
				t.Fatalf("want a warning naming %q and no value; probe returned %+v", tc.want, f)
			}
		})
	}
}

// nativeNpm gates a test that holds doctor's reading of an npmrc against
// npm's own. A developer's machine without npm skips it. CI does not: its
// test job installs a pinned Node, so a missing npm there is a broken job
// that would otherwise pass every oracle test unrun.
func nativeNpm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native npm is required in CI: the test job installs it with actions/setup-node")
		}
		t.Skip("native npm is not installed")
	}
}

func TestAudit10GitCommentCannotHideProbeOverride(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native git is required in CI")
		}
		t.Skip("native git is not installed")
	}
	p, ca, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	target := filepath.Join(p.Home, ".gitconfig")
	body := "[url \"" + base + "/git/gh/\"]\n\tinsteadOf = https://github.com/\n[http \"" + base + "/\"]\n\tsslCAInfo = " + ca + "\n[http \"" + base + "/git/gh/\"]\n# corporate policy \\\n\tsslCAInfo = /missing/corporate.pem\n"
	writeTrustFile(t, target, body)
	out, err := exec.Command("git", "config", "--file", target, "--get-urlmatch", "http.sslCAInfo", base+"/git/gh/repo").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "/missing/corporate.pem" {
		t.Fatalf("native git control: %q, %v", out, err)
	}
	f := p.Apply([]Finding{{Check: "git-config", Status: StatusOK}}, base)[0]
	if f.Status != StatusWarn {
		t.Fatalf("native git selects a missing CA but doctor reports %+v", f)
	}
}

// A client's endpoint is the one its effective configuration gives it: a
// value the environment sets hides the file below it, for the trust verdict
// as for the row, so a hidden file naming bodega owes and proves nothing.
func TestTrustFollowsTheEffectiveEndpoint(t *testing.T) {
	p, _, base := reviewTrust(t)
	p.Home = t.TempDir()
	conf := filepath.Join(p.Home, ".config")
	p.ConfigDir = func() (string, error) { return conf, nil }
	writeTrustFile(t, filepath.Join(conf, "go", "env"), "GOPROXY="+base+"/go,off\n")
	elsewhere := t.TempDir()
	writeTrustFile(t, filepath.Join(elsewhere, "goenv"), "GOPROXY=https://proxy.golang.org,direct\n")

	state := func(check string, env map[string]string) TrustState {
		t.Helper()
		p.Getenv = func(k string) string { return env[k] }
		got, err := p.Judge([]string{check}, base)
		if err != nil || len(got) != 1 {
			t.Fatalf("Judge(%s) = %+v, %v", check, got, err)
		}
		return got[0].State
	}
	for _, c := range []struct {
		name, check string
		env         map[string]string
		want        TrustState
	}{
		{"go env file alone", "goproxy-env", nil, TrustFailed},
		{"GOPROXY names another proxy", "goproxy-env", map[string]string{"GOPROXY": "https://proxy.golang.org,direct"}, TrustAbsent},
		{"GOPROXY reaches bodega after off", "goproxy-env", map[string]string{"GOPROXY": "off," + base + "/go"}, TrustAbsent},
		{"GOPROXY names bodega", "goproxy-env", map[string]string{"GOPROXY": base + "/go,off"}, TrustFailed},
		{"GOENV selects another file", "goproxy-env", map[string]string{"GOENV": filepath.Join(elsewhere, "goenv")}, TrustAbsent},
		{"GOENV=off", "goproxy-env", map[string]string{"GOENV": "off"}, TrustAbsent},
		{"GOENV names a directory", "goproxy-env", map[string]string{"GOENV": elsewhere}, TrustUnchecked},
	} {
		if got := state(c.check, c.env); got != c.want {
			t.Errorf("%s: state = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAudit12PipEndpointAndCAUseTheSameCommand(t *testing.T) {
	p, ca, base := reviewTrust(t)
	p.Home = t.TempDir()
	file := filepath.Join(p.Root, "etc", "pip.conf")
	writeTrustFile(t, file, "[global]\nindex-url = "+base+"/pypi/simple/\ncert = /missing/default-ca.pem\n[install]\nindex-url = https://packages.corp.example/simple/\ncert = "+ca+"\n")
	got, err := p.Judge([]string{"pip-config"}, base)
	if err != nil || len(got) != 1 {
		t.Fatalf("Judge = %+v, %v", got, err)
	}
	if got[0].State == TrustVerified {
		t.Fatalf("the global endpoint reaches bodega with a missing CA; the trusted install CA belongs to another endpoint, but the verdict is %+v", got[0])
	}
}

func TestAudit13PipDefaultsUseTheInstallCA(t *testing.T) {
	p, ca, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	file := filepath.Join(p.Root, "etc", "pip.conf")
	missing := filepath.Join(p.Root, "missing.pem")
	writeTrustFile(t, file, "[DEFAULT]\ncert = "+missing+"\n[global]\nindex-url = "+base+"/pypi/simple/\ncert = "+ca+"\n[install]\n")
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("native pip oracle needs python3")
	}
	cmd := exec.Command(python, "-m", "pip", "config", "list")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + p.Home, "PIP_CONFIG_FILE=" + file}
	native, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native pip: %v: %s", err, native)
	}
	if !strings.Contains(string(native), "install.cert='"+missing+"'") {
		t.Fatalf("native pip install.cert = %q, want %q", native, missing)
	}
	got := p.Apply([]Finding{checkPipConfig(p.Root, p.GOOS, p.Home)}, base)[0]
	if got.Status != StatusWarn || !(strings.Contains(got.Detail, missing) || strings.Contains(got.Detail, "unchecked") && strings.Contains(got.Detail, "DEFAULT")) || !strings.Contains(got.Remediation, "--ca-file") {
		t.Fatalf("native pip install.cert = %s, but doctor returned %+v", strings.TrimSpace(string(native)), got)
	}
}

func TestAudit13PipDefaultsStillDiscoverBodega(t *testing.T) {
	p, _, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	file := filepath.Join(p.Root, "etc", "pip.conf")
	missing := filepath.Join(p.Root, "missing.pem")
	writeTrustFile(t, file, "[DEFAULT]\nindex-url = "+base+"/pypi/simple/\ncert = "+missing+"\n[install]\n")
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("native pip oracle needs python3")
	}
	cmd := exec.Command(python, "-m", "pip", "config", "list")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + p.Home, "PIP_CONFIG_FILE=" + file}
	native, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native pip: %v: %s", err, native)
	}
	if !strings.Contains(string(native), "install.index-url='"+base+"/pypi/simple/'") {
		t.Fatalf("native pip install.index-url = %q", native)
	}
	got := p.Apply([]Finding{checkPipConfig(p.Root, p.GOOS, p.Home)}, base)[0]
	if got.Status != StatusWarn || !(strings.Contains(got.Detail, missing) || strings.Contains(got.Detail, "unchecked") && strings.Contains(got.Detail, "DEFAULT")) || !strings.Contains(got.Remediation, "--ca-file") {
		t.Fatalf("native pip install.index-url = %s and cert = %s, but doctor returned %+v", strings.TrimSpace(string(native)), missing, got)
	}
}

func TestAudit14PipRejectsDuplicatePolicy(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, tail := range []string{"timeout = 1\ntimeout = 2\n", "[global]\ntimeout = 1\n"} {
		t.Run(strings.ReplaceAll(tail, "\n", "_"), func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			p.Home = filepath.Join(p.Root, "home")
			file := filepath.Join(p.Root, "etc", "pip.conf")
			writeTrustFile(t, file, "[global]\nindex-url = "+base+"/pypi/simple/\ncert = "+ca+"\n"+tail)
			cmd := exec.Command(python, "-m", "pip", "config", "list")
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + p.Home, "PIP_CONFIG_FILE=" + file}
			native, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(native), "already exists") {
				t.Fatalf("oracle did not reject duplicate: %v: %s", err, native)
			}
			got := p.Apply([]Finding{checkPipConfig(p.Root, p.GOOS, p.Home)}, base)[0]
			verdict, err := p.Judge([]string{"pip-config"}, base)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != StatusWarn || !strings.Contains(got.Detail, "unchecked") || !strings.Contains(got.Detail, file) || !strings.Contains(got.Remediation, "--ca-file") || len(verdict) != 1 || verdict[0].State != TrustUnchecked {
				t.Fatalf("native pip rejects this file:\n%s\ndoctor row: %+v; selected verdict: %+v", native, got, verdict)
			}
		})
	}
}

// F116 R2: a row for any client other than apt, pip, npm, git, helm, go,
// Docker Engine and containerd comes back as its check wrote it, whatever
// the chain bodega serves, and owes no verdict after an install.
func TestTrustProbeLeavesOtherRowsAsWritten(t *testing.T) {
	p, _, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	host := strings.TrimPrefix(base, "https://")
	// Each is configured for bodega, whose chain no store on the host verifies.
	writeTrustFile(t, filepath.Join(p.Home, ".cargo/config.toml"), "[source.bodega]\nregistry = \"sparse+"+base+"/cargo/\"\n")
	writeTrustFile(t, filepath.Join(p.Home, ".gemrc"), "---\n:sources:\n- "+base+"/rubygems/\n")
	writeTrustFile(t, filepath.Join(p.Home, ".m2/settings.xml"), "<settings><mirrors><mirror><id>bodega</id><mirrorOf>*</mirrorOf><url>"+base+"/maven/</url></mirror></mirrors></settings>")
	writeTrustFile(t, filepath.Join(p.Home, ".config/composer/config.json"), `{"repositories":{"bodega":{"type":"composer","url":"`+base+`/composer/"}}}`)
	writeTrustFile(t, filepath.Join(p.Root, "etc/yum.repos.d/bodega.repo"), "[bodega-baseos]\nbaseurl="+base+"/rpm/baseos/\n")
	writeTrustFile(t, filepath.Join(p.Root, "usr/local/etc/pkg/repos/bodega.conf"), "bodega: { url: \""+base+"/freebsd\" }\n")
	writeTrustFile(t, filepath.Join(p.Root, "etc/make.conf"), "MASTER_SITE_OVERRIDE?= "+base+"/distfiles/\n")
	writeTrustFile(t, filepath.Join(p.Root, "etc/containers/registries.conf.d/bodega.conf"), "[[registry]]\nprefix = \"docker.io\"\n[[registry.mirror]]\nlocation = \""+host+"\"\n")
	var rows []Finding
	var checks []string
	for _, check := range []string{"cargo-config", "rubygems", "maven", "composer", "dnf-repos", "pkg-repos", "make-conf", "oci-podman"} {
		checks = append(checks, check)
		rows = append(rows, Finding{Check: check, Status: StatusOK, Detail: "as written"}, Finding{Check: check, Status: StatusWarn, Detail: "as written", Remediation: "as written"})
	}
	if got := p.Apply(rows, base); !slices.Equal(got, rows) {
		t.Errorf("rows for clients outside --ca-file changed:\n got %+v\nwant %+v", got, rows)
	}
	if got, err := p.Judge(checks, base); err != nil || len(got) != 0 {
		t.Errorf("Judge(%v) = %+v, %v; want no verdict owed", checks, got, err)
	}
	for check, system := range TrustSystems() {
		if !slices.Contains([]string{"apt", "pypi", "npm", "git", "helm", "gomod", "oci"}, system) || check == "oci-podman" {
			t.Errorf("the probe judges %s for %s, a client --ca-file refuses", check, system)
		}
	}
}

func TestAudit15PipSyntaxErrorIsUnchecked(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, tail := range []string{"not-an-assignment\n", "= nameless\n"} {
		t.Run(strings.ReplaceAll(tail, "\n", "_"), func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			p.Home = filepath.Join(p.Root, "home")
			file := filepath.Join(p.Root, "etc", "pip.conf")
			writeTrustFile(t, file, "[global]\nindex-url = "+base+"/pypi/simple/\ncert = "+ca+"\n"+tail)
			cmd := exec.Command(python, "-m", "pip", "config", "list")
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + p.Home, "PIP_CONFIG_FILE=" + file}
			native, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(native), "parsing errors") {
				t.Fatalf("oracle did not reject malformed line: %v: %s", err, native)
			}
			got := p.Apply([]Finding{checkPipConfig(p.Root, p.GOOS, p.Home)}, base)[0]
			verdict, err := p.Judge([]string{"pip-config"}, base)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != StatusWarn || !strings.Contains(got.Detail, "unchecked") || !strings.Contains(got.Detail, file) || !strings.Contains(got.Remediation, "--ca-file") || len(verdict) != 1 || verdict[0].State != TrustUnchecked {
				t.Fatalf("native pip rejects this file:\n%s\ndoctor row: %+v; selected verdict: %+v", native, got, verdict)
			}
		})
	}
}

func TestAudit16GitLoadErrorIsUnchecked(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	p, ca, base := reviewTrust(t)
	p.Home = filepath.Join(p.Root, "home")
	file := filepath.Join(p.Home, ".gitconfig")
	body := "[user]\n name = \"bad\\q\"\n[url \"" + base + "/git/gh/\"]\n insteadOf = https://github.com/\n[http]\n sslCAInfo = " + ca + "\n"
	writeTrustFile(t, file, body)
	cmd := exec.Command(git, "config", "--file", file, "--get", "http.sslCAInfo")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + p.Home, "GIT_CONFIG_NOSYSTEM=1"}
	native, nativeErr := cmd.CombinedOutput()
	if nativeErr == nil || !strings.Contains(string(native), "bad config line 2") {
		t.Fatalf("oracle did not reject fixture: %v: %s", nativeErr, native)
	}
	verdict, err := p.Judge([]string{"git-config"}, base)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Apply([]Finding{{Check: "git-config", Status: StatusOK}}, base)[0]
	if len(verdict) != 1 || verdict[0].State != TrustUnchecked || got.Status != StatusWarn || !strings.Contains(got.Detail, file) || !strings.Contains(got.Detail, "unchecked") {
		t.Fatalf("native git refuses this file: %s; doctor row=%+v, verdict=%+v", native, got, verdict)
	}
}
