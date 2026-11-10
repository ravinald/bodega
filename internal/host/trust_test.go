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
		"pip-config":   {"the system trust store, which pip reads while no cert setting names a bundle, does not verify", "--configure pypi --ca-file"},
		"cargo-config": {"the system trust store does not verify", "--configure cargo --ca-file"},
		"oci-podman":   {filepath.Join(root, "etc/containers/certs.d", hostport), "--configure oci --ca-file"},
	} {
		f := got[check]
		if f.Status != StatusWarn || !strings.Contains(f.Detail, want.store) || !strings.Contains(f.Detail, hostport) || !strings.Contains(f.Remediation, want.system) {
			t.Errorf("%s = %s %q, remediation %q; want a warning naming %q and %q", check, f.Status, f.Detail, f.Remediation, want.store, want.system)
		}
	}
	for _, check := range []string{"npm-config", "oci-docker", "oci-containerd", "apt-sources", "snapd"} {
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
	// the right CA, and each other client reads the system store.
	probe.System = func([]*x509.Certificate, string) error { return nil }
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

func TestReviewTrustProbesConfiguredMaven(t *testing.T) {
	p, _, base := reviewTrust(t)
	home := t.TempDir()
	p.Home = home
	writeTrustFile(t, filepath.Join(home, ".m2/settings.xml"), "<settings><mirrors><mirror><id>bodega</id><mirrorOf>*</mirrorOf><url>"+base+"/maven/</url></mirror></mirrors></settings>")
	before, ok := checkMaven(mavenTools{home: home, getenv: func(string) string { return "" }, lookPath: func(name string) (string, error) {
		if name == "mvn" {
			return "/stub/mvn", nil
		}
		return "", exec.ErrNotFound
	}})
	if !ok || before.Status != StatusOK {
		t.Fatalf("fixture is not configured: %+v", before)
	}
	called := false
	p.Chain = func(string) ([]*x509.Certificate, error) { called = true; return nil, os.ErrNotExist }
	p.Apply([]Finding{before}, base)
	if !called {
		t.Fatal("configured Maven row never probes bodega's chain")
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

func TestReviewTrustFindsDnfReposdir(t *testing.T) {
	p, _, base := reviewTrust(t)
	main := filepath.Join(p.Root, "etc/dnf/dnf.conf")
	repos := filepath.Join(p.Root, "srv/repos")
	writeTrustFile(t, main, "[main]\nreposdir="+repos+"\n")
	writeTrustFile(t, filepath.Join(repos, "bodega.repo"), "[bodega]\nbaseurl="+base+"/rpm/repo/\nenabled=1\n")
	before, ok := (RpmHost{MainConf: main, Dirs: []string{repos}, LookPath: func(string) (string, error) { return "/stub/dnf", nil }}).Check(base)
	if !ok || before.Status != StatusOK {
		t.Fatalf("fixture not configured: %+v", before)
	}
	f := p.Apply([]Finding{before}, base)[0]
	if f.Status != StatusWarn {
		t.Fatalf("configured dnf custom reposdir and untrusted CA: got %+v; want WARN", f)
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

// F116 R2: the Maven row is judged against the JVM trust store and nothing
// else. The system store verifying does not settle it, a store holding the
// CA does, and one keytool cannot list is reported as unchecked.
func TestTrustProbeReadsTheJVMStoreForMaven(t *testing.T) {
	const base = "https://bodega.internal:8443"
	caPEM, chain := trustFixture(t)
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	writeTrustFile(t, filepath.Join(home, ".gradle/init.d/bodega.gradle"), "def bodegaUrl = '"+base+"/maven/'\n")
	var stored []*x509.Certificate
	var storeErr error
	probe := TrustProbe{
		Home: home, GOOS: "linux",
		Chain:  func(string) ([]*x509.Certificate, error) { return chain, nil },
		System: func([]*x509.Certificate, string) error { return nil },
		JVM:    func() (string, []*x509.Certificate, error) { return "the cacerts keystore of /jdk", stored, storeErr },
	}
	row := []Finding{{Check: "maven", Status: StatusOK, Detail: "Gradle's init script points at bodega"}}

	f := probe.Apply(row, base)[0]
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "the cacerts keystore of /jdk") || !strings.Contains(f.Remediation, "--configure maven --ca-file") {
		t.Errorf("JVM store without the CA, system store verifying = %+v; want a warning naming the keystore", f)
	}
	stored = []*x509.Certificate{ca}
	probe.System = func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }
	if f := probe.Apply(row, base)[0]; f.Status != StatusOK || f.Detail != row[0].Detail {
		t.Errorf("JVM store holding the CA = %+v; want the row as the check wrote it", f)
	}
	storeErr = errors.New("keytool: exit status 1")
	if f := probe.Apply(row, base)[0]; f.Status != StatusOK || !strings.Contains(f.Detail, "unchecked") || !strings.Contains(f.Detail, "exit status 1") {
		t.Errorf("unreadable JVM store = %+v; want OK saying the certificate is unchecked", f)
	}
	// Not pointed at bodega: nothing is listed and nothing is dialed.
	probe.JVM = func() (string, []*x509.Certificate, error) {
		t.Error("keytool ran for a host not configured")
		return "", nil, nil
	}
	probe.Home = t.TempDir()
	probe.Apply(row, base)
}
