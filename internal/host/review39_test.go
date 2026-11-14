package host

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
)

func TestReview39ContainerdImplicitServerKeepsItsStore(t *testing.T) {
	p, ca, base := auditTrust(t)
	p.System = func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }
	writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/config.toml"), "version = 3\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n")
	file := filepath.Join(p.Root, "etc/containerd/certs.d", strings.TrimPrefix(base, "https://"), "hosts.toml")
	wrong, _ := trustFixture(t)
	foreign := filepath.Join(p.Root, "foreign.pem")
	writeTrustFile(t, foreign, string(wrong))
	writeTrustFile(t, file, "ca=\""+foreign+"\"\ncapabilities=[\"pull\",\"resolve\"]\n")
	doc, err := clientconf.LoadContainerdHostsFile(file)
	if err != nil || doc == nil || len(doc.Hosts) != 1 || !doc.Hosts[0].Server || doc.Hosts[0].Key != "" {
		t.Fatalf("fixture: %+v, %v", doc, err)
	}
	for _, alongside := range []bool{false, true} {
		if alongside {
			writeTrustFile(t, filepath.Join(p.Root, "etc/containerd/certs.d/docker.io/hosts.toml"), "server=\"https://registry-1.docker.io\"\n[host.\""+base+"\"]\nca=\""+ca+"\"\ncapabilities=[\"pull\",\"resolve\"]\n")
		}
		v := auditState(t, p, "oci-containerd", base)
		if v.State != TrustFailed {
			t.Errorf("alongside=%v: implicit server with unrelated CA must fail, got %+v", alongside, v)
		}
		rows := (OCIHost{Root: p.Root, LookPath: func(name string) (string, error) {
			if name == "containerd" {
				return "/fixture/containerd", nil
			}
			return "", os.ErrNotExist
		}}).Check(base)
		rows = p.Apply(rows, base)
		if len(rows) != 1 || rows[0].Status != StatusWarn || !strings.Contains(rows[0].Detail, file) || !strings.Contains(rows[0].Remediation, "--ca-file") {
			t.Errorf("alongside=%v: ordinary report must name the untrusted implicit server's store: %+v", alongside, rows)
		}
	}
}
