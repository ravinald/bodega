package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/policy"
)

// TestMain points the host-wide search paths at a scratch directory before any
// test builds a Server, and stops the import path's publish-time reads at the
// loopback interface, so an import test never reaches a public registry.
//
// New() reads the apt signing key from /etc/bodega/apt-signing.key and the
// token pepper from /etc/bodega/pepper or the user's config directory, none of
// which a test can neutralize by passing a different config. Left alone, this
// package passes or fails on whether the host running it has bodega installed
// and signing — a workstation running the service, a CI runner built from the
// deploy image — and every run writes a pepper into the developer's own config
// directory on the way past. A gate that is green only on the machine that
// wrote it proves nothing.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bodega-server-test")
	if err != nil {
		panic(err)
	}
	aptsign.SystemKeyPath = filepath.Join(dir, "etc", aptsign.KeyFileName)
	audit.DefaultPepperPaths = []string{filepath.Join(dir, "etc", "pepper")}
	// Unset rather than redirected: a test that wants a key installed at
	// position 1 sets this itself, and t.Setenv restores it to unset.
	_ = os.Unsetenv(aptsign.CredentialsEnv)

	admit.NewPublishReader = func() *policy.AgeChecker {
		ac := policy.NewAgeChecker(nil)
		ac.HTTP = &http.Client{Transport: loopbackOnly{}}
		return ac
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// loopbackOnly refuses every host but this one. Swapping the reader's
// endpoints is not enough: an entry's url overrides them, and the catalogs
// these tests import name the public registries.
type loopbackOnly struct{}

func (loopbackOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(r.URL.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("test binary refuses %s: only a loopback stub may be read", r.URL.Host)
	}
	return http.DefaultTransport.RoundTrip(r)
}
