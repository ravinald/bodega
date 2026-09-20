package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
)

// TestMain points the host-wide search paths at a scratch directory before any
// test builds a Server.
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

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
