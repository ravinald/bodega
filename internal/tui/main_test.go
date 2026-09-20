package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
)

// TestMain steers the signing-key search away from the host. newDetailsModel
// reads it to decide which apt sources form the pane emits, so without this a
// workstation with bodega installed and a key in /etc/bodega runs a different
// test than a build agent does.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bodega-tui-test")
	if err != nil {
		panic(err)
	}
	aptsign.SystemKeyPath = filepath.Join(dir, "etc", aptsign.KeyFileName)
	_ = os.Unsetenv(aptsign.CredentialsEnv)

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
