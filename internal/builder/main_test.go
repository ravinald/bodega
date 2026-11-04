package builder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/provenance"
)

// TestMain stops the upstream provenance and checksum database checks at the
// loopback interface: // a fetch admits every version through admit.VersionCheckers, and an entry naming a public registry would otherwise
// have them read npm, GitHub, Sigstore's TUF repository and sum.golang.org.
func TestMain(m *testing.M) {
	admit.NewProvenanceVerifier = func(*config.Config) *provenance.Verifier {
		v := provenance.NewVerifier("")
		v.HTTP = &http.Client{Transport: loopbackOnly{}}
		v.Root = func(context.Context) (root.TrustedMaterial, error) {
			return nil, errors.New("a test binary fetches no Sigstore trusted root")
		}
		return v
	}
	admit.NewChecksumDatabase = func(cfg *config.Config, trees provenance.ChecksumDatabaseStore, events provenance.EventRecorder, readOnly bool) *provenance.ChecksumDatabase {
		c := admit.ChecksumDatabaseConfig(cfg, trees, events, readOnly)
		c.HTTP = &http.Client{Transport: loopbackOnly{}}
		return provenance.NewChecksumDatabase(c)
	}
	os.Exit(m.Run())
}

// loopbackOnly refuses every host but this one.
type loopbackOnly struct{}

func (loopbackOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(r.URL.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("test binary refuses %s: only a loopback stub may be read", r.URL.Host)
	}
	return http.DefaultTransport.RoundTrip(r)
}
