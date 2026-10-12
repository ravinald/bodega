package main

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
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"
)

// TestMain stops the import path's publish-time and upstream provenance reads
// at the loopback interface, so a test that imports a manifest never reaches a
// public registry, GitHub or Sigstore, and never depends on one.
func TestMain(m *testing.M) {
	admit.NewPublishReader = func() *policy.AgeChecker {
		ac := policy.NewAgeChecker(nil)
		ac.HTTP = &http.Client{Transport: loopbackOnly{}}
		return ac
	}
	admit.NewProvenanceVerifier = func(*config.Config) *provenance.Verifier {
		v := provenance.NewVerifier("")
		v.HTTP = &http.Client{Transport: loopbackOnly{}}
		v.Root = func(context.Context) (root.TrustedMaterial, error) {
			return nil, errors.New("a test binary fetches no Sigstore trusted root")
		}
		return v
	}
	os.Exit(m.Run())
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
