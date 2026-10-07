package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/policy"
)

// TestMain stops the import path's publish-time reads at the loopback
// interface, so a test that imports an npm, pypi, gomod or cargo manifest
// never reaches a public registry and never depends on one.
func TestMain(m *testing.M) {
	admit.NewPublishReader = func() *policy.AgeChecker {
		ac := policy.NewAgeChecker(nil)
		ac.HTTP = &http.Client{Transport: loopbackOnly{}}
		return ac
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
