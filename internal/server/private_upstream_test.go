package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// fakeUpstreamDNS answers checkUpstreamHost's lookups from a table, and lists
// hosts in private_upstream_hosts for the test's duration.
func fakeUpstreamDNS(t *testing.T, answers map[string][]string, listed ...string) {
	t.Helper()
	savedLookup := upstreamLookupHost
	upstreamLookupHost = func(host string) ([]string, error) {
		if ips, ok := answers[strings.ToLower(host)]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("no such host %q in the test's table", host)
	}
	savedList := privateUpstreamHosts.Load()
	setPrivateUpstreamHosts(listed)
	t.Cleanup(func() {
		upstreamLookupHost = savedLookup
		privateUpstreamHosts.Store(savedList)
	})
}

func TestCheckUpstreamHost_PrivateUpstreamHosts(t *testing.T) {
	fakeUpstreamDNS(t, map[string][]string{
		"registry.corp.example": {"10.0.0.5"},
		"ula.corp.example":      {"fd00::5"},
		"unlisted.corp.example": {"10.0.0.6"},
		"loop.corp.example":     {"10.0.0.7", "127.0.0.1"},
		"meta.corp.example":     {"169.254.169.254"},
		"v6loop.corp.example":   {"::1"},
		"zero.corp.example":     {"0.0.0.0"},
		"public.example":        {"93.184.216.34"},
	}, "registry.corp.example", "ula.corp.example", "loop.corp.example", "meta.corp.example", "v6loop.corp.example", "zero.corp.example")

	for _, host := range []string{"registry.corp.example", "Registry.Corp.Example", "ula.corp.example", "public.example"} {
		if err := checkUpstreamHost(host); err != nil {
			t.Errorf("checkUpstreamHost(%q) = %v, want admitted", host, err)
		}
	}

	err := checkUpstreamHost("unlisted.corp.example")
	if err == nil {
		t.Fatal("unlisted host resolving to 10.0.0.6 was admitted")
	}
	for _, want := range []string{"upstream resolves to non-routable IP 10.0.0.6", `add "unlisted.corp.example" to private_upstream_hosts if it is an internal registry you trust`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q lacks %q", err, want)
		}
	}

	for _, host := range []string{"loop.corp.example", "meta.corp.example", "v6loop.corp.example", "zero.corp.example"} {
		err := checkUpstreamHost(host)
		if err == nil {
			t.Errorf("listed host %q was admitted onto a loopback, link-local or unspecified address", host)
			continue
		}
		if strings.Contains(err.Error(), "private_upstream_hosts") {
			t.Errorf("refusal for %q offers private_upstream_hosts as the fix, which cannot clear it: %v", host, err)
		}
	}
}

// TestUpstreamRedirect_ListedHostToUnlisted runs the redirect hook the shared
// client consults on every hop, so a listed host cannot hand the fetch to an
// internal address nobody listed.
func TestUpstreamRedirect_ListedHostToUnlisted(t *testing.T) {
	fakeUpstreamDNS(t, map[string][]string{
		"registry.corp.example": {"10.0.0.5"},
		"other.corp.example":    {"10.0.0.9"},
	}, "registry.corp.example")

	first, _ := http.NewRequest(http.MethodGet, "https://registry.corp.example/lab-hello", nil)
	hop, _ := http.NewRequest(http.MethodGet, "https://registry.corp.example/lab-hello/-/lab-hello-1.0.0.tgz", nil)
	if err := upstreamClient.CheckRedirect(hop, []*http.Request{first}); err != nil {
		t.Errorf("redirect within the listed host refused: %v", err)
	}

	away, _ := http.NewRequest(http.MethodGet, "https://other.corp.example/lab-hello", nil)
	err := upstreamClient.CheckRedirect(away, []*http.Request{first})
	if err == nil || !strings.Contains(err.Error(), "10.0.0.9") {
		t.Errorf("redirect from a listed host to an unlisted private one = %v, want refused at that hop", err)
	}
}

func TestDistfilesGuard_PrivateUpstreamHosts(t *testing.T) {
	fakeUpstreamDNS(t, map[string][]string{
		"distfiles.corp.example": {"10.0.0.5"},
		"other.corp.example":     {"10.0.0.9"},
	}, "distfiles.corp.example")

	if err := distfilesGuard("http://distfiles.corp.example/ports-distfiles/x.tar.gz"); err != nil {
		t.Errorf("distfilesGuard refused a listed host: %v", err)
	}
	if err := distfilesGuard("http://other.corp.example/ports-distfiles/x.tar.gz"); err == nil {
		t.Error("distfilesGuard admitted an unlisted private host")
	}
}
