package config

import (
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
)

func TestResolveTLSMinVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"", tls.VersionTLS13, false},
		{"1.3", tls.VersionTLS13, false},
		{"1.2", tls.VersionTLS12, false},
		{" 1.2 ", tls.VersionTLS12, false},
		{"1.1", 0, true},
		{"1.0", 0, true},
		{"tls1.3", 0, true},
		{"garbage", 0, true},
	}

	for _, tc := range cases {
		c := &Config{TLSMinVersion: tc.in}
		got, err := c.ResolveTLSMinVersion()
		if tc.wantErr {
			if err == nil {
				t.Errorf("ResolveTLSMinVersion(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveTLSMinVersion(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolveTLSMinVersion(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

// TLS 1.0 and 1.1 are refused by name rather than rounded up, so the operator
// learns the key did not do what they wrote.
func TestResolveTLSMinVersionNamesTheRefusedVersion(t *testing.T) {
	c := &Config{TLSMinVersion: "1.0"}
	_, err := c.ResolveTLSMinVersion()
	if err == nil {
		t.Fatal("want an error for TLS 1.0")
	}
	if want := `"1.0"`; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %s", err, want)
	}
}

// trusted_proxies is tri-state and carries no omitempty, so an explicit empty
// list survives a Save and comes back as "trust nobody" rather than "unset".
func TestTrustedProxiesRoundTripsTriState(t *testing.T) {
	cases := []struct {
		name      string
		blob      string
		wantNil   bool
		wantCount int
	}{
		{"absent", `{}`, true, 0},
		{"explicit null", `{"trusted_proxies":null}`, true, 0},
		{"explicit empty", `{"trusted_proxies":[]}`, false, 0},
		{"populated", `{"trusted_proxies":["10.9.0.0/16"]}`, false, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			if err := json.Unmarshal([]byte(tc.blob), &c); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if (c.TrustedProxies == nil) != tc.wantNil {
				t.Fatalf("TrustedProxies nil = %v, want %v", c.TrustedProxies == nil, tc.wantNil)
			}
			if len(c.TrustedProxies) != tc.wantCount {
				t.Fatalf("len = %d, want %d", len(c.TrustedProxies), tc.wantCount)
			}

			out, err := json.Marshal(&c)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var back Config
			if err := json.Unmarshal(out, &back); err != nil {
				t.Fatalf("re-unmarshal: %v", err)
			}
			if (back.TrustedProxies == nil) != tc.wantNil {
				t.Errorf("after round trip nil = %v, want %v", back.TrustedProxies == nil, tc.wantNil)
			}
			if len(back.TrustedProxies) != tc.wantCount {
				t.Errorf("after round trip len = %d, want %d", len(back.TrustedProxies), tc.wantCount)
			}
		})
	}
}
