package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
)

// Save preserves a key it did not parse, so a retired key survives every write
// and goes on looking like a setting in force. B29 gave --tls-autocert and
// --tls-domain equal treatment on the command line and scoped itself there;
// the config half asked only about tls_autocert, so a file carrying tls_domain
// and nothing else started silently.
func TestDoctorReportsRetiredConfigKeys(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status host.Status
		want   []string
		absent []string
	}{
		{
			name:   "tls_domain alone",
			body:   `{"config_version":1,"tls_domain":"bodega.example.com"}`,
			status: host.StatusWarn,
			want:   []string{"tls_domain"},
		},
		{
			name:   "custom_paths, which gated nothing",
			body:   `{"config_version":1,"custom_paths":true}`,
			status: host.StatusWarn,
			want:   []string{"custom_paths"},
		},
		{
			name:   "every retired key at once",
			body:   `{"config_version":1,"tls_autocert":true,"tls_domain":"x.example.com","custom_paths":true}`,
			status: host.StatusWarn,
			want:   []string{"tls_autocert", "tls_domain", "custom_paths"},
		},
		{
			// A key at its zero value says nothing was asked for. Reporting it
			// would make the shipped template warn on a fresh install.
			name:   "zero values are not settings",
			body:   `{"config_version":1,"tls_autocert":false,"tls_domain":"","custom_paths":false}`,
			status: host.StatusOK,
			absent: []string{"tls_autocert", "tls_domain", "custom_paths"},
		},
		{
			name:   "nothing retired",
			body:   `{"config_version":1,"region":"us-east-1"}`,
			status: host.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv(config.EnvConfigFile, path)

			f := retiredConfigKeys(&globalFlags{})
			if f.Status != tc.status {
				t.Fatalf("status = %s, want %s: %s", f.Status, tc.status, f.Detail)
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Detail, want) {
					t.Errorf("detail does not name %q: %s", want, f.Detail)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(f.Detail, absent) {
					t.Errorf("detail names %q, which is held at its zero value: %s", absent, f.Detail)
				}
			}
		})
	}
}

// A config carrying a retired key loads rather than being refused: an install
// that upgrades must keep starting, and the report is what tells the operator
// to clean it up.
func TestARetiredKeyDoesNotRefuseTheConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"config_version":1,"custom_paths":false,"apt_root":"/srv/apt","tls_domain":"x.example.com"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("a config carrying a retired key was refused: %v", err)
	}
	// The per-type root is honored whatever custom_paths said, which is what
	// builder.rootFor already did and why deleting the flag moves nobody's
	// artifacts.
	if cfg.AptRoot != "/srv/apt" {
		t.Errorf("apt_root = %q, want /srv/apt; custom_paths: false must not suppress it", cfg.AptRoot)
	}
}

// reportRetiredTLSKeys is the server's own half, logged at startup. It read
// back one of the two keys, so an install carrying tls_domain alone said
// nothing.
func TestServeReportsTLSDomainFromTheConfigFile(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"tls_domain alone", `{"config_version":1,"tls_domain":"bodega.example.com"}`, "tls_domain"},
		{"tls_autocert alone", `{"config_version":1,"tls_autocert":true}`, "tls_autocert"},
		{"both", `{"config_version":1,"tls_autocert":true,"tls_domain":"x.example.com"}`, "tls_domain"},
		{"empty tls_domain is not a setting", `{"config_version":1,"tls_domain":""}`, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv(config.EnvConfigFile, path)
			cfg, err := config.Load("", "", "", "", false, false)
			if err != nil {
				t.Fatalf("load: %v", err)
			}

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			reportRetiredTLSKeys(cfg, nil, logger)

			switch {
			case tc.want == "" && buf.Len() != 0:
				t.Errorf("reported a key held at its zero value: %s", buf.String())
			case tc.want != "" && !strings.Contains(buf.String(), tc.want):
				t.Errorf("startup report does not name %s: %s", tc.want, buf.String())
			}
		})
	}
}
