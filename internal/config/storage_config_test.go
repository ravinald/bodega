package config_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// writeConfig points Load at a config file containing body.
func writeConfig(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)
	t.Setenv(config.EnvBucket, "")
	t.Setenv(config.EnvRegion, "")
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvListenAddr, "")
}

// withDrivers installs a driver registry for the duration of the test.
// internal/storage does this from init in the real binary; this package cannot
// import it without a cycle.
func withDrivers(t *testing.T, names ...string) {
	t.Helper()
	prev := config.StorageDrivers
	config.StorageDrivers = func() []string { return names }
	t.Cleanup(func() { config.StorageDrivers = prev })
}

// TestLoadWithoutNamedBackendsResolvesToDefault is the back-compat guard. A
// config written before named backends existed has to load and behave exactly
// as it did: one backend, no placement rules, nothing to resolve.
func TestLoadWithoutNamedBackendsResolvesToDefault(t *testing.T) {
	withDrivers(t, "local", "s3")
	writeConfig(t, `{"storage_backend":"local","storage_path":"/var/lib/bodega"}`)

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.StorageBackends) != 0 {
		t.Errorf("StorageBackends = %v, want empty", cfg.StorageBackends)
	}
	if len(cfg.StorageByType) != 0 {
		t.Errorf("StorageByType = %v, want empty", cfg.StorageByType)
	}
	if cfg.StorageBackend != "local" || cfg.StoragePath != "/var/lib/bodega" {
		t.Errorf("storage_backend/storage_path = %q/%q, want local//var/lib/bodega",
			cfg.StorageBackend, cfg.StoragePath)
	}
}

func TestLoadRejectsBackendNameCollisions(t *testing.T) {
	withDrivers(t, "local", "s3")
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "reserved default",
			body: `{"storage_backends":{"default":{"driver":"local","path":"/tmp/x"}}}`,
			want: "reserved for the backend defined by",
		},
		{
			name: "driver name as backend name",
			body: `{"storage_backends":{"s3":{"driver":"s3","bucket":"b"}}}`,
			want: "that is a storage driver, not a backend name",
		},
		{
			name: "missing driver",
			body: `{"storage_backends":{"bulk":{"path":"/tmp/x"}}}`,
			want: "driver is required",
		},
		{
			name: "unknown driver",
			body: `{"storage_backends":{"bulk":{"driver":"gcs"}}}`,
			want: `unknown driver "gcs"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeConfig(t, tc.body)
			_, err := config.Load("", "", "", "", false, false)
			if err == nil {
				t.Fatalf("Load accepted %s", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestLoadRejectsDanglingStorageByType pins the failure at load rather than at
// the upload that would use the name. Discovered mid-upload it has already
// decided where an artifact went.
func TestLoadRejectsDanglingStorageByType(t *testing.T) {
	withDrivers(t, "local", "s3")
	writeConfig(t, `{
	  "storage_backends": {"bulk": {"driver":"local","path":"/mnt/bulk"}},
	  "storage_by_type": {"apt": "archive"}
	}`)

	_, err := config.Load("", "", "", "", false, false)
	if err == nil {
		t.Fatal("Load accepted storage_by_type naming an undefined backend")
	}
	for _, want := range []string{`storage_by_type["apt"]`, `"archive"`, "defined: default, bulk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// TestLoadAcceptsDefaultAsAStorageByTypeValue keeps the reserved name usable
// where it is a value rather than a key: naming it is how an operator pins one
// type to the original backend while moving the rest.
func TestLoadAcceptsDefaultAsAStorageByTypeValue(t *testing.T) {
	withDrivers(t, "local", "s3")
	writeConfig(t, `{
	  "storage_backends": {"bulk": {"driver":"local","path":"/mnt/bulk"}},
	  "storage_by_type": {"apt": "default", "pypi": "bulk"}
	}`)

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StorageByType["apt"] != "default" {
		t.Errorf("storage_by_type[apt] = %q, want default", cfg.StorageByType["apt"])
	}
}

// TestLoadRejectsNonCanonicalPrefix pins the admission half of #189. A prefix
// is operator-facing and was unvalidated, so "cold/x" and "cold//x" over one
// storage_path were two backend identities over one directory: the same-
// location refusal in 'bodega pkg move' could not fire and --delete-source
// removed the only copy. Label() now cleans the prefix, and cleaning is only
// truthful because these spellings never reach it.
func TestLoadRejectsNonCanonicalPrefix(t *testing.T) {
	withDrivers(t, "local", "s3")
	cases := []struct {
		name   string
		prefix string
		want   string
	}{
		{"empty segment", "cold//x", `write it as "cold/x"`},
		{"leading dot segment", "./cold/x", `write it as "cold/x"`},
		{"interior traversal", "cold/y/../x", "leaves the backend root"},
		{"leading traversal", "../cold/x", "leaves the backend root"},
		{"bare dot", ".", "names no location"},
		{"doubled leading slash", "//cold/x", `write it as "cold/x"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeConfig(t, `{"storage_backends":{"bulk":{"driver":"local","path":"/tmp/x","prefix":`+
				strconv.Quote(tc.prefix)+`}}}`)
			_, err := config.Load("", "", "", "", false, false)
			if err == nil {
				t.Fatalf("Load accepted prefix %q", tc.prefix)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestLoadAcceptsPrefixSpellingsWithPrefixStrips guards the other direction.
// withPrefix strips a leading and a trailing "/" itself, so those are the same
// prefix rather than a second spelling of it, and refusing them would break
// configs that load today.
func TestLoadAcceptsPrefixSpellingsWithPrefixStrips(t *testing.T) {
	withDrivers(t, "local", "s3")
	for _, prefix := range []string{"", "/", "cold/x", "/cold/x", "cold/x/", "/cold/x/"} {
		t.Run(strconv.Quote(prefix), func(t *testing.T) {
			writeConfig(t, `{"storage_backends":{"bulk":{"driver":"local","path":"/tmp/x","prefix":`+
				strconv.Quote(prefix)+`}}}`)
			if _, err := config.Load("", "", "", "", false, false); err != nil {
				t.Fatalf("Load rejected prefix %q: %v", prefix, err)
			}
		})
	}
}
