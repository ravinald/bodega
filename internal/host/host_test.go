package host

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFirstHit covers the substring-scan logic that underlies every
// client-config check. The per-check functions are thin wrappers; testing
// firstHit directly avoids OS-state dependencies.
func TestFirstHit(t *testing.T) {
	dir := t.TempDir()

	clean := filepath.Join(dir, "clean.conf")
	if err := os.WriteFile(clean, []byte("index-url = http://bodega.internal/pypi/simple/\n"), 0o644); err != nil {
		t.Fatalf("write clean: %v", err)
	}

	dirty := filepath.Join(dir, "dirty.conf")
	if err := os.WriteFile(dirty, []byte("index-url = https://pypi.org/simple/\n"), 0o644); err != nil {
		t.Fatalf("write dirty: %v", err)
	}

	tests := []struct {
		name       string
		paths      []string
		markers    []string
		wantPath   string
		wantMarker string
	}{
		{
			name:    "no markers match",
			paths:   []string{clean},
			markers: publicUpstreams["pip"],
		},
		{
			name:       "first file matches",
			paths:      []string{dirty, clean},
			markers:    publicUpstreams["pip"],
			wantPath:   dirty,
			wantMarker: "pypi.org",
		},
		{
			name:       "later file matches when earlier missing",
			paths:      []string{filepath.Join(dir, "missing"), dirty},
			markers:    publicUpstreams["pip"],
			wantPath:   dirty,
			wantMarker: "pypi.org",
		},
		{
			name:    "missing files only",
			paths:   []string{filepath.Join(dir, "nope")},
			markers: publicUpstreams["pip"],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstHit(tt.paths, tt.markers)
			if got.path != tt.wantPath {
				t.Errorf("path: got %q want %q", got.path, tt.wantPath)
			}
			if got.marker != tt.wantMarker {
				t.Errorf("marker: got %q want %q", got.marker, tt.wantMarker)
			}
		})
	}
}

// TestCheckGoproxyEnv exercises every branch of the GOPROXY classifier. Env
// var manipulation is isolated via t.Setenv (auto-restored on cleanup).
func TestCheckGoproxyEnv(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		unset  bool
		want   Status
	}{
		{name: "unset", unset: true, want: StatusWarn},
		{name: "direct fallthrough", value: "http://bodega/gomod,direct", want: StatusWarn},
		{name: "references proxy.golang.org", value: "https://proxy.golang.org,direct", want: StatusWarn},
		{name: "bodega-only with off", value: "http://bodega/gomod,off", want: StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unset {
				t.Setenv("GOPROXY", "")
				// t.Setenv to empty string still sets it; explicit unset:
				_ = os.Unsetenv("GOPROXY")
			} else {
				t.Setenv("GOPROXY", tt.value)
			}
			got := CheckGoproxyEnv()
			if got.Status != tt.want {
				t.Errorf("status: got %v want %v (detail=%q)", got.Status, tt.want, got.Detail)
			}
		})
	}
}

// TestFindingIsFinding verifies the boolean classification used by the
// doctor command's exit-code logic.
func TestFindingIsFinding(t *testing.T) {
	cases := []struct {
		status Status
		want   bool
	}{
		{StatusOK, false},
		{StatusNA, false},
		{StatusWarn, true},
		{StatusFail, true},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			if got := (Finding{Status: c.status}).IsFinding(); got != c.want {
				t.Errorf("IsFinding(%v) = %v want %v", c.status, got, c.want)
			}
		})
	}
}

// TestAllChecksRunCleanly exercises every registered check on the host
// running the tests. The goal is not to assert a particular status (which
// depends on the host) but to ensure no check panics, leaks file handles,
// or returns an empty Check field.
func TestAllChecksRunCleanly(t *testing.T) {
	for _, fn := range AllChecks() {
		f := fn()
		if f.Check == "" {
			t.Errorf("check returned empty Check identifier: %+v", f)
		}
		if f.Status == "" {
			t.Errorf("check %q returned empty Status: %+v", f.Check, f)
		}
		if f.Detail == "" {
			t.Errorf("check %q returned empty Detail: %+v", f.Check, f)
		}
	}
}
