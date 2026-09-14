package server

import (
	"strings"
	"testing"
)

// filterHelmIndex walks the entries block and copies lines through. A
// top-level key written after that block — which `helm repo index` does write,
// and which the doc comment claims this function handles — survived a
// keep-everything pass and disappeared once the last release above it was
// dropped.
//
// Unreachable through handleHelmIndex, which serves only what
// builder.PackageHelm writes and that writes no trailing key. The first caller
// feeding it an upstream index meets it.
func TestFilterHelmIndexKeepsATrailingTopLevelKey(t *testing.T) {
	const doc = `apiVersion: v1
entries:
  cert-manager:
  - name: cert-manager
    version: 1.14.0
    urls:
    - charts/cert-manager-1.14.0.tgz
  - name: cert-manager
    version: 1.15.0
    urls:
    - charts/cert-manager-1.15.0.tgz
generated: "2026-09-13T00:00:00Z"
`

	cases := []struct {
		name        string
		permit      func(chart, version string) bool
		wantVersion []string
		dropVersion []string
	}{
		{
			name:        "keep everything",
			permit:      func(string, string) bool { return true },
			wantVersion: []string{"1.14.0", "1.15.0"},
		},
		{
			name:        "drop the last release above the trailing key",
			permit:      func(_, version string) bool { return version != "1.15.0" },
			wantVersion: []string{"1.14.0"},
			dropVersion: []string{"1.15.0"},
		},
		{
			name:        "drop every release",
			permit:      func(string, string) bool { return false },
			dropVersion: []string{"1.14.0", "1.15.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(filterHelmIndex([]byte(doc),
				func(string) bool { return true }, tc.permit))

			if !strings.Contains(got, `generated: "2026-09-13T00:00:00Z"`) {
				t.Errorf("the trailing top-level key did not survive:\n%s", got)
			}
			if !strings.Contains(got, "apiVersion: v1") {
				t.Errorf("the leading top-level key did not survive:\n%s", got)
			}
			for _, v := range tc.wantVersion {
				if !strings.Contains(got, "version: "+v) {
					t.Errorf("permitted release %s was dropped:\n%s", v, got)
				}
			}
			for _, v := range tc.dropVersion {
				if strings.Contains(got, "version: "+v) {
					t.Errorf("refused release %s was served:\n%s", v, got)
				}
			}
		})
	}
}
