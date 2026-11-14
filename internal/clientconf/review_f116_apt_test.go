package clientconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func TestReviewF116APTHTTPCRLRefusesCAPlan(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "bodega.example.com::"} {
		t.Run(scope, func(t *testing.T) {
			home := t.TempDir()
			file := filepath.Join(home, "etc/apt/apt.conf")
			before := "Acquire::http::" + scope + "CrlFile \"/corp/revocations.crl\";\n"
			writeUnder(t, home, map[string]string{"etc/apt/apt.conf": before})
			f := File{System: manifest.TypeApt, Paths: map[string]string{OSLinux: AptSourcesPath}, Content: "Types: deb\nURIs: " + testBase + "/apt\nSuites: stable\nComponents: main\n"}
			h := CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"), Getenv: func(string) string { return "" }}
			in, err := AddCA(caPlan(t, home, f), ca, h)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "crl") || len(in.Changes) != 0 || len(in.Step) != 0 {
				t.Errorf("APT HTTPS inherits Acquire::http::%sCrlFile; want refusal before a CA plan, got err=%v changes=%d step=%v", scope, err, len(in.Changes), in.Step)
			}
			if got, err := os.ReadFile(file); err != nil || string(got) != before {
				t.Errorf("changed CRL policy: %v %q", err, got)
			}
		})
	}
}
