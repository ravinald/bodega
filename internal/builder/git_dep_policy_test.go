package builder

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in test")
}

// TestFetchGitHonorsDepPolicy fetches one local repository carrying a
// requirements.txt and a go.mod under each dep_policy value, with
// AutoImportDeps on as the CLI sets it, and asserts which manifests the fetch
// left in the store.
func TestFetchGitHonorsDepPolicy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	saved := descClient
	descClient = &http.Client{Transport: failTransport{}}
	t.Cleanup(func() { descClient = saved })

	src := t.TempDir()
	gitIn(t, src, "-c", "init.defaultBranch=main", "init", "-q")
	files := map[string]string{
		"requirements.txt": "requests==2.31.0\n",
		"go.mod":           "module example.com/demo\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n",
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(src, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, src, "add", ".")
	gitIn(t, src, "-c", "user.email=e2e@bodega.test", "-c", "user.name=bodega", "commit", "-q", "-m", "v1.0.0")
	gitIn(t, src, "tag", "v1.0.0")

	tests := []struct {
		policy     string
		wantImport bool
		wantErr    bool
	}{
		{policy: ""},
		{policy: "none"},
		{policy: "direct", wantImport: true},
		{policy: "transitive", wantImport: true},
		{policy: "drect", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("policy="+tt.policy, func(t *testing.T) {
			store := manifest.NewLocalStore(t.TempDir())
			ve := manifest.VersionEntry{URL: src, Ref: "v1.0.0", Source: "clone"}
			if err := store.AddVersion(t.Context(), manifest.TypeGit, "demo", ve); err != nil {
				t.Fatal(err)
			}
			pm, err := store.GetPackage(t.Context(), manifest.TypeGit, "demo")
			if err != nil || pm == nil {
				t.Fatalf("GetPackage: %v", err)
			}
			pm.DepPolicy = tt.policy
			if err := store.SavePackage(t.Context(), pm); err != nil {
				t.Fatal(err)
			}

			var log strings.Builder
			cfg := &Config{
				BuildRoot:      t.TempDir(),
				BuildEnvInfo:   &manifest.BuildEnv{Platform: "linux/arm64"},
				Stdout:         &log,
				AutoImportDeps: true,
			}
			sum := FetchGit(cfg, store, "demo")

			if tt.wantErr {
				if sum.Failures != 1 || len(sum.Results) != 1 || sum.Results[0].Err == nil {
					t.Fatalf("unknown dep_policy fetched: failures=%d results=%+v\n%s", sum.Failures, sum.Results, log.String())
				}
				msg := sum.Results[0].Err.Error()
				for _, want := range []string{"git/demo", `"drect"`, `"none"`, `"direct"`, `"transitive"`} {
					if !strings.Contains(msg, want) {
						t.Errorf("error %q does not name %s", msg, want)
					}
				}
				if cfg.LastDiscovery != nil {
					t.Errorf("unknown dep_policy still scanned: %+v", cfg.LastDiscovery)
				}
			} else if sum.Failures != 0 {
				t.Fatalf("fetch failed: %+v\n%s", sum.Results, log.String())
			}

			for _, m := range []struct{ typ, name string }{
				{manifest.TypePypi, "requests"},
				{manifest.TypeGomod, "example.com/dep"},
			} {
				got, err := store.GetPackage(t.Context(), m.typ, m.name)
				if err != nil {
					t.Fatalf("GetPackage %s/%s: %v", m.typ, m.name, err)
				}
				if (got != nil) != tt.wantImport {
					t.Errorf("%s/%s in store = %v, want %v\n%s", m.typ, m.name, got != nil, tt.wantImport, log.String())
				}
			}

			if tt.wantErr || tt.wantImport {
				return
			}
			if cfg.LastDiscovery == nil || len(cfg.LastDiscovery.Deps) != 2 {
				t.Errorf("LastDiscovery = %+v, want the 2 scanned deps", cfg.LastDiscovery)
			}
			if !strings.Contains(log.String(), `2 dependencies found (2 new), none imported: dep_policy is `) ||
				!strings.Contains(log.String(), `"direct" or "transitive" would import them`) {
				t.Errorf("fetch did not report the unimported deps:\n%s", log.String())
			}
		})
	}
}
