package builder

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// TestFetchAptHonorsDepPolicy runs a policy entry through FetchApt under each
// dep_policy value against an apt-cache shim whose answer differs with and
// without --recurse, and asserts which dependencies the fetch left in the
// store. An unknown value used to discover the direct set and report success.
func TestFetchAptHonorsDepPolicy(t *testing.T) {
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "argv.log")
	write := func(name, body string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("direct.txt", "hello\n  Depends: libfoo\n", 0o600)
	write("recurse.txt", "hello\n  Depends: libfoo\nlibfoo\n  Depends: libbar\n", 0o600)
	write("apt-cache", "#!/bin/sh\necho \"$@\" >> "+argvLog+"\n"+
		"[ \"$1\" = depends ] || exit 0\n"+
		"case \"$*\" in *--recurse*) cat "+dir+"/recurse.txt ;; *) cat "+dir+"/direct.txt ;; esac\n", 0o700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	tests := []struct {
		policy  string
		want    []string
		wantErr bool
	}{
		{policy: "direct", want: []string{"libfoo"}},
		{policy: "transitive", want: []string{"libfoo", "libbar"}},
		{policy: "trasnitive", wantErr: true},
		{policy: "Direct", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("policy="+tt.policy, func(t *testing.T) {
			_ = os.Remove(argvLog)
			// The frozen concrete version keeps the fetch from resolving or
			// downloading, so the policy entry's discovery is all that runs.
			cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
				Type:      manifest.TypeApt,
				Name:      "hello",
				DepPolicy: tt.policy,
				Versions: []manifest.VersionEntry{
					{Version: "*", VersionConstraint: manifest.ConstraintAny, SourceName: "hello"},
					{Version: "2.10-2", Frozen: true},
				},
			})
			var log strings.Builder
			cfg.Stdout = &log

			sum := FetchApt(cfg, store, "hello")

			if tt.wantErr {
				if sum.Failures != 1 || len(sum.Results) != 1 || sum.Results[0].Err == nil {
					t.Fatalf("unknown dep_policy fetched: failures=%d results=%+v\n%s", sum.Failures, sum.Results, log.String())
				}
				msg := sum.Results[0].Err.Error()
				for _, want := range []string{"apt/hello", strconv.Quote(tt.policy), `"none"`, `"direct"`, `"transitive"`} {
					if !strings.Contains(msg, want) {
						t.Errorf("error %q does not name %s", msg, want)
					}
				}
				if !strings.Contains(log.String(), "ERROR") || !strings.Contains(log.String(), strconv.Quote(tt.policy)) {
					t.Errorf("log does not report the refusal at ERROR:\n%s", log.String())
				}
				if argv := readArgv(t, argvLog); argv != "" {
					t.Errorf("unknown dep_policy still ran apt-cache: %q", argv)
				}
			} else if sum.Failures != 0 {
				t.Fatalf("fetch failed: %+v\n%s", sum.Results, log.String())
			}

			for _, dep := range []string{"libfoo", "libbar"} {
				got, err := store.GetPackage(t.Context(), manifest.TypeApt, dep)
				if err != nil {
					t.Fatalf("GetPackage apt/%s: %v", dep, err)
				}
				want := false
				for _, w := range tt.want {
					want = want || w == dep
				}
				if (got != nil) != want {
					t.Errorf("apt/%s in store = %v, want %v\n%s", dep, got != nil, want, log.String())
				}
			}
		})
	}
}
