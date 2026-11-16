package main

import (
	"os"
	"os/exec"

	"github.com/ravinald/bodega/internal/oracletest"
	"path/filepath"
	"strings"
	"testing"
)

func TestReview47EncodedQueryCredential(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review47-query-password-marker"
	before := "[global]\nindex-url=https://packages.example/simple/?%74oken=" + secret + "\n"
	if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, apply := range [][]string{nil, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
		if err != nil {
			t.Fatalf("valid plan control: %v\n%s", err, out)
		}
		if !strings.Contains(out, "index-url") {
			t.Fatalf("no diff: %s", out)
		}
		if strings.Contains(out, secret) {
			t.Errorf("apply=%v exposes encoded query credential:\n%s", apply, out)
		}
		if len(apply) == 0 {
			got, err := os.ReadFile(f.config)
			if err != nil || string(got) != before {
				t.Fatalf("preview wrote policy: %v", err)
			}
		}
	}
}

func TestReview47EncodedQueryCredentialOrdinaryReport(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review47-report-password-marker"
	t.Setenv("GOPROXY", "ftp://bodega.internal/proxy?%74oken="+secret)
	oldExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = oldExit })
	out, err := runDoctor(t, "--url", f.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "goproxy-env ") {
			continue
		}
		if !strings.Contains(line, "WARN") || !strings.Contains(line, "invalid proxy URL scheme") || !strings.Contains(line, "unchecked") {
			t.Fatalf("refusal control: %s", line)
		}
		if strings.Contains(out, secret) {
			t.Errorf("ordinary report exposes encoded credential: %s", line)
		}
		return
	}
	t.Fatal("ordinary report omitted goproxy-env")
}

func TestReview47EscapedNpmCredential(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearClientEnv(t)
	stubRuntimes(t)
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "issuer.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, ".npmrc")
	const secret = "review47-npm-password-marker"
	before := `registry="https:\u002f\u002freview-user:` + secret + `@creds.example/repo/"` + "\n"
	if err := os.WriteFile(file, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, apply := range [][]string{nil, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "npm", "--ca-file", caFile, "--url", srv.URL}, apply...)...)
		if err != nil {
			t.Fatalf("loadable npm plan control: %v\n%s", err, out)
		}
		if !strings.Contains(out, "registry=") {
			t.Fatalf("no registry diff: %s", out)
		}
		if strings.Contains(out, secret) {
			t.Errorf("apply=%v exposes escaped userinfo:\n%s", apply, out)
		}
		if len(apply) == 0 {
			got, err := os.ReadFile(file)
			if err != nil || string(got) != before {
				t.Fatalf("preview wrote policy: %v", err)
			}
		}
	}
}

func TestReview47NpmEscapedRegistryNative(t *testing.T) {
	npm := oracletest.Npm(t)
	for _, tc := range []struct {
		name, value, want string
		protected         bool
	}{
		{"escaped credential", `"https:\u002f\u002freview-user:review47-npm-password-marker@creds.example/repo/"`, "", true},
		{"plain credential", `https://review-user:review47-npm-password-marker@creds.example/repo/`, "", true},
		{"escaped without credential", `"https:\u002f\u002fcreds.example/repo/"`, "https://creds.example/repo/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			file := filepath.Join(home, ".npmrc")
			if err := os.WriteFile(file, []byte("registry="+tc.value+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(npm, "config", "get", "registry")
			cmd.Dir = home
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NPM_CONFIG_GLOBALCONFIG=" + filepath.Join(home, "absent")}
			got, err := cmd.CombinedOutput()
			if tc.protected {
				if err == nil || !strings.Contains(string(got), "The registry option is protected") {
					t.Fatalf("native npm did not recognize registry credentials: %q, %v", got, err)
				}
			} else if err != nil || strings.TrimSpace(string(got)) != tc.want {
				t.Fatalf("native npm did not decode registry: %q, %v", got, err)
			}
		})
	}
}
