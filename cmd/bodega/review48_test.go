package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/oracletest"
)

func TestReview48PipQueryCommaPreviewApply(t *testing.T) {
	for _, suffix := range []string{"?token=prefix,review48-secret-marker", "#prefix,review48-secret-marker"} {
		t.Run(suffix[:1], func(t *testing.T) {
			f := review44PipSetup(t)
			before := "[global]\nindex-url=https://packages.example/simple/" + suffix + "\n"
			if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
				t.Fatal(err)
			}
			for _, apply := range [][]string{nil, {"--apply"}} {
				out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
				if err != nil {
					t.Fatalf("valid plan control: %v\n%s", err, out)
				}
				if !strings.Contains(out, "-index-url=https://packages.example/simple/") {
					t.Fatalf("missing removed location diff: %s", out)
				}
				if strings.Contains(out, "review48-secret-marker") {
					t.Errorf("apply=%v prints query/fragment bytes as a list member:\n%s", apply, out)
				}
				if len(apply) == 0 {
					if got, err := os.ReadFile(f.config); err != nil || string(got) != before {
						t.Fatalf("preview changed policy: %v\n%s", err, got)
					}
				}
			}
		})
	}
}

func TestReview48PipQueryCommaRefusal(t *testing.T) {
	f := review44PipSetup(t)
	before := "[install]\nindex-url=https://packages.example/simple/?token=prefix,review48-secret-marker\n"
	if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, apply := range [][]string{nil, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
		if err == nil || !strings.Contains(err.Error(), "under [install]") || !strings.Contains(err.Error(), "https://packages.example/simple/") {
			t.Fatalf("wrong refusal: %v\n%s", err, out)
		}
		if strings.Contains(out+err.Error(), "review48-secret-marker") {
			t.Errorf("apply=%v leaks query in refusal: %v\n%s", apply, err, out)
		}
		if got, err := os.ReadFile(f.config); err != nil || string(got) != before {
			t.Fatalf("refusal changed policy: %v\n%s", err, got)
		}
	}
}

func TestReview48PipQueryCommaOrdinaryReport(t *testing.T) {
	f := review44PipSetup(t)
	file := filepath.Join(f.home, ".config/pip/pip.conf")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	before := "[global]\nindex-url=" + f.base + "/pypi/simple/\ncert=" + f.issuer + "\nfind-links=" + strings.Replace(f.base, "https://", "http://", 1) + "/demo.whl?token=prefix,review48-secret-marker\n"
	if err := os.WriteFile(file, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	oldExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = oldExit })
	out, err := runDoctor(t, "--url", f.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "pip-config ") {
			continue
		}
		if !strings.Contains(line, "bodega.internal") || !strings.Contains(line, "find-links") || !strings.Contains(line, "plain http") || !strings.Contains(line, "unchecked") || !strings.Contains(line, "WARN") {
			t.Fatalf("report did not consume credential-bearing index: %s", line)
		}
		if strings.Contains(out, "review48-secret-marker") {
			t.Errorf("ordinary report leaks query: %s", line)
		}
		return
	}
	t.Fatal("report omitted pip-config")
}

func TestReview48PipQueryCommaNative(t *testing.T) {
	python := oracletest.Pip(t)
	cmd := exec.Command(python, "-c", `
from pip._vendor.requests import Request
from urllib.parse import urlsplit
u = Request("GET", "https://packages.example/simple/?token=prefix,review48-secret-marker").prepare().url
p = urlsplit(u)
assert p.hostname == "packages.example", u
assert p.path == "/simple/", u
assert p.query == "token=prefix,review48-secret-marker", u
print("comma remains in the query")
`)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "comma remains in the query" {
		t.Fatalf("native request control: %v\n%s", err, out)
	}
}
