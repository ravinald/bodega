package main

import (
	"os"
	"strings"
	"testing"
)

func TestReview46PipPlanRedactsQueryCredential(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review46-query-password-marker"
	before := "[global]\nindex-url=https://packages.example/simple/?token=" + secret + "\n"
	if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, apply := range [][]string{nil, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
		if err != nil {
			t.Fatalf("valid plan control: %v\n%s", err, out)
		}
		if !strings.Contains(out, "index-url") {
			t.Fatalf("no configuration diff: %s", out)
		}
		if strings.Contains(out, secret) {
			t.Errorf("apply=%v preview exposes query credential:\n%s", apply, out)
		}
		if len(apply) == 0 {
			got, err := os.ReadFile(f.config)
			if err != nil || string(got) != before {
				t.Fatalf("preview wrote policy: %v", err)
			}
		}
	}
}

func TestReview46PipPreflightRedactsCommandIndex(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review46-userinfo-password-marker"
	before := "[install]\nindex-url=https://review-user:" + secret + "@packages.example/simple/\n"
	if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, apply := range [][]string{nil, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
		if err == nil || !strings.Contains(err.Error(), "command's own section") || !strings.Contains(err.Error(), f.config) {
			t.Fatalf("command-scope refusal control: %v\n%s", err, out)
		}
		if strings.Contains(out+err.Error(), secret) {
			t.Errorf("apply=%v preflight exposes userinfo: %v\n%s", apply, err, out)
		}
		got, e := os.ReadFile(f.config)
		if e != nil || string(got) != before {
			t.Fatalf("refusal wrote policy: %v", e)
		}
	}
}

func TestReview46GoOrdinaryReportRedactsQueryCredential(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review46-go-query-password-marker"
	t.Setenv("GOPROXY", "ftp://review-user:discarded-password@bodega.internal/proxy?token="+secret)
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
			t.Errorf("ordinary report exposes query credential: %s", line)
		}
		return
	}
	t.Fatal("ordinary report omitted goproxy-env")
}
