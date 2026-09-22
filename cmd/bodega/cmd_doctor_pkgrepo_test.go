package main

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/pkgrepos"
)

func statusWith(t *testing.T, states ...pkgrepos.State) pkgClientStatus {
	t.Helper()
	out := pkgClientStatus{PublicURL: "https://bodega.internal"}
	for _, st := range states {
		st.PublicURL = out.PublicURL
		rendered, err := pkgrepos.Render(st)
		if err != nil {
			out.Refused = append(out.Refused, pkgRepoRefusal{Repo: st.Repo, ABI: st.ABI, Error: err.Error()})
			continue
		}
		out.Repos = append(out.Repos, rendered)
	}
	return out
}

func TestPkgRepoForABIPicksTheOneMatchingEntry(t *testing.T) {
	st := statusWith(t,
		pkgrepos.State{ABI: "FreeBSD:14:amd64", Repo: "latest", Upstream: "https://u/14"},
		pkgrepos.State{ABI: "FreeBSD:15:aarch64", Repo: "latest", Upstream: "https://u/15"},
	)
	got, err := pkgRepoForABI(st, "FreeBSD:15:aarch64")
	if err != nil {
		t.Fatalf("pkgRepoForABI: %v", err)
	}
	if got.ABI != "FreeBSD:15:aarch64" {
		t.Fatalf("picked %s; a host installs the file for its own ABI and no other", got.ABI)
	}
	if !strings.Contains(got.Conf, "FreeBSD-ports-kmods: { enabled: no }") {
		t.Errorf("the 15 conf does not disable the split tags:\n%s", got.Conf)
	}
}

// Several repositories for one ABI is the operator's decision, not the
// server's. Naming one would point a host at a repository nobody chose, and
// the file it lands in reads as authoritative.
func TestPkgRepoForABIRefusesWhenSeveralAnswer(t *testing.T) {
	st := statusWith(t,
		pkgrepos.State{ABI: "FreeBSD:14:amd64", Repo: "latest", Upstream: "https://u/latest"},
		pkgrepos.State{ABI: "FreeBSD:14:amd64", Repo: "quarterly", Upstream: "https://u/quarterly"},
	)
	_, err := pkgRepoForABI(st, "FreeBSD:14:amd64")
	if err == nil {
		t.Fatal("picked one of two repositories for the same ABI")
	}
	for _, want := range []string{"latest", "quarterly"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot choose: %v", want, err)
		}
	}
}

// A server serving other ABIs names them. "no repository" and "no repository
// for your architecture" are different problems with different next steps.
func TestPkgRepoForABINamesWhatItDoesServe(t *testing.T) {
	st := statusWith(t, pkgrepos.State{ABI: "FreeBSD:14:amd64", Repo: "latest", Upstream: "https://u/14"})
	_, err := pkgRepoForABI(st, "FreeBSD:15:aarch64")
	if err == nil {
		t.Fatal("returned a configuration for an ABI this bodega does not serve")
	}
	if !strings.Contains(err.Error(), "latest@FreeBSD:14:amd64") {
		t.Errorf("the refusal does not name what is served: %v", err)
	}
}

// An entry the renderer refused is reported as that rather than as absent.
// Absent sends the operator to `pkg create`; refused sends them to the
// manifest field that contradicts itself.
func TestPkgRepoForABISurfacesARefusedEntry(t *testing.T) {
	st := statusWith(t, pkgrepos.State{
		ABI: "FreeBSD:14:amd64", Repo: "muddle", Generated: true, Upstream: "https://u/14",
	})
	_, err := pkgRepoForABI(st, "FreeBSD:14:amd64")
	if err == nil {
		t.Fatal("returned a configuration for an entry the renderer refused")
	}
	if !strings.Contains(err.Error(), "muddle") || !strings.Contains(err.Error(), "generated") {
		t.Errorf("the refusal does not carry the renderer's reason: %v", err)
	}
}

func TestPkgRepoForABIOnAServerWithNoFreeBSDEntries(t *testing.T) {
	_, err := pkgRepoForABI(pkgClientStatus{}, "FreeBSD:14:amd64")
	if err == nil {
		t.Fatal("returned a configuration from a server serving no pkg repository")
	}
	if !strings.Contains(err.Error(), "no pkg repository") {
		t.Errorf("unhelpful refusal: %v", err)
	}
}
