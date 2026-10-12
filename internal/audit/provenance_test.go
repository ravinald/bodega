package audit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestProvenancePolicyAndPin(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.GetProvenancePolicy(ctx, "npm"); !errors.Is(err, ErrProvenancePolicyNotFound) {
		t.Fatalf("unset policy: %v", err)
	}
	if err := db.SetProvenancePolicy(ctx, ProvenancePolicy{Ecosystem: "npm", Action: "block", Actor: "ravi"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProvenancePolicy(ctx, ProvenancePolicy{Ecosystem: "npm", Action: "allow"}); err == nil {
		t.Error("an action outside warn|block|ignore was stored")
	}
	if p, err := db.GetProvenancePolicy(ctx, "npm"); err != nil || p.Action != "block" || p.Actor != "ravi" {
		t.Errorf("policy = %+v, %v", p, err)
	}
	if list, err := db.ListProvenancePolicies(ctx); err != nil || len(list) != 1 {
		t.Errorf("list = %+v, %v", list, err)
	}

	first := ProvenancePin{PkgType: "npm", PkgName: "sigstore", SourceRepositoryURI: "https://github.com/sigstore/sigstore-js",
		BuilderID: "https://github.com/actions/runner/github-hosted", PinnedVersion: "3.0.0"}
	got, created, err := db.PinProvenance(ctx, first)
	if err != nil || !created || got.SourceRepositoryURI != first.SourceRepositoryURI {
		t.Fatalf("first pin = %+v, %v, %v", got, created, err)
	}
	other := first
	other.SourceRepositoryURI, other.PinnedVersion = "https://github.com/example/fork", "3.1.0"
	got, created, err = db.PinProvenance(ctx, other)
	if err != nil || created || got.SourceRepositoryURI != first.SourceRepositoryURI || got.PinnedVersion != "3.0.0" {
		t.Fatalf("second pin replaced the first: %+v, %v, %v", got, created, err)
	}
	old, err := db.ResetProvenancePin(ctx, "npm", "sigstore")
	if err != nil || old.SourceRepositoryURI != first.SourceRepositoryURI {
		t.Fatalf("reset = %+v, %v", old, err)
	}
	if _, err := db.GetProvenancePin(ctx, "npm", "sigstore"); !errors.Is(err, ErrProvenancePinNotFound) {
		t.Errorf("pin after reset: %v", err)
	}
	if _, err := db.ResetProvenancePin(ctx, "npm", "sigstore"); !errors.Is(err, ErrProvenancePinNotFound) {
		t.Errorf("second reset: %v", err)
	}
	if _, created, _ := db.PinProvenance(ctx, other); !created {
		t.Error("the version after a reset did not pin afresh")
	}
}

// A pin with no decision lists the upstream provenance check as not
// evaluated, like every other check, rather than leaving it out.
func TestUnadmittedPinListsUpstreamProvenance(t *testing.T) {
	for _, c := range NotEvaluatedChecks("x") {
		if c.Check == CheckUpstreamProvenance && c.Status == CheckNotEvaluated {
			return
		}
	}
	t.Error("NotEvaluatedChecks leaves out upstream_provenance")
}
