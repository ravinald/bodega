package tui

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// TestTUIFetchRefusesBlockedUpstream drives the TUI's own fetch stage against
// an allow-list that names a different crate. builderCfg left Policy nil, and
// Config.EnforcePolicy returns nil on a nil checker, so a crate `bodega build
// fetch` refused was downloaded by `bodega shell` with nothing printed and no
// audit row written.
//
// cargo is the type under test because it is also the one `bodega pkg package`
// reaches through ensureFetchedCargo; all eight fetchers call EnforcePolicy on
// their own entries, so the wiring this proves is the same for each.
//
// The crate is not on disk and no upstream is configured: reaching the network
// at all would be the failure, since the refusal is decided before any fetch.
func TestTUIFetchRefusesBlockedUpstream(t *testing.T) {
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeCargo,
		Name:     "serde",
		Versions: []manifest.VersionEntry{{Version: "1.0.210"}},
	}
	cfg, store, db, _ := pinEnv(t, pm)

	if err := db.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "cargo-anyhow",
		RegistryType: manifest.TypeCargo,
		RuleKind:     policy.KindPackage,
		Pattern:      "anyhow",
	}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}

	msg := executeStage(StageFetch, manifest.TypeCargo, "serde", cfg, store, nil, db)()
	out, ok := msg.(cmdOutputMsg)
	if !ok {
		t.Fatalf("executeStage returned %T, want cmdOutputMsg", msg)
	}
	if out.err == nil {
		t.Fatalf("a blocked crate fetched clean through the TUI\n%s", out.output)
	}
	// app.go appends out.output to the log pane, so this is what the operator
	// reads; the error alone names a count and not the rule that refused.
	if !strings.Contains(out.output, "BLOCKED by policy") {
		t.Errorf("log pane output = %q, want the refusal in it", out.output)
	}

	events, err := db.Query(t.Context(), audit.Filter{
		EventType: audit.EventFetch,
		PkgType:   manifest.TypeCargo,
		PkgName:   "serde",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("a refused TUI fetch wrote %d audit rows, want 1\n%s", len(events), out.output)
	}
	if events[0].Status != "policy_violation" {
		t.Errorf("audit row status = %q, want policy_violation", events[0].Status)
	}
}
