package main

import (
	"context"
	"regexp"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
)

// A token minted on the CLI records the invoking user as its creator, which
// the override quorum reads to discount a vote cast on it by that user's
// request. approve and superadmin are accepted by name.
func TestTokenGenerateRecordsCreator(t *testing.T) {
	dbPath, _ := osquerySecretEnv(t)
	t.Setenv("SUDO_USER", "alice")

	gen := newTokenGenerateCmd(&globalFlags{})
	if err := gen.Flags().Set("scope", "read,approve,superadmin"); err != nil {
		t.Fatal(err)
	}
	var runErr error
	out := captureStdout(t, func() { runErr = gen.RunE(gen, []string{"oncall"}) })
	if runErr != nil {
		t.Fatalf("generate: %v\n%s", runErr, out)
	}
	id := regexp.MustCompile(`ID:\s+([0-9a-f]{32})`).FindStringSubmatch(out)
	if id == nil {
		t.Fatalf("generate printed no id:\n%s", out)
	}

	adb, err := audit.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	tokens, err := adb.ListTokens(context.Background())
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens = %+v, %v; want the one minted", tokens, err)
	}
	if got := tokens[0]; got.ID != id[1] || got.CreatedBy != "alice" || got.Scope != "read,approve,superadmin" {
		t.Errorf("stored token = %+v, want id %s created by alice with scope read,approve,superadmin", got, id[1])
	}
}
