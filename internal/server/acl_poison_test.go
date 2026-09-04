package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// One typo in admin_permit_cidr used to poison a fresh install permanently:
// seedACLs copied the raw strings in before Start applied its refusal, so the
// table was marked database-owned with a row no parser can read, and the
// refusal that followed named only the config file.
func TestSeedRefusesUnparseableAdminList(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{AdminPermitCIDR: []string{"10.0.0.0/833"}})
	owned, err := s.auditDB.ACLSeeded(ctx, audit.ACLAdmin)
	if err != nil {
		t.Fatalf("seeded: %v", err)
	}
	if owned {
		cidrs, _ := s.auditDB.ACLCIDRs(ctx, audit.ACLAdmin)
		t.Fatalf("admin list claimed for the database with %v; a list ParseDenyList cannot read must not be copied", cidrs)
	}
	// Start's refusal still fires, and it is now the whole repair.
	if _, err := parseAdminPermitCIDR([]string{"10.0.0.0/833"}); err == nil {
		t.Error("parseAdminPermitCIDR accepted 10.0.0.0/833")
	}
}

// A good list still seeds. The refusal must not cost the working path.
func TestSeedStillCopiesAParseableList(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{AdminPermitCIDR: []string{"127.0.0.0/8", "10.0.0.0/8"}})
	owned, err := s.auditDB.ACLSeeded(ctx, audit.ACLAdmin)
	if err != nil || !owned {
		t.Fatalf("admin owned = %v, %v; want the parseable list copied in", owned, err)
	}
	cidrs, _ := s.auditDB.ACLCIDRs(ctx, audit.ACLAdmin)
	if len(cidrs) != 2 {
		t.Errorf("admin entries = %v, want both copied", cidrs)
	}
}

// The already-poisoned install: a table that holds a bad row before this
// change shipped. Discarding the whole list fell back to the config file the
// database already outranks, so every later `bodega acl admin` change was
// inert while reporting success. Skipping the row lets the rest take effect.
func TestPoisonedRowIsSkippedNotFatal(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{AdminPermitCIDR: []string{"127.0.0.0/8"}})
	// Poison it the way a pre-fix start did, past the CLI's validation.
	if _, err := s.auditDB.AddACL(ctx, audit.ACLEntry{
		List: audit.ACLAdmin, CIDR: "10.0.0.0/833", Actor: "test",
	}); err != nil {
		t.Fatalf("plant the bad row: %v", err)
	}
	if _, err := s.auditDB.AddACL(ctx, audit.ACLEntry{
		List: audit.ACLAdmin, CIDR: "192.0.2.5/32", Actor: "test",
	}); err != nil {
		t.Fatalf("add a good row: %v", err)
	}
	s.refreshACLs(ctx)

	admin := s.aclNow().admin
	if len(admin) != 2 {
		t.Fatalf("admin nets = %v, want the two readable rows with the bad one skipped", admin)
	}
	h := s.handler()
	if code := getPath(t, h, "/api/v1/config", "192.0.2.5:1234"); code != http.StatusOK {
		t.Errorf("/api/v1/config from a row added after the poisoning = %d, want 200", code)
	}

	// And a later removal takes effect, which is the defect stated plainly.
	if _, err := s.auditDB.RemoveACL(ctx, audit.ACLAdmin, "192.0.2.5/32"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	s.refreshACLs(ctx)
	if code := getPath(t, h, "/api/v1/config", "192.0.2.5:1234"); code != http.StatusForbidden {
		t.Errorf("/api/v1/config after removing that row = %d, want 403: the change was inert", code)
	}
}

// parseACLEntries is the partition ParseDenyList cannot express. Pinned
// directly because both callers depend on the bad entries coming back as
// their raw text: that text is what `acl remove --raw` has to be given.
func TestParseACLEntriesPartitions(t *testing.T) {
	nets, bad := parseACLEntries([]string{"127.0.0.1", "10.0.0.0/833", "10.0.0.0/8", "nope"})
	if len(nets) != 2 {
		t.Errorf("parsed = %v, want the two readable entries", nets)
	}
	want := []string{"10.0.0.0/833", "nope"}
	if len(bad) != len(want) {
		t.Fatalf("bad = %v, want %v", bad, want)
	}
	for i := range want {
		if bad[i] != want[i] {
			t.Errorf("bad[%d] = %q, want %q (the raw text `acl remove --raw` needs)", i, bad[i], want[i])
		}
	}
}
