package audit

import (
	"context"
	"path/filepath"
	"testing"
)

func newACLTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// The tri-state has to survive the store, not just the JSON. "No rows" is the
// answer to two different questions, and only the acl_lists marker tells them
// apart.
func TestACLTrustedProxiesTriState(t *testing.T) {
	ctx := context.Background()

	t.Run("absent", func(t *testing.T) {
		db := newACLTestDB(t)
		owned, err := db.ACLSeeded(ctx, ACLProxies)
		if err != nil {
			t.Fatalf("seeded: %v", err)
		}
		if owned {
			t.Fatal("a fresh database claims to own trusted_proxies; the config file must still decide")
		}
	})

	t.Run("explicitly empty", func(t *testing.T) {
		db := newACLTestDB(t)
		if _, err := db.SeedACL(ctx, ACLProxies, nil, "ravi"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		owned, err := db.ACLSeeded(ctx, ACLProxies)
		if err != nil {
			t.Fatalf("seeded: %v", err)
		}
		if !owned {
			t.Fatal("an explicitly empty trusted_proxies did not survive the store; it now reads as unset")
		}
		cidrs, err := db.ACLCIDRs(ctx, ACLProxies)
		if err != nil {
			t.Fatalf("cidrs: %v", err)
		}
		if len(cidrs) != 0 {
			t.Fatalf("entries = %v, want none", cidrs)
		}
	})

	t.Run("populated", func(t *testing.T) {
		db := newACLTestDB(t)
		if _, err := db.SeedACL(ctx, ACLProxies, []string{"127.0.0.1/32"}, "ravi"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		owned, err := db.ACLSeeded(ctx, ACLProxies)
		if err != nil || !owned {
			t.Fatalf("seeded = %v, %v; want true", owned, err)
		}
		cidrs, err := db.ACLCIDRs(ctx, ACLProxies)
		if err != nil {
			t.Fatalf("cidrs: %v", err)
		}
		if len(cidrs) != 1 || cidrs[0] != "127.0.0.1/32" {
			t.Fatalf("entries = %v, want [127.0.0.1/32]", cidrs)
		}
	})
}

// An emptied list is still owned: removing the last trusted proxy means trust
// nobody, not "fall back to the RFC 1918 default".
func TestACLEmptiedListStaysOwned(t *testing.T) {
	ctx := context.Background()
	db := newACLTestDB(t)
	if _, err := db.SeedACL(ctx, ACLProxies, []string{"127.0.0.1/32"}, "ravi"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	removed, err := db.RemoveACL(ctx, ACLProxies, "127.0.0.1/32")
	if err != nil || !removed {
		t.Fatalf("remove = %v, %v; want true", removed, err)
	}
	owned, err := db.ACLSeeded(ctx, ACLProxies)
	if err != nil || !owned {
		t.Fatalf("seeded after emptying = %v, %v; want true", owned, err)
	}
}

func TestACLSeedIsOnce(t *testing.T) {
	ctx := context.Background()
	db := newACLTestDB(t)
	first, err := db.SeedACL(ctx, ACLAdmin, []string{"127.0.0.0/8"}, "ravi")
	if err != nil || !first {
		t.Fatalf("first seed = %v, %v; want true", first, err)
	}
	second, err := db.SeedACL(ctx, ACLAdmin, []string{"10.0.0.0/8"}, "ravi")
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if second {
		t.Fatal("a second seed rewrote a list the database already owned")
	}
	cidrs, err := db.ACLCIDRs(ctx, ACLAdmin)
	if err != nil {
		t.Fatalf("cidrs: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "127.0.0.0/8" {
		t.Fatalf("entries = %v, want the first seed's [127.0.0.0/8]", cidrs)
	}
}

func TestACLAddRemove(t *testing.T) {
	ctx := context.Background()
	db := newACLTestDB(t)
	if _, err := db.SeedACL(ctx, ACLDeny, nil, ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	added, err := db.AddACL(ctx, ACLEntry{List: ACLDeny, CIDR: "203.0.113.0/24", Comment: "scanner", Actor: "ravi"})
	if err != nil || !added {
		t.Fatalf("add = %v, %v; want true", added, err)
	}
	dup, err := db.AddACL(ctx, ACLEntry{List: ACLDeny, CIDR: "203.0.113.0/24"})
	if err != nil {
		t.Fatalf("duplicate add: %v", err)
	}
	if dup {
		t.Error("a duplicate add reported as a new entry")
	}
	entries, err := db.ListACL(ctx, ACLDeny)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Comment != "scanner" || entries[0].Actor != "ravi" {
		t.Fatalf("entries = %+v, want one entry carrying its comment and actor", entries)
	}
	if entries[0].CreatedAt.IsZero() {
		t.Error("created_at did not parse")
	}
	gone, err := db.RemoveACL(ctx, ACLDeny, "203.0.113.0/24")
	if err != nil || !gone {
		t.Fatalf("remove = %v, %v; want true", gone, err)
	}
	missing, err := db.RemoveACL(ctx, ACLDeny, "203.0.113.0/24")
	if err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if missing {
		t.Error("removing an absent entry reported success")
	}
}

func TestACLUnknownListRejected(t *testing.T) {
	ctx := context.Background()
	db := newACLTestDB(t)
	if _, err := db.ACLSeeded(ctx, "admins"); err == nil {
		t.Error("a misspelled list name was accepted")
	}
	if _, err := db.AddACL(ctx, ACLEntry{List: "proxy", CIDR: "10.0.0.0/8"}); err == nil {
		t.Error("a misspelled list name was accepted on add")
	}
}

func TestACLMigrationTables(t *testing.T) {
	db := newACLTestDB(t)
	for _, tbl := range []string{"acl_lists", "acl_entries"} {
		var name string
		if err := db.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&name); err != nil {
			t.Errorf("missing table %s: %v", tbl, err)
		}
	}
}
