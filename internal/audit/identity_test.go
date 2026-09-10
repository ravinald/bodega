package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func newIdentityTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// One CIDR resolves to at most one identity, and the second write is what
// says so. Resolving it at read time would mean the answer depended on row
// order, which nothing about the table guarantees.
func TestBindingRefusesASecondIdentityForOneKey(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)

	for _, b := range []IdentityBinding{
		{Kind: BindCIDR, Key: "10.20.0.0/16", Identity: "devbox"},
		{Kind: BindToken, Key: "abc123", Identity: "build-07"},
	} {
		if ok, err := db.AddIdentityBinding(ctx, b); err != nil || !ok {
			t.Fatalf("seed %s %s: ok=%v err=%v", b.Kind, b.Key, ok, err)
		}
	}

	for _, tc := range []struct {
		name string
		want IdentityBinding
		says string
	}{
		{"cidr", IdentityBinding{Kind: BindCIDR, Key: "10.20.0.0/16", Identity: "ci"}, "devbox"},
		{"token", IdentityBinding{Kind: BindToken, Key: "abc123", Identity: "ci"}, "build-07"},
		// Masked to the same key, so the same refusal, and this is the
		// spelling an operator reaches for.
		{"unmasked cidr", IdentityBinding{Kind: BindCIDR, Key: "10.20.5.9/16", Identity: "ci"}, "devbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := db.AddIdentityBinding(ctx, tc.want)
			if ok || err == nil {
				t.Fatalf("second binding accepted (ok=%v, err=%v); the read path would have to break the tie", ok, err)
			}
			if !IsBindingConflict(err) {
				t.Fatalf("refused with %T, want a *BindingConflict so the CLI can print it", err)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("refusal does not name the binding it collided with (%q):\n%s", tc.says, err)
			}
		})
	}
}

// Requirement 3's refusal. Two /8s covering 10.0.0.1 are the same network
// spelled two ways, and NormalizeBindCIDR is what makes them one key: the
// refusal an operator sees names the key collision, and the equal-prefix
// overlap check never has to fire on a write that came through here.
func TestBindingRefusesEqualPrefixCoveringTheSameAddress(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)

	if ok, err := db.AddIdentityBinding(ctx, IdentityBinding{
		Kind: BindCIDR, Key: "10.0.0.0/8", Identity: "fleet",
	}); err != nil || !ok {
		t.Fatalf("first binding: ok=%v err=%v", ok, err)
	}

	ok, err := db.AddIdentityBinding(ctx, IdentityBinding{
		Kind: BindCIDR, Key: "::ffff:10.0.0.0/104", Identity: "other",
	})
	if ok || err == nil {
		t.Fatalf("::ffff:10.0.0.0/104 accepted alongside 10.0.0.0/8 (ok=%v, err=%v); they are one network", ok, err)
	}
	if !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("refusal does not name the first binding:\n%s", err)
	}
	if !strings.Contains(err.Error(), `already bound to "fleet"`) {
		t.Fatalf("refusal does not read as the key collision normalization makes it:\n%s", err)
	}

	// A different prefix length over the same addresses is legal: that is what
	// longest-prefix resolution is for.
	if ok, err := db.AddIdentityBinding(ctx, IdentityBinding{
		Kind: BindCIDR, Key: "10.20.0.0/16", Identity: "devbox",
	}); err != nil || !ok {
		t.Fatalf("a longer prefix inside the first was refused: ok=%v err=%v", ok, err)
	}
}

// Rebinding to the identity it already has is what a config-management run
// does every hour. It must not be an error.
func TestBindingRebindToSameIdentityIsANoOp(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	b := IdentityBinding{Kind: BindCIDR, Key: "192.168.4.0/24", Identity: "lab"}
	if ok, err := db.AddIdentityBinding(ctx, b); err != nil || !ok {
		t.Fatalf("first: ok=%v err=%v", ok, err)
	}
	ok, err := db.AddIdentityBinding(ctx, b)
	if err != nil {
		t.Fatalf("rebinding to the same identity failed: %v", err)
	}
	if ok {
		t.Fatal("rebinding reported a write; it should report that nothing changed")
	}
}

func TestNormalizeBindCIDR(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.5/8", "10.0.0.0/8"},
		{"10.0.0.5", "10.0.0.5/32"},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8"},
		{"2001:db8::1/64", "2001:db8::/64"},
	} {
		got, err := NormalizeBindCIDR(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got.String() != tc.want {
			t.Fatalf("%s normalized to %s, want %s", tc.in, got, tc.want)
		}
	}
	if _, err := NormalizeBindCIDR("not-an-address"); err == nil {
		t.Fatal("a non-address was accepted as a CIDR binding key")
	}
}

// CIDRBindingCount is what bodega serve asks before it binds a listener, so it
// must count CIDR bindings and nothing else.
func TestCIDRBindingCountIgnoresTokenBindings(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	if _, err := db.AddIdentityBinding(ctx, IdentityBinding{Kind: BindToken, Key: "t1", Identity: "a"}); err != nil {
		t.Fatalf("token binding: %v", err)
	}
	n, err := db.CIDRBindingCount(ctx)
	if err != nil || n != 0 {
		t.Fatalf("count with only a token binding = %d, %v; want 0", n, err)
	}
	if _, err := db.AddIdentityBinding(ctx, IdentityBinding{Kind: BindCIDR, Key: "10.0.0.0/8", Identity: "a"}); err != nil {
		t.Fatalf("cidr binding: %v", err)
	}
	if n, err = db.CIDRBindingCount(ctx); err != nil || n != 1 {
		t.Fatalf("count = %d, %v; want 1", n, err)
	}
}

// Requirement 5 at the storage layer: the identity lands beside the address,
// and neither displaces the other.
func TestEventAndDiscoveryRowsCarryIdentityBesideTheAddress(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)

	if err := db.Record(ctx, Event{
		EventType: EventServeFetch, PkgType: "npm", PkgName: "left-pad",
		ClientIP: "10.20.0.9", Identity: "devbox-3", Status: "success",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	events, err := db.Query(ctx, Filter{Identity: "devbox-3"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("filtering on identity returned %d rows, want 1", len(events))
	}
	if events[0].ClientIP != "10.20.0.9" || events[0].Identity != "devbox-3" {
		t.Fatalf("row lost one of the two: ip=%q identity=%q", events[0].ClientIP, events[0].Identity)
	}

	if n, err := db.RecordDiscovery(ctx, DiscoveryRow{
		RegistryType: "npm", PatternHint: "left-pad", PkgName: "left-pad",
		Decision: DecisionAllowed, LastClient: "10.20.0.9", LastIdentity: "devbox-3",
	}); err != nil || n != 1 {
		t.Fatalf("record discovery: n=%d err=%v", n, err)
	}
	rows, err := db.ListDiscovery(ctx, DiscoveryFilter{RegistryType: "npm"})
	if err != nil {
		t.Fatalf("list discovery: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("discovery returned %d rows, want 1", len(rows))
	}
	if rows[0].LastClient != "10.20.0.9" || rows[0].LastIdentity != "devbox-3" {
		t.Fatalf("discovery row lost one of the two: client=%q identity=%q", rows[0].LastClient, rows[0].LastIdentity)
	}
}
