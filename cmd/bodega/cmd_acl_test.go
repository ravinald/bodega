package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

func aclTestDB(t *testing.T) *audit.DB {
	t.Helper()
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// There are three lists and the caller has to name one. Cobra would answer
// "unknown command"; the operator needs the three names and a command to type.
func TestACLBareAddIsRefused(t *testing.T) {
	cmd := newACLCmd(&globalFlags{})
	cmd.SetArgs([]string{"add", "10.0.0.0/8"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil {
		t.Fatal("bodega acl add <cidr> was accepted; it names no list")
	}
	msg := err.Error()
	for _, want := range []string{"admin", "deny", "proxies", "bodega acl admin add 10.0.0.0/8"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not mention %q:\n%s", want, msg)
		}
	}
}

func TestACLListSubcommandsExist(t *testing.T) {
	cmd := newACLCmd(&globalFlags{})
	for _, list := range []string{"admin", "deny", "proxies"} {
		sub, _, err := cmd.Find([]string{list, "add"})
		if err != nil {
			t.Fatalf("bodega acl %s add: %v", list, err)
		}
		if sub.Name() != "add" {
			t.Errorf("bodega acl %s add resolved to %q", list, sub.Name())
		}
		for _, verb := range []string{"remove", "list"} {
			if sub, _, err := cmd.Find([]string{list, verb}); err != nil || sub.Name() != verb {
				t.Errorf("bodega acl %s %s did not resolve: %v", list, verb, err)
			}
		}
	}
}

// Widening past localhost turns on the Bearer requirement. With no token
// issued, the next mutation is a 401 that names nothing.
func TestCheckAdminWidening(t *testing.T) {
	ctx := context.Background()
	db := aclTestDB(t)

	if err := checkAdminWidening(ctx, db, []string{"127.0.0.0/8"}, "::1/128"); err != nil {
		t.Errorf("a still-localhost-only result was refused: %v", err)
	}

	err := checkAdminWidening(ctx, db, []string{"127.0.0.0/8"}, "10.0.0.0/8")
	if err == nil {
		t.Fatal("widening past localhost with no tokens was accepted; the next mutation would 401")
	}
	for _, want := range []string{"bodega token generate", "--force", "401"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q:\n%s", want, err)
		}
	}

	if err := db.InsertToken(ctx, "id1", "ci", "hash", "", nil); err != nil {
		t.Fatalf("insert token: %v", err)
	}
	if err := checkAdminWidening(ctx, db, []string{"127.0.0.0/8"}, "10.0.0.0/8"); err != nil {
		t.Errorf("widening with a token issued was refused: %v", err)
	}
}

func TestNormalizeCIDR(t *testing.T) {
	cases := map[string]string{
		"10.0.0.0/8":  "10.0.0.0/8",
		"10.0.0.1/8":  "10.0.0.0/8", // host bits masked, so add and remove agree
		"192.168.1.5": "192.168.1.5/32",
		"::1":         "::1/128",
	}
	for in, want := range cases {
		got, err := normalizeCIDR(in)
		if err != nil {
			t.Errorf("normalizeCIDR(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "not-an-address", "10.0.0.0/64"} {
		if _, err := normalizeCIDR(bad); err == nil {
			t.Errorf("normalizeCIDR(%q) was accepted", bad)
		}
	}
}

func TestACLChangeIsAudited(t *testing.T) {
	ctx := context.Background()
	db := aclTestDB(t)
	recordACLChange(ctx, db, audit.EventCreate, audit.ACLAdmin, "10.0.0.0/8", "add", false)
	recordACLChange(ctx, db, audit.EventDelete, audit.ACLDeny, "203.0.113.0/24", "remove", true)

	rows, err := db.Query(ctx, audit.Filter{PkgType: "acl"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("acl audit rows = %d, want 2", len(rows))
	}
	byList := map[string]audit.StoredEvent{}
	for _, r := range rows {
		byList[r.PkgName] = r
	}
	add, ok := byList[audit.ACLAdmin]
	if !ok {
		t.Fatal("no row for the admin list")
	}
	if add.PkgVersion != "10.0.0.0/8" || add.EventType != audit.EventCreate ||
		!strings.Contains(add.Details, "direction=add") || add.Actor == "" {
		t.Errorf("admin row does not carry list, CIDR, direction and actor: %+v", add)
	}
	del := byList[audit.ACLDeny]
	if !strings.Contains(del.Details, "direction=remove") || !strings.Contains(del.Details, "force=true") {
		t.Errorf("remove row does not record the direction and the override: %+v", del)
	}
}

// Removing the last admin entry locks out both halves of the admin surface,
// including the command that would undo it.
func TestCheckAdminLockout(t *testing.T) {
	if err := checkAdminLockout([]string{"127.0.0.0/8", "::1/128"}, "::1/128"); err != nil {
		t.Errorf("removing one of two entries was refused: %v", err)
	}
	err := checkAdminLockout([]string{"127.0.0.0/8"}, "127.0.0.0/8")
	if err == nil {
		t.Fatal("removing the last admin entry was accepted; every mutation would 403")
	}
	for _, want := range []string{"last entry", "/api/v1/audit", "bodega acl admin add", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q:\n%s", want, err)
		}
	}
	// An entry that is not in the list leaves the list as it stands.
	if err := checkAdminLockout([]string{"127.0.0.0/8"}, "10.0.0.0/8"); err != nil {
		t.Errorf("removing an absent entry was refused: %v", err)
	}
}

// trusted_proxies is the list whose widening defeats the other two: bodega
// returns X-Real-IP verbatim from any peer in it, so admitting a private range
// hands the mutation API to anything on that network no matter how narrow
// admin_permit_cidr looks. The narrowing direction already says so out loud.
func TestWarnProxyWidening(t *testing.T) {
	ctx := context.Background()
	db := aclTestDB(t)
	localhostOnly := &config.Config{AdminPermitCIDR: []string{"127.0.0.0/8", "::1/128"}}

	warn, err := warnProxyWidening(ctx, db, localhostOnly, "10.0.0.0/8")
	if err != nil {
		t.Fatalf("warnProxyWidening: %v", err)
	}
	if warn == "" {
		t.Fatal("no warning for an RFC 1918 range added while admin is localhost-only")
	}
	for _, want := range []string{"X-Real-IP: 127.0.0.1", "10.0.0.0/8", "no token", "bodega acl proxies add"} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning does not name %q:\n%s", want, warn)
		}
	}

	// The proxy's own address is the shape the warning recommends.
	if warn, _ := warnProxyWidening(ctx, db, localhostOnly, "127.0.0.1/32"); warn != "" {
		t.Errorf("loopback warned: %s", warn)
	}
	if warn, _ := warnProxyWidening(ctx, db, localhostOnly, "198.51.100.7/32"); warn != "" {
		t.Errorf("a public address warned: %s", warn)
	}
	// An admin list already past localhost is not the case this guards.
	wide := &config.Config{AdminPermitCIDR: []string{"10.0.0.0/8"}}
	if warn, _ := warnProxyWidening(ctx, db, wide, "192.168.0.0/16"); warn != "" {
		t.Errorf("warned with a non-localhost admin list: %s", warn)
	}
	// A /8 added as a narrower slice of one is still inside the private range.
	if warn, _ := warnProxyWidening(ctx, db, localhostOnly, "172.16.5.0/24"); warn == "" {
		t.Error("no warning for a /24 inside 172.16.0.0/12")
	}
}

// A row the CIDR parser cannot read can only have arrived before this shipped,
// and `acl remove` refuses its own argument on the way to deleting it. --raw
// is the repair path; without one, every already-poisoned install stays broken.
func TestACLRemoveRawDeletesAnUnparseableRow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"audit_db":`+strconv.Quote(dbPath)+`}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	db, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if _, err := db.SeedACL(ctx, audit.ACLAdmin, []string{"127.0.0.0/8", "10.0.0.0/833"}, "test"); err != nil {
		t.Fatalf("seed the poisoned list: %v", err)
	}
	_ = db.Close()

	// Without --raw the command refuses its own argument, and says where to go.
	if _, err := runACL(t, "admin", "remove", "10.0.0.0/833"); err == nil {
		t.Fatal("remove without --raw accepted an unparseable argument")
	} else if !strings.Contains(err.Error(), "--raw") {
		t.Errorf("the refusal does not name --raw:\n%s", err)
	}

	out, err := runACL(t, "admin", "remove", "--raw", "10.0.0.0/833")
	if err != nil {
		t.Fatalf("remove --raw: %v\n%s", err, out)
	}
	db, err = audit.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen audit db: %v", err)
	}
	defer db.Close()
	cidrs, err := db.ACLCIDRs(ctx, audit.ACLAdmin)
	if err != nil {
		t.Fatalf("read admin list: %v", err)
	}
	if len(cidrs) != 1 || cidrs[0] != "127.0.0.0/8" {
		t.Errorf("admin list = %v, want only 127.0.0.0/8 left", cidrs)
	}
}

// runACL drives the real cobra command, so the flag registration and the
// argument validation are under test rather than the helper beneath them.
func runACL(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newACLCmd(&globalFlags{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// --raw is on all three lists: any of them can hold a row planted before the
// seed-time parse existed.
func TestACLRemoveRawFlagOnEveryList(t *testing.T) {
	cmd := newACLCmd(&globalFlags{})
	for _, list := range []string{"admin", "deny", "proxies"} {
		sub, _, err := cmd.Find([]string{list, "remove"})
		if err != nil {
			t.Fatalf("bodega acl %s remove: %v", list, err)
		}
		if sub.Flags().Lookup("raw") == nil {
			t.Errorf("bodega acl %s remove has no --raw", list)
		}
	}
}
