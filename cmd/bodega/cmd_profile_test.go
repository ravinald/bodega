package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// runProfile drives the command tree the way an operator does, so a refusal
// that lives in the wrong layer cannot pass by being unreachable.
func runProfile(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newProfileCmd(&globalFlags{})
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true

	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	execErr := cmd.Execute()
	_ = w.Close()
	os.Stdout = stdout
	var printed bytes.Buffer
	_, _ = printed.ReadFrom(r)
	return printed.String() + out.String(), execErr
}

// seedCatalog writes packages carrying an origin, through the same accessor
// `bodega pkg convert --origin` writes it with.
func seedCatalog(t *testing.T, env *discoverEnv, origin string, pkgs map[string][]string) {
	t.Helper()
	ctx := context.Background()
	store := manifest.NewLocalStore(env.manifestDir)
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("load index: %v", err)
	}
	for name, versions := range pkgs {
		pm := &manifest.PackageManifest{
			ConfigVersion: manifest.CurrentConfigVersion,
			Name:          name,
			Type:          manifest.TypePypi,
		}
		for _, v := range versions {
			pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: v})
		}
		if err := admit.ApplyOrigin(pm, origin); err != nil {
			t.Fatalf("apply origin: %v", err)
		}
		if err := store.SavePackage(ctx, pm); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("save index: %v", err)
	}
}

func mustRunProfile(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runProfile(t, args...)
	if err != nil {
		t.Fatalf("bodega profile %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// A closed type with nothing listed permits nothing of that type. It is
// reachable, it is almost never meant, and the refusal follows the empty
// admin_permit_cidr precedent: name what the flag does rather than only
// refusing.
func TestProfileClosedAndEmptyIsRefusedWithoutForce(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")

	out, err := runProfile(t, "set", "web", "apt", "--membership", "closed")
	if err == nil {
		t.Fatalf("a closed apt marker with no entries was accepted:\n%s", out)
	}
	msg := err.Error()
	for _, want := range []string{"permits nothing", "--force", "bodega profile add web apt", "--membership open"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, msg)
		}
	}

	if _, err := runProfile(t, "set", "web", "apt", "--membership", "closed", "--force"); err != nil {
		t.Fatalf("--force did not accept the state the refusal says it accepts: %v", err)
	}
	if out := mustRunProfile(t, "show", "web"); !strings.Contains(out, "Closed for apt with nothing listed") {
		t.Errorf("show does not report the forced state, so it reads like a profile nobody consults:\n%s", out)
	}
}

// Removing the last entry of a closed type reaches the same state by the more
// likely route, so it meets the same refusal.
func TestProfileRemovingTheLastEntryOfAClosedTypeIsRefused(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "apt", "nginx")
	mustRunProfile(t, "set", "web", "apt", "--membership", "closed")

	if _, err := runProfile(t, "remove", "web", "apt", "nginx"); err == nil {
		t.Fatal("removing the last entry of a closed type was accepted, leaving it permitting nothing")
	}
	if _, err := runProfile(t, "remove", "web", "apt", "nginx", "--force"); err != nil {
		t.Fatalf("--force did not accept the removal: %v", err)
	}
}

// --from-origin refuses to create anything. The baseline goes through a file
// so a host's accidents get read before they become a control.
func TestProfileFromOriginRefusesWithoutAFile(t *testing.T) {
	env := newDiscoverEnv(t)
	seedCatalog(t, env, "db01", map[string][]string{"requests": {"2.31.0"}})

	_, err := runProfile(t, "create", "web", "--from-origin", "db01")
	if err == nil {
		t.Fatal("--from-origin created a profile directly")
	}
	for _, want := range []string{"--out", "--from-file", "accidents"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, err)
		}
	}

	if _, err := runProfile(t, "create", "web", "--from-origin", "db01", "--out", "-"); err == nil {
		t.Fatal("--out - was accepted; a baseline piped straight on was never read by anyone")
	}
	if _, err := runProfile(t, "create", "web", "--from-file", "-"); err == nil {
		t.Fatal("--from-file - was accepted")
	}
}

// The baseline names what the host was cataloged with, defaults every entry to
// name-only `any`, and pins only what --pin names.
func TestProfileFromOriginBaselineAndCreate(t *testing.T) {
	env := newDiscoverEnv(t)
	seedCatalog(t, env, "db01", map[string][]string{
		"requests": {"2.31.0"},
		"psycopg2": {"2.9.9"},
	})
	seedCatalog(t, env, "web01", map[string][]string{"django": {"5.0"}})

	baseline := filepath.Join(t.TempDir(), "db.json")
	out := mustRunProfile(t, "create", "db", "--from-origin", "db01", "--out", baseline, "--pin", "psycopg2")
	if !strings.Contains(out, "Nothing was created") {
		t.Errorf("the baseline step does not say it created nothing:\n%s", out)
	}

	blob, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var doc profileDoc
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	if len(doc.Entries) != 2 {
		t.Fatalf("the baseline holds %d entries, want the 2 cataloged from db01: %+v", len(doc.Entries), doc.Entries)
	}
	for _, e := range doc.Entries {
		if e.Name == "django" {
			t.Error("the baseline carries a package cataloged from another host")
		}
		if e.Name == "requests" {
			if e.Constraint != manifest.ConstraintAny || e.Version != "" {
				t.Errorf("an unpinned entry is not name-only: %+v", e)
			}
		}
		if e.Name == "psycopg2" {
			if e.Constraint != manifest.ConstraintExact || e.Version != "2.9.9" {
				t.Errorf("--pin did not pin: %+v", e)
			}
		}
	}
	if len(doc.Types) != 1 || doc.Types[0].Membership != audit.MembershipClosed ||
		doc.Types[0].VersionDefault != audit.VersionFloating {
		t.Errorf("the baseline's type marker is not closed+floating: %+v", doc.Types)
	}

	if _, err := runProfile(t, "create", "db", "--from-file", baseline); err != nil {
		t.Fatalf("create from the baseline: %v", err)
	}
	shown := mustRunProfile(t, "show", "db")
	for _, want := range []string{"psycopg2", "2.9.9", "requests", "closed", "floating"} {
		if !strings.Contains(shown, want) {
			t.Errorf("show does not carry %q:\n%s", want, shown)
		}
	}
}

// A pin has to name one version. The host reporting two is the operator's
// decision to make, not the generator's.
func TestProfilePinOfATwoVersionPackageIsRefused(t *testing.T) {
	env := newDiscoverEnv(t)
	seedCatalog(t, env, "db01", map[string][]string{"requests": {"2.31.0", "2.32.0"}})

	_, err := runProfile(t, "create", "db", "--from-origin", "db01",
		"--out", filepath.Join(t.TempDir(), "db.json"), "--pin", "requests")
	if err == nil {
		t.Fatal("--pin picked one of two cataloged versions")
	}
	for _, want := range []string{"2.31.0", "2.32.0", "bodega profile pin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, err)
		}
	}
}

// A pin with no reason outlives the problem it was written for.
func TestProfilePinRequiresAReason(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")

	if _, err := runProfile(t, "pin", "web", "apt", "postgresql", "14.11"); err == nil {
		t.Fatal("a pin with no reason was accepted")
	}
	mustRunProfile(t, "pin", "web", "apt", "postgresql", "14.11", "--reason", "15 breaks the config")

	out := mustRunProfile(t, "show", "web")
	if !strings.Contains(out, "15 breaks the config") {
		t.Errorf("show does not carry the reason, so nobody can tell a deliberate hold from an accident:\n%s", out)
	}

	mustRunProfile(t, "unpin", "web", "apt", "postgresql")
	out = mustRunProfile(t, "show", "web")
	if strings.Contains(out, "exact") {
		t.Errorf("unpin left the constraint in place:\n%s", out)
	}
	if !strings.Contains(out, "postgresql") {
		t.Errorf("unpin removed the entry; releasing a pin keeps the package listed:\n%s", out)
	}
}

// check is the CI gate: an entry naming a package the catalog does not hold,
// or a version it does not carry, exits non-zero.
func TestProfileCheckFailsOnAnEntryThatStoppedResolving(t *testing.T) {
	env := newDiscoverEnv(t)
	seedCatalog(t, env, "db01", map[string][]string{"requests": {"2.31.0"}})
	mustRunProfile(t, "create", "db")
	mustRunProfile(t, "add", "db", "pypi", "requests")

	if out, err := runProfile(t, "check"); err != nil {
		t.Fatalf("check failed on a profile whose entries resolve: %v\n%s", err, out)
	}

	mustRunProfile(t, "pin", "db", "pypi", "requests", "9.9.9", "--reason", "held")
	out, err := runProfile(t, "check")
	if err == nil {
		t.Fatalf("check passed on a pin the catalog cannot serve:\n%s", out)
	}
	if !strings.Contains(out, "9.9.9") {
		t.Errorf("the violation does not name the version:\n%s", out)
	}

	mustRunProfile(t, "add", "db", "pypi", "gone")
	if out, err := runProfile(t, "check", "db"); err == nil {
		t.Fatalf("check passed on an entry naming no cataloged package:\n%s", out)
	}
}

// A range constraint the catalog cannot satisfy is the same defect as a pin it
// cannot serve, and it is the one a string comparison in the gate would miss.
// The gate asks entitle for the answer, so it catches both.
func TestProfileCheckAsksThePredicate(t *testing.T) {
	env := newDiscoverEnv(t)
	seedCatalog(t, env, "db01", map[string][]string{"requests": {"2.31.0"}})
	mustRunProfile(t, "create", "db")
	mustRunProfile(t, "add", "db", "pypi", "requests", "--constraint", "compatible", "--version", "3.0.0")

	out, err := runProfile(t, "check", "db")
	if err == nil {
		t.Fatalf("check passed on a constraint no cataloged version satisfies:\n%s", out)
	}
	if !strings.Contains(out, "2.31.0") {
		t.Errorf("the violation does not name what the catalog does carry:\n%s", out)
	}

	mustRunProfile(t, "add", "db", "pypi", "requests", "--constraint", "compatible", "--version", "2.0.0")
	if out, err := runProfile(t, "check", "db"); err != nil {
		t.Fatalf("check failed on a constraint 2.31.0 satisfies: %v\n%s", err, out)
	}
}

// Without diff a baseline is an assertion nobody can falsify.
func TestProfileDiffNamesBothDirections(t *testing.T) {
	env := newDiscoverEnv(t)
	seedCatalog(t, env, "db01", map[string][]string{
		"requests": {"2.31.0"},
		"psycopg2": {"2.9.9"},
	})
	mustRunProfile(t, "create", "db")
	mustRunProfile(t, "add", "db", "pypi", "requests")
	mustRunProfile(t, "add", "db", "pypi", "retired")

	out := mustRunProfile(t, "diff", "db", "--origin", "db01")
	if !strings.Contains(out, "pypi/psycopg2") {
		t.Errorf("diff does not name what the host has and the profile does not:\n%s", out)
	}
	if !strings.Contains(out, "pypi/retired") {
		t.Errorf("diff does not name what the profile has and the host does not:\n%s", out)
	}
	if strings.Contains(out, "pypi/requests\t") {
		t.Errorf("diff reported a package both sides carry:\n%s", out)
	}
	if _, err := runProfile(t, "diff", "db"); err == nil {
		t.Error("diff with no --origin was accepted; it has nothing to compare against")
	}
}

// A profile bound to a name no identity resolves to is inert and looks
// identical to one that works.
func TestProfileBindRefusesAnUnknownIdentity(t *testing.T) {
	env := newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")

	_, err := runProfile(t, "bind", "web", "db01")
	if err == nil {
		t.Fatal("a binding to a name no identity binding produces was accepted")
	}
	for _, want := range []string{"bodega identity list", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, err)
		}
	}

	adb, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if _, err := adb.AddIdentityBinding(context.Background(), audit.IdentityBinding{
		Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "db01",
	}); err != nil {
		t.Fatalf("seed identity binding: %v", err)
	}
	_ = adb.Close()

	if out := mustRunProfile(t, "bind", "web", "db01"); !strings.Contains(out, "Bound db01 to web") {
		t.Errorf("bind did not report what it bound:\n%s", out)
	}
	mustRunProfile(t, "create", "db")
	if out := mustRunProfile(t, "bind", "db", "db01"); !strings.Contains(out, "moved from web") {
		t.Errorf("a rebind did not say where the host came from:\n%s", out)
	}
	if out := mustRunProfile(t, "unbind", "db01"); !strings.Contains(out, "Unbound db01") {
		t.Errorf("unbind did not report what it removed:\n%s", out)
	}
}

// Every mutation writes an audit event, as `bodega acl` does. A control whose
// changes are not recorded is one nobody can review.
func TestProfileMutationsAreAudited(t *testing.T) {
	env := newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "set", "web", "apt", "--membership", "open", "--version-default", "floating")
	mustRunProfile(t, "add", "web", "apt", "nginx")
	mustRunProfile(t, "pin", "web", "apt", "postgresql", "14.11", "--reason", "held")
	mustRunProfile(t, "remove", "web", "apt", "nginx")

	adb, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = adb.Close() }()
	events, err := adb.Query(context.Background(), audit.Filter{PkgType: "profile", Limit: 100})
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	if len(events) < 5 {
		t.Fatalf("5 mutations produced %d audit rows", len(events))
	}
	for _, ev := range events {
		if ev.PkgName != "web" {
			t.Errorf("an audit row does not name the profile: %+v", ev)
		}
		if ev.Actor == "" {
			t.Errorf("an audit row names no actor: %+v", ev)
		}
	}
}

// A typo in the type is a marker or an entry nothing will ever read.
func TestProfileRefusesAnUnknownPackageType(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	if _, err := runProfile(t, "add", "web", "rpm", "httpd"); err == nil {
		t.Fatal("an entry under a type bodega does not serve was accepted")
	}
	if _, err := runProfile(t, "set", "web", "rpm", "--membership", "open"); err == nil {
		t.Fatal("a marker for a type bodega does not serve was accepted")
	}
}
