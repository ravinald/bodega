package main

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// R1: a freebsd rule is keyed by package name and takes the same vocabulary
// as the others, and the two shapes that would filter nothing by membership
// are refused with the trade they would make named.
func TestFreeBSDRuleRefusesAShapeThatFiltersNothing(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "freebsd", "nginx")

	for _, args := range [][]string{
		{"--membership", "open"},
		{"--membership", "closed"},
		{"--membership", "closed", "--expansion", "warn"},
		{"--membership", "closed", "--expansion", "ignore"},
	} {
		_, err := runProfile(t, append([]string{"set", "web", "freebsd"}, args...)...)
		if err == nil {
			t.Fatalf("set freebsd %v was accepted, which re-signs the whole repository for nothing filtered", args)
		}
		for _, want := range []string{"--expansion block", "re-signed by bodega", "bodega profile set web freebsd"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("set freebsd %v: the refusal does not name %q:\n%s", args, want, err)
			}
		}
	}

	out, err := runProfile(t, "set", "web", "freebsd", "--membership", "closed", "--expansion", "block", "--version-default", "pinned")
	if err != nil {
		t.Fatalf("closed with block was refused: %v", err)
	}
	if !strings.Contains(out, "/freebsd-profile/web/") {
		t.Errorf("set does not say where the filtered catalogue is served:\n%s", out)
	}
	mustRunProfile(t, "pin", "web", "freebsd", "nginx", "1.26.2_1,3", "--reason", "config format")
	mustRunProfile(t, "add", "web", "freebsd", "curl", "--constraint", "any")
}

// R1: compatible and patch compare semantic versions, and a pkg version is
// not one, so an entry carrying either would drop every version it names.
func TestFreeBSDEntryRefusesAConstraintPkgVersionsCannotMeet(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	for _, kind := range []string{manifest.ConstraintCompatible, manifest.ConstraintPatch} {
		_, err := runProfile(t, "add", "web", "freebsd", "nginx", "--constraint", kind, "--version", "1.26.2_1")
		if err == nil {
			t.Fatalf("--constraint %s was accepted on a freebsd entry", kind)
		}
		if !strings.Contains(err.Error(), "port revision") || !strings.Contains(err.Error(), "--constraint exact") {
			t.Errorf("--constraint %s: the refusal does not say why or what to use instead:\n%s", kind, err)
		}
	}
	// The same constraint on another type is untouched.
	mustRunProfile(t, "add", "web", "npm", "left-pad", "--constraint", manifest.ConstraintCompatible, "--version", "1.3.0")
}

// The baseline road reaches both refusals too.
func TestFreeBSDBaselineIsCheckedLikeTheFlags(t *testing.T) {
	doc := profileDoc{
		ConfigVersion: 1,
		Name:          "web",
		Types: []profileDocType{{
			Type: manifest.TypeFreeBSD, Membership: audit.MembershipClosed,
			VersionDefault: audit.VersionFloating, Expansion: audit.ExpansionWarn,
		}},
		Entries: []profileDocEntry{{Type: manifest.TypeFreeBSD, Name: "nginx"}},
	}
	if err := validateDoc(&doc); err == nil || !strings.Contains(err.Error(), "types[0]") {
		t.Errorf("a baseline with a warn freebsd rule = %v, want a refusal naming types[0]", err)
	}
	doc.Types[0].Expansion = audit.ExpansionBlock
	doc.Entries[0].Constraint, doc.Entries[0].Version = manifest.ConstraintPatch, "1.26.2"
	if err := validateDoc(&doc); err == nil || !strings.Contains(err.Error(), "entries[0]") {
		t.Errorf("a baseline with a patch freebsd entry = %v, want a refusal naming entries[0]", err)
	}
	doc.Entries[0].Constraint = manifest.ConstraintExact
	if err := validateDoc(&doc); err != nil {
		t.Errorf("a closed, block freebsd baseline with an exact entry was refused: %v", err)
	}
}

// A freebsd entry names a package inside a repository, which the manifest
// store never holds, so profile check reports it as unchecked rather than
// failing CI on every one.
func TestProfileCheckDoesNotFailOnFreeBSDEntries(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "add", "web", "freebsd", "nginx")
	out, err := runProfile(t, "check", "web")
	if err != nil {
		t.Fatalf("profile check failed on a freebsd entry: %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 freebsd entry not checked") {
		t.Errorf("profile check does not say the freebsd entry went unchecked:\n%s", out)
	}
}
