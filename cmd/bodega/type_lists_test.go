package main

import (
	"context"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/manifest"
)

// The rejection named four of eight types while isValidType accepted all
// eight, so an operator who mistyped "gomod" was told bodega supports four
// ecosystems. Six commands inherit this message.
func TestResolveTypesRejectionNamesEveryType(t *testing.T) {
	_, err := resolveTypes([]string{"nosuchtype"})
	if err == nil {
		t.Fatal("resolveTypes accepted an unknown type")
	}
	msg := err.Error()
	for _, typ := range manifest.AllTypes {
		if !strings.Contains(msg, typ) {
			t.Errorf("rejection omits %q, so the tool understates what it supports: %s", typ, msg)
		}
	}
}

// Every type isValidType accepts must be one resolveTypes returns, and the
// reverse. A type in one and not the other is how cargo went missing.
func TestResolveTypesAgreesWithIsValidType(t *testing.T) {
	got, err := resolveTypes(nil)
	if err != nil {
		t.Fatalf("resolveTypes(nil): %v", err)
	}
	if len(got) != len(manifest.AllTypes) {
		t.Fatalf("resolveTypes(nil) returned %d types, AllTypes has %d", len(got), len(manifest.AllTypes))
	}
	for _, typ := range manifest.AllTypes {
		if !isValidType(typ) {
			t.Errorf("isValidType rejects %q, which is in AllTypes", typ)
		}
	}
}

// The three build subcommands carried their type order as prose. Two said
// four and one said seven, against eight, because nothing tied the sentence to
// the list. A ninth ecosystem must not be able to leave any of them stale.
func TestBuildSubcommandHelpNamesEveryType(t *testing.T) {
	loadFrom(t, "{}")
	gf := &globalFlags{}
	cmds := map[string]*cobra.Command{
		"build run":     newBuildRunCmd(gf),
		"build fetch":   newFetchCmd(gf),
		"build package": newPackageCmd(gf),
	}

	for name, cmd := range cmds {
		t.Run(name, func(t *testing.T) {
			long := cmd.Long
			for _, typ := range manifest.AllTypes {
				if !strings.Contains(long, typ) {
					t.Errorf("%s help never names %q:\n%s", name, typ, long)
				}
			}
			// The stale counts were spelled out as words, so the count is
			// asserted as a rendered number rather than by absence of "seven".
			for _, stale := range []string{"all four", "all seven", "all six", "all five"} {
				if strings.Contains(long, stale) {
					t.Errorf("%s help hardcodes a type count (%q); render it from AllTypes", name, stale)
				}
			}
		})
	}
}

// fbsd is accepted for freebsd at the command line and is a type nowhere else.
// Each absence below is a way the alias would become a second name for one
// type: listed in AllTypes it is a tenth type, printed in help it is a
// documented one, and written into a key it is a prefix no reader of freebsd
// ever lists.
func TestFbsdAliasResolvesAndGoesNoFurther(t *testing.T) {
	got, err := resolveTypes([]string{"fbsd"})
	if err != nil {
		t.Fatalf("resolveTypes(fbsd): %v", err)
	}
	if !slices.Equal(got, []string{manifest.TypeFreeBSD}) {
		t.Fatalf("resolveTypes(fbsd) = %v, want [%s]", got, manifest.TypeFreeBSD)
	}
	if !isTypeArg("fbsd") {
		t.Error("isTypeArg(fbsd) is false, so 'bodega build fetch fbsd' filters for a package named fbsd instead")
	}

	if slices.Contains(manifest.AllTypes, "fbsd") {
		t.Error("fbsd is in manifest.AllTypes, which makes it a type rather than an alias")
	}
	if isValidType("fbsd") {
		t.Error("isValidType accepts fbsd; the single-type commands would write it into a manifest path")
	}
	for _, verb := range []string{"fetched", "built", "packaged"} {
		if s := typeOrderSentence(verb); strings.Contains(s, "fbsd") {
			t.Errorf("typeOrderSentence(%q) names the alias: %s", verb, s)
		}
	}

	// A manifest saved under what the alias resolves to, and every artifact key
	// that entry derives. Nothing on disk or in a key may carry the alias.
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	ctx := context.Background()
	ve := manifest.VersionEntry{Version: "FreeBSD:14:amd64", URL: "https://pkg.freebsd.org/FreeBSD:14:amd64/latest"}
	if err := store.AddVersion(ctx, got[0], "latest", ve); err != nil {
		t.Fatalf("AddVersion(%s): %v", got[0], err)
	}
	err = filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, "fbsd") {
			t.Errorf("the store wrote %s under the alias", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pm, err := store.GetPackage(ctx, got[0], "latest")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage(%s, latest) = %v, %v", got[0], pm, err)
	}
	keys, err := manifest.ArtifactKeys(pm, ve)
	if err != nil {
		t.Fatalf("ArtifactKeys: %v", err)
	}
	for _, k := range keys {
		if typ, _, _ := manifest.ParseKey(k); typ != manifest.TypeFreeBSD || strings.Contains(k, "fbsd") {
			t.Errorf("key %q reads back as type %q; want %s with no alias in it", k, typ, manifest.TypeFreeBSD)
		}
	}
}
