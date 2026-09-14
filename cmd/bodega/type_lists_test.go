package main

import (
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
