package tui

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// The create form's type list and its per-type field switches were all
// hand-maintained, and all of them stopped at npm. A crate could be made from
// the CLI and not from the TUI, and adding the option alone would have fallen
// through to the apt form, which is what the switches default to.
func TestCreateFormOffersEveryType(t *testing.T) {
	offered := make(map[string]bool, len(createTypeOptions))
	for _, opt := range createTypeOptions {
		offered[opt] = true
	}
	for _, typ := range manifest.AllTypes {
		if !offered[typ] {
			t.Errorf("createTypeOptions omits %q, so it cannot be created from the TUI", typ)
		}
	}
}

// Every type must reach an arm that builds its own fields. The switch falls
// through to apt, so a missing arm is a form that silently asks for a Package
// Name and a Build Cmd.
func TestEveryTypeReachesItsOwnCreateFields(t *testing.T) {
	aptOnly := fieldLabels(rebuildCreateFields(manifest.TypeApt, nil))

	for _, typ := range manifest.AllTypes {
		t.Run(typ, func(t *testing.T) {
			fields := rebuildCreateFields(typ, nil)
			if len(fields) == 0 {
				t.Fatalf("%s builds no fields", typ)
			}
			if typ != manifest.TypeApt && fieldLabels(fields) == aptOnly {
				t.Errorf("%s falls through to the apt form: %s", typ, fieldLabels(fields))
			}
		})
	}
}

// Cargo's form asks for what `bodega pkg create cargo` prompts for: the crate
// name, a version, and the sparse index URL as an optional override.
func TestCargoCreateFormAsksForACrate(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeCargo, nil)
	labels := fieldLabels(fields)
	for _, want := range []string{"Name", "Version", "Source URL", "Mode"} {
		if !strings.Contains(labels, want) {
			t.Errorf("cargo form has no %q field: %s", want, labels)
		}
	}

	var nameHint string
	for _, f := range fields {
		if f.Label == "Name" {
			nameHint = f.Hint
		}
	}
	if !strings.Contains(nameHint, "crate") {
		t.Errorf("cargo Name hint does not name a crate: %q", nameHint)
	}
}

func fieldLabels(fields []formField) string {
	var labels []string
	for _, f := range fields {
		labels = append(labels, f.Label)
	}
	return strings.Join(labels, ",")
}
