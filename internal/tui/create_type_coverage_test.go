package tui

import (
	"slices"
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

// The audit query's package-type filter was hardcoded to eight values and lost
// cargo when cargo landed. Unlike the create form's list, nothing held it to
// anything, so the filter silently returned no rows for the missing type.
func TestAuditTypeOptionsCoverEveryType(t *testing.T) {
	got := auditTypeOptions()
	if len(got) == 0 || got[0] != "" {
		t.Fatalf("auditTypeOptions()[0] = %q, want an empty first entry meaning any type", got[0])
	}
	for _, typ := range manifest.AllTypes {
		if !slices.Contains(got, typ) {
			t.Errorf("the audit type filter omits %q, so a query for it returns nothing", typ)
		}
	}
	if len(got) != len(manifest.AllTypes)+1 {
		t.Errorf("auditTypeOptions() has %d entries, want %d: AllTypes plus the any-type blank",
			len(got), len(manifest.AllTypes)+1)
	}
}

// The freebsd form asks for an ABI rather than a Version, and every path out
// of it has to carry that: saveCreateEntry read "Version", found nothing, and
// fell through to the unknown-type error, so the form could be filled in and
// never saved. A test that checked the form's field list passed throughout.
func TestFreeBSDCreateFormSavesTheABIAsTheVersion(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeFreeBSD, nil)
	setFieldValue(fields, "Type", manifest.TypeFreeBSD)
	setFieldValue(fields, "Mode", "proxy")
	setFieldValue(fields, "Name", "base_latest")
	setFieldValue(fields, "ABI", "FreeBSD:14:amd64")
	setFieldValue(fields, "Source URL", "https://pkg.freebsd.org/FreeBSD:14:amd64/base_latest")
	setFieldValue(fields, "Skip validation", "yes")

	if msg := validateCreateFields(fields); msg != "" {
		t.Fatalf("a complete freebsd form was refused: %s", msg)
	}
	ve := saveAndReadBack(t, fields, manifest.TypeFreeBSD, "base_latest")
	if ve.Version != "FreeBSD:14:amd64" {
		t.Errorf("Version = %q, want the ABI; the route resolves a mode, a URL and a backend by it", ve.Version)
	}
	if ve.URL != "https://pkg.freebsd.org/FreeBSD:14:amd64/base_latest" {
		t.Errorf("URL = %q, want the repository root", ve.URL)
	}
	if ve.Mode != manifest.ModeProxy {
		t.Errorf("Mode = %q, want proxy", ve.Mode)
	}
}

// An entry the route will refuse is worth refusing at the form, where it
// costs a keystroke rather than a client that 400s on every request.
func TestFreeBSDCreateFormRefusesWhatTheRouteWould(t *testing.T) {
	for _, tc := range []struct{ name, abi, repo, url, want string }{
		{"no ABI", "", "latest", "https://pkg.freebsd.org/x/latest", "ABI is required"},
		{"ABI with a slash", "FreeBSD:14/amd64", "latest", "https://pkg.freebsd.org/x/latest", "ABI must be"},
		{"repository with a slash", "FreeBSD:14:amd64", "All/latest", "https://pkg.freebsd.org/x/latest", "Name must be"},
		{"no URL", "FreeBSD:14:amd64", "latest", "", "Source URL is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := rebuildCreateFields(manifest.TypeFreeBSD, nil)
			setFieldValue(fields, "Type", manifest.TypeFreeBSD)
			setFieldValue(fields, "Name", tc.repo)
			setFieldValue(fields, "ABI", tc.abi)
			setFieldValue(fields, "Source URL", tc.url)
			setFieldValue(fields, "Skip validation", "yes")

			msg := validateCreateFields(fields)
			if !strings.Contains(msg, tc.want) {
				t.Errorf("validate = %q, want it to name %q", msg, tc.want)
			}
		})
	}
}

// A pasted manifest reaches the same form, and its version is the ABI. The
// generic set writes "Version", which no freebsd field is called, so the
// paste populated everything but the one value the entry cannot be saved
// without.
func TestJSONApplyPopulatesTheFreeBSDABI(t *testing.T) {
	m := &appModel{}
	m.popup.formFields = rebuildCreateFields(manifest.TypeFreeBSD, nil)
	setFieldValue(m.popup.formFields, "Type", manifest.TypeFreeBSD)

	apply := m.makeJSONApplyFn()
	if msg := apply(`{"type":"freebsd","name":"latest",
	  "versions":[{"version":"FreeBSD:14:amd64","mode":"proxy",
	               "url":"https://pkg.freebsd.org/FreeBSD:14:amd64/latest"}]}`); msg != "" {
		t.Fatalf("apply: %s", msg)
	}
	for _, tc := range []struct{ label, want string }{
		{"Name", "latest"},
		{"ABI", "FreeBSD:14:amd64"},
		{"Source URL", "https://pkg.freebsd.org/FreeBSD:14:amd64/latest"},
	} {
		if got := fieldValueFromSlice(m.popup.formFields, tc.label); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.label, got, tc.want)
		}
	}
}
