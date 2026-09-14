package builder

import (
	"context"
	"reflect"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// operatorOwnedFields are the ones fillResolvedVersion must NOT copy: the
// placeholder holds what the operator typed, and the resolve exists to add the
// version and what apt knows, not to overwrite a decision.
var operatorOwnedFields = map[string]string{
	"URL":               "the operator's direct-URL entry",
	"BuildCmd":          "the operator's source build",
	"DebGlob":           "the operator's source build",
	"Mode":              "hosted or proxy is a decision, not a fact about the package",
	"VersionConstraint": "the constraint the operator chose",
	"Checksum":          "set by the fetch that verified it",
	"Hidden":            "an operator toggle",
	"Frozen":            "an operator toggle",
	"Suites":            "publishing placement, not provenance",
	"Storage":           "a placement decision",
	"RequiredBy":        "pypi only",
	"Ref":               "git only",
	"Filename":          "binary only",
	"SHA256":            "binary only",
	"AppVersion":        "helm only",
	"ChecksumVerified":  "set by the fetch that verified it",
	"Metadata":          "asserted separately: merged wholesale, not field by field",
}

// fillResolvedVersion carries a hand-maintained list of fields from the
// resolved entry onto the placeholder, and it went stale: CaptureSuite reached
// FetchAptMetadata and stopped here, so `pkg create apt` wrote an entry
// carrying a source package and no release, which the OSV gate then declined
// to answer.
//
// This walks every field rather than naming the one that broke, because the
// next omission will be a different field and a test naming CaptureSuite would
// not see it.
func TestResolvedFieldsReachThePlaceholder(t *testing.T) {
	ctx := context.Background()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("load index: %v", err)
	}

	// The placeholder cmd_create writes before the version is known.
	if err := store.AddVersion(ctx, manifest.TypeApt, "nginx-common",
		manifest.VersionEntry{SourceName: "nginx-common"}); err != nil {
		t.Fatalf("seed placeholder: %v", err)
	}

	resolved := &manifest.VersionEntry{
		Version:       "1.24.0-2ubuntu7",
		SourceName:    "nginx-common",
		SourcePackage: "nginx",
		CaptureSuite:  "noble",
		Description:   "small, powerful, scalable web/proxy server",
		Platform:      "linux/all",
		ArtifactSize:  37834,
		Metadata:      map[string]string{"Section": "httpd"},
	}
	if !fillResolvedVersion(ctx, store, "nginx-common", resolved) {
		t.Fatal("fillResolvedVersion found no placeholder to fill")
	}

	pm, err := store.GetPackage(ctx, manifest.TypeApt, "nginx-common")
	if err != nil || pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("read back: %v (%d versions)", err, len(pm.Versions))
	}
	got := pm.Versions[0]

	rv := reflect.ValueOf(*resolved)
	gv := reflect.ValueOf(got)
	for i := 0; i < rv.NumField(); i++ {
		name := rv.Type().Field(i).Name
		if _, owned := operatorOwnedFields[name]; owned {
			continue
		}
		want := rv.Field(i)
		if want.IsZero() {
			continue // the resolver produced nothing for it, so nothing to carry
		}
		if !reflect.DeepEqual(want.Interface(), gv.Field(i).Interface()) {
			t.Errorf("%s did not reach the placeholder: resolved %v, stored %v\n"+
				"  add it to fillResolvedVersion, or to operatorOwnedFields with the reason it must not be copied",
				name, want.Interface(), gv.Field(i).Interface())
		}
	}
}
