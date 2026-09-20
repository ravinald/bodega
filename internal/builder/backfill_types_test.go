package builder

import (
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// globTypes map one entry onto several files matched by a glob, so there is no
// single artifact path to return and "" is the right answer.
var globTypes = []string{manifest.TypeApt, manifest.TypePypi}

// artifactPathForVersion returned "" for two different reasons through one
// default arm: apt and pypi belong there, and cargo landed there by omission.
// BackfillArtifactSizes loops AllTypes, so the missing arm meant cargo entries
// never had a size backfilled and nothing said so.
func TestArtifactPathForVersionCoversEveryType(t *testing.T) {
	cfg := &Config{}
	ve := manifest.VersionEntry{Version: "1.0.0", Ref: "v1.0.0"}

	for _, typ := range manifest.AllTypes {
		got := artifactPathForVersion(cfg, typ, "example-pkg", ve)
		skip := slices.Contains(globTypes, typ)
		switch {
		case skip && got != "":
			t.Errorf("%s is listed as a glob type but returned %q", typ, got)
		case !skip && got == "":
			t.Errorf("%s has no arm in artifactPathForVersion, so BackfillArtifactSizes skips it "+
				"without reporting; add an arm or add it to globTypes with a reason", typ)
		case !skip && !strings.Contains(got, "example-pkg"):
			t.Errorf("%s returned %q, which does not name the package", typ, got)
		}
	}
}
