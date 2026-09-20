package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// npmVersionDoc pulls one version out of a generated packument.
func npmVersionDoc(t *testing.T, body, version string) map[string]any {
	t.Helper()
	doc := decodeJSON(t, body)
	versions, ok := doc["versions"].(map[string]any)
	if !ok {
		t.Fatalf("packument carries no versions object: %s", body)
	}
	entry, ok := versions[version].(map[string]any)
	if !ok {
		t.Fatalf("packument names no %s: %s", version, body)
	}
	return entry
}

// R3: a hosted package's recorded dependencies reach the packument. Without
// them npm resolves the package as a leaf, installs one directory, and the
// consumer's build fails at require time with MODULE_NOT_FOUND — naming no
// registry, and sending whoever hits it to their own disk first.
func TestPackumentCarriesRecordedDependencies(t *testing.T) {
	s := hostedServer(t)
	ve := sha256Entry("2.0.1", leftPadTarball)
	ve.Dependencies = []manifest.Dependency{{Name: "color-name", Req: "~1.1.4"}}
	addVersion(t, s, manifest.TypeNpm, "color-convert", ve)
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmTarballKey("color-convert", "2.0.1"): leftPadTarball,
	})

	status, body := getStatusAndBody(t, s, "/npm/color-convert")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/color-convert = %d, want 200: %s", status, body)
	}
	deps, ok := npmVersionDoc(t, body, "2.0.1")["dependencies"].(map[string]any)
	if !ok {
		t.Fatalf("the version declares no dependencies: %s", body)
	}
	if deps["color-name"] != "~1.1.4" {
		t.Errorf("dependencies = %v, want color-name ~1.1.4", deps)
	}
}

// The key is absent rather than empty for a version that recorded none. npm
// reads {} as "needs nothing" and no key as "the registry declares nothing",
// and only the second is honest about an entry fetched before bodega recorded
// any dependency at all.
func TestPackumentOmitsDependenciesWhenNoneRecorded(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmTarballKey("left-pad", "1.3.0"): leftPadTarball,
	})

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	if _, present := npmVersionDoc(t, body, "1.3.0")["dependencies"]; present {
		t.Errorf("a version recording no dependencies published the key anyway: %s", body)
	}
}

// R5: integrity names the bytes the fetch stage stored, not the digest the
// manifest declares. The two are separate records and the download is what npm
// verifies, so a version carrying both publishes the stored one.
func TestIntegrityRendersFromTheRecordedArtifactDigest(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", manifest.VersionEntry{
		Version:        "1.3.0",
		ArtifactDigest: sha256Hex(leftPadTarball),
	})
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmTarballKey("left-pad", "1.3.0"): leftPadTarball,
	})

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	dist, _ := npmVersionDoc(t, body, "1.3.0")["dist"].(map[string]any)
	if dist["integrity"] != sha256SRI(leftPadTarball) {
		t.Errorf("dist.integrity = %v, want the recorded artifact digest %q",
			dist["integrity"], sha256SRI(leftPadTarball))
	}
}

// Two records that contradict each other publish neither. npm reports an
// integrity mismatch as a corrupt download, so a contradicted value costs more
// than none: the version stays resolvable and installable while the operator
// gets a log line naming both digests.
func TestIntegrityIsOmittedWhenTheTwoRecordsDisagree(t *testing.T) {
	s := hostedServer(t)
	ve := sha256Entry("1.3.0", "the bytes the manifest declares")
	ve.ArtifactDigest = sha256Hex(leftPadTarball)
	addVersion(t, s, manifest.TypeNpm, "left-pad", ve)
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmTarballKey("left-pad", "1.3.0"): leftPadTarball,
	})

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	entry := npmVersionDoc(t, body, "1.3.0")
	dist, _ := entry["dist"].(map[string]any)
	if _, present := dist["integrity"]; present {
		t.Errorf("a contradicted digest was published: %v", dist["integrity"])
	}
	// Resolvable is the point. A dropped version sends npm to a 404 on the one
	// route it resolves through, which is the failure this avoids.
	if tarball, _ := dist["tarball"].(string); !strings.Contains(tarball, "/npm/left-pad/-/") {
		t.Errorf("the version left the packument: %s", body)
	}
}
