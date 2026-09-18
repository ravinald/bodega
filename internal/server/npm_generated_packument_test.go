package server

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// The builder's package stage used to write a packument to storage under
// NpmPackumentKey. Nothing served it: handleNpm looks the entry up first and
// generates the document from it whenever one exists, so the stored key is
// reachable only on the pm == nil fall-through, which is the proxy cache slot
// for a package no entry names.
//
// This is the assertion that makes deleting the stage safe rather than
// mechanical. A stored object is planted under exactly the key the stage
// wrote, carrying a version the manifest does not name, and the response is
// required to be the generated document byte for byte. A handler that ever
// preferred storage fails on the planted version; one that merged the two
// fails on the comparison.
func TestNpmPackumentIgnoresTheStoredKeyForAManifestPackage(t *testing.T) {
	const base = "https://bodega.example.com"
	s := hostedServer(t)
	s.cfg.PublicURL = base
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))

	// Valid JSON in the shape a client would accept, so nothing but the
	// handler's choice of source keeps it out of the response.
	planted := `{"name":"left-pad","dist-tags":{"latest":"9.9.9"},` +
		`"versions":{"9.9.9":{"name":"left-pad","version":"9.9.9",` +
		`"dist":{"tarball":"` + base + `/npm/left-pad/-/left-pad-9.9.9.tgz"}}}}`
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmPackumentKey("left-pad"): planted,
	})

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}

	pm, err := s.store.GetPackage(context.Background(), manifest.TypeNpm, "left-pad")
	if err != nil || pm == nil {
		t.Fatalf("read the left-pad entry back: %v", err)
	}
	raw, err := json.Marshal(npmPackumentFromManifest("left-pad", base+"/npm", pm, s.logger))
	if err != nil {
		t.Fatalf("marshal the generated packument: %v", err)
	}
	want := decodeJSON(t, string(raw))

	// dist-tags is the one key the generator does not produce:
	// serveManifestPackument stamps latest from npmLatestVersion once the
	// manifest and profile filters have run, so it reflects what survived
	// them rather than what was generated. Everything else must match.
	got := decodeJSON(t, body)
	tags, _ := got["dist-tags"].(map[string]any)
	delete(got, "dist-tags")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the served packument is not npmPackumentFromManifest's:\n got %v\nwant %v", got, want)
	}
	if tags["latest"] != "1.3.0" {
		t.Errorf("dist-tags.latest = %v, want the manifest's 1.3.0", tags["latest"])
	}

	// Named separately from the comparison above: a future change to the
	// generator moves `want`, and this clause still says which document lost.
	if strings.Contains(body, "9.9.9") {
		t.Errorf("the response carries the planted stored packument's version, so %s was read: %s",
			manifest.NpmPackumentKey("left-pad"), body)
	}
}
