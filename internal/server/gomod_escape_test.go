package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// The proxy protocol carries github.com/BurntSushi/toml as
// github.com/!burnt!sushi/toml. Every name bodega matches or records is the
// go.mod spelling; only the upstream URL and the storage key keep the wire form.
const (
	tomlModule  = "github.com/BurntSushi/toml"
	tomlEscaped = "github.com/!burnt!sushi/toml"
	tomlList    = "/go/" + tomlEscaped + "/@v/list"
	tomlInfo    = "/go/" + tomlEscaped + "/@v/v1.4.0.info"
)

func tomlUpstream(t *testing.T) (*Server, *recordingUpstream) {
	t.Helper()
	s, up := sumdbServer(t)
	up.route("/"+tomlEscaped+"/@v/list", "v1.4.0\n")
	up.route("/"+tomlEscaped+"/@v/v1.4.0.info", `{"Version":"v1.4.0"}`)
	return s, up
}

func TestGomodProfileEntryInGoModSpellingAdmitsEscapedRequest(t *testing.T) {
	s, up := tomlUpstream(t)
	f := bindProfile(t, s, "build", "build01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeGomod, Name: tomlModule}})

	for _, p := range []string{tomlList, tomlInfo} {
		if status, body := f.get(t, p); status != http.StatusOK {
			t.Errorf("GET %s with %s listed = %d, want 200: %s", p, tomlModule, status, body)
		}
	}
	for _, p := range []string{"/" + tomlEscaped + "/@v/list", "/" + tomlEscaped + "/@v/v1.4.0.info"} {
		if !up.sawPath(p) {
			t.Errorf("the upstream was not asked for the escaped path %s; it saw %v", p, up.paths())
		}
	}
	if keys := storedKeys(t, s, manifest.TypeGomod, "gomod/"+tomlEscaped+"/"); len(keys) == 0 {
		t.Errorf("nothing was cached under the escaped key gomod/%s/", tomlEscaped)
	}
}

func TestGomodDiscoveryRowNamesTheGoModSpelling(t *testing.T) {
	s, _ := tomlUpstream(t)
	f := bindProfile(t, s, "build", "build01",
		[]audit.ProfileTypeRule{{
			Type: manifest.TypeGomod, Membership: audit.MembershipClosed,
			VersionDefault: audit.VersionFloating,
		}},
		[]audit.ProfileEntry{{Type: manifest.TypeGomod, Name: "example.com/other"}})

	for _, p := range []string{tomlList, tomlInfo} {
		f.get(t, p)
	}
	rows := waitForDecision(t, s, audit.DecisionDenied, 2)
	want := "bodega profile add build gomod " + tomlModule
	for _, row := range rows {
		if row.PkgName != tomlModule {
			t.Errorf("the denied row names %q, want the go.mod spelling %q", row.PkgName, tomlModule)
		}
		if row.PatternHint != want {
			t.Errorf("the denied row's pattern_hint is %q, want %q", row.PatternHint, want)
		}
	}
}

func TestGomodCatalogEntryInGoModSpellingIsFound(t *testing.T) {
	s := proxyingServer(t)
	const info = `{"Version":"v1.4.0","Time":"2024-06-01T00:00:00Z"}`
	seed(t, s, manifest.TypeGomod, map[string]string{
		"gomod/" + tomlEscaped + "/@v/v1.4.0.info": info,
	})
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          tomlModule,
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.4.0"}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}
	status, body := getStatusAndBody(t, s, tomlInfo)
	if status != http.StatusOK || !strings.Contains(body, "v1.4.0") {
		t.Fatalf("GET %s with %s catalogued = %d %q, want 200 and the stored .info", tomlInfo, tomlModule, status, body)
	}

	pm, err := s.store.GetPackage(t.Context(), manifest.TypeGomod, tomlModule)
	if err != nil || pm == nil {
		t.Fatalf("reload the manifest: %v", err)
	}
	pm.Versions[0].Hidden = true
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("hide the version: %v", err)
	}
	if status, _ := getStatusAndBody(t, s, tomlInfo); status == http.StatusOK {
		t.Errorf("GET %s answered 200 with every version of %s hidden", tomlInfo, tomlModule)
	}
}

// An object cached under the escaped key before the handler decoded the path
// is still the one served.
func TestGomodCachedObjectUnderEscapedKeyStillServed(t *testing.T) {
	s, up := sumdbServer(t)
	seed(t, s, manifest.TypeGomod, map[string]string{
		"gomod/" + tomlEscaped + "/@v/v1.4.0.info": `{"Version":"v1.4.0"}`,
	})
	if status, body := getStatusAndBody(t, s, tomlInfo); status != http.StatusOK {
		t.Fatalf("GET %s = %d %q, want 200 from the cache", tomlInfo, status, body)
	}
	if up.sawPath("/" + tomlEscaped + "/@v/v1.4.0.info") {
		t.Errorf("a cached immutable .info went upstream: the key did not match")
	}
}

func TestGomodUndecodablePathIs400(t *testing.T) {
	s, up := sumdbServer(t)
	for _, p := range []string{
		"/go/github.com/BurntSushi/toml/@v/list",
		"/go/github.com/!!burnt/toml/@v/v1.4.0.info",
		"/go/github.com/burnt!/toml/@latest",
	} {
		status, body := getStatusAndBody(t, s, p)
		if status != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", p, status)
		}
		module := strings.TrimPrefix(p, "/go/")
		module = module[:strings.Index(module, "/@")]
		if !strings.Contains(body, module) {
			t.Errorf("the 400 for %s does not name the path %s: %q", p, module, body)
		}
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("an undecodable path reached the upstream: %v", got)
	}
}
