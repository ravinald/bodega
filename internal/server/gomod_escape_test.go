package server

import (
	"net/http"
	"slices"
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

// Before the handler decoded the wire path, the escaped form was the only
// spelling a request matched, so an existing install catalogued, hid and
// listed uppercase modules that way. These run the rename an upgraded server
// runs before it serves.

func saveGomodManifest(t *testing.T, s *Server, name string, hidden bool) {
	t.Helper()
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion, Name: name, Type: manifest.TypeGomod,
		Versions: []manifest.VersionEntry{{Version: "v1.4.0", Hidden: hidden}},
	}); err != nil {
		t.Fatalf("save gomod manifest %s: %v", name, err)
	}
}

func profileEntryNames(t *testing.T, s *Server, profile string) []string {
	t.Helper()
	d, err := s.auditDB.GetProfile(t.Context(), profile)
	if err != nil {
		t.Fatalf("read profile %s: %v", profile, err)
	}
	var names []string
	for _, e := range d.Entries {
		names = append(names, e.Name)
	}
	return names
}

func TestGomodHiddenManifestUnderEscapedNameStaysHiddenAfterRename(t *testing.T) {
	s, up := tomlUpstream(t)
	saveGomodManifest(t, s, tomlEscaped, true)

	renamed, err := s.store.RenameEscapedGomod(t.Context())
	if err != nil || len(renamed) != 1 {
		t.Fatalf("RenameEscapedGomod = %v, %v; want one rename and no error", renamed, err)
	}
	status, body := getStatusAndBody(t, s, tomlInfo)
	if status != http.StatusNotFound || !strings.Contains(body, "hidden") {
		t.Errorf("GET %s with every version hidden = %d %q, want the hidden refusal", tomlInfo, status, body)
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("a hidden module reached the upstream: %v", got)
	}
}

func TestGomodProfileEntryUnderEscapedNameAdmitsAfterRewrite(t *testing.T) {
	s, _ := tomlUpstream(t)
	f := bindProfile(t, s, "build", "build01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeGomod, Name: tomlEscaped}})

	if _, _, err := s.auditDB.RewriteEscapedGomodNames(t.Context()); err != nil {
		t.Fatalf("RewriteEscapedGomodNames: %v", err)
	}
	s.refreshProfiles(t.Context())
	for _, p := range []string{tomlList, tomlInfo} {
		if status, body := f.get(t, p); status != http.StatusOK {
			t.Errorf("GET %s with %s listed before the rewrite = %d, want 200: %s", p, tomlEscaped, status, body)
		}
	}
	if got := profileEntryNames(t, s, "build"); len(got) != 1 || got[0] != tomlModule {
		t.Errorf("the profile lists %v, want [%s]", got, tomlModule)
	}
}

func TestGomodEscapedNameRewriteRenamesOnlyEscapedNamesAndIsIdempotent(t *testing.T) {
	s, _ := tomlUpstream(t)
	const lower = "golang.org/x/mod"
	saveGomodManifest(t, s, tomlEscaped, false)
	saveGomodManifest(t, s, lower, false)
	writeProfile(t, s, "build",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeGomod, Name: tomlEscaped}, {Type: manifest.TypeGomod, Name: lower}})

	renamed, err := s.store.RenameEscapedGomod(t.Context())
	if err != nil || len(renamed) != 1 || renamed[0].Stored != tomlEscaped || renamed[0].Canonical != tomlModule {
		t.Fatalf("RenameEscapedGomod = %+v, %v; want %s renamed to %s", renamed, err, tomlEscaped, tomlModule)
	}
	rows, collisions, err := s.auditDB.RewriteEscapedGomodNames(t.Context())
	if err != nil || rows != 1 || len(collisions) != 0 {
		t.Fatalf("RewriteEscapedGomodNames = %d, %v, %v; want one row renamed", rows, collisions, err)
	}

	got := s.store.ListPackages(manifest.TypeGomod)
	if !slices.Contains(got, manifest.SafeName(tomlModule)) || !slices.Contains(got, manifest.SafeName(lower)) || slices.Contains(got, manifest.SafeName(tomlEscaped)) {
		t.Errorf("the index lists %v, want %s and %s and not %s", got, tomlModule, lower, tomlEscaped)
	}
	for _, name := range []string{tomlModule, lower} {
		if pm, err := s.store.GetPackage(t.Context(), manifest.TypeGomod, name); err != nil || pm == nil {
			t.Errorf("GetPackage(%s) = %v, %v; want the manifest", name, pm, err)
		}
	}
	if names := profileEntryNames(t, s, "build"); !slices.Equal(names, []string{tomlModule, lower}) {
		t.Errorf("the profile lists %v, want [%s %s]", names, tomlModule, lower)
	}

	if renamed, err := s.store.RenameEscapedGomod(t.Context()); err != nil || len(renamed) != 0 {
		t.Errorf("a second RenameEscapedGomod = %v, %v; want nothing", renamed, err)
	}
	if rows, collisions, err := s.auditDB.RewriteEscapedGomodNames(t.Context()); err != nil || rows != 0 || len(collisions) != 0 {
		t.Errorf("a second RewriteEscapedGomodNames = %d, %v, %v; want nothing", rows, collisions, err)
	}
}

// Both spellings already present is two sets of entries for one module; the
// rewrite names the pair and moves neither.
func TestGomodEscapedNameRewriteRefusesACollision(t *testing.T) {
	s, _ := tomlUpstream(t)
	saveGomodManifest(t, s, tomlEscaped, true)
	saveGomodManifest(t, s, tomlModule, false)
	writeProfile(t, s, "build",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeGomod, Name: tomlEscaped}, {Type: manifest.TypeGomod, Name: tomlModule}})

	renamed, err := s.store.RenameEscapedGomod(t.Context())
	if err == nil || len(renamed) != 0 || !strings.Contains(err.Error(), tomlEscaped) || !strings.Contains(err.Error(), tomlModule) {
		t.Errorf("RenameEscapedGomod over a collision = %v, %v; want an error naming both and nothing renamed", renamed, err)
	}
	if pm, _ := s.store.GetPackage(t.Context(), manifest.TypeGomod, tomlModule); pm == nil || pm.Versions[0].Hidden {
		t.Errorf("the manifest under %s was overwritten: %+v", tomlModule, pm)
	}

	rows, collisions, err := s.auditDB.RewriteEscapedGomodNames(t.Context())
	if err != nil || rows != 0 || len(collisions) != 1 || collisions[0].Escaped != tomlEscaped || collisions[0].Decoded != tomlModule {
		t.Errorf("RewriteEscapedGomodNames over a collision = %d, %+v, %v; want the pair reported and nothing renamed", rows, collisions, err)
	}
	if names := profileEntryNames(t, s, "build"); len(names) != 2 {
		t.Errorf("the profile lists %v, want both spellings left in place", names)
	}
}
