package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

// The fixture every ecosystem below shares: two releases well outside a 7d
// window, one a day old, and one whose publish time the upstream cannot
// supply. A client asking for ^4.1.0 (or v1, or >=4.1) should resolve to the
// newest old release, and only the day-old one is withheld.
var (
	filterNow = time.Now()
	filterOld = map[string]time.Duration{"1.0": 400 * 24 * time.Hour, "2.0": 200 * 24 * time.Hour}
)

func stamp(ago time.Duration) string { return filterNow.Add(-ago).UTC().Format(time.RFC3339) }

// filteringServer is a proxying server with a 7d blocking age gate and the
// index filter on for typ.
func filteringServer(t *testing.T, typ string) *Server {
	t.Helper()
	s := proxyingServer(t)
	ctx := t.Context()
	if err := s.auditDB.SetAgePolicy(ctx, audit.AgePolicy{Ecosystem: typ, MinAgeSeconds: 7 * 24 * 3600, Action: "block"}); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.SetIndexFilter(ctx, audit.IndexFilter{Ecosystem: typ, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Server, path string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// filterRows counts the index_filtered rows written for one package.
func filterRows(t *testing.T, s *Server, typ, name string) []audit.StoredEvent {
	t.Helper()
	evs, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache, PkgType: typ, PkgName: name})
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.StoredEvent
	for _, e := range evs {
		if e.Status == audit.CacheIndexFiltered {
			out = append(out, e)
		}
	}
	return out
}

func deniedWithheld(t *testing.T, s *Server, typ, name, version string) bool {
	t.Helper()
	evs, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventDenied, PkgType: typ, PkgName: name})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Status == audit.DenialWithheldVersion && e.PkgVersion == version {
			return true
		}
	}
	return false
}

// newestMatching is the resolver half of the test: the highest release with
// the given major at or above floor, which is what ^floor picks.
func newestMatching(versions []string, floor string) string {
	fl, _ := builder.ParseSemVer(floor)
	best := ""
	var bestSV builder.SemVer
	for _, v := range versions {
		sv, ok := builder.ParseSemVer(v)
		if !ok || sv.Pre != "" || sv.Major != fl.Major || sv.Less(fl) {
			continue
		}
		if best == "" || bestSV.Less(sv) {
			best, bestSV = v, sv
		}
	}
	return best
}

// ---- npm --------------------------------------------------------------------

func npmFilterUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	var base string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := func(name, v string) string {
			return fmt.Sprintf(`%q:{"name":%q,"version":%q,"dist":{"tarball":"%s/%s/-/%s-%s.tgz"}}`, v, name, v, base, name, name, v)
		}
		switch {
		case r.URL.Path == "/widget":
			// 4.0.5 has no time entry: undatable, so it has to stay.
			_, _ = fmt.Fprintf(w, `{"name":"widget","dist-tags":{"latest":"4.3.0","next":"4.4.0-beta.1"},`+
				`"versions":{%s,%s,%s,%s,%s},`+
				`"time":{"created":%q,"modified":%q,"4.1.0":%q,"4.2.0":%q,"4.3.0":%q,"4.4.0-beta.1":%q}}`,
				entry("widget", "4.0.5"), entry("widget", "4.1.0"), entry("widget", "4.2.0"), entry("widget", "4.3.0"), entry("widget", "4.4.0-beta.1"),
				stamp(500*24*time.Hour), stamp(time.Hour),
				stamp(filterOld["1.0"]), stamp(filterOld["2.0"]), stamp(24*time.Hour), stamp(300*24*time.Hour))
		case r.URL.Path == "/fresh":
			_, _ = fmt.Fprintf(w, `{"name":"fresh","dist-tags":{"latest":"1.0.1"},"versions":{%s,%s},"time":{"1.0.0":%q,"1.0.1":%q}}`,
				entry("fresh", "1.0.0"), entry("fresh", "1.0.1"), stamp(48*time.Hour), stamp(time.Hour))
		case strings.Contains(r.URL.Path, "/-/"):
			_, _ = w.Write([]byte("tarball bytes"))
		default:
			http.NotFound(w, r)
		}
	}))
	base = ts.URL
	t.Cleanup(ts.Close)
	return ts
}

func TestIndexFilterNpm(t *testing.T) {
	s := filteringServer(t, manifest.TypeNpm)
	s.cfg.NpmUpstream = npmFilterUpstream(t).URL

	rec := get(t, s, "/npm/widget")
	if rec.Code != http.StatusOK {
		t.Fatalf("packument status = %d, body %s", rec.Code, rec.Body)
	}
	var doc struct {
		DistTags map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var listed []string
	for v := range doc.Versions {
		listed = append(listed, v)
	}

	t.Run("range resolves to the newest compliant version", func(t *testing.T) {
		if _, ok := doc.Versions["4.3.0"]; ok {
			t.Errorf("4.3.0 is a day old under a 7d block and is still listed: %v", listed)
		}
		if got := newestMatching(listed, "4.1.0"); got != "4.2.0" {
			t.Errorf("^4.1.0 resolves to %q against %v, want 4.2.0", got, listed)
		}
	})
	t.Run("latest repoints to the newest remaining release", func(t *testing.T) {
		if got := doc.DistTags["latest"]; got != "4.2.0" {
			t.Errorf("latest = %q, want 4.2.0 (newest non-prerelease left; 4.4.0-beta.1 is newer and a prerelease)", got)
		}
		if got := doc.DistTags["next"]; got != "4.4.0-beta.1" {
			t.Errorf("next = %q, want the untouched 4.4.0-beta.1", got)
		}
	})
	t.Run("a version with no publish time is kept", func(t *testing.T) {
		if _, ok := doc.Versions["4.0.5"]; !ok {
			t.Errorf("4.0.5 has no time entry and was dropped: %v", listed)
		}
	})
	t.Run("the response names what it withheld", func(t *testing.T) {
		if got := rec.Header().Get(filteredHeader); got != "1; age=1" {
			t.Errorf("%s = %q, want \"1; age=1\"", filteredHeader, got)
		}
		rows := filterRows(t, s, manifest.TypeNpm, "widget")
		if len(rows) != 1 {
			t.Fatalf("got %d index_filtered rows for one request, want 1", len(rows))
		}
		if !strings.Contains(rows[0].Details, `"age":1`) {
			t.Errorf("row details = %s, want the age count", rows[0].Details)
		}
	})
	t.Run("a direct request for the withheld tarball is refused", func(t *testing.T) {
		if rec := get(t, s, "/npm/widget/-/widget-4.3.0.tgz"); rec.Code != http.StatusForbidden {
			t.Errorf("withheld tarball status = %d, want 403 (body %s)", rec.Code, rec.Body)
		}
		if !deniedWithheld(t, s, manifest.TypeNpm, "widget", "4.3.0") {
			t.Error("no withheld_version denial row for 4.3.0")
		}
		if rec := get(t, s, "/npm/widget/-/widget-4.2.0.tgz"); rec.Code != http.StatusOK {
			t.Errorf("compliant tarball status = %d, want 200 (body %s)", rec.Code, rec.Body)
		}
	})
	t.Run("all filtered still serves the index", func(t *testing.T) {
		rec := get(t, s, "/npm/fresh")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 so npm reports no matching version itself", rec.Code)
		}
		var doc struct {
			DistTags map[string]string `json:"dist-tags"`
			Versions map[string]any    `json:"versions"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Versions) != 0 || doc.DistTags["latest"] != "" {
			t.Errorf("versions = %v, latest = %q; want both empty", doc.Versions, doc.DistTags["latest"])
		}
		if got := rec.Header().Get(filteredHeader); got != "2; age=2" {
			t.Errorf("%s = %q, want \"2; age=2\"", filteredHeader, got)
		}
	})
}

// A proxy-mode entry's packument is generated from the manifest rather than
// proxied, and its tarballs are filled from upstream all the same, so it
// withholds and refuses exactly what the uncatalogued path does.
func TestIndexFilterNpmProxyModeEntry(t *testing.T) {
	s := filteringServer(t, manifest.TypeNpm)
	s.cfg.NpmUpstream = npmFilterUpstream(t).URL
	pm := &manifest.PackageManifest{ConfigVersion: manifest.CurrentConfigVersion, Name: "widget", Type: manifest.TypeNpm}
	for _, v := range []string{"4.0.5", "4.1.0", "4.2.0", "4.3.0"} {
		pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: v, Mode: manifest.ModeProxy})
	}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatal(err)
	}

	rec := get(t, s, "/npm/widget")
	if rec.Code != http.StatusOK {
		t.Fatalf("packument status = %d, body %s", rec.Code, rec.Body)
	}
	var doc struct {
		DistTags map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var listed []string
	for v := range doc.Versions {
		listed = append(listed, v)
	}

	t.Run("a range resolves to the newest compliant version", func(t *testing.T) {
		if got := newestMatching(listed, "4.1.0"); got != "4.2.0" {
			t.Errorf("^4.1.0 resolves to %q against %v, want 4.2.0", got, listed)
		}
	})
	t.Run("latest names a version that survived", func(t *testing.T) {
		if got := doc.DistTags["latest"]; got != "4.2.0" {
			t.Errorf("latest = %q, want 4.2.0", got)
		}
	})
	t.Run("a version with no publish time is kept", func(t *testing.T) {
		if _, ok := doc.Versions["4.0.5"]; !ok {
			t.Errorf("4.0.5 has no time entry upstream and was dropped: %v", listed)
		}
	})
	t.Run("the response names what it withheld", func(t *testing.T) {
		if got := rec.Header().Get(filteredHeader); got != "1; age=1" {
			t.Errorf("%s = %q, want \"1; age=1\"", filteredHeader, got)
		}
		if rows := filterRows(t, s, manifest.TypeNpm, "widget"); len(rows) != 1 {
			t.Errorf("got %d index_filtered rows for one request, want 1", len(rows))
		}
	})
	t.Run("a direct request for the withheld tarball is refused", func(t *testing.T) {
		if rec := get(t, s, "/npm/widget/-/widget-4.3.0.tgz"); rec.Code != http.StatusForbidden {
			t.Errorf("withheld tarball status = %d, want 403 (body %s)", rec.Code, rec.Body)
		}
		if !deniedWithheld(t, s, manifest.TypeNpm, "widget", "4.3.0") {
			t.Error("no withheld_version denial row for 4.3.0")
		}
		if rec := get(t, s, "/npm/widget/-/widget-4.2.0.tgz"); rec.Code != http.StatusOK {
			t.Errorf("compliant tarball status = %d, want 200 (body %s)", rec.Code, rec.Body)
		}
	})
}

// A hosted entry was admitted on import, so neither its packument nor its
// tarball route consults the filter.
func TestIndexFilterNpmHostedEntryUntouched(t *testing.T) {
	s := filteringServer(t, manifest.TypeNpm)
	s.cfg.NpmUpstream = npmFilterUpstream(t).URL
	pm := &manifest.PackageManifest{ConfigVersion: manifest.CurrentConfigVersion, Name: "widget", Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{{Version: "4.3.0", Mode: manifest.ModeHosted}}}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatal(err)
	}
	rec := get(t, s, "/npm/widget")
	if !strings.Contains(rec.Body.String(), `"4.3.0"`) || rec.Header().Get(filteredHeader) != "" {
		t.Errorf("hosted 4.3.0 withheld; header %q, body %s", rec.Header().Get(filteredHeader), rec.Body)
	}
	if rec := get(t, s, "/npm/widget/-/widget-4.3.0.tgz"); rec.Code == http.StatusForbidden {
		t.Errorf("hosted tarball refused as withheld: %s", rec.Body)
	}
}

// A warn gate, or the filter off, leaves the packument as upstream wrote it:
// the filter applies a block and nothing weaker.
func TestIndexFilterNpmOffOrWarnWithholdsNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		on     bool
	}{{"filter off", "block", false}, {"age gate warns", "warn", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyingServer(t)
			s.cfg.NpmUpstream = npmFilterUpstream(t).URL
			ctx := t.Context()
			_ = s.auditDB.SetAgePolicy(ctx, audit.AgePolicy{Ecosystem: manifest.TypeNpm, MinAgeSeconds: 7 * 24 * 3600, Action: tc.action})
			_ = s.auditDB.SetIndexFilter(ctx, audit.IndexFilter{Ecosystem: manifest.TypeNpm, Enabled: tc.on})
			rec := get(t, s, "/npm/widget")
			if !strings.Contains(rec.Body.String(), `"4.3.0"`) || rec.Header().Get(filteredHeader) != "" {
				t.Errorf("4.3.0 withheld with %s; header %q", tc.name, rec.Header().Get(filteredHeader))
			}
			if rec := get(t, s, "/npm/widget/-/widget-4.3.0.tgz"); rec.Code != http.StatusOK {
				t.Errorf("tarball status = %d with %s, want 200", rec.Code, tc.name)
			}
		})
	}
}

// ---- pypi -------------------------------------------------------------------

// pypiFilterUpstream answers the JSON page to an Accept header or to the
// format parameter spelled literally, as pypi.org does; pypi.org answers HTML
// to the percent-encoded spelling.
func pypiFilterUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	type file struct {
		name string
		ago  time.Duration // zero: no upload-time on the JSON page
	}
	dists := map[string][]file{
		"widget": {
			{"widget-4.0.5-py3-none-any.whl", 0},
			{"widget-4.1.0-py3-none-any.whl", filterOld["1.0"]},
			{"widget-4.2.0.tar.gz", filterOld["2.0"]},
			{"widget-4.2.0-py3-none-any.whl", filterOld["2.0"] - time.Hour},
			{"widget-4.3.0-py3-none-any.whl", 24 * time.Hour},
		},
		"fresh": {
			{"fresh-1.0.0-py3-none-any.whl", 48 * time.Hour},
		},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/files/") {
			_, _ = w.Write([]byte("wheel bytes"))
			return
		}
		dist := strings.Trim(strings.TrimPrefix(r.URL.Path, "/simple/"), "/")
		files, ok := dists[dist]
		if !ok || !strings.HasPrefix(r.URL.Path, "/simple/") {
			// Includes the JSON API fallback, so 4.0.5 cannot be dated at all.
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.Header.Get("Accept"), pypiSimpleJSON) || r.URL.RawQuery == "format="+pypiSimpleJSON {
			var out []map[string]any
			var versions []string
			for _, f := range files {
				e := map[string]any{"filename": f.name, "url": "/files/" + f.name,
					"hashes": map[string]string{"sha256": "00"}, "core-metadata": true}
				if f.ago > 0 {
					e["upload-time"] = stamp(f.ago)
				}
				out = append(out, e)
				if v := pypiPageVersion(dist, f.name); !slices.Contains(versions, v) {
					versions = append(versions, v)
				}
			}
			w.Header().Set("Content-Type", pypiSimpleJSON)
			_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"api-version": "1.1"},
				"name": dist, "files": out, "versions": versions})
			return
		}
		var b strings.Builder
		b.WriteString("<!DOCTYPE html><html><body>\n")
		for _, f := range files {
			fmt.Fprintf(&b, "<a href=\"/files/%s#sha256=00\">%s</a><br/>\n", f.name, f.name)
		}
		b.WriteString("</body></html>\n")
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func pypiPageVersions(dist, body string) []string {
	var out []string
	for _, m := range pypiHrefPattern.FindAllStringSubmatch(body, -1) {
		if v := pypiPageVersion(dist, pypiHrefFilename(m[1])); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func TestIndexFilterPypi(t *testing.T) {
	s := filteringServer(t, manifest.TypePypi)
	up := pypiFilterUpstream(t)
	s.cfg.PypiUpstream = up.URL
	seedProxyPypi(t, s, "widget", up.URL)
	seedProxyPypi(t, s, "fresh", up.URL)

	rec := get(t, s, "/pypi/simple/widget/")
	if rec.Code != http.StatusOK {
		t.Fatalf("simple page status = %d, body %s", rec.Code, rec.Body)
	}
	listed := pypiPageVersions("widget", rec.Body.String())

	t.Run("a range resolves to the newest compliant version", func(t *testing.T) {
		if strings.Contains(rec.Body.String(), "widget-4.3.0") {
			t.Errorf("4.3.0 is a day old under a 7d block and is still linked: %v", listed)
		}
		if got := newestMatching(listed, "4.1.0"); got != "4.2.0" {
			t.Errorf(">=4.1,<5 resolves to %q against %v, want 4.2.0", got, listed)
		}
		if n := strings.Count(rec.Body.String(), "widget-4.2.0"); n != 2*2 {
			t.Errorf("4.2.0 should keep both its wheel and its sdist, saw %d mentions", n)
		}
	})
	t.Run("pip has no latest tag; the newest listed is the newest compliant", func(t *testing.T) {
		if got := newestMatching(listed, "4.0.0"); got != "4.2.0" {
			t.Errorf("newest listed = %q, want 4.2.0", got)
		}
	})
	t.Run("a version with no publish time is kept", func(t *testing.T) {
		if !strings.Contains(rec.Body.String(), "widget-4.0.5") {
			t.Errorf("4.0.5 has no upload-time and no JSON API answer, and was dropped: %v", listed)
		}
	})
	t.Run("the response names what it withheld", func(t *testing.T) {
		if got := rec.Header().Get(filteredHeader); got != "1; age=1" {
			t.Errorf("%s = %q, want \"1; age=1\"", filteredHeader, got)
		}
		if rows := filterRows(t, s, manifest.TypePypi, "widget"); len(rows) != 1 {
			t.Errorf("got %d index_filtered rows for one request, want 1", len(rows))
		}
	})
	t.Run("a direct request for the withheld wheel is refused", func(t *testing.T) {
		if rec := get(t, s, "/pypi/wheels/widget-4.3.0-py3-none-any.whl"); rec.Code != http.StatusForbidden {
			t.Errorf("withheld wheel status = %d, want 403 (body %s)", rec.Code, rec.Body)
		}
		if !deniedWithheld(t, s, manifest.TypePypi, "widget", "4.3.0") {
			t.Error("no withheld_version denial row for 4.3.0")
		}
		if rec := get(t, s, "/pypi/wheels/widget-4.2.0-py3-none-any.whl"); rec.Code != http.StatusOK {
			t.Errorf("compliant wheel status = %d, want 200 (body %s)", rec.Code, rec.Body)
		}
	})
	t.Run("all filtered still serves the index", func(t *testing.T) {
		rec := get(t, s, "/pypi/simple/fresh/")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 so pip reports no matching distribution itself", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<a ") {
			t.Errorf("page still links a file: %s", rec.Body)
		}
	})
}

// pipAccept is the Accept header pip 24 sends to a simple index.
const pipAccept = "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01"

type pypiJSONPageView struct {
	Files []struct {
		Filename     string            `json:"filename"`
		URL          string            `json:"url"`
		Hashes       map[string]string `json:"hashes"`
		CoreMetadata any               `json:"core-metadata"`
	} `json:"files"`
	Versions []string `json:"versions"`
}

func TestIndexFilterPypiJSON(t *testing.T) {
	s := filteringServer(t, manifest.TypePypi)
	up := pypiFilterUpstream(t)
	s.cfg.PypiUpstream = up.URL
	seedProxyPypi(t, s, "widget", up.URL)
	seedProxyPypi(t, s, "fresh", up.URL)

	rec := get(t, s, "/pypi/simple/widget/", "Accept", pipAccept)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON simple page status = %d, body %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != pypiSimpleJSON {
		t.Fatalf("Content-Type = %q, want %s (body %s)", got, pypiSimpleJSON, rec.Body)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept") {
		t.Errorf("Vary = %q, want Accept", got)
	}
	var page pypiJSONPageView
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, f := range page.Files {
		listed = append(listed, pypiPageVersion("widget", f.Filename))
	}

	t.Run("a range resolves to the newest compliant version", func(t *testing.T) {
		if got := newestMatching(listed, "4.1.0"); got != "4.2.0" {
			t.Errorf(">=4.1,<5 resolves to %q against %v, want 4.2.0", got, listed)
		}
		if slices.Contains(page.Versions, "4.3.0") || !slices.Contains(page.Versions, "4.2.0") {
			t.Errorf("versions = %v, want 4.3.0 gone and 4.2.0 kept", page.Versions)
		}
	})
	t.Run("every file lands on bodega with its hashes and without the metadata promise", func(t *testing.T) {
		for _, f := range page.Files {
			if f.URL != "/pypi/wheels/"+f.Filename {
				t.Errorf("%s url = %q, want the wheel route", f.Filename, f.URL)
			}
			if f.Hashes["sha256"] != "00" {
				t.Errorf("%s lost its hashes", f.Filename)
			}
			if f.CoreMetadata != nil {
				t.Errorf("%s still promises core-metadata bodega cannot serve", f.Filename)
			}
		}
	})
	t.Run("a version with no publish time is kept", func(t *testing.T) {
		if !slices.Contains(listed, "4.0.5") {
			t.Errorf("4.0.5 has no upload-time and was dropped: %v", listed)
		}
	})
	t.Run("the response names what it withheld", func(t *testing.T) {
		if got := rec.Header().Get(filteredHeader); got != "1; age=1" {
			t.Errorf("%s = %q, want \"1; age=1\"", filteredHeader, got)
		}
		if rows := filterRows(t, s, manifest.TypePypi, "widget"); len(rows) != 1 {
			t.Errorf("got %d index_filtered rows for one request, want 1", len(rows))
		}
	})
	t.Run("a direct request for the withheld wheel is refused", func(t *testing.T) {
		if rec := get(t, s, "/pypi/wheels/widget-4.3.0-py3-none-any.whl"); rec.Code != http.StatusForbidden {
			t.Errorf("withheld wheel status = %d, want 403 (body %s)", rec.Code, rec.Body)
		}
	})
	t.Run("all filtered still serves the page", func(t *testing.T) {
		rec := get(t, s, "/pypi/simple/fresh/", "Accept", pipAccept)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 so pip reports no matching distribution itself", rec.Code)
		}
		var page pypiJSONPageView
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Files) != 0 || len(page.Versions) != 0 {
			t.Errorf("files = %v, versions = %v; want both empty", page.Files, page.Versions)
		}
	})
	t.Run("a client preferring HTML still gets HTML", func(t *testing.T) {
		rec := get(t, s, "/pypi/simple/widget/", "Accept", "text/html, */*")
		if strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "{") || strings.Contains(rec.Body.String(), "widget-4.3.0") {
			t.Errorf("HTML request answered %q", rec.Body)
		}
	})
}

// An upstream that ignores ?format= answers HTML, and the client asking for
// JSON gets that HTML, filtered and rewritten, rather than an error.
func TestIndexFilterPypiJSONUpstreamAnswersHTML(t *testing.T) {
	s := filteringServer(t, manifest.TypePypi)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<a href="/files/widget-4.2.0-py3-none-any.whl#sha256=00">a</a>`+"\n"+
			`<a href="/files/widget-4.3.0-py3-none-any.whl#sha256=00">b</a>`+"\n")
	}))
	t.Cleanup(ts.Close)
	s.cfg.PypiUpstream = ts.URL
	seedProxyPypi(t, s, "widget", ts.URL)
	s.publishTimes.put(manifest.TypePypi, "widget", "4.2.0", filterNow.Add(-filterOld["2.0"]))
	s.publishTimes.put(manifest.TypePypi, "widget", "4.3.0", filterNow.Add(-24*time.Hour))

	rec := get(t, s, "/pypi/simple/widget/", "Accept", pipAccept)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "4.3.0") || !strings.Contains(rec.Body.String(), `href="/pypi/wheels/widget-4.2.0`) {
		t.Errorf("status %d, body %s; want the HTML page filtered and rewritten", rec.Code, rec.Body)
	}
}

func TestPypiWantsJSON(t *testing.T) {
	for accept, want := range map[string]bool{
		pipAccept:                             true,
		"application/vnd.pypi.simple.v1+json": true,
		"application/vnd.pypi.simple.v1+json;q=0.5, text/html": false,
		"text/html": false,
		"*/*":       false,
		"":          false,
		"application/vnd.pypi.simple.v1+json;q=0":               false,
		"application/vnd.pypi.simple.latest+json":               true,
		"application/vnd.pypi.simple.v1+json; q=0, text/html":   false,
		"text/html, application/vnd.pypi.simple.v1+json; q=0.5": false,
		// A tie goes to HTML, the form this route served before it spoke JSON.
		"application/vnd.pypi.simple.v1+json, text/html": false,
	} {
		if got := pypiWantsJSON(accept); got != want {
			t.Errorf("pypiWantsJSON(%q) = %v, want %v", accept, got, want)
		}
	}
}

// ---- gomod ------------------------------------------------------------------

func gomodFilterUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	modules := map[string]map[string]time.Duration{
		// v1.0.5's .info 404s, so it cannot be dated.
		"example.com/widget": {"v1.0.5": 0, "v1.1.0": filterOld["1.0"], "v1.2.0": filterOld["2.0"], "v1.3.0": 24 * time.Hour},
		"example.com/fresh":  {"v1.0.0": time.Hour},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mod, file, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/@v/")
		versions := modules[mod]
		if !ok || versions == nil {
			http.NotFound(w, r)
			return
		}
		if file == "list" {
			for v := range versions {
				_, _ = fmt.Fprintln(w, v)
			}
			return
		}
		v := gomodVersionFromFile(file)
		ago, known := versions[v]
		switch {
		case !known:
			http.NotFound(w, r)
		case strings.HasSuffix(file, ".info"):
			if ago == 0 {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": v, "Time": stamp(ago)})
		default:
			_, _ = w.Write([]byte("zip bytes"))
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestIndexFilterGomod(t *testing.T) {
	s := filteringServer(t, manifest.TypeGomod)
	s.cfg.GomodUpstream = gomodFilterUpstream(t).URL

	rec := get(t, s, "/go/example.com/widget/@v/list")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body %s", rec.Code, rec.Body)
	}
	listed := strings.Fields(rec.Body.String())

	t.Run("a query resolves to the newest compliant version", func(t *testing.T) {
		if strings.Contains(rec.Body.String(), "v1.3.0") {
			t.Errorf("v1.3.0 is a day old under a 7d block and is still listed: %v", listed)
		}
		if got := newestMatching(listed, "v1.1.0"); got != "v1.2.0" {
			t.Errorf("v1 resolves to %q against %v, want v1.2.0", got, listed)
		}
	})
	t.Run("go has no latest tag; the newest listed is the newest compliant", func(t *testing.T) {
		if got := newestMatching(listed, "v1.0.0"); got != "v1.2.0" {
			t.Errorf("newest listed = %q, want v1.2.0", got)
		}
	})
	t.Run("a version with no publish time is kept", func(t *testing.T) {
		if !strings.Contains(rec.Body.String(), "v1.0.5") {
			t.Errorf("v1.0.5 has no readable .info and was dropped: %v", listed)
		}
	})
	t.Run("the response names what it withheld", func(t *testing.T) {
		if got := rec.Header().Get(filteredHeader); got != "1; age=1" {
			t.Errorf("%s = %q, want \"1; age=1\"", filteredHeader, got)
		}
		if rows := filterRows(t, s, manifest.TypeGomod, "example.com/widget"); len(rows) != 1 {
			t.Errorf("got %d index_filtered rows for one request, want 1", len(rows))
		}
	})
	t.Run("publish times are cached rather than refetched", func(t *testing.T) {
		if _, ok := s.publishTimes.get(manifest.TypeGomod, "example.com/widget", "v1.2.0"); !ok {
			t.Error("v1.2.0's .info time was not cached")
		}
	})
	t.Run("a direct request for the withheld .zip is refused", func(t *testing.T) {
		if rec := get(t, s, "/go/example.com/widget/@v/v1.3.0.zip"); rec.Code != http.StatusForbidden {
			t.Errorf("withheld zip status = %d, want 403 (body %s)", rec.Code, rec.Body)
		}
		if !deniedWithheld(t, s, manifest.TypeGomod, "example.com/widget", "v1.3.0") {
			t.Error("no withheld_version denial row for v1.3.0")
		}
		if rec := get(t, s, "/go/example.com/widget/@v/v1.2.0.zip"); rec.Code != http.StatusOK {
			t.Errorf("compliant zip status = %d, want 200 (body %s)", rec.Code, rec.Body)
		}
	})
	t.Run("all filtered still serves the index", func(t *testing.T) {
		rec := get(t, s, "/go/example.com/fresh/@v/list")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 so go reports no matching version itself", rec.Code)
		}
		if strings.TrimSpace(rec.Body.String()) != "" {
			t.Errorf("list = %q, want empty", rec.Body)
		}
	})
}
