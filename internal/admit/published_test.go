package admit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// stubRegistry answers each path in docs with its JSON body and everything
// else with 404, counting every request it serves.
func stubRegistry(t *testing.T, docs map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// The case the age gate left undated: no audit database, so no age policy and
// no gate at all. Each registry is reached through the url the entry names,
// the one a fetch would read.
func TestRecordPublishedDatesAnImportWithNoAgePolicy(t *testing.T) {
	srv, _ := stubRegistry(t, map[string]string{
		"/left-pad": `{"time":{"1.3.0":"2018-04-09T01:22:46.500Z"}}`,
		"/pypi/requests/2.31.0/json": `{"urls":[
			{"upload_time_iso_8601":"2023-05-22T15:12:44.000000Z"},
			{"upload_time_iso_8601":"2023-05-22T15:12:42.000000Z"}]}`,
		"/golang.org/x/text/@v/v0.14.0.info": `{"Version":"v0.14.0","Time":"2023-10-11T22:24:51Z"}`,
	})
	for _, tc := range []struct {
		typ, name, version, want string
	}{
		{manifest.TypeNpm, "left-pad", "1.3.0", "2018-04-09T01:22:46Z"},
		{manifest.TypePypi, "requests", "2.31.0", "2023-05-22T15:12:42Z"},
		{manifest.TypeGomod, "golang.org/x/text", "v0.14.0", "2023-10-11T22:24:51Z"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			pm := &manifest.PackageManifest{Type: tc.typ, Name: tc.name,
				Versions: []manifest.VersionEntry{{Version: tc.version, URL: srv.URL + "/"}}}
			res := Admit(t.Context(), nil, nil, nil, pm, "")
			if !res.OK() {
				t.Fatalf("admit refused: %s", res.Reason)
			}
			RecordPublished(t.Context(), pm, nil, &res)
			if got := pm.Versions[0].PublishedAt; got != tc.want {
				t.Errorf("published_at = %q, want %q", got, tc.want)
			}
			if len(res.Warnings) != 0 {
				t.Errorf("warnings = %v, want none", res.Warnings)
			}
		})
	}
}

// Crates publish their times on the API host, which no entry url names.
func TestRecordPublishedDatesACrateFromTheAPIHost(t *testing.T) {
	srv, _ := stubRegistry(t, map[string]string{
		"/api/v1/crates/serde/1.0.190": `{"version":{"created_at":"2023-10-17T19:45:01.123456+00:00"}}`,
	})
	ac := policy.NewAgeChecker(nil)
	ac.CratesBase = srv.URL
	pm := &manifest.PackageManifest{Type: manifest.TypeCargo, Name: "serde",
		Versions: []manifest.VersionEntry{{Version: "1.0.190", URL: "https://static.crates.io/crates"}}}
	var res Result
	recordPublished(t.Context(), ac, pm, nil, &res)
	if got := pm.Versions[0].PublishedAt; got != "2023-10-17T19:45:01Z" {
		t.Errorf("published_at = %q, want 2023-10-17T19:45:01Z", got)
	}
}

// A version upstream cannot date stays undated, is named in a warning, and
// does not stop its siblings from being dated.
func TestRecordPublishedLeavesAnUndatableVersionUndated(t *testing.T) {
	srv, _ := stubRegistry(t, map[string]string{
		"/left-pad": `{"time":{"1.3.0":"2018-04-09T01:22:46Z"}}`,
	})
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad", Versions: []manifest.VersionEntry{
		{Version: "9.9.9", URL: srv.URL},
		{Version: "1.3.0", URL: srv.URL},
	}}
	var res Result
	RecordPublished(t.Context(), pm, nil, &res)
	if got := pm.Versions[0].PublishedAt; got != "" {
		t.Errorf("9.9.9 published_at = %q; a version upstream has no time for was given one", got)
	}
	if got := pm.Versions[1].PublishedAt; got != "2018-04-09T01:22:46Z" {
		t.Errorf("1.3.0 published_at = %q, want 2018-04-09T01:22:46Z", got)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "9.9.9") ||
		!strings.Contains(res.Warnings[0], "no publish time recorded") {
		t.Errorf("warnings = %v, want one naming 9.9.9", res.Warnings)
	}
}

type refusingTransport struct{ calls atomic.Int32 }

func (rt *refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	return nil, errors.New("connect: network is unreachable")
}

// Offline, one registry is tried once per manifest: every version is still
// named undated, but a long version list does not cost a timeout apiece.
func TestRecordPublishedTriesAnUnreachableRegistryOnce(t *testing.T) {
	rt := &refusingTransport{}
	ac := policy.NewAgeChecker(nil)
	ac.HTTP = &http.Client{Transport: rt}
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad", Versions: []manifest.VersionEntry{
		{Version: "1.1.0"}, {Version: "1.2.0"}, {Version: "1.3.0"},
	}}
	var res Result
	recordPublished(t.Context(), ac, pm, nil, &res)
	if n := rt.calls.Load(); n != 1 {
		t.Errorf("registry tried %d times, want 1", n)
	}
	for _, ve := range pm.Versions {
		if ve.PublishedAt != "" {
			t.Errorf("%s dated %q with no registry reachable", ve.Version, ve.PublishedAt)
		}
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "3 versions") {
		t.Errorf("warnings = %v, want one line covering 3 versions", res.Warnings)
	}
}

// Nothing is read for a version that is already dated, pins no release, is
// already in the stored package a merge keeps, or belongs to a type no
// registry dates.
func TestRecordPublishedReadsOnlyWhatItWillWrite(t *testing.T) {
	srv, hits := stubRegistry(t, nil)
	existing := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad",
		Versions: []manifest.VersionEntry{{Version: "1.2.0"}}}
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad", Versions: []manifest.VersionEntry{
		{Version: "1.3.0", URL: srv.URL, PublishedAt: "2018-04-09T00:00:00Z"},
		{Version: "latest", URL: srv.URL},
		{Version: "*", URL: srv.URL},
		{Version: "", URL: srv.URL},
		{Version: "1.2.0", URL: srv.URL},
	}}
	var res Result
	RecordPublished(t.Context(), pm, existing, &res)

	apt := &manifest.PackageManifest{Type: manifest.TypeApt, Name: "hello",
		Versions: []manifest.VersionEntry{{Version: "2.10", URL: srv.URL}}}
	RecordPublished(t.Context(), apt, nil, &res)

	if n := hits.Load(); n != 0 {
		t.Errorf("registry read %d times, want 0", n)
	}
	if got := pm.Versions[0].PublishedAt; got != "2018-04-09T00:00:00Z" {
		t.Errorf("a supplied published_at was replaced with %q", got)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
}
