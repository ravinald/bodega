package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func TestVersionAllowed(t *testing.T) {
	const (
		exact      = manifest.ConstraintExact
		compatible = manifest.ConstraintCompatible
		patch      = manifest.ConstraintPatch
		anyVer     = manifest.ConstraintAny
	)
	semverTypes := []string{manifest.TypeNpm, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeMaven, manifest.TypeRubygems}
	type tc struct {
		typ, entry, req, constraint string
		allowed, ordered            bool
	}
	var cases []tc
	// The release-number cases read the same under every ordering bodega has.
	for _, typ := range semverTypes {
		cases = append(cases,
			tc{typ, "1.9.0", "1.9.0", exact, true, true},
			tc{typ, "1.9.0", "1.9.1", exact, false, true},
			tc{typ, "1.9.0", "1.9.0", "", true, true},
			tc{typ, "1.9.0", "1.10.0", compatible, true, true},
			tc{typ, "1.9.0", "1.9.0", compatible, true, true},
			tc{typ, "1.9.0", "1.8.9", compatible, false, true},
			tc{typ, "1.9.0", "2.0.0", compatible, false, true},
			tc{typ, "1.9.0", "1.9.5", patch, true, true},
			tc{typ, "1.9.0", "1.10.0", patch, false, true},
			tc{typ, "1.9.0", "2.9.5", patch, false, true},
			tc{typ, "1.9.0", "1.8.9", patch, false, true},
			tc{typ, "1.9.0", "9.9.9", anyVer, true, true},
			tc{typ, "1.9.0", "1.9.0", "unknown", false, true},
		)
	}
	cases = append(cases,
		tc{manifest.TypeGomod, "v1.9.0", "v2.0.0+incompatible", compatible, false, true},
		tc{manifest.TypeGomod, "v2.0.0+incompatible", "v2.1.0+incompatible", compatible, true, true},
		tc{manifest.TypeGomod, "v1.9.0", "v1.10.0", compatible, true, true},
		tc{manifest.TypeNpm, "1.9.0", "2.0.0-rc.1", compatible, false, true},
		tc{manifest.TypeNpm, "1.0.0", "1.0.0-rc.1", compatible, false, true},
		tc{manifest.TypeMaven, "1.0", "1.0-rc1", compatible, false, true},
		tc{manifest.TypeMaven, "1.0-rc1", "1.0", compatible, true, true},
		tc{manifest.TypeMaven, "1.0", "1.0.0", exact, true, true},
		tc{manifest.TypeMaven, "1.9", "1.9.5", patch, true, true},
		tc{manifest.TypeRubygems, "2.0.0", "2.0.0.pre", compatible, false, true},
		tc{manifest.TypeRubygems, "2.0.0.pre", "2.0.0", compatible, true, true},
		tc{manifest.TypeRubygems, "1.0", "1.0.0", exact, true, true},
	)
	// A version the ordering cannot place is refused under every constraint
	// but any, on either side of the comparison and even when the strings
	// are equal.
	for _, typ := range semverTypes {
		bad := "not a version"
		if typ == manifest.TypeMaven {
			bad = "1.0 junk"
		}
		for _, c := range []string{exact, "", compatible, patch} {
			cases = append(cases,
				tc{typ, "1.9.0", bad, c, false, false},
				tc{typ, bad, "1.9.0", c, false, false},
				tc{typ, bad, bad, c, false, false},
			)
		}
		cases = append(cases, tc{typ, "1.9.0", bad, anyVer, true, true})
	}
	cases = append(cases, tc{manifest.TypeApt, "1.0", "1.0", exact, false, false})

	for _, c := range cases {
		allowed, ordered := versionAllowed(c.typ, c.entry, c.req, c.constraint)
		if allowed != c.allowed || ordered != c.ordered {
			t.Errorf("versionAllowed(%s, %q, %q, %q) = %v, %v; want %v, %v",
				c.typ, c.entry, c.req, c.constraint, allowed, ordered, c.allowed, c.ordered)
		}
	}
}

// Each route below compared versions as strings, which refused 1.10.0
// under a compatible 1.9.0 and admitted 2.0.0.
func TestCompatibleConstraintBoundsTheMajorOnEveryRoute(t *testing.T) {
	compatible := func(v string) manifest.VersionEntry {
		return manifest.VersionEntry{Version: v, Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintCompatible}
	}
	t.Run("npm tarball", func(t *testing.T) {
		s := proxyingServer(t)
		up := newRecordingUpstream(t)
		s.cfg.NpmUpstream = up.ts.URL
		up.route("/leftpad/-/leftpad-1.10.0.tgz", "leftpad 1.10.0")
		addVersion(t, s, manifest.TypeNpm, "leftpad", compatible("1.9.0"))

		if rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.10.0.tgz", nil); rec.Code != http.StatusOK {
			t.Errorf("1.10.0 under compatible 1.9.0 = %d %q, want 200", rec.Code, rec.Body.String())
		}
		rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-2.0.0.tgz", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("2.0.0 under compatible 1.9.0 = %d, want 403", rec.Code)
		}
		refusalIncident(t, rec.Header(), checkConstraint)
	})

	t.Run("npm packument filter", func(t *testing.T) {
		raw := []byte(`{"name":"leftpad","dist-tags":{"latest":"2.0.0"},"versions":{` +
			`"1.9.0":{"version":"1.9.0"},"1.10.0":{"version":"1.10.0"},"2.0.0":{"version":"2.0.0"}}}`)
		pm := &manifest.PackageManifest{Name: "leftpad", Type: manifest.TypeNpm,
			Versions: []manifest.VersionEntry{compatible("1.9.0")}}
		out, err := filterPackumentByManifest(raw, pm)
		if err != nil {
			t.Fatalf("filter: %v", err)
		}
		var doc struct {
			Versions map[string]any `json:"versions"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("unmarshal filtered: %v", err)
		}
		if _, ok := doc.Versions["1.10.0"]; !ok {
			t.Errorf("1.10.0 stripped under compatible 1.9.0: %s", out)
		}
		if _, ok := doc.Versions["2.0.0"]; ok {
			t.Errorf("2.0.0 kept under compatible 1.9.0: %s", out)
		}
	})

	t.Run("cargo index", func(t *testing.T) {
		s := hostedServer(t)
		ve := sha256Entry("1.9.0", "itoa 1.9.0")
		ve.VersionConstraint = manifest.ConstraintCompatible
		addVersion(t, s, manifest.TypeCargo, "itoa", ve)
		addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.10.0", "itoa 1.10.0"))
		addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("2.0.0", "itoa 2.0.0"))

		status, body := getStatusAndBody(t, s, "/cargo/it/oa/itoa")
		if status != http.StatusOK {
			t.Fatalf("GET /cargo/it/oa/itoa = %d: %s", status, body)
		}
		if !strings.Contains(body, `"vers":"1.10.0"`) {
			t.Errorf("1.10.0 dropped under compatible 1.9.0: %s", body)
		}
		if strings.Contains(body, `"vers":"2.0.0"`) {
			t.Errorf("2.0.0 offered under compatible 1.9.0: %s", body)
		}
	})

	t.Run("cargo download", func(t *testing.T) {
		s := proxyingServer(t)
		up := newRecordingUpstream(t)
		s.cfg.CargoDLUpstream = up.ts.URL
		up.route("/itoa/1.9.5/download", "itoa 1.9.5")
		up.route("/itoa/2.0.0/download", "itoa 2.0.0")
		addVersion(t, s, manifest.TypeCargo, "itoa", compatible("1.9.0"))

		rec := doRequest(s, http.MethodGet, "/cargo/itoa/2.0.0/download", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("2.0.0 under compatible 1.9.0 = %d %q, want 403", rec.Code, rec.Body.String())
		}
		refusalIncident(t, rec.Header(), checkConstraint)
		if up.sawPath("/itoa/2.0.0/download") {
			t.Errorf("refused 2.0.0 download reached the upstream: %v", up.paths())
		}
		wantOneDenial(t, s, audit.DenialVersionConstraint, "127.0.0.1")

		if rec := doRequest(s, http.MethodGet, "/cargo/itoa/1.9.5/download", nil); rec.Code != http.StatusOK {
			t.Errorf("1.9.5 under compatible 1.9.0 = %d %q, want 200", rec.Code, rec.Body.String())
		}
	})

	t.Run("gomod", func(t *testing.T) {
		s := proxyingServer(t)
		up := newRecordingUpstream(t)
		s.cfg.GomodUpstream = up.ts.URL
		up.route("/example.com/mod/@v/v1.10.0.mod", "module example.com/mod\n")
		addVersion(t, s, manifest.TypeGomod, "example.com/mod", compatible("v1.9.0"))

		if rec := doRequest(s, http.MethodGet, "/go/example.com/mod/@v/v1.10.0.mod", nil); rec.Code != http.StatusOK {
			t.Errorf("v1.10.0 under compatible v1.9.0 = %d %q, want 200", rec.Code, rec.Body.String())
		}
		rec := doRequest(s, http.MethodGet, "/go/example.com/mod/@v/v2.0.0+incompatible.mod", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("v2.0.0+incompatible under compatible v1.9.0 = %d, want 403", rec.Code)
		}
		refusalIncident(t, rec.Header(), checkConstraint)
	})

	t.Run("maven", func(t *testing.T) {
		s, up := mavenServer(t)
		up.route(mavenWidgetDir+"1.10.0/widget-1.10.0.jar", "widget jar 1.10.0")
		addVersion(t, s, manifest.TypeMaven, mavenWidgetName, compatible("1.9.0"))

		if code, body, _ := getMaven(t, s, "org/example/core/widget/1.10.0/widget-1.10.0.jar"); code != http.StatusOK {
			t.Errorf("1.10.0 under compatible 1.9.0 = %d %q, want 200", code, body)
		}
		code, _, h := getMaven(t, s, "org/example/core/widget/2.0.0/widget-2.0.0.jar")
		if code != http.StatusForbidden {
			t.Fatalf("2.0.0 under compatible 1.9.0 = %d, want 403", code)
		}
		refusalIncident(t, h, checkConstraint)
	})

	t.Run("rubygems", func(t *testing.T) {
		g := newGemRegistry(t)
		s := gemServer(t, g)
		g.routes["/gems/nokogiri-1.10.0-x86_64-linux.gem"] = "\x00nokogiri 1.10.0"
		addVersion(t, s, manifest.TypeRubygems, "nokogiri", compatible("1.9.0"))

		if rec := doRequest(s, http.MethodGet, "/rubygems/gems/nokogiri-1.10.0-x86_64-linux.gem", nil); rec.Code != http.StatusOK {
			t.Errorf("1.10.0 under compatible 1.9.0 = %d %q, want 200", rec.Code, rec.Body.String())
		}
		rec := doRequest(s, http.MethodGet, "/rubygems/gems/nokogiri-2.0.0-x86_64-linux.gem", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("2.0.0 under compatible 1.9.0 = %d, want 403", rec.Code)
		}
		refusalIncident(t, rec.Header(), checkConstraint)
	})
}

// A version the ordering cannot place is refused with a reason that says so,
// in the body and on the row, rather than calling it out of range.
func TestUnorderableVersionRefusalSaysSo(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
	addVersion(t, s, manifest.TypeNpm, "leftpad", manifest.VersionEntry{
		Version: "1.9.0", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintCompatible,
	})

	rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-banana.tgz", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unorderable version = %d %q, want 403", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"could not be ordered as a npm version", "banana", "1.9.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q does not carry %q", body, want)
		}
	}
	if strings.Contains(body, "is outside the version_constraint") {
		t.Errorf("body calls an unorderable version out of range: %q", body)
	}
	details := wantOneDenial(t, s, audit.DenialVersionConstraint, "127.0.0.1")
	if !strings.Contains(details["reason"], "could not be ordered") {
		t.Errorf("row details %v carry no unorderable reason", details)
	}
}
