package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const consoleMetadataPath = "/composer/p2/symfony/console.json"

// composerExpand reads a package's versions out of a p2 document the way
// Composer's MetadataMinifier::expand does: each version of a minified list
// starts from the one before it, takes its own keys over, and drops a key
// set to "__unset".
func composerExpand(t *testing.T, body, name string) []map[string]any {
	t.Helper()
	var doc struct {
		Packages map[string][]map[string]any `json:"packages"`
		Minified string                      `json:"minified"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("metadata does not parse: %v\n%s", err, body)
	}
	var out []map[string]any
	var current map[string]any
	for i, v := range doc.Packages[name] {
		if doc.Minified != "composer/2.0" || i == 0 {
			current = map[string]any{}
		} else {
			next := map[string]any{}
			for k, val := range current {
				next[k] = val
			}
			current = next
		}
		for k, val := range v {
			if val == "__unset" {
				delete(current, k)
				continue
			}
			current[k] = val
		}
		out = append(out, current)
	}
	return out
}

func expandedVersions(vs []map[string]any) string {
	var out []string
	for _, v := range vs {
		s, _ := v["version"].(string)
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

func TestComposerClosedProfileAtBlock(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeComposer, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeComposer, Name: "symfony/console", Version: "v7.1.4"}})

	t.Run("an unlisted package is refused at metadata and dist", func(t *testing.T) {
		if status, body := pf.get(t, "/composer/p2/psr/log.json"); status != http.StatusNotFound {
			t.Errorf("psr/log metadata = %d, want 404: %s", status, body)
		}
		status, body := pf.get(t, "/composer/dist/psr/log/3.0.2/"+logRef+".zip")
		if status != http.StatusForbidden || !strings.Contains(body, "membership") {
			t.Errorf("psr/log dist = %d, want a 403 naming membership: %s", status, body)
		}
		if n := f.packagist.hitsFor("/p2/psr/log.json") + f.archives.hitsFor("/php-fig/log/legacy.zip/"+logRef); n != 0 {
			t.Errorf("the refused package reached Packagist or the archive host %d times", n)
		}
		rows := waitForDecision(t, s, audit.DecisionDenied, 2)
		for _, row := range rows {
			if row.PatternHint != "bodega profile add web composer psr/log" {
				t.Errorf("the denied row's pattern_hint = %q, want the command that closes it", row.PatternHint)
			}
		}
	})

	t.Run("a listed package is served at its pin", func(t *testing.T) {
		if status, body := pf.get(t, consoleDistPath("v7.1.4", consoleRef514)); status != http.StatusOK || body != "PK\x03\x04 console 7.1.4" {
			t.Errorf("the pinned console dist answered %d: %q", status, body)
		}
		if status, _ := pf.get(t, consoleDistPath("v7.1.5", consoleRef515)); status != http.StatusForbidden {
			t.Errorf("console v7.1.5, past the pin, answered %d, want 403", status)
		}
	})

	t.Run("metadata lists only the pin and still expands to it", func(t *testing.T) {
		status, body := pf.get(t, consoleMetadataPath)
		if status != http.StatusOK {
			t.Fatalf("console metadata = %d: %s", status, body)
		}
		vs := composerExpand(t, body, "symfony/console")
		if got := expandedVersions(vs); got != "v7.1.4" {
			t.Fatalf("metadata expands to %q, want only the pinned v7.1.4:\n%s", got, body)
		}
		v := vs[0]
		// v7.1.4 inherits name, description and require from v7.1.5 in the
		// upstream document; dropping v7.1.5 without re-minifying loses them.
		if v["name"] != "symfony/console" || v["description"] == nil {
			t.Errorf("the kept version lost the keys it inherited from the dropped one: %v", v)
		}
		if req, _ := v["require"].(map[string]any); req["psr/log"] != "^1|^2|^3" {
			t.Errorf("the kept version's require = %v, want the one it inherited", v["require"])
		}
		dist, _ := v["dist"].(map[string]any)
		if url, _ := dist["url"].(string); !strings.HasSuffix(url, "/composer/dist/symfony/console/v7.1.4/"+consoleRef514+".zip") {
			t.Errorf("the kept version's dist.url = %q, want the dist route for v7.1.4", url)
		}
	})

	t.Run("the cache holds the upstream document", func(t *testing.T) {
		if got := storedObject(t, s, manifest.TypeComposer, manifest.ComposerMetadataKey("symfony/console", false)); got != f.console {
			t.Errorf("the cached metadata is not Packagist's document:\n%s", got)
		}
		if _, hdr := getHeaderWithToken(t, s, pf.token, consoleMetadataPath); hdr.Get("Cache-Control") != cacheNoStore {
			t.Errorf("filtered metadata Cache-Control = %q, want %q", hdr.Get("Cache-Control"), cacheNoStore)
		}
		_, body := getWithToken(t, s, "", consoleMetadataPath)
		if got := expandedVersions(composerExpand(t, body, "symfony/console")); got != "v7.1.5,v7.1.4,v7.1.3" {
			t.Errorf("an unidentified request was filtered to %q", got)
		}
	})
}

// A vendor-wide entry admits every package of its vendor and none of
// another, and an entry naming one package of that vendor still sets its own
// version rule.
func TestComposerVendorWideEntry(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeComposer, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeComposer, Name: "psr/*"}})

	if status, body := pf.get(t, "/composer/dist/psr/log/3.0.2/"+logRef+".zip"); status != http.StatusOK || body != "PK\x03\x04 psr/log 3.0.2" {
		t.Errorf("a package under the vendor-wide entry answered %d: %q", status, body)
	}
	if status, _ := pf.get(t, "/composer/p2/psr/log.json"); status != http.StatusOK {
		t.Errorf("metadata under the vendor-wide entry answered %d", status)
	}
	if status, _ := pf.get(t, consoleDistPath("v7.1.5", consoleRef515)); status != http.StatusForbidden {
		t.Errorf("symfony/console, outside psr/*, answered %d, want 403", status)
	}
	if status, _ := pf.get(t, consoleMetadataPath); status != http.StatusNotFound {
		t.Errorf("symfony/console metadata, outside psr/*, answered %d, want 404", status)
	}

	writeProfile(t, s, "pinned", []audit.ProfileTypeRule{closedRule(manifest.TypeComposer, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeComposer, Name: "symfony/*"},
			{Type: manifest.TypeComposer, Name: "symfony/console", Constraint: manifest.ConstraintExact, Version: "v7.1.5"},
		})
	bindProfileTo(t, s, "pinned", "web01")
	if status, _ := pf.get(t, consoleDistPath("v7.1.4", consoleRef514)); status != http.StatusForbidden {
		t.Errorf("console v7.1.4 answered %d; its own exact entry should override the floating vendor-wide one", status)
	}
	_, body := pf.get(t, consoleMetadataPath)
	if got := expandedVersions(composerExpand(t, body, "symfony/console")); got != "v7.1.5" {
		t.Errorf("metadata under the overriding entry expands to %q, want v7.1.5", got)
	}
}

func TestComposerWarnServesAndRecordsTheReach(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeComposer, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{{Type: manifest.TypeComposer, Name: "symfony/console"}})

	if status, body := pf.get(t, "/composer/dist/psr/log/3.0.2/"+logRef+".zip"); status != http.StatusOK || body != "PK\x03\x04 psr/log 3.0.2" {
		t.Fatalf("warn refused an unlisted package: %d %q", status, body)
	}
	rows := waitForDecision(t, s, audit.DecisionDenied, 1)
	if rows[0].PkgName != "psr/log" || rows[0].PatternHint != "bodega profile add web composer psr/log" {
		t.Errorf("the reach row = %s with hint %q", rows[0].PkgName, rows[0].PatternHint)
	}
	status, body := pf.get(t, "/composer/p2/psr/log.json")
	if got := expandedVersions(composerExpand(t, body, "psr/log")); status != http.StatusOK || got != "3.0.2" {
		t.Errorf("warn metadata for a package it permits by expansion = %d %q", status, got)
	}
}

// A pin inside an open, floating type holds one package and nothing else.
func TestComposerPinnedVersion(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{{Type: manifest.TypeComposer, Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating}},
		[]audit.ProfileEntry{{Type: manifest.TypeComposer, Name: "symfony/console", Constraint: manifest.ConstraintExact, Version: "v7.1.5", Reason: "7.1.4 predates the php2shell fix"}})

	if status, body := pf.get(t, consoleDistPath("v7.1.5", consoleRef515)); status != http.StatusOK || body != "PK\x03\x04 console 7.1.5" {
		t.Errorf("the pinned version answered %d: %q", status, body)
	}
	status, body := pf.get(t, consoleDistPath("v7.1.4", consoleRef514))
	if status != http.StatusForbidden || !strings.Contains(body, "v7.1.5") {
		t.Errorf("console v7.1.4 = %d, want a 403 naming the pin: %s", status, body)
	}
	if n := f.archives.hitsFor("/archives/symfony/console/" + consoleRef514); n != 0 {
		t.Errorf("the refused version reached the archive host %d times", n)
	}

	_, meta := pf.get(t, consoleMetadataPath)
	if got := expandedVersions(composerExpand(t, meta, "symfony/console")); got != "v7.1.5" {
		t.Errorf("metadata expands to %q, want v7.1.5:\n%s", got, meta)
	}
	_, dev := pf.get(t, "/composer/p2/symfony/console~dev.json")
	if got := expandedVersions(composerExpand(t, dev, "symfony/console")); got != "" {
		t.Errorf("~dev.json under a pin expands to %q, want no versions", got)
	}

	if status, body := pf.get(t, "/composer/dist/psr/log/3.0.2/"+logRef+".zip"); status != http.StatusOK || body != "PK\x03\x04 psr/log 3.0.2" {
		t.Errorf("an unpinned package in the open type answered %d: %q", status, body)
	}
}

// Whatever set of versions the filter keeps, Composer's expansion of the
// filtered document is the expansion of the upstream's with the dropped
// versions removed: no kept version gains or loses a key.
func TestFilterComposerMetadataKeepsEachVersionsExpansion(t *testing.T) {
	t.Parallel()
	const doc = `{"packages":{"a/b":[` +
		`{"name":"a/b","version":"3.0.0","require":{"php":">=8.2"},"dist":{"url":"https://x/3","type":"zip","reference":"r3"},"extra":{"k":1}},` +
		`{"version":"2.0.0","dist":{"url":"https://x/2","type":"zip","reference":"r2"},"extra":"__unset"},` +
		`{"version":"1.1.0","require":{"php":">=7.4"},"dist":"__unset","source":{"url":"https://git/x","type":"git","reference":"r11"}},` +
		`{"version":"1.0.0","dist":{"url":"https://x/1","type":"zip","reference":"r1"}}` +
		`]},"minified":"composer/2.0","security-advisories":[]}`
	all := composerExpand(t, doc, "a/b")
	versions := []string{"3.0.0", "2.0.0", "1.1.0", "1.0.0"}

	for mask := range 1 << len(versions) {
		var keep []string
		var want []map[string]any
		for i, v := range versions {
			if mask&(1<<i) != 0 {
				keep = append(keep, v)
				want = append(want, all[i])
			}
		}
		permit := func(v string) bool {
			for _, k := range keep {
				if k == v {
					return true
				}
			}
			return false
		}
		got, err := filterComposerMetadata([]byte(doc), "a/b", permit)
		if err != nil {
			t.Fatalf("keep %v: %v", keep, err)
		}
		if !strings.HasSuffix(string(got), `]},"minified":"composer/2.0","security-advisories":[]}`) {
			t.Errorf("keep %v: the members outside the version list changed:\n%s", keep, got)
		}
		if exp := composerExpand(t, string(got), "a/b"); !reflect.DeepEqual(exp, want) && (len(exp) != 0 || len(want) != 0) {
			t.Errorf("keep %v: expands to\n%v\nwant\n%v\nfrom\n%s", keep, exp, want, got)
		}
	}

	if got, err := filterComposerMetadata([]byte(`{"packages":[],"minified":"composer/2.0"}`), "a/b", func(string) bool { return false }); err != nil || string(got) != `{"packages":[],"minified":"composer/2.0"}` {
		t.Errorf("Packagist's empty answer = %s, %v", got, err)
	}
}
