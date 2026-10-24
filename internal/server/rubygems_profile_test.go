package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5" //nolint:gosec // G501: the compact index's own checksum, which Bundler compares; it guards nothing here.
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// Fixtures written by Ruby 2.6's own Marshal, not by rbMarshal, so the reader
// is tested against the format rather than against itself.
//
//	specs: [[name, Gem::Version, platform]] for concurrent-ruby 1.3.4,
//	       nokogiri 1.15.0, 1.16.7 and 1.16.7-x86_64-linux, rails 7.1.0, the
//	       "ruby" platform one shared String so the stream carries object links
//	deps:  [{name:, number:, platform:, dependencies:}] for nokogiri 1.15.0,
//	       nokogiri 1.16.7 and rails 7.1.0
const (
	gemProfileSpecsB64 = "H4sIADn/22oAA2PhiOaK5vBUEknOz0suLSpKzSvRLSpNqmSzYnMNCbUSdE/NtbIKSy0qzszPi2bzVOIy1DPWM2GzZgjxVOIEKwQyQQbw5uVn56dnFmWCBEKt2UCKuQ31DE31DEAiDtz4FJnpmeNQ5CDsqSRYYWEWb2aim5OZV1oBs4+rKDEzpxjJHC5zPUOYXQCX9smy1gAAAA=="
	gemProfileDepsB64  = "BAhbCHsJOgluYW1lSSINbm9rb2dpcmkGOgZFVDoLbnVtYmVySSILMS4xNS4wBjsGVDoNcGxhdGZvcm1JIglydWJ5BjsGVDoRZGVwZW5kZW5jaWVzWwZbB0kiCXJhY2MGOwZUSSILfj4gMS40BjsGVHsJOwBJIg1ub2tvZ2lyaQY7BlQ7B0kiCzEuMTYuNwY7BlQ7CEkiCXJ1YnkGOwZUOwlbBlsHSSIJcmFjYwY7BlRJIgt+PiAxLjQGOwZUewk7AEkiCnJhaWxzBjsGVDsHSSIKNy4xLjAGOwZUOwhJIglydWJ5BjsGVDsJWwA="

	gemProfileInfoNokogiri = "---\n" +
		"1.15.0 racc:~> 1.4|checksum:dddd\n" +
		"1.16.7 mini_portile2:~> 2.8.2,racc:~> 1.4|checksum:bbbb\n" +
		"1.16.7-x86_64-linux racc:~> 1.4|checksum:cccc\n"
	gemProfileInfoConcurrent = "---\n1.3.4 |checksum:aaaa,ruby:>= 2.3\n"
	gemProfileInfoRails      = "---\n7.1.0 |checksum:eeee\n"
)

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // G401: the compact index's own checksum.
	return hex.EncodeToString(sum[:])
}

func mustB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return string(b)
}

// gemProfileRegistry is the gem fixture with a third gem, a second nokogiri
// release, real checksums in versions and real Marshal in the full index and
// the dependency API.
func gemProfileRegistry(t *testing.T) (*gemRegistry, string) {
	t.Helper()
	g := newGemRegistry(t)
	versions := "created_at: 2026-10-01T00:00:00Z\n---\n" +
		"concurrent-ruby 1.3.4 " + md5Hex(gemProfileInfoConcurrent) + "\n" +
		"nokogiri 1.15.0 0000000000000000000000000000000f\n" +
		"rails 7.1.0 " + md5Hex(gemProfileInfoRails) + "\n" +
		"nokogiri 1.16.7,1.16.7-x86_64-linux " + md5Hex(gemProfileInfoNokogiri) + "\n"
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routes["/versions"] = versions
	g.routes["/info/concurrent-ruby"] = gemProfileInfoConcurrent
	g.routes["/info/nokogiri"] = gemProfileInfoNokogiri
	g.routes["/info/rails"] = gemProfileInfoRails
	g.routes["/gems/nokogiri-1.15.0.gem"] = "\x00nokogiri 1.15.0 gem bytes"
	g.routes["/gems/rails-7.1.0.gem"] = "\x00rails gem bytes"
	g.routes["/quick/Marshal.4.8/rails-7.1.0.gemspec.rz"] = "\x78\x9crails gemspec"
	g.routes["/specs.4.8.gz"] = mustB64(t, gemProfileSpecsB64)
	g.routes["/api/v1/dependencies"] = mustB64(t, gemProfileDepsB64)
	return g, versions
}

// versionsLine is the line Bundler takes a gem's checksum from: the last one
// naming it.
func versionsLine(body, gem string) (versions, checksum string, ok bool) {
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == gem {
			versions, checksum, ok = f[1], f[2], true
		}
	}
	return versions, checksum, ok
}

// specsTuples reads a served full index back into "name version" pairs.
func specsTuples(t *testing.T, body string) []string {
	t.Helper()
	zr, err := gzip.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("the full index is not gzip: %v", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip the full index: %v", err)
	}
	doc, err := rbUnmarshal(raw)
	if err != nil {
		t.Fatalf("the full index is not Marshal: %v", err)
	}
	var out []string
	for _, el := range doc.items {
		name, _ := rbString(el.items[0])
		version, _ := rbGemVersion(el.items[1])
		platform, _ := rbString(el.items[2])
		out = append(out, name+" "+version+" "+platform)
	}
	return out
}

func depsEntries(t *testing.T, body string) []string {
	t.Helper()
	doc, err := rbUnmarshal([]byte(body))
	if err != nil {
		t.Fatalf("the dependency answer is not Marshal: %v", err)
	}
	var out []string
	for _, el := range doc.items {
		name, _ := rbHashString(el, "name")
		number, _ := rbHashString(el, "number")
		out = append(out, name+" "+number)
	}
	return out
}

func TestRubygemsClosedProfileAtBlock(t *testing.T) {
	g, upstreamVersions := gemProfileRegistry(t)
	s := gemServer(t, g)
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRubygems, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeRubygems, Name: "concurrent-ruby"},
			{Type: manifest.TypeRubygems, Name: "nokogiri"},
		})

	t.Run("an unlisted gem is refused", func(t *testing.T) {
		for _, p := range []string{"/rubygems/gems/rails-7.1.0.gem", "/rubygems/quick/Marshal.4.8/rails-7.1.0.gemspec.rz"} {
			if status, body := f.get(t, p); status != http.StatusForbidden || !strings.Contains(body, "membership") {
				t.Errorf("GET %s = %d, want a 403 naming membership: %s", p, status, body)
			}
		}
		if n := g.hitsFor("/gems/rails-7.1.0.gem"); n != 0 {
			t.Errorf("the refused gem reached the upstream %d times", n)
		}
		for _, row := range waitForDecision(t, s, audit.DecisionDenied, 1) {
			if row.PatternHint != "bodega profile add web rubygems rails" {
				t.Errorf("the denied row's pattern_hint = %q, want the command that closes it", row.PatternHint)
			}
		}
		// One refused request, one denial row: the gem and its gemspec are
		// two requests.
		denials, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
		if err != nil {
			t.Fatalf("query denials: %v", err)
		}
		var paths []string
		for _, row := range denials {
			if row.Status != audit.DenialProfileMembership || row.PkgName != "rails" {
				t.Errorf("denial row %+v, want a membership refusal of rails", row.Event)
			}
			paths = append(paths, denialDetails(t, row)["path"])
		}
		if len(paths) != 2 || paths[0] == paths[1] {
			t.Errorf("denial rows for paths %v, want one per refused request", paths)
		}
	})

	t.Run("a listed gem is served", func(t *testing.T) {
		if status, body := f.get(t, "/rubygems/gems/concurrent-ruby-1.3.4.gem"); status != http.StatusOK || body != "\x00concurrent-ruby gem bytes" {
			t.Errorf("the listed gem answered %d: %q", status, body)
		}
	})

	t.Run("info answers 404 for an excluded gem", func(t *testing.T) {
		if status, body := f.get(t, "/rubygems/info/rails"); status != http.StatusNotFound {
			t.Errorf("info/rails = %d, want 404: %s", status, body)
		}
		if status, body := f.get(t, "/rubygems/info/nokogiri"); status != http.StatusOK || body != gemProfileInfoNokogiri {
			t.Errorf("info/nokogiri, which floats, = %d and was changed:\n%s", status, body)
		}
	})

	t.Run("versions lists only covered gems", func(t *testing.T) {
		status, body := f.get(t, "/rubygems/versions")
		if status != http.StatusOK {
			t.Fatalf("versions = %d: %s", status, body)
		}
		if _, _, ok := versionsLine(body, "rails"); ok {
			t.Errorf("versions lists rails, which the profile excludes:\n%s", body)
		}
		if !strings.HasPrefix(body, "created_at: 2026-10-01T00:00:00Z\n---\n") {
			t.Errorf("versions lost its header:\n%s", body)
		}
		// A floating gem's info goes out unfiltered, so its line, and the
		// upstream's checksum on it, go out as they came.
		_, sum, _ := versionsLine(body, "nokogiri")
		_, info := f.get(t, "/rubygems/info/nokogiri")
		if sum != md5Hex(info) {
			t.Errorf("versions gives nokogiri checksum %s, and the info file served hashes to %s", sum, md5Hex(info))
		}
		if !strings.Contains(upstreamVersions, "nokogiri 1.15.0 0000000000000000000000000000000f\n") ||
			!strings.Contains(body, "nokogiri 1.15.0 0000000000000000000000000000000f\n") {
			t.Errorf("an unfiltered gem's earlier line was rewritten:\n%s", body)
		}
	})

	t.Run("the full index and the dependency API are filtered", func(t *testing.T) {
		_, specs := f.get(t, "/rubygems/specs.4.8.gz")
		got := strings.Join(specsTuples(t, specs), "; ")
		want := "concurrent-ruby 1.3.4 ruby; nokogiri 1.15.0 ruby; nokogiri 1.16.7 ruby; nokogiri 1.16.7 x86_64-linux"
		if got != want {
			t.Errorf("specs.4.8.gz holds %q, want %q", got, want)
		}
		_, deps := f.get(t, "/rubygems/api/v1/dependencies")
		if got := strings.Join(depsEntries(t, deps), "; "); got != "nokogiri 1.15.0; nokogiri 1.16.7" {
			t.Errorf("the dependency API answered %q", got)
		}
	})

	t.Run("the cache holds the upstream documents", func(t *testing.T) {
		if got := storedObject(t, s, manifest.TypeRubygems, manifest.RubygemsIndexKey("versions")); got != upstreamVersions {
			t.Errorf("the cached versions file is a filtered document:\n%s", got)
		}
		if got := storedObject(t, s, manifest.TypeRubygems, manifest.RubygemsIndexKey("specs.4.8.gz")); got != mustB64(t, gemProfileSpecsB64) {
			t.Error("the cached specs.4.8.gz is a filtered document")
		}
		for _, p := range []string{"/rubygems/versions", "/rubygems/specs.4.8.gz", "/rubygems/api/v1/dependencies", "/rubygems/info/nokogiri"} {
			if _, hdr := getHeaderWithToken(t, s, f.token, p); hdr.Get("Cache-Control") != cacheNoStore {
				t.Errorf("GET %s Cache-Control = %q, want %q", p, hdr.Get("Cache-Control"), cacheNoStore)
			}
		}
		if _, body := getWithToken(t, s, "", "/rubygems/versions"); body != upstreamVersions {
			t.Errorf("an unidentified request was filtered:\n%s", body)
		}
	})
}

func TestRubygemsWarnServesAndRecordsTheReach(t *testing.T) {
	g, upstreamVersions := gemProfileRegistry(t)
	s := gemServer(t, g)
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRubygems, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{{Type: manifest.TypeRubygems, Name: "nokogiri"}})

	if status, body := f.get(t, "/rubygems/gems/rails-7.1.0.gem"); status != http.StatusOK || body != "\x00rails gem bytes" {
		t.Fatalf("warn refused an unlisted gem: %d %q", status, body)
	}
	rows := waitForDecision(t, s, audit.DecisionDenied, 1)
	if rows[0].PkgName != "rails" || rows[0].PatternHint != "bodega profile add web rubygems rails" {
		t.Errorf("the reach row = %s with hint %q", rows[0].PkgName, rows[0].PatternHint)
	}
	if _, body := f.get(t, "/rubygems/versions"); body != upstreamVersions {
		t.Errorf("warn filtered the versions file, which keeps every gem it permits:\n%s", body)
	}
}

func TestRubygemsPinnedVersion(t *testing.T) {
	g, _ := gemProfileRegistry(t)
	s := gemServer(t, g)
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRubygems, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeRubygems, Name: "nokogiri",
			Constraint: manifest.ConstraintExact, Version: "1.16.7",
		}})

	status, info := f.get(t, "/rubygems/info/nokogiri")
	if status != http.StatusOK {
		t.Fatalf("info/nokogiri = %d: %s", status, info)
	}
	want := "---\n" +
		"1.16.7 mini_portile2:~> 2.8.2,racc:~> 1.4|checksum:bbbb\n" +
		"1.16.7-x86_64-linux racc:~> 1.4|checksum:cccc\n"
	if info != want {
		t.Errorf("info/nokogiri under the pin =\n%s\nwant\n%s", info, want)
	}

	// Bundler's check: the MD5 of the info file it was served against the
	// checksum the versions file gives that gem.
	_, versions := f.get(t, "/rubygems/versions")
	list, sum, ok := versionsLine(versions, "nokogiri")
	if !ok || sum != md5Hex(info) {
		t.Errorf("versions gives nokogiri checksum %q; Bundler hashes the info file it was served to %s:\n%s",
			sum, md5Hex(info), versions)
	}
	if strings.Contains(versions, "1.15.0") || list != "1.16.7,1.16.7-x86_64-linux" {
		t.Errorf("versions lists a version the pin refuses:\n%s", versions)
	}
	if strings.Contains(versions, "concurrent-ruby") || strings.Contains(versions, "rails") {
		t.Errorf("versions lists a gem the profile does not:\n%s", versions)
	}

	if status, body := f.get(t, "/rubygems/gems/nokogiri-1.15.0.gem"); status != http.StatusForbidden || !strings.Contains(body, "constraint") {
		t.Errorf("a gem file outside the pin = %d, want a 403 naming the constraint: %s", status, body)
	}
	if status, body := f.get(t, "/rubygems/gems/nokogiri-1.16.7-x86_64-linux.gem"); status != http.StatusOK {
		t.Errorf("a platform build of the pinned release = %d: %s", status, body)
	}

	_, specs := f.get(t, "/rubygems/specs.4.8.gz")
	if got := strings.Join(specsTuples(t, specs), "; "); got != "nokogiri 1.16.7 ruby; nokogiri 1.16.7 x86_64-linux" {
		t.Errorf("specs.4.8.gz under the pin holds %q", got)
	}
	_, deps := f.get(t, "/rubygems/api/v1/dependencies")
	if got := strings.Join(depsEntries(t, deps), "; "); got != "nokogiri 1.16.7" {
		t.Errorf("the dependency API under the pin answered %q", got)
	}
}

// gemPinnedPlusUncut is TestRubygemsPinnedVersion's profile with a second
// gem whose listed versions all pass, so its line goes out byte for byte and
// costs no info read.
func gemPinnedPlusUncut(t *testing.T, s *Server) *profileFixture {
	t.Helper()
	return bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRubygems, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeRubygems, Name: "nokogiri", Constraint: manifest.ConstraintExact, Version: "1.16.7"},
			{Type: manifest.TypeRubygems, Name: "concurrent-ruby", Constraint: manifest.ConstraintExact, Version: "1.3.4"},
		})
}

// One gem whose info the filter cannot read costs that gem, not the versions
// file: a 502 there fails every bundle install on every host the profile binds.
func TestRubygemsVersionsDropsAGemWhoseInfoCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(t *testing.T, g *gemRegistry, s *Server)
	}{
		{"its upstream info answers 404", func(_ *testing.T, g *gemRegistry, _ *Server) {
			g.mu.Lock()
			delete(g.routes, "/info/nokogiri")
			g.mu.Unlock()
		}},
		// The profile lists the gem before the allow-list approves it, which is
		// the order an operator adds the two in.
		{"the allow-list has not approved it", func(t *testing.T, _ *gemRegistry, s *Server) {
			if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
				ID: "gems", RegistryType: manifest.TypeRubygems, RuleKind: policy.KindPackage, Pattern: "concurrent-ruby",
			}); err != nil {
				t.Fatalf("insert policy: %v", err)
			}
			s.policy.Invalidate()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := gemProfileRegistry(t)
			s := gemServer(t, g)
			f := gemPinnedPlusUncut(t, s)
			tc.breakIt(t, g, s)

			status, body := f.get(t, "/rubygems/versions")
			if status != http.StatusOK {
				t.Fatalf("versions = %d, want 200 with nokogiri dropped: %s", status, body)
			}
			if _, _, ok := versionsLine(body, "nokogiri"); ok {
				t.Errorf("versions lists nokogiri, whose filtered info nobody could checksum:\n%s", body)
			}
			want := "concurrent-ruby 1.3.4 " + md5Hex(gemProfileInfoConcurrent) + "\n"
			if !strings.HasPrefix(body, "created_at: 2026-10-01T00:00:00Z\n---\n") || !strings.Contains(body, want) {
				t.Errorf("versions lost its header or the uncut gem's line %q:\n%s", want, body)
			}
		})
	}
}

// The versions filter reads info/<gem> to checksum it, and that read is
// bodega's, not the host's: a row naming web01 for it says the host reached
// for a document it never asked for.
func TestRubygemsVersionsSideReadWritesNoRowsForTheHost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy bool
	}{
		{"filled from upstream and then from the cache", false},
		{"refused by the allow-list", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := gemProfileRegistry(t)
			s := gemServer(t, g)
			f := gemPinnedPlusUncut(t, s)
			if tc.policy {
				if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
					ID: "gems", RegistryType: manifest.TypeRubygems, RuleKind: policy.KindPackage, Pattern: "concurrent-ruby",
				}); err != nil {
					t.Fatalf("insert policy: %v", err)
				}
				s.policy.Invalidate()
			}

			// Stale on every request: three upstream fills.
			for range 3 {
				if status, body := f.get(t, "/rubygems/versions"); status != http.StatusOK {
					t.Fatalf("versions = %d: %s", status, body)
				}
			}
			if !tc.policy && g.hitsFor("/info/nokogiri") != 3 {
				t.Fatalf("the filter read info/nokogiri upstream %d times, want 3; the test asserts nothing", g.hitsFor("/info/nokogiri"))
			}
			// Fresh: the side read is a cache hit.
			s.cache.MetadataTTL = time.Hour
			f.get(t, "/rubygems/versions")

			// The recorder writes off the request goroutine and in order, so
			// a row the host did cause, landing, means every earlier one has.
			f.get(t, "/rubygems/gems/concurrent-ruby-1.3.4.gem")
			deadline := time.Now().Add(3 * time.Second)
			var rows []audit.DiscoveryRow
			for {
				var err error
				rows, err = s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{})
				if err != nil {
					t.Fatalf("list discovery: %v", err)
				}
				if slices.ContainsFunc(rows, func(r audit.DiscoveryRow) bool { return strings.Contains(r.UpstreamURL, "/gems/") }) ||
					time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, row := range rows {
				if strings.Contains(row.UpstreamURL, "/info/") {
					t.Errorf("discovery row for bodega's own read: %+v", row)
				}
			}

			events, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
			if err != nil {
				t.Fatalf("query cache events: %v", err)
			}
			for _, ev := range events {
				if strings.Contains(ev.Details, "info/") {
					t.Errorf("cache event for bodega's own read: status=%s pkg=%s details=%s", ev.Status, ev.PkgName, ev.Details)
				}
			}
			queued, err := s.auditDB.ListQueue(t.Context(), audit.QueueFilter{})
			if err != nil {
				t.Fatalf("list queue: %v", err)
			}
			for _, q := range queued {
				t.Errorf("review queue row for bodega's own read: %+v", q)
			}
		})
	}
}

// The writer rebuilds the link and symbol tables, so a document re-read from
// its own output has to come back as the same tree Ruby wrote.
func TestRubygemsMarshalRoundTripsRubyOutput(t *testing.T) {
	raw := []byte(mustB64(t, gemProfileDepsB64))
	doc, err := rbUnmarshal(raw)
	if err != nil {
		t.Fatalf("decode Ruby's output: %v", err)
	}
	if out := rbMarshal(doc); !bytes.Equal(out, raw) {
		t.Errorf("re-encoding Ruby's output changed it:\n got %x\nwant %x", out, raw)
	}
	if _, err := rbUnmarshal([]byte{4, 8, '[', 0x7f}); err == nil {
		t.Error("an array claiming 122 elements in a 4-byte stream decoded")
	}
}
