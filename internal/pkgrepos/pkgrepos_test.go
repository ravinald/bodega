package pkgrepos_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// mirror is the ordinary state: a repository copied from upstream, on a
// release whose base system defines one repository tag.
func mirror() pkgrepos.State {
	return pkgrepos.State{
		PublicURL: "https://bodega.internal",
		ABI:       "FreeBSD:14:amd64",
		Repo:      "latest",
		Upstream:  "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
	}
}

// confProse is the emitted file's comment block as one line. An assertion
// about what the file says has to survive a rewrap of the paragraph that says
// it, or the next person to reflow a comment is failing tests about a claim
// they did not change.
func confProse(conf string) string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if trimmed := strings.TrimPrefix(line, "#"); trimmed != line {
			out = append(out, strings.TrimSpace(trimmed))
		}
	}
	return strings.Join(out, " ")
}

func render(t *testing.T, st pkgrepos.State) pkgrepos.Repo {
	t.Helper()
	got, err := pkgrepos.Render(st)
	if err != nil {
		t.Fatalf("Render(%+v) = %v", st, err)
	}
	return got
}

// The upstream repository is disabled by the tag the target release actually
// ships. Getting this wrong fails nothing: the upstream repository stays
// enabled beside bodega's and the host keeps fetching from the internet.
func TestDisablesTheTagsTheReleaseShips(t *testing.T) {
	for _, tc := range []struct {
		abi  string
		want []string
	}{
		{"FreeBSD:13:amd64", []string{"FreeBSD"}},
		{"FreeBSD:14:amd64", []string{"FreeBSD"}},
		{"FreeBSD:15:aarch64", []string{"FreeBSD-ports", "FreeBSD-ports-kmods", "FreeBSD-base"}},
		{"FreeBSD:16:amd64", []string{"FreeBSD-ports", "FreeBSD-ports-kmods", "FreeBSD-base"}},
	} {
		t.Run(tc.abi, func(t *testing.T) {
			st := mirror()
			st.ABI, st.Upstream = tc.abi, "https://example.invalid/"+tc.abi+"/latest"
			got := render(t, st)
			if !slices.Equal(got.Disabled, tc.want) {
				t.Fatalf("Disabled = %v, want %v", got.Disabled, tc.want)
			}
			for _, tag := range tc.want {
				if !strings.Contains(got.Conf, tag+": { enabled: no }") {
					t.Errorf("the conf does not disable %s, so it stays enabled beside bodega's:\n%s", tag, got.Conf)
				}
			}
			// The pre-split tag is a prefix of every split one, so a
			// substring check alone would pass on 15 with only "FreeBSD"
			// written. Assert the line nobody should find there.
			if tc.want[0] != "FreeBSD" && strings.Contains(got.Conf, "\nFreeBSD: { enabled: no }") {
				t.Errorf("disables the pre-15 tag on a release that does not define it:\n%s", got.Conf)
			}
		})
	}
}

// The release is a parameter, not an assumption. An operator configuring a
// FreeBSD 15 host against a repository mirrored for 14 says so, and the
// override follows the host rather than the mirror.
func TestReleaseOverridesTheABI(t *testing.T) {
	st := mirror()
	st.Release = 15
	got := render(t, st)
	if !slices.Equal(got.Disabled, pkgrepos.UpstreamTags(15)) {
		t.Fatalf("Disabled = %v with Release 15 against a FreeBSD:14 ABI, want the 15 tags", got.Disabled)
	}
	if got.Release != 15 {
		t.Errorf("Release = %d, want 15", got.Release)
	}
}

// An ABI nothing resolves is refused rather than defaulted. A default here
// disables a tag the host does not define, which reports no error anywhere.
func TestRefusesAnUnreadableRelease(t *testing.T) {
	for _, abi := range []string{"", "FreeBSD", "FreeBSD:amd64", "FreeBSD:sometime:amd64", "FreeBSD:0:amd64"} {
		st := mirror()
		st.ABI = abi
		if got, err := pkgrepos.Render(st); err == nil {
			t.Errorf("Render with ABI %q returned a conf rather than refusing:\n%s", abi, got.Conf)
		}
	}
}

// signature_type follows what the repository is. A mirror carries FreeBSD's
// own signature inside the catalogue archive and verifies against the stock
// trust store; nothing of bodega's is in that path.
func TestMirrorVerifiesAgainstTheStockTrustStore(t *testing.T) {
	got := render(t, mirror())
	if got.SignatureType != "fingerprints" {
		t.Errorf("SignatureType = %q, want fingerprints", got.SignatureType)
	}
	if got.Fingerprints != pkgrepos.StockFingerprints {
		t.Errorf("Fingerprints = %q, want %q", got.Fingerprints, pkgrepos.StockFingerprints)
	}
	if strings.Contains(got.Conf, pkgrepos.BodegaFingerprints) {
		t.Errorf("a mirror's conf names bodega's fingerprint directory, which fails pkg update on a signature that is present and valid:\n%s", got.Conf)
	}
	if !strings.Contains(got.Note(), "does not work") {
		t.Errorf("no note says pkg bootstrap will not work against a hosted mirror: %q", got.Note())
	}
}

// The bootstrap answer follows both facts that decide it, and the serving
// mode is neither of them.
//
// The first is whether a request for a path outside the catalogue is fetched
// from upstream, which the route reads as three terms: the entry records a
// url, and either the mode is proxy or the server's proxy cache is on
// (internal/server/freebsd.go:127,155, internal/server/proxy.go:116). The
// second is whether upstream publishes the pair, which comes off the upstream
// repository's name.
//
// Every row here has been keyed off r.Proxy at some point and two of them
// were wrong for it in opposite directions: "hosted ports mirror, cache on"
// was called absent while the route served both paths 200 off
// pkg.FreeBSD.org, and "proxied base mirror" was called working while
// upstream answered 403.
func TestBootstrapAnswerFollowsWhatReachesUpstream(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
		proxy    bool
		cache    bool
		want     pkgrepos.BootstrapAnswer
		reaches  bool
		conf     string

		// refused is an entry Render will not emit for at all, which is a
		// separate question from what reaches upstream: the predicate still
		// has to answer, and the row is here because it is the one that
		// proves the predicate reads the url rather than the two flags.
		refused bool
	}{
		{
			name:     "hosted ports mirror, cache off",
			upstream: "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
			want:     pkgrepos.BootstrapAbsent,
			conf:     "every request stops here",
		},
		{
			name:     "hosted ports mirror, cache on",
			upstream: "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
			cache:    true,
			want:     pkgrepos.BootstrapWorks,
			reaches:  true,
			conf:     "`pkg bootstrap` works here",
		},
		{
			name:     "proxied ports mirror, cache off",
			upstream: "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
			proxy:    true,
			want:     pkgrepos.BootstrapWorks,
			reaches:  true,
			conf:     "`pkg bootstrap` works here",
		},
		{
			name:     "hosted base mirror, cache off",
			upstream: "https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1",
			want:     pkgrepos.BootstrapAbsent,
			conf:     "every request stops here",
		},
		{
			name:     "hosted base mirror, cache on",
			upstream: "https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1",
			cache:    true,
			want:     pkgrepos.BootstrapAbsent,
			reaches:  true,
			conf:     "neither a base nor a kmods repository",
		},
		{
			name:     "proxied base mirror",
			upstream: "https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1",
			proxy:    true,
			want:     pkgrepos.BootstrapAbsent,
			reaches:  true,
			conf:     "neither a base nor a kmods repository",
		},
		{
			// release_<n> publishes the pair on 15 and 404s on 14, so a name
			// that looks like a ports repository is not enough to assert it.
			name:     "proxied mirror of a repository nobody measured",
			upstream: "https://pkg.freebsd.org/FreeBSD:14:amd64/release_1",
			proxy:    true,
			want:     pkgrepos.BootstrapUnknown,
			reaches:  true,
			conf:     "`pkg bootstrap` may not work",
		},
		{
			// No url, so there is nothing to fall through to whatever the
			// mode and the toggle say. This row is why the predicate reads
			// the url rather than trusting the two flags. No stanza comes
			// out of it: an entry with no url and no generated flag names
			// neither of the two things that decide a trust store, and
			// Render refuses it rather than handing the reader the mirrored
			// answer for a repository nobody mirrored.
			name:    "hosted repository with no upstream, cache on",
			cache:   true,
			refused: true,
		},
		{
			name:    "proxy mode with no upstream, cache on",
			proxy:   true,
			cache:   true,
			refused: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := mirror()
			st.Upstream, st.Proxy, st.CacheEnabled = tc.upstream, tc.proxy, tc.cache
			if strings.Contains(tc.upstream, "base_release") {
				st.ABI, st.Repo = "FreeBSD:15:amd64", "base"
			}
			if got := st.ReachesUpstream(); got != tc.reaches {
				t.Errorf("ReachesUpstream() = %v, want %v", got, tc.reaches)
			}
			if tc.refused {
				if got, err := pkgrepos.Render(st); err == nil {
					t.Fatalf("Render emitted a stanza for an entry with no url and no generated flag:\n%s", got.Conf)
				}
				return
			}
			got := render(t, st)
			if got.Bootstrap != tc.want {
				t.Errorf("Bootstrap = %q, want %q", got.Bootstrap, tc.want)
			}
			if got.UpstreamFallthrough != tc.reaches {
				t.Errorf("upstream_fallthrough = %v, want %v: it is the isolation claim a consumer reads instead of parsing the conf",
					got.UpstreamFallthrough, tc.reaches)
			}
			if !strings.Contains(got.Conf, tc.conf) {
				t.Errorf("the conf does not carry %q:\n%s", tc.conf, got.Conf)
			}
			if got.Proxy != tc.proxy {
				t.Errorf("Proxy = %v, want %v: the serving mode is what HoldsCatalogue reads, and it crosses the wire for that", got.Proxy, tc.proxy)
			}
		})
	}
}

// A file that says every request stops at bodega is the isolation claim, and
// it may appear only where nothing reaches upstream. It was false for a
// hosted mirror on a cache-enabled server, which is the form an operator
// reaches for precisely because they believe it is finished and isolated.
func TestOnlyAnIsolatedRepositoryClaimsToBeOne(t *testing.T) {
	const isolation = "this server fetches nothing under it from upstream"
	for _, cache := range []bool{false, true} {
		st := mirror()
		st.CacheEnabled = cache
		got := render(t, st)
		claims := strings.Contains(got.Note(), isolation) || strings.Contains(got.Conf, "every request stops here")
		if claims == got.UpstreamFallthrough {
			t.Errorf("proxy_cache_enabled=%v: the file claims isolation=%v while upstream_fallthrough=%v:\n%s",
				cache, claims, got.UpstreamFallthrough, got.Conf)
		}
		if got.UpstreamFallthrough && !strings.Contains(got.Note(), "reaches the internet") {
			t.Errorf("proxy_cache_enabled=%v: a repository that fetches from upstream does not say so: %q", cache, got.Note())
		}
	}
}

// How much of this repository leaves the host is two facts, and a file that
// answers it with one gets a whole case wrong.
//
// The sentence this covers was not in a switch at all. It was a constant at
// the end of the bootstrap paragraph, "That one path reaches the internet,
// unlike every other request this repository answers": true of the hosted
// mirror it was written for, and printed unchanged for a proxy, where
// "pkg update" itself comes off pkg.FreeBSD.org. Its neighbor claimed the
// repository was mirrored byte for byte, which a proxy is not either.
func TestTheConfSaysHowMuchOfTheRepositoryLeavesTheHost(t *testing.T) {
	// Printed for the case each was written for and never for another.
	const (
		isolated = "every request stops here"
		hosted   = "This catalogue is served from what was published here"
		proxied  = "may reach the internet, the"
	)
	for _, tc := range []struct {
		name         string
		proxy, cache bool
		holds        bool
		want, absent []string
	}{
		{
			name:   "hosted mirror, cache off",
			holds:  true,
			want:   []string{isolated, "a 404 rather than a fetch from the internet"},
			absent: []string{hosted, proxied},
		},
		{
			name:  "hosted mirror, cache on",
			cache: true,
			holds: true,
			want: []string{
				hosted,
				"a miss on meta.conf, packagesite.pkg or data.pkg is refused rather than fetched",
				"this server's proxy cache is on",
				"an install can succeed here against a package nobody mirrored",
			},
			absent: []string{isolated, proxied},
		},
		{
			name:  "proxied repository",
			proxy: true,
			want: []string{
				proxied,
				"catalogue included",
				"served in proxy mode",
				"whatever earlier requests cached, not a copy of the",
			},
			absent: []string{isolated, hosted},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := mirror()
			st.Proxy, st.CacheEnabled = tc.proxy, tc.cache
			got := render(t, st)
			if got.HoldsCatalogue() != tc.holds {
				t.Errorf("HoldsCatalogue() = %v, want %v: a proxied repository fetches meta.conf from upstream like any other path",
					got.HoldsCatalogue(), tc.holds)
			}
			prose := confProse(got.Conf)
			for _, want := range tc.want {
				if !strings.Contains(prose, want) {
					t.Errorf("the conf does not carry %q:\n%s", want, got.Conf)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(prose, absent) {
					t.Errorf("the conf carries %q, which describes another case:\n%s", absent, got.Conf)
				}
			}
		})
	}
}

// The isolation claim names the term that would make it false, and the two
// repositories it is true of do not have the same term.
//
// A generated repository has no upstream to resolve a miss against and no
// setting on the server changes that. A hosted mirror is isolated because
// proxy_cache_enabled happens to be off, and the file is installed on a host
// that never hears about that toggle again: turn it on and the installed
// stanza goes on asserting isolation while All/*.pkg misses are fetched from
// pkg.FreeBSD.org and served under this repository's name.
//
// One sentence covered both and named neither term, while the mirrored and
// proxied paragraphs beside it each named theirs. That is the defect this
// holds: an arm whose prose was written for a narrower case than its
// predicate admits reads as measured and is not.
func TestTheIsolationClaimNamesWhatWouldFlipIt(t *testing.T) {
	const (
		flip     = "Change either"
		toggle   = "proxy_cache_enabled is off"
		noUpstre = "records no upstream"
	)
	for _, tc := range []struct {
		name         string
		generated    bool
		fingerprint  string
		want, absent []string
		wantNote     []string
		absentNote   []string
	}{
		{
			name:       "hosted mirror, cache off",
			want:       []string{"every request stops here", toggle, "not served in proxy mode", flip},
			absent:     []string{noUpstre},
			wantNote:   []string{"stops at this server", toggle, "not served in proxy mode"},
			absentNote: []string{noUpstre},
		},
		{
			name:       "generated, no key",
			generated:  true,
			want:       []string{"every request stops here", noUpstre, "no URL to resolve a miss against"},
			absent:     []string{flip, toggle},
			wantNote:   []string{"stops at this server", noUpstre},
			absentNote: []string{flip, toggle},
		},
		{
			name:        "generated and signed",
			generated:   true,
			fingerprint: "SHA256:deadbeef",
			want:        []string{"every request stops here", noUpstre},
			absent:      []string{flip, toggle},
			wantNote:    []string{"stops at this server", noUpstre},
			absentNote:  []string{flip, toggle},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := mirror()
			if tc.generated {
				st.Upstream, st.Generated, st.Fingerprint = "", true, tc.fingerprint
			}
			got := render(t, st)
			if got.UpstreamFallthrough {
				t.Fatalf("upstream_fallthrough is true, so this row is not the isolated case at all")
			}
			prose := confProse(got.Conf)
			for _, want := range tc.want {
				if !strings.Contains(prose, want) {
					t.Errorf("the conf claims isolation without saying %q:\n%s", want, got.Conf)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(prose, absent) {
					t.Errorf("the conf carries %q, which explains the other isolated case:\n%s", absent, got.Conf)
				}
			}
			// The wire-level note answers the same question in one line, so
			// a consumer that never renders the file reads the same terms.
			for _, want := range tc.wantNote {
				if !strings.Contains(got.Note(), want) {
					t.Errorf("Note() claims isolation without saying %q: %q", want, got.Note())
				}
			}
			for _, absent := range tc.absentNote {
				if strings.Contains(got.Note(), absent) {
					t.Errorf("Note() carries %q, which explains the other isolated case: %q", absent, got.Note())
				}
			}
		})
	}
}

// Generated is the absence of an upstream and not merely correlated with it,
// which is what licenses Repo.RecordsUpstream reading one for the other.
//
// The reach claim is the caller that cares: what makes a generated repository
// isolated is having no URL to resolve a miss against. Render refuses both
// entries where the two part company, so the equality holds for every
// configuration it returns, and this is the test that fails if either refusal
// is lifted without the reach paragraph being revisited.
func TestGeneratedIsExactlyTheAbsenceOfAnUpstream(t *testing.T) {
	const upstream = "https://pkg.freebsd.org/FreeBSD:14:amd64/latest"
	for _, tc := range []struct {
		name      string
		generated bool
		upstream  string
		refused   bool
		records   bool
	}{
		{name: "mirror", upstream: upstream, records: true},
		{name: "generated", generated: true},
		{name: "both", generated: true, upstream: upstream, refused: true},
		{name: "neither", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := mirror()
			st.Generated, st.Upstream = tc.generated, tc.upstream
			got, err := pkgrepos.Render(st)
			if tc.refused {
				if err == nil {
					t.Fatalf("Render emitted a stanza for generated=%v upstream=%q:\n%s", tc.generated, tc.upstream, got.Conf)
				}
				return
			}
			if err != nil {
				t.Fatalf("Render(%+v) = %v", st, err)
			}
			if got.RecordsUpstream() != tc.records {
				t.Errorf("RecordsUpstream() = %v, want %v: the reach paragraph reads it as \"there is a URL to resolve a miss against\"",
					got.RecordsUpstream(), tc.records)
			}
		})
	}
}

// A wire shape carrying no upstream_fallthrough decodes it as false, and a
// proxied repository re-rendered from one may not be called isolated.
//
// doctor reads a rendered Repo off /api/v1/status and re-renders it for
// another release, so the two ends can differ in age: a server that predates
// the field hands a proxy a Repo whose isolation bit reads false. Reading the
// serving mode before that field puts it in the arm the mode already proves,
// which is why the reach switch tests HoldsCatalogue above
// UpstreamFallthrough rather than below it.
func TestAProxyReRenderedFromAnOlderWireShapeIsNotCalledIsolated(t *testing.T) {
	var decoded pkgrepos.Repo
	wire := `{"tag":"bodega-latest","abi":"FreeBSD:14:amd64","repo":"latest","release":14,` +
		`"proxy":true,"url":"https://bodega.internal/freebsd/${ABI}/latest",` +
		`"signature_type":"fingerprints","fingerprints":"/usr/share/keys/pkg","disabled":["FreeBSD"]}`
	if err := json.Unmarshal([]byte(wire), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.UpstreamFallthrough {
		t.Fatalf("this wire shape is supposed to omit upstream_fallthrough, so it decodes as false")
	}
	got, err := decoded.WithRelease(14)
	if err != nil {
		t.Fatalf("WithRelease(14) = %v", err)
	}
	prose := confProse(got.Conf)
	if strings.Contains(prose, "every request stops here") {
		t.Errorf("a proxy re-rendered from a wire shape with no upstream_fallthrough is told nothing leaves the host:\n%s", got.Conf)
	}
	if !strings.Contains(prose, "served in proxy mode") {
		t.Errorf("the re-rendered conf never says the mode it carries reaches upstream:\n%s", got.Conf)
	}
	if !strings.Contains(got.Note(), "may reach the internet") {
		t.Errorf("Note() withholds from a proxy what the conf says about it: %q", got.Note())
	}
}

// The mirror note names the catalogue files rather than saying "the
// catalogue", because the route recognizes exactly three names
// (manifest.FreeBSDCatalogFiles) and a repository-root file under any other
// spelling falls through to upstream like a package does. A name added there
// and not here is a file this claim silently stops covering.
func TestTheMirrorNoteNamesEveryCatalogueFileTheRouteKnows(t *testing.T) {
	st := mirror()
	st.CacheEnabled = true
	got := render(t, st)
	for _, file := range manifest.FreeBSDCatalogFiles {
		if !strings.Contains(pkgrepos.MirrorReachNote, file) {
			t.Errorf("MirrorReachNote claims a refusal without naming %s: %q", file, pkgrepos.MirrorReachNote)
		}
		if !strings.Contains(confProse(got.Conf), file) {
			t.Errorf("the emitted file does not name %s among the paths it refuses to fetch:\n%s", file, got.Conf)
		}
	}
}

// The two sentences that made the claim before anything derived it. Neither
// may be printed for any repository: the first is false wherever a path falls
// through, which is the only condition it was printed under, and the second
// says bodega holds a copy of a repository it may hold nothing of.
func TestTheConfNeverClaimsOnePathReachesUpstream(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		for _, cache := range []bool{false, true} {
			st := mirror()
			st.Proxy, st.CacheEnabled = proxy, cache
			got := render(t, st)
			for _, claim := range []string{
				"unlike every other request this repository answers",
				"mirrored byte for byte",
			} {
				if strings.Contains(got.Conf+got.Note(), claim) {
					t.Errorf("proxy=%v cache=%v: the file claims %q:\n%s", proxy, cache, claim, got.Conf)
				}
			}
		}
	}
}

// What a proxy reaches for the bootstrap pair, by upstream repository. Every
// row measured with fetch(1) against pkg.FreeBSD.org, both paths per
// repository, on 2026-09-21.
func TestUpstreamBootstrap(t *testing.T) {
	const host = "https://pkg.freebsd.org/"
	for _, tc := range []struct {
		upstream string
		want     pkgrepos.BootstrapAnswer
	}{
		{host + "FreeBSD:15:aarch64/latest", pkgrepos.BootstrapWorks},
		{host + "FreeBSD:15:aarch64/quarterly", pkgrepos.BootstrapWorks},
		{host + "FreeBSD:14:amd64/latest/", pkgrepos.BootstrapWorks},
		{host + "FreeBSD:14:amd64/quarterly", pkgrepos.BootstrapWorks},
		// pkg.pkg 200 and the .sig the bootstrapper checks it against 403,
		// which is absent as far as bootstrapping is concerned.
		{host + "FreeBSD:15:aarch64/base_release_0", pkgrepos.BootstrapAbsent},
		{host + "FreeBSD:15:aarch64/base_release_1", pkgrepos.BootstrapAbsent},
		{host + "FreeBSD:15:aarch64/base_latest", pkgrepos.BootstrapAbsent},
		{host + "FreeBSD:15:aarch64/base_weekly", pkgrepos.BootstrapAbsent},
		{host + "FreeBSD:15:aarch64/kmods_quarterly_1", pkgrepos.BootstrapAbsent},
		{host + "FreeBSD:15:aarch64/kmods_latest", pkgrepos.BootstrapAbsent},
		{host + "FreeBSD:14:amd64/base_release_1", pkgrepos.BootstrapAbsent},
		// 200 on 15 and 404 on 14, so the name alone cannot assert it.
		{host + "FreeBSD:15:aarch64/release_1", pkgrepos.BootstrapUnknown},
		{host + "FreeBSD:14:amd64/release_1", pkgrepos.BootstrapUnknown},
		{"https://mirror.internal/freebsd/house/", pkgrepos.BootstrapUnknown},
		{"", pkgrepos.BootstrapUnknown},
	} {
		if got := pkgrepos.UpstreamBootstrap(tc.upstream); got != tc.want {
			t.Errorf("UpstreamBootstrap(%q) = %q, want %q", tc.upstream, got, tc.want)
		}
	}
}

// A generated repository serves what the build tree uploaded, and poudriere
// publishes Latest/pkg.pkg as a symlink the upload skips. bodega cannot see
// from here whether somebody put a real file there, so it says so rather than
// picking the answer that is usually right.
func TestGeneratedHedgesTheBootstrapAnswer(t *testing.T) {
	st := mirror()
	st.Upstream, st.Generated, st.Fingerprint = "", true, "SHA256:deadbeef"
	got := render(t, st)
	if got.Bootstrap != pkgrepos.BootstrapUnknown {
		t.Errorf("Bootstrap = %q for a generated repository, want %q", got.Bootstrap, pkgrepos.BootstrapUnknown)
	}
	if !strings.Contains(got.Conf, "only if the build tree published") {
		t.Errorf("the conf does not say what bootstrap depends on here:\n%s", got.Conf)
	}
}

// A generated repository is signed by bodega, so it verifies against bodega's
// fingerprint. Emitting the stock path here fails pkg update with an error
// about the signature, which sends the reader to the wrong file.
func TestGeneratedVerifiesAgainstBodegasFingerprint(t *testing.T) {
	st := mirror()
	st.Upstream, st.Generated, st.Fingerprint = "", true, "SHA256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	got := render(t, st)
	if got.SignatureType != "fingerprints" {
		t.Errorf("SignatureType = %q, want fingerprints", got.SignatureType)
	}
	if got.Fingerprints != pkgrepos.BodegaFingerprints {
		t.Errorf("Fingerprints = %q, want %q", got.Fingerprints, pkgrepos.BodegaFingerprints)
	}
	if strings.Contains(got.Conf, pkgrepos.StockFingerprints) {
		t.Errorf("a generated repository's conf names the stock trust store, which holds no key that signed it:\n%s", got.Conf)
	}
	if !strings.Contains(got.Note(), "out of band") {
		t.Errorf("no note tells the operator to install the fingerprint out of band: %q", got.Note())
	}
}

// A generated repository with no key loaded is honestly unsigned. none rather
// than a fingerprint path that resolves to nothing, and a note saying what
// that costs.
func TestGeneratedWithNoKeyIsUnsignedAndSaysSo(t *testing.T) {
	st := mirror()
	st.Upstream, st.Generated = "", true
	got := render(t, st)
	if got.SignatureType != "none" {
		t.Fatalf("SignatureType = %q, want none", got.SignatureType)
	}
	if got.Fingerprints != "" {
		t.Errorf("Fingerprints = %q with signature_type none; pkg has nothing to check against", got.Fingerprints)
	}
	if strings.Contains(got.Stanza, "fingerprints:") {
		t.Errorf("the stanza carries a fingerprints key beside signature_type none:\n%s", got.Stanza)
	}
	if !strings.Contains(got.Note(), "TLS as the only thing authenticating") {
		t.Errorf("no note names what signature_type none costs: %q", got.Note())
	}
}

// The conf for a generated repository claims what its own stanza renders, and
// says how much of it leaves the host.
//
// Both halves were one arm's constants. "generated and signed by bodega" sat
// in the prefix both signature cases share, so an unsigned repository read
// "signed by bodega" three lines above "it carries no signature at all". That
// is the first file an operator gets for every `bodega pkg create freebsd`
// with a blank URL, because no key is loaded until somebody runs
// `bodega freebsd key generate`. And the arm printed no reach paragraph at
// all, which left the one repository class Render's own refusals make
// unconditionally isolated as the only class never told so.
func TestTheGeneratedConfMatchesItsOwnStanza(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fingerprint string
		wantSig     string
		wantProse   []string
		denyProse   []string
	}{
		{
			name:      "no key loaded",
			wantSig:   "none",
			wantProse: []string{"carries no signature at all", "every request stops here"},
			denyProse: []string{"signed by bodega", "bodega signs it"},
		},
		{
			// The positive row, so the fix cannot be made by deleting the
			// claim for everybody: a signed repository still names the key.
			name:        "key loaded",
			fingerprint: "SHA256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
			wantSig:     "fingerprints",
			wantProse:   []string{"bodega signs it", "every request stops here"},
			denyProse:   []string{"carries no signature at all"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := mirror()
			st.Upstream, st.Generated, st.Fingerprint = "", true, tc.fingerprint
			got := render(t, st)
			if got.SignatureType != tc.wantSig {
				t.Fatalf("SignatureType = %q, want %q", got.SignatureType, tc.wantSig)
			}
			prose := confProse(got.Conf)
			for _, want := range tc.wantProse {
				if !strings.Contains(prose, want) {
					t.Errorf("the conf never says %q:\n%s", want, got.Conf)
				}
			}
			for _, deny := range tc.denyProse {
				if strings.Contains(prose, deny) {
					t.Errorf("the conf says %q beside signature_type %q:\n%s", deny, got.SignatureType, got.Conf)
				}
			}
			// The wire-level list and the file answer the same question, so
			// a consumer with one line to spend gets the same claim.
			if !strings.Contains(got.Note(), "stops at this server") {
				t.Errorf("Note() never says how much of a generated repository leaves the host: %q", got.Note())
			}
		})
	}
}

// An entry naming neither a url nor generated is refused, because nothing
// here knows who signed its catalogue.
//
// Generated and Upstream are independent and manifest.VersionEntry requires
// neither, so they are four cases rather than two: `bodega pkg import`
// accepts the fourth and the route serves it from the store. Every switch in
// the renderer keys off Generated alone, so before this refusal that entry
// was told bodega copied its bytes from upstream, that upstream called it
// something else, and to verify it against the ports trust store, which
// checks whatever the operator uploaded only by luck.
func TestRefusesAnEntryThatIsNeitherMirroredNorGenerated(t *testing.T) {
	st := mirror()
	st.Upstream, st.Generated = "", false
	got, err := pkgrepos.Render(st)
	if err == nil {
		t.Fatalf("rendered a stanza for an entry with no upstream and no generated flag; the conf tells its reader FreeBSD signed bytes nobody mirrored:\n%s", got.Conf)
	}
	for _, want := range []string{"url", "generated", pkgrepos.StockFingerprints} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator has to guess which field to set: %v", want, err)
		}
	}
}

// An entry claiming to be both is refused rather than resolved to a guess.
// The two want opposite client configuration and the wrong one fails at pkg
// update with an error naming the signature.
func TestRefusesAnEntryThatIsBothMirroredAndGenerated(t *testing.T) {
	st := mirror()
	st.Generated = true
	got, err := pkgrepos.Render(st)
	if err == nil {
		t.Fatalf("Render returned a conf for an entry marked generated with an upstream url:\n%s", got.Conf)
	}
	for _, want := range []string{"generated", "url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator has to guess which field to change: %v", want, err)
		}
	}
}

// A generated repository served in proxy mode is one the server refuses to
// route: proxy holds no snapshot for a generated catalogue to name, so every
// request under it answers 500. The stanza for it installs cleanly and
// points a host at a repository that never replies, which is why the refusal
// happens here rather than at the fetch that discovers it.
func TestRefusesAGeneratedRepositoryServedByProxy(t *testing.T) {
	st := mirror()
	st.Upstream, st.Generated, st.Proxy = "", true, true
	got, err := pkgrepos.Render(st)
	if err == nil {
		t.Fatalf("Render returned a conf for a generated repository in proxy mode:\n%s", got.Conf)
	}
	for _, want := range []string{"generated", "proxy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator has to guess which field to change: %v", want, err)
		}
	}
}

// Render refuses every contradiction the server refuses to route, and one
// more the server has no reason to.
//
// One direction is the invariant. The server decides per request through
// manifest.VersionEntry.FreeBSDGenerated, and a contradiction that refuses
// there and renders here is published as installable configuration with an
// empty refusal list beside it, for a repository that answers 500 on every
// path: neither artifact says so.
//
// The other direction is not, because the two answer different questions. The
// route asks whether it can serve these bytes and reads the store to do it,
// which needs no url; this asks which trust store verifies them, and the url
// is the only authority for that. An entry with neither a url nor generated
// serves whatever was uploaded and gets a refusal row rather than a stanza,
// and a guard at the route would answer 500 for a repository that answers 200
// today: internal/server/freebsd_test.go seeds exactly that entry.
func TestRefusalsMatchTheServersOwn(t *testing.T) {
	const (
		abi = "FreeBSD:14:amd64"
		url = "https://pkg.freebsd.org/FreeBSD:14:amd64/latest"
	)
	for _, tc := range []struct {
		name string
		ve   manifest.VersionEntry

		// emitterOnly is the asymmetric row: routed, and refused here.
		emitterOnly bool
	}{
		{"mirrored", manifest.VersionEntry{Version: abi, URL: url}, false},
		{"mirrored by proxy", manifest.VersionEntry{Version: abi, URL: url, Mode: manifest.ModeProxy}, false},
		{"generated", manifest.VersionEntry{Version: abi, Generated: true}, false},
		{"generated and hosted", manifest.VersionEntry{Version: abi, Generated: true, Mode: manifest.ModeHosted}, false},
		{"generated with an upstream url", manifest.VersionEntry{Version: abi, URL: url, Generated: true}, false},
		{"generated by proxy", manifest.VersionEntry{Version: abi, Generated: true, Mode: manifest.ModeProxy}, false},
		{"generated by proxy with an upstream url", manifest.VersionEntry{Version: abi, URL: url, Generated: true, Mode: manifest.ModeProxy}, false},
		{"neither mirrored nor generated", manifest.VersionEntry{Version: abi}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, routed := tc.ve.FreeBSDGenerated()

			st := mirror()
			st.ABI = tc.ve.Version
			st.Upstream, st.Generated = tc.ve.URL, tc.ve.Generated
			st.Proxy = tc.ve.EffectiveMode() == manifest.ModeProxy
			_, rendered := pkgrepos.Render(st)

			switch {
			case routed != nil && rendered == nil:
				t.Fatalf("the server refuses to route this entry (%v) and Render emits a stanza for it, which publishes installable configuration for a repository that answers 500", routed)
			case routed == nil && rendered != nil && !tc.emitterOnly:
				t.Fatalf("the server routes this entry and Render refuses it (%v), which withholds the configuration for a repository that answers", rendered)
			case tc.emitterOnly && rendered == nil:
				t.Fatal("Render emitted a stanza for an entry naming neither the url that says who signed the catalogue nor the generated flag that says bodega did; the file would hand its reader the mirrored answer for a repository nobody mirrored")
			}
		})
	}
}

// pkg+https is SRV mirror discovery, not a spelling of https. The emitted
// file says so, because the reader will have seen it in /etc/pkg/FreeBSD.conf.
func TestPlainSchemeWithMirrorTypeNoneAndTheReasonWhy(t *testing.T) {
	got := render(t, mirror())
	if !strings.HasPrefix(got.URL, "https://bodega.internal/freebsd/${ABI}/latest") {
		t.Errorf("URL = %q, want a plain https URL under /freebsd/${ABI}/", got.URL)
	}
	if strings.Contains(got.Conf, "pkg+https://") {
		t.Errorf("the conf configures a pkg+ URL, which sends the client looking for SRV records bodega does not publish:\n%s", got.Conf)
	}
	if !strings.Contains(got.Stanza, `mirror_type: "none"`) {
		t.Errorf("the stanza sets no mirror_type, leaving the client on whatever it inherited:\n%s", got.Stanza)
	}
	if !strings.Contains(got.Conf, "SRV") {
		t.Errorf("the conf never says why the scheme is not pkg+https, which is the first thing a reader asks:\n%s", got.Conf)
	}
}

// The tag is bodega's own. A definition tagged FreeBSD-ports here would merge
// into the upstream one rather than stand beside it, and the override two
// lines up would then disable bodega as well.
func TestTagIsNamespacedAndDoesNotCollideWithAnUpstreamOne(t *testing.T) {
	got := render(t, mirror())
	if got.Tag != "bodega-latest" {
		t.Fatalf("Tag = %q, want bodega-latest", got.Tag)
	}
	if slices.Contains(pkgrepos.UpstreamTags(14), got.Tag) || slices.Contains(pkgrepos.UpstreamTags(15), got.Tag) {
		t.Errorf("Tag %q collides with a tag the base system defines", got.Tag)
	}
	enabled := strings.Index(got.Conf, got.Tag+": {")
	if enabled < 0 {
		t.Fatalf("the conf carries no %s definition:\n%s", got.Tag, got.Conf)
	}
	// Ordering is not cosmetic: pkg takes the last definition of a tag, so
	// the overrides have to precede nothing that shares a name with them.
	for _, tag := range got.Disabled {
		if i := strings.Index(got.Conf, tag+": {"); i > enabled {
			t.Errorf("%s is disabled after bodega's own definition; pkg reads the file in order", tag)
		}
	}
}

// Nothing reported a public URL, so the host is a placeholder and the file
// says so. A hostname the server guessed at reads as authoritative.
func TestPlaceholderHostIsNamedAsOne(t *testing.T) {
	st := mirror()
	st.PublicURL, st.LocalScheme = "", "http"
	got := render(t, st)
	if !strings.Contains(got.URL, pkgrepos.PlaceholderHost) {
		t.Errorf("URL = %q, want the placeholder host", got.URL)
	}
	if !strings.Contains(got.Note(), "public_url is unset") {
		t.Errorf("no note says the host is a placeholder: %q", got.Note())
	}
}

// An entry with no name has no repository directory to point a url at.
func TestRefusesAnEmptyRepositoryName(t *testing.T) {
	st := mirror()
	st.Repo = ""
	if got, err := pkgrepos.Render(st); err == nil {
		t.Fatalf("Render with no repository name returned:\n%s", got.Conf)
	}
}

func TestReleaseFromABI(t *testing.T) {
	for _, tc := range []struct {
		abi  string
		want int
		ok   bool
	}{
		{"FreeBSD:14:amd64", 14, true},
		{"FreeBSD:15:aarch64", 15, true},
		{"freebsd:15:aarch64:64", 0, false},
		{"FreeBSD:14", 0, false},
		{"", 0, false},
	} {
		got, ok := pkgrepos.ReleaseFromABI(tc.abi)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ReleaseFromABI(%q) = %d, %v; want %d, %v", tc.abi, got, ok, tc.want, tc.ok)
		}
	}
}

// pkgbaseMirror is the second mirrored case: one of FreeBSD's
// release-engineered base repositories, which release engineering signs with
// a key set the ports trust store does not hold.
func pkgbaseMirror() pkgrepos.State {
	return pkgrepos.State{
		PublicURL: "https://bodega.internal",
		ABI:       "FreeBSD:15:amd64",
		Repo:      "base",
		Upstream:  "https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1",
	}
}

// A mirror is two cases, not one, and the ports trust store is wrong for the
// second. Measured on FreeBSD 15.1-RELEASE with pkg 2.7.5 against
// FreeBSD:15:aarch64/base_release_1: /usr/share/keys/pkg fetched the
// catalogue, printed "No trusted public keys found", processed 0 entries and
// exited 0; /usr/share/keys/pkgbase-15 processed 502. Both exit 0, so the
// wrong one leaves an empty repository behind and pkg install reports every
// package as missing.
func TestPkgbaseMirrorVerifiesAgainstThePkgbaseTrustStore(t *testing.T) {
	got := render(t, pkgbaseMirror())
	if !got.Pkgbase {
		t.Fatalf("Pkgbase = false for a mirror of %s", pkgbaseMirror().Upstream)
	}
	if got.SignatureType != "fingerprints" || got.Fingerprints != pkgrepos.PkgbaseFingerprints {
		t.Fatalf("signature_type %q fingerprints %q, want fingerprints against %q",
			got.SignatureType, got.Fingerprints, pkgrepos.PkgbaseFingerprints)
	}
	if strings.Contains(got.Stanza, `"`+pkgrepos.StockFingerprints+`"`) {
		t.Errorf("the stanza names the ports trust store, which processes no entries and reports nothing:\n%s", got.Stanza)
	}
	if !strings.Contains(got.Conf, "pkgbase trust store") {
		t.Errorf("the conf never says which of the host's two trust stores this is:\n%s", got.Conf)
	}
}

// The trust store is right for a base_release_<n> mirror below ReleaseSplit
// and the sentence above it used to say the repository was not one, which is
// the pair that costs a reader something: they conclude bodega misread their
// URL, move fingerprints to the pkgbase store, and land in the silent failure
// the paragraph next door warns about. On 13 and 14 that directory does not
// exist at all. Measured with pkg 2.7.5 against
// FreeBSD:14:amd64/base_release_1: the ports store verifies the catalogue and
// reaches the ABI check past verification, the pkgbase one prints "No trusted
// public keys found" and processes nothing.
func TestABaseReleaseMirrorBelowTheSplitIsNotToldItIsNotOne(t *testing.T) {
	for _, abi := range []string{"FreeBSD:13:amd64", "FreeBSD:14:amd64"} {
		t.Run(abi, func(t *testing.T) {
			st := pkgbaseMirror()
			st.ABI, st.Upstream = abi, "https://pkg.freebsd.org/"+abi+"/base_release_1"
			got := render(t, st)
			if got.Pkgbase {
				t.Fatalf("Pkgbase = true: no release below %d ships a pkgbase trust store", pkgrepos.ReleaseSplit)
			}
			if !got.BaseRelease {
				t.Fatalf("BaseRelease = false for a mirror of %s", st.Upstream)
			}
			if got.Fingerprints != pkgrepos.StockFingerprints {
				t.Errorf("Fingerprints = %q, want %q", got.Fingerprints, pkgrepos.StockFingerprints)
			}
			prose := confProse(got.Conf)
			if strings.Contains(prose, "this one something else") {
				t.Errorf("the conf tells a base_release_1 mirror that upstream calls it something else:\n%s", got.Conf)
			}
			if !strings.Contains(prose, "installs no pkgbase directory") {
				t.Errorf("the conf never says which term excused this repository from the pkgbase store:\n%s", got.Conf)
			}
		})
	}
}

// The positive row, so the fix above cannot be made by deleting the sentence
// for everybody: a base_release_<n> mirror at or above the split keeps the
// pkgbase paragraph.
func TestABaseReleaseMirrorAtTheSplitKeepsThePkgbaseParagraph(t *testing.T) {
	got := render(t, pkgbaseMirror())
	if !got.BaseRelease || !got.Pkgbase {
		t.Fatalf("BaseRelease %v Pkgbase %v, want both true", got.BaseRelease, got.Pkgbase)
	}
	prose := confProse(got.Conf)
	if !strings.Contains(prose, "pkgbase trust store") {
		t.Errorf("the conf never names the pkgbase store:\n%s", got.Conf)
	}
	// Both terms of the predicate that selected this arm, so a reader on an
	// older release cannot read the name alone and move their own file.
	if !strings.Contains(prose, "base_release_<n>") ||
		!strings.Contains(prose, "or later, whose base system") {
		t.Errorf("the conf explains the pkgbase store with fewer terms than decided it:\n%s", got.Conf)
	}
}

// Every other repository upstream publishes comes off the package builders'
// key, base snapshots included, so "is it a base repository" is the wrong
// question: answering it sends base_latest — the base repository bodega's own
// prompts suggest — to a store that verifies nothing. Each row measured
// against pkg 2.7.5 by fetching the upstream catalogue under both of the
// host's trust stores.
func TestIsPkgbaseSigned(t *testing.T) {
	for _, tc := range []struct {
		upstream string
		release  int
		want     bool
	}{
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_1", 15, true},
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/base_release_0", 15, true},
		{"https://mirror.internal/freebsd/base_release_1/", 15, true},
		// Snapshot base repositories are built and signed like ports.
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/base_latest", 15, false},
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/base_weekly", 15, false},
		// No release before 15 publishes a repository signed that way, and
		// none installs the trust store either: share/keys in the base system
		// lists pkg alone on stable/13 and stable/14.
		{"https://pkg.freebsd.org/FreeBSD:14:amd64/base_release_1", 14, false},
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/latest", 15, false},
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/quarterly", 15, false},
		{"https://pkg.freebsd.org/FreeBSD:15:amd64/kmods_quarterly_1", 15, false},
		{"", 15, false},
	} {
		if got := pkgrepos.IsPkgbaseSigned(tc.upstream, tc.release); got != tc.want {
			t.Errorf("IsPkgbaseSigned(%q, %d) = %v, want %v", tc.upstream, tc.release, got, tc.want)
		}
	}
}

// The trust store follows the repository, and --release follows the host.
// An operator writing the file for a host of another release moves the
// overrides; the key that signed the catalogue does not move with them.
func TestTheTargetReleaseDoesNotMoveTheTrustStore(t *testing.T) {
	st := pkgbaseMirror()
	st.Release = 14
	got := render(t, st)
	if got.Fingerprints != pkgrepos.PkgbaseFingerprints {
		t.Errorf("Fingerprints = %q for a 15 repository written for a 14 host, want %q",
			got.Fingerprints, pkgrepos.PkgbaseFingerprints)
	}
	if !slices.Equal(got.Disabled, pkgrepos.UpstreamTags(14)) {
		t.Errorf("Disabled = %v, want the 14 tags", got.Disabled)
	}
}

// Re-rendering for another target release moves the overrides and nothing
// else. The caller that does it — doctor --write-pkg-repo --release — holds
// what crossed the wire, and the upstream URL the trust half was derived from
// is not on it; rebuilding a State there is what pointed a pkgbase mirror at
// the ports trust store.
func TestWithReleaseMovesTheOverridesAndNothingElse(t *testing.T) {
	// The cache is on, so this entry reaches upstream and the bootstrap note
	// is the one blaming upstream rather than the catalogue. A wire shape that
	// dropped upstream_fallthrough would re-render the other text, which is
	// the round trip that already lost the trust half once.
	base := pkgbaseMirror()
	base.CacheEnabled = true
	fifteen := render(t, base)
	if !fifteen.UpstreamFallthrough {
		t.Fatal("the fixture does not reach upstream, so this test cannot tell a dropped field from a zero one")
	}

	// Through the wire shape, because that is the trip the caller makes.
	var decoded pkgrepos.Repo
	encoded, err := json.Marshal(fifteen)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, err := decoded.WithRelease(14)
	if err != nil {
		t.Fatalf("WithRelease(14) = %v", err)
	}
	if got.Fingerprints != fifteen.Fingerprints || got.SignatureType != fifteen.SignatureType {
		t.Errorf("re-rendering for another release changed the trust half: %q/%q became %q/%q",
			fifteen.SignatureType, fifteen.Fingerprints, got.SignatureType, got.Fingerprints)
	}
	if got.URL != fifteen.URL || got.Tag != fifteen.Tag || got.Pkgbase != fifteen.Pkgbase ||
		got.BaseRelease != fifteen.BaseRelease {
		t.Errorf("re-rendering changed url/tag/pkgbase/base_release: %+v against %+v", got, fifteen)
	}
	if got.UpstreamFallthrough != fifteen.UpstreamFallthrough {
		t.Errorf("re-rendering changed upstream_fallthrough: %v became %v; the cache toggle it comes from is the server's and does not cross",
			fifteen.UpstreamFallthrough, got.UpstreamFallthrough)
	}
	if got.Bootstrap != fifteen.Bootstrap {
		t.Errorf("re-rendering changed the bootstrap answer: %q became %q; the upstream URL it was derived from is not on the wire",
			fifteen.Bootstrap, got.Bootstrap)
	}
	if got.Note() != fifteen.Note() {
		t.Errorf("re-rendering changed the notes: %q became %q", fifteen.Note(), got.Note())
	}
	if !slices.Equal(got.Disabled, pkgrepos.UpstreamTags(14)) {
		t.Errorf("Disabled = %v, want the 14 tags", got.Disabled)
	}
	if !strings.Contains(got.Conf, "written for a\n# FreeBSD 14 host") {
		t.Errorf("the conf still names the release it was first rendered for:\n%s", got.Conf)
	}
	if _, err := got.WithRelease(0); err == nil {
		t.Errorf("WithRelease(0) returned a conf rather than refusing; the overrides would name no tag at all")
	}
}

// The serving mode survives the wire, because the reach paragraph is derived
// from it and doctor --release re-renders the whole file from what crossed.
// Every fact this file lost in that round trip so far was one nothing carried.
func TestWithReleaseKeepsTheReachParagraph(t *testing.T) {
	st := mirror()
	st.ABI, st.Proxy = "FreeBSD:15:amd64", true
	proxied := render(t, st)

	var decoded pkgrepos.Repo
	encoded, err := json.Marshal(proxied)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := decoded.WithRelease(14)
	if err != nil {
		t.Fatalf("WithRelease(14) = %v", err)
	}
	if !got.Proxy || got.HoldsCatalogue() {
		t.Fatalf("the serving mode did not survive the wire: proxy=%v, HoldsCatalogue=%v", got.Proxy, got.HoldsCatalogue())
	}
	if !strings.Contains(got.Conf, "catalogue included") {
		t.Errorf("re-rendering turned a proxy into a mirror that holds its own catalogue:\n%s", got.Conf)
	}
}

// A generated repository's two claims survive the wire as well, and they are
// decided by two different fields: Generated says bodega built the catalogue
// and SignatureType says whether it signed it. Carried by one, doctor
// --release would re-render the pair as agreeing when the server said they
// did not.
func TestWithReleaseKeepsTheGeneratedClaimsApart(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fingerprint string
		wantProse   string
	}{
		{"no key loaded", "", "carries no"},
		{"key loaded", "SHA256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "bodega signs it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := mirror()
			st.Upstream, st.Generated, st.Fingerprint = "", true, tc.fingerprint
			encoded, err := json.Marshal(render(t, st))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded pkgrepos.Repo
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got, err := decoded.WithRelease(15)
			if err != nil {
				t.Fatalf("WithRelease(15) = %v", err)
			}
			prose := confProse(got.Conf)
			if !strings.Contains(prose, tc.wantProse) {
				t.Errorf("re-rendering lost %q:\n%s", tc.wantProse, got.Conf)
			}
			if !strings.Contains(prose, "every request stops here") {
				t.Errorf("re-rendering dropped the reach paragraph, which Render's own refusals make unconditionally true of a generated repository:\n%s", got.Conf)
			}
			if strings.Contains(prose, "signed by bodega") {
				t.Errorf("the re-rendered conf claims bodega signed a catalogue it renders signature_type %q for:\n%s", got.SignatureType, got.Conf)
			}
		})
	}
}

// A Repo decoded without a bootstrap field hedges rather than asserting the
// answer the field replaced. The wire shape is what a doctor on one release
// reads off a server on another, so the two can differ in age, and the old
// answer for a proxied repository was that bootstrap works.
func TestABootstrapAnswerMissingFromTheWireHedges(t *testing.T) {
	var decoded pkgrepos.Repo
	wire := `{"tag":"bodega-base","abi":"FreeBSD:15:amd64","repo":"base","release":15,` +
		`"proxy":true,"url":"https://bodega.internal/freebsd/${ABI}/base",` +
		`"signature_type":"fingerprints","disabled":["FreeBSD-ports"]}`
	if err := json.Unmarshal([]byte(wire), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := decoded.WithRelease(15)
	if err != nil {
		t.Fatalf("WithRelease(15) = %v", err)
	}
	if strings.Contains(got.Conf, "`pkg bootstrap` works here") {
		t.Errorf("a configuration re-rendered from a wire shape carrying no bootstrap answer claims one:\n%s", got.Conf)
	}
	if !strings.Contains(got.Conf, "`pkg bootstrap` may not work") {
		t.Errorf("the conf neither asserts nor hedges the bootstrap answer:\n%s", got.Conf)
	}
}
