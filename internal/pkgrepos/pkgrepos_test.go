package pkgrepos_test

import (
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

// The bootstrap answer follows how the repository is served, not what pkg is.
// A proxy composes an upstream URL for any path outside the catalogue, so
// both bootstrap paths resolve; a hosted mirror 404s them. Measured against
// a proxied repository: Latest/pkg.pkg came back 200 at 5,477,177 bytes and
// its .sig at 727.
func TestBootstrapNoteFollowsTheServingMode(t *testing.T) {
	hosted := render(t, mirror())
	if !strings.Contains(hosted.Conf, "`pkg bootstrap` does not work") {
		t.Errorf("a hosted mirror's conf does not say bootstrap fails against it:\n%s", hosted.Conf)
	}

	st := mirror()
	st.Proxy = true
	proxied := render(t, st)
	if !proxied.Proxy {
		t.Error("Proxy did not survive into the rendered configuration")
	}
	if strings.Contains(proxied.Conf, "`pkg bootstrap` does not work") {
		t.Errorf("a proxied repository's conf claims bootstrap fails, which sends an operator to rebuild a repository that already answers:\n%s", proxied.Conf)
	}
	if !strings.Contains(proxied.Note(), "reaches the internet") {
		t.Errorf("the proxy note does not name what bootstrapping through a proxy costs: %q", proxied.Note())
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

// Render refuses what the server refuses to route, and nothing more.
//
// The server decides per request through manifest.VersionEntry.FreeBSDGenerated.
// A contradiction that refuses there and renders here is published as
// installable configuration with an empty refusal list beside it, and the
// repository it names answers 500 on every path: neither artifact says so.
// One that renders there and refuses here withholds a working repository's
// configuration for no reason a reader can act on.
func TestRefusalsMatchTheServersOwn(t *testing.T) {
	const (
		abi = "FreeBSD:14:amd64"
		url = "https://pkg.freebsd.org/FreeBSD:14:amd64/latest"
	)
	for _, tc := range []struct {
		name string
		ve   manifest.VersionEntry
	}{
		{"mirrored", manifest.VersionEntry{Version: abi, URL: url}},
		{"mirrored by proxy", manifest.VersionEntry{Version: abi, URL: url, Mode: manifest.ModeProxy}},
		{"generated", manifest.VersionEntry{Version: abi, Generated: true}},
		{"generated and hosted", manifest.VersionEntry{Version: abi, Generated: true, Mode: manifest.ModeHosted}},
		{"generated with an upstream url", manifest.VersionEntry{Version: abi, URL: url, Generated: true}},
		{"generated by proxy", manifest.VersionEntry{Version: abi, Generated: true, Mode: manifest.ModeProxy}},
		{"generated by proxy with an upstream url", manifest.VersionEntry{Version: abi, URL: url, Generated: true, Mode: manifest.ModeProxy}},
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
			case routed == nil && rendered != nil:
				t.Fatalf("the server routes this entry and Render refuses it (%v), which withholds the configuration for a repository that answers", rendered)
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
