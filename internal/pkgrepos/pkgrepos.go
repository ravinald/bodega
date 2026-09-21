// Package pkgrepos renders the FreeBSD pkg client configuration for a bodega
// instance: the repository stanza, the override that disables the upstream
// repository beside it, and the consequences of whichever form it chose.
//
// One renderer, for the reason internal/aptsources is one renderer. The TUI
// and the web UI each grew a pkg stanza of their own and both were wrong in
// the same three ways: neither disabled the upstream repository, so a host
// configured from either went on fetching from pkg.FreeBSD.org beside bodega
// with nothing in `pkg update` output saying so; neither set mirror_type, so
// the client was left on whatever it inherited; and both hard-coded the stock
// fingerprint path, which is right for a mirror and fails `pkg update` on a
// repository bodega generated and signed itself.
//
// Each was guessing at something only the running server knows. State carries
// those facts, and nothing in the tree composes a pkg stanza without one.
package pkgrepos

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// ClientReposDir is the directory pkg reads client-side repository
	// definitions from. /etc/pkg/ is the base system's and an override
	// written there is replaced by the next freebsd-update.
	ClientReposDir = "/usr/local/etc/pkg/repos"

	// ClientConfPath is the file Conf is written to. One file holds both the
	// bodega repository and the overrides that disable the upstream one,
	// because the two are a single decision: a host that has one without the
	// other is either fetching from the internet or fetching from nowhere.
	ClientConfPath = ClientReposDir + "/bodega.conf"

	// StockFingerprints is the trust store every FreeBSD host already ships,
	// holding the key pkg.FreeBSD.org signs with. A mirrored repository is
	// copied byte for byte so that signature arrives intact, and this is what
	// verifies it.
	StockFingerprints = "/usr/share/keys/pkg"

	// PkgbaseFingerprints is the trust store FreeBSD's release-engineered
	// base repositories verify against. It is a second key set in a second
	// directory and both ship on the same host: /usr/share/keys/pkg holds
	// pkg.freebsd.org.2013102301, /usr/share/keys/pkgbase-15 holds awskms-15
	// and backup-signing-15, and neither verifies what the other signed.
	//
	// ${VERSION_MAJOR} stays literal for the reason ${ABI} does. pkg
	// substitutes the running host's own release, the repository a client
	// fetches is the one under its own ABI, and the keys are installed by the
	// base system of that release. It is also how /etc/pkg/FreeBSD.conf
	// spells its own FreeBSD-base entry, which is the authority here.
	PkgbaseFingerprints = "/usr/share/keys/pkgbase-${VERSION_MAJOR}"

	// BodegaFingerprints is where a client installs bodega's own fingerprint,
	// and is what a generated repository's stanza names. pkg expects a
	// directory holding trusted/ and revoked/, not a file, which is why
	// `bodega freebsd key export --fingerprint` writes into trusted/ beneath
	// this path.
	BodegaFingerprints = "/usr/local/etc/pkg/fingerprints/bodega"

	// TagPrefix keeps bodega's repository tag out of the namespace the base
	// system publishes. A definition tagged "FreeBSD-ports" in this file
	// would merge into the upstream one rather than stand beside it.
	TagPrefix = "bodega-"

	// PlaceholderHost stands in when nothing reported a public URL. A
	// placeholder the operator must replace beats a hostname the server
	// guessed at: behind a proxy the guess is wrong and reads as
	// authoritative.
	PlaceholderHost = "<bodega-host>:8080"
)

const (
	// UnknownURLNote fires whenever nothing reported a public URL, so the
	// host in the stanza is a placeholder. Behind a reverse proxy the server
	// sees a loopback listener with no TLS and no hostname: it cannot name
	// the URL clients use, and the scheme it prints describes its own back
	// end.
	UnknownURLNote = `public_url is unset, so the host in this stanza is a placeholder and the scheme describes this server's own listener, not what a proxy publishes. Set public_url to the external base URL.`

	// MirroredNote names what verifies a mirrored repository. bodega copies
	// packagesite.pkg and data.pkg byte for byte, and each carries its own
	// .sig and .pub as tar members, so FreeBSD's attestation reaches the
	// client and the stock trust store checks it. No key of bodega's is in
	// that path.
	MirroredNote = `bodega copies this repository's bytes from upstream without transforming them, so FreeBSD's own signature arrives inside the catalogue archive and pkg verifies it against ` + StockFingerprints + `, which every FreeBSD host already ships. Do not point fingerprints at a bodega key here: bodega signs nothing in this path, and the stanza would fail "pkg update" on a signature that is present and valid.`

	// PkgbaseMirroredNote is MirroredNote's other half, and the reason a
	// mirror is two cases rather than one. A release-engineered base
	// repository carries FreeBSD's signature the way any mirror does, signed
	// by a key the ports trust store does not hold, and naming the wrong
	// store fails no louder than an empty repository: pkg reports "No trusted
	// public keys found", exits 0, processes no entries, and the next
	// `pkg install` says the package does not exist rather than that it could
	// not be verified.
	PkgbaseMirroredNote = `The repository these bytes come from is one of FreeBSD's release-engineered base repositories, which release engineering signs with the pkgbase key set rather than the one the package builders use, so it verifies against ` + PkgbaseFingerprints + ` and not ` + StockFingerprints + `. Pointed at the ports store it fails silently: "pkg update" prints "No trusted public keys found", exits 0 and processes no entries, and "pkg install" then reports every package as missing.`

	// FingerprintNote is the out-of-band delivery a generated repository
	// needs. The first fetch of any public key is authenticated by TLS alone;
	// comparing the fingerprint against something that is not the server is
	// the only thing that closes that hop.
	FingerprintNote = `Install bodega's fingerprint on the client before this stanza: "bodega freebsd key export --fingerprint > ` + BodegaFingerprints + `/trusted/bodega", delivered out of band rather than fetched from this server. pkg reads the .pub member out of the catalogue archive and checks its SHA-256 against that file.`

	// UnsignedNote is the consequence of signature_type: none, which is what
	// a generated repository renders with no key loaded. It travels beside
	// the stanza rather than in place of it: an operator pasting this into an
	// Ansible template needs to read it before the paste.
	UnsignedNote = `signature_type: none accepts whatever this server returns, with TLS as the only thing authenticating the packages, and it propagates into Ansible templates and image builds that outlive whatever made it necessary. Run "bodega freebsd key generate", reload the server, and re-read this stanza to get a verified one.`

	// IsolatedNote, ProxyReachNote and MirrorReachNote answer how much of
	// this repository leaves the host, which is the question an operator
	// pastes the file to settle. Two facts decide it: State.ReachesUpstream
	// says whether any path falls through, and Repo.HoldsCatalogue says
	// whether the catalogue is one of them.
	//
	// One text used to cover all three, keyed off nothing: the bootstrap
	// note ended on "unlike every other request this repository answers",
	// which was true of the hosted mirror it was written for and printed for
	// a proxy, where every request reaches upstream and the catalogue with
	// them.

	// IsolatedNote is the isolation claim, and it may be printed only where
	// nothing falls through: no url on the entry, or neither the proxy mode
	// nor the server's proxy cache.
	IsolatedNote = `Every request this repository answers stops at this server: it publishes the paths its catalogue names and this server fetches nothing under it from upstream, so a package it does not hold is a 404 here rather than a fetch from the internet.`

	// ProxyReachNote is the answer for a repository served in proxy mode,
	// where the catalogue falls through with everything else and bodega holds
	// no copy of the repository at all.
	ProxyReachNote = `Every request this repository answers may reach the internet, the catalogue included: it is served in proxy mode, so this server composes an upstream URL for each path and fetches it whenever it holds no fresh copy. What is stored here is whatever earlier requests cached, not a copy of the repository.`

	// MirrorReachNote is the mirror whose own catalogue is served from here
	// and whose misses are not. Hosted and falling through means the server's
	// proxy cache is on, since that is the only other term the route reads,
	// and the cost is that an install can succeed against a package the
	// mirror never held.
	//
	// The three files are named rather than called "the catalogue" because
	// the route recognizes exactly those three (manifest.FreeBSDCatalogFiles)
	// and a root file under any other spelling falls through like a package.
	// TestTheMirrorNoteNamesEveryCatalogueFileTheRouteKnows holds the
	// sentence and that list together.
	MirrorReachNote = `This repository's catalogue is served from what was published here, and a miss on meta.conf, packagesite.pkg or data.pkg is refused rather than fetched, but every other path reaches the internet on a miss: this server's proxy cache is on, so a package the mirror does not hold is fetched from upstream, cached and served under this repository's name. An install can succeed here against a package nobody mirrored.`

	// NoBootstrapNote is the answer when nothing under this repository is
	// fetched from upstream. pkg's own bootstrapper (usr.sbin/pkg/pkg.c)
	// fetches <repo>/Latest/pkg.pkg and its .sig and nothing else, and a
	// mirror publishes only the repopaths its catalogue names, which never
	// include that pair.
	//
	// That a mirror publishes only its catalogue is the premise rather than
	// the answer, and it is the whole answer only where State.ReachesUpstream
	// is false: the route serves a path the catalogue does not name from
	// upstream wherever it can. The isolation claim itself is IsolatedNote's,
	// which reads the same fact and answers how much of this repository is
	// here rather than what one command does.
	NoBootstrapNote = `"pkg bootstrap" does not work against this repository: it fetches Latest/pkg.pkg and Latest/pkg.pkg.sig, a catalogue never names that pair, and nothing under this repository falls through to upstream to fetch it from. Install pkg on the host from upstream first, then switch it over.`

	// BootstrapResolvesNote is the answer when a path outside the catalogue
	// reaches upstream and upstream publishes the pair. Two facts decide it
	// and the serving mode is neither: State.ReachesUpstream is the first and
	// UpstreamBootstrap the second. The cost of the working case is reaching
	// pkg.FreeBSD.org, which a host the operator believes is isolated is not
	// doing on any other path, so the note says so rather than leaving it to
	// the server log.
	//
	// Not named BootstrapWorksNote, which would read better: gosec's G101
	// credential-name pattern matches "pw" case-insensitively, the camelCase
	// boundary in "BootstrapWorks" spells one, and the lint then fails on a
	// string holding no secret.
	BootstrapResolvesNote = `"pkg bootstrap" works against this repository: this server fetches a path outside its catalogue from the upstream the repository records, and upstream publishes Latest/pkg.pkg and Latest/pkg.pkg.sig under it, so that path reaches the internet through this server.`

	// NoBootstrapUpstreamNote is the repository whose paths reach upstream
	// and whose upstream publishes no pkg package. The route resolves the
	// path, upstream refuses it, and what the client sees depends on how:
	// internal/server/proxy.go:477 passes a 404 through and turns every other
	// non-200 into a 502 whose body says "upstream fetch failed" and names
	// nothing. Measured through a proxied FreeBSD:15:aarch64/base_release_1,
	// where upstream answers 403 for both paths: the client got 502 and the
	// upstream URL stayed in bodega's log.
	NoBootstrapUpstreamNote = `"pkg bootstrap" does not work against this repository: it fetches Latest/pkg.pkg and Latest/pkg.pkg.sig, this server fetches a path outside the catalogue from the upstream the repository records, and upstream publishes that pair under neither a base nor a kmods repository. The client sees upstream's 404, or a 502 where upstream answers 403, and the refusing URL is in bodega's log rather than in the error. Bootstrap the host from a ports repository first, then switch it over.`

	// BootstrapUnknownNote is the honest answer for a repository nobody drove
	// the pair against, and it is the default rather than the exception: the
	// measured list is short, upstream adds repositories, and a note claiming
	// bootstrap works reads as measured whether or not anybody measured it.
	BootstrapUnknownNote = `"pkg bootstrap" may not work against this repository: it fetches Latest/pkg.pkg and Latest/pkg.pkg.sig, and upstream publishes that pair under some repositories and not others. Nobody measured this one, so try it rather than planning on it: a 404 or a 502 means bootstrapping the host from a ports repository first.`

	// GeneratedBootstrapNote is the other reason the answer is unknown, and
	// it is nothing to do with upstream: a generated repository has none, and
	// serves whatever the build tree uploaded. poudriere publishes
	// Latest/pkg.pkg as a symlink into All/ and the upload skips it
	// (internal/builder/freebsd.go:632-644), so it is absent on an ordinary
	// tree and present where somebody put a real file there. bodega cannot
	// tell which from the manifest, and the emitted file says so rather than
	// guessing.
	GeneratedBootstrapNote = `"pkg bootstrap" reaches this repository only if the build tree published Latest/pkg.pkg under it as a real file. poudriere publishes that path as a symlink and the upload skips it, to keep one package out of the catalogue twice, so on an ordinary poudriere tree it is absent.`
)

// ReleaseSplit is the first FreeBSD major release whose base system defines
// the ports repository under three tags instead of one.
//
// Below it /etc/pkg/FreeBSD.conf holds a single "FreeBSD" definition. From it,
// the same file holds FreeBSD-ports, FreeBSD-ports-kmods and FreeBSD-base.
// Disabling the wrong one is the failure this package exists to prevent, and
// it is silent: pkg reports nothing about an upstream repository that stayed
// enabled, and the host goes on fetching from the internet while the operator
// believes it is isolated.
const ReleaseSplit = 15

// upstreamTagsPreSplit and upstreamTagsSplit are what each side of
// ReleaseSplit ships. FreeBSD-base is disabled by default on a stock 15 host
// and is still named here, because a host that enabled it is exactly the host
// an override has to reach.
var (
	upstreamTagsPreSplit = []string{"FreeBSD"}
	upstreamTagsSplit    = []string{"FreeBSD-ports", "FreeBSD-ports-kmods", "FreeBSD-base"}
)

// UpstreamTags names the repository tags the base system defines on a given
// major release, which are the tags an override has to disable by name.
func UpstreamTags(release int) []string {
	if release >= ReleaseSplit {
		return upstreamTagsSplit
	}
	return upstreamTagsPreSplit
}

// BootstrapAnswer is what `pkg bootstrap` does against one repository, which
// is three answers and not two. It is on the wire because a consumer holding
// a rendered Repo cannot work it out again: the upstream URL that decides it
// is the server's fact and never crosses.
type BootstrapAnswer string

const (
	// BootstrapWorks is measured: the pair resolves through bodega.
	BootstrapWorks BootstrapAnswer = "works"

	// BootstrapAbsent is measured: one or both of the two paths answers 403
	// or 404, so the bootstrapper has nothing to fetch.
	BootstrapAbsent BootstrapAnswer = "absent"

	// BootstrapUnknown is nobody's measurement, and it is what an
	// unrecognized repository gets. It is also what an empty value decodes
	// as, so a Repo from a server that predates this field hedges rather than
	// claiming the answer the old code claimed.
	BootstrapUnknown BootstrapAnswer = "unknown"
)

// State is what the running server reports about how pkg clients reach one
// repository. Every field is a fact the server holds and no emitter can
// derive on its own.
type State struct {
	// PublicURL is the base URL clients use, from the public_url chain or
	// from the request that asked. Empty renders PlaceholderHost.
	PublicURL string

	// LocalScheme is the scheme this server's own listener answers on. It
	// decides the placeholder's scheme when PublicURL is empty, and it is
	// wrong the moment a proxy terminates TLS in front. Empty means https.
	LocalScheme string

	// ABI is the repository's ABI directory, "FreeBSD:14:amd64". Its middle
	// field is the release the override targets when Release is zero.
	ABI string

	// Repo is the repository directory a pkg client asks under, which is a
	// freebsd entry's package name: "latest", "base_latest".
	Repo string

	// Release overrides the major release read out of ABI, for an operator
	// configuring a host whose release is not the one the mirror is named
	// for. Zero means read it from ABI.
	Release int

	// Generated marks a catalogue bodega builds and signs, as opposed to one
	// copied from upstream. It decides the whole trust half of the stanza.
	Generated bool

	// Upstream is the mirrored repository's upstream root, straight off the
	// entry. It is here so Render can refuse an entry that claims to be both
	// rather than picking one.
	Upstream string

	// Fingerprint is the loaded pkg signing key's fingerprint, empty when the
	// server holds no key. Read only when Generated is set: bodega's key
	// signs what bodega generates and nothing else.
	Fingerprint string

	// Proxy marks a repository served from upstream on a miss rather than
	// from a finished mirror. It contradicts Generated, which is the second
	// pair Render refuses, and it is one of the three terms ReachesUpstream
	// reads. Whether any of the repository falls through is that predicate's
	// question; how much of it does is this field's alone, read through
	// Repo.HoldsCatalogue.
	Proxy bool

	// CacheEnabled is the server's proxy_cache_enabled toggle. It is here
	// because it is the other half of the question the route asks before
	// fetching a miss, and no emitter can see it: a consumer holding a
	// rendered Repo has the repository's own fields and nothing about the
	// server that rendered them.
	CacheEnabled bool
}

// ReachesUpstream reports whether a request for a path outside this
// repository's catalogue is fetched from upstream. Every claim the emitted
// file makes about Latest/pkg.pkg rests on this and not on the serving mode.
//
// Three terms, because that is what the route evaluates.
// internal/server/freebsd.go:127,188 composes an upstream URL whenever the
// entry records a url, whatever its mode; :155 passes the mode to
// proxyOrCache as forceProxy rather than as a gate; and
// internal/server/proxy.go:116 fetches the miss when
// cacheEnabled() || forceProxy. So a hosted mirror on a server with the proxy
// cache on reaches upstream exactly as a proxied one does.
//
// Measured against a bodega with proxy_cache_enabled: true and three
// FreeBSD:15:aarch64 entries, requesting Latest/pkg.pkg and its .sig on each:
//
//	ports        mode: proxy, url .../quarterly        200 5477177, 200 727
//	portsmirror  hosted,      url .../quarterly        200 5477177, 200 727
//	basemirror   hosted,      url .../base_release_1   502,         502
//
// portsmirror is byte-identical to ports on both paths and differs from it
// only in carrying no mode. bodega's own cache_origins table names where the
// bytes came from for the hosted entry:
//
//	freebsd/FreeBSD:15:aarch64/portsmirror/Latest/pkg.pkg
//	  <- https://pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly/Latest/pkg.pkg
//
// Driven from the client as well, with fetch(1) on a 15.1-RELEASE host
// running pkg 2.7.5 against that same hosted entry: both Latest paths OK, and
// meta.conf and packagesite.pkg Not Found. So the two halves differ on one
// repository, which is why the catalogue's own guard
// (internal/server/freebsd.go:128) does not answer this question.
//
// Keying a claim off Proxy alone has been wrong twice in opposite directions,
// which is why the predicate is named once here and read rather than
// re-spelled at each claim.
func (s State) ReachesUpstream() bool {
	return strings.TrimSpace(s.Upstream) != "" && (s.Proxy || s.CacheEnabled)
}

// Repo is one rendered client configuration. The JSON tags are the wire shape
// of the freebsd block of /api/v1/status.
type Repo struct {
	// Tag is the repository tag this stanza defines, "bodega-latest".
	Tag string `json:"tag"`

	ABI       string `json:"abi"`
	Repo      string `json:"repo"`
	Release   int    `json:"release"`
	Generated bool   `json:"generated,omitempty"`

	// Proxy is the serving mode. One claim rests on it and it is not the one
	// a reader expects: HoldsCatalogue reads it to say how much of this
	// repository falls through to upstream, while whether any of it does is
	// UpstreamFallthrough, and the two disagree on a hosted mirror with the
	// cache on.
	Proxy bool `json:"proxy,omitempty"`

	// UpstreamFallthrough reports whether a request for a path outside this
	// repository's catalogue is fetched from upstream, which is
	// State.ReachesUpstream carried across the wire. It is the isolation
	// claim: false says every request this repository answers stops at
	// bodega.
	//
	// It is here rather than re-derived because two of its three terms are
	// the server's and neither crosses: the upstream URL is not on this wire
	// and the cache toggle is a fact about the server, not the repository.
	// Never omitted, because false is the claim a reader acts on.
	UpstreamFallthrough bool `json:"upstream_fallthrough"`

	// Pkgbase marks the second mirrored case: a repository release
	// engineering signed, which verifies against the pkgbase trust store
	// rather than the ports one. It is carried here rather than re-derived
	// because the upstream URL it comes from is the server's fact and never
	// crosses the wire, and a consumer re-rendering this configuration from
	// the fields it can see would resolve it back into the ports store.
	Pkgbase bool `json:"pkgbase,omitempty"`

	// BaseRelease is the first of Pkgbase's two terms: upstream calls this
	// repository base_release_<n>. Pkgbase is that name and a release whose
	// base system ships the pkgbase trust store, so the two part company on
	// exactly one repository, a mirror of base_release_<n> built for a
	// release below ReleaseSplit. That one verifies against the ports store
	// like ports, and the comment saying so has to name the release rather
	// than deny the repository its name.
	//
	// Carried for the reason Pkgbase is: it comes from the upstream URL,
	// which is the server's fact and never crosses the wire.
	BaseRelease bool `json:"base_release,omitempty"`

	// Bootstrap is what `pkg bootstrap` does here. Never omitted: an absent
	// value and "unknown" mean the same thing and both hedge, while a field
	// that disappears on the common answer invites a consumer to read its
	// absence as the other one.
	Bootstrap BootstrapAnswer `json:"bootstrap"`

	URL string `json:"url"`

	// SignatureType is the rendered signature_type value, lowercase as pkg's
	// own configuration files spell it.
	SignatureType string `json:"signature_type"`

	// Fingerprints is the rendered fingerprints path, empty when
	// SignatureType is "none".
	Fingerprints string `json:"fingerprints,omitempty"`

	// Disabled names the upstream tags the override turns off, in the order
	// they are rendered. A consumer checking whether a host is isolated reads
	// this rather than parsing Conf back apart.
	Disabled []string `json:"disabled"`

	// Stanza is the repository definition alone, for a pane with room for one
	// block. It is not installable on its own: without the Disabled overrides
	// the host fetches from both.
	Stanza string `json:"stanza"`

	// Conf is the whole file, comments and overrides included, ready to land
	// at ClientConfPath.
	Conf string `json:"conf"`

	Notes []string `json:"notes,omitempty"`
}

// Note joins the consequences of this form into one paragraph, for a consumer
// with a single line to spend on them.
func (r Repo) Note() string { return strings.Join(r.Notes, " ") }

// HoldsCatalogue reports whether this repository's catalogue is served from
// what was published here rather than fetched from upstream per request.
//
// State.ReachesUpstream answers whether any path falls through; this answers
// how much, and the two disagree on exactly the catalogue.
// internal/server/freebsd.go:128-140 zeroes the composed upstream URL for one
// of manifest.FreeBSDCatalogFiles when the entry is not proxied, so a hosted
// mirror answers a catalogue miss with 404 and never with upstream's bytes,
// while a proxied repository fetches meta.conf, packagesite.pkg and data.pkg
// from upstream the way it fetches everything else.
//
// The two questions were one sentence in the bootstrap paragraph, keyed off
// nothing, and it told a proxy operator that a single path left the building.
// Measured on 2026-09-21 against a bodega built from this tree, with
// proxy_cache_enabled: true, a local backend holding no objects, and two
// FreeBSD:15:aarch64 entries recording the same
// pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly url, one at mode: proxy and one
// hosted:
//
//	         meta.conf  packagesite.pkg  data.pkg  All/pv-1.9.31.pkg  Latest/pkg.pkg
//	proxy    200 179    200 10878141     200 10877713  200 106010     200 5477177
//	hosted   404 19     404 19           404 19        200 106010     200 5477177
//
// Latest/pkg.pkg.sig answers 200 727 on both rows. The two entries differ in
// the mode and nothing else, so the catalogue is the whole of what the mode
// decides. cache_origins names where the bytes came from: six rows under the
// proxied entry, all pointing at pkg.FreeBSD.org, and three under the hosted
// one, none of them a catalogue file.
func (r Repo) HoldsCatalogue() bool { return !r.Proxy }

// BaseURL returns the base URL a client fetches from, resolving the
// placeholder when State reports no public URL.
func (s State) BaseURL() string {
	if base := strings.TrimRight(s.PublicURL, "/"); base != "" {
		return base
	}
	scheme := s.LocalScheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + PlaceholderHost
}

// ReleaseFromABI reads the major release out of an ABI directory:
// "FreeBSD:14:amd64" is 14. It is the middle field by construction, which is
// why the release need not be configured separately for the ordinary case.
func ReleaseFromABI(abi string) (int, bool) {
	parts := strings.Split(abi, ":")
	if len(parts) != 3 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// IsPkgbaseSigned reports whether a mirror of this upstream repository, for a
// repository built for this FreeBSD release, verifies against the pkgbase
// trust store rather than the ports one.
//
// "A base repository" is the wrong question and answering it points working
// configuration at a store that verifies nothing. What decides the key is who
// built the repository, and only release engineering uses the pkgbase set:
// /etc/pkg/FreeBSD.conf defines FreeBSD-base as base_release_${VERSION_MINOR}
// against /usr/share/keys/pkgbase-${VERSION_MAJOR} and names no other base
// repository at all. Measured against pkg 2.7.5 on 15.1-RELEASE, fetching
// each upstream catalogue under each of the host's two trust stores:
//
//	FreeBSD:15:aarch64/base_release_0   pkgbase-15 verifies, pkg does not
//	FreeBSD:15:aarch64/base_release_1   pkgbase-15 verifies, pkg does not
//	FreeBSD:15:aarch64/base_latest      pkg verifies, pkgbase-15 does not
//	FreeBSD:15:aarch64/base_weekly      pkg verifies, pkgbase-15 does not
//	FreeBSD:14:amd64/base_release_1     pkg verifies, pkgbase-15 does not
//	FreeBSD:15:aarch64/kmods_quarterly_1, latest, quarterly: pkg verifies
//
// So the snapshot repositories come off the package builders' key like ports,
// and a pre-15 release has no pkgbase repository to mirror: share/keys in the
// base system installs pkg alone on stable/13 and stable/14, and pkg plus
// pkgbase-15 from stable/15.
//
// The upstream name is the authority and the local one says nothing: bodega
// publishes a repository under whatever name the operator gave the entry,
// while the URL is the repository root exactly as pkg.conf would spell it, so
// its last path segment is what upstream calls it.
func IsPkgbaseSigned(upstream string, release int) bool {
	return release >= ReleaseSplit && IsBaseRelease(upstream)
}

// IsBaseRelease reports whether upstream calls this repository
// base_release_<n>, which is release engineering's own rather than the
// package builders'.
//
// It is the first of IsPkgbaseSigned's two terms and is exported because the
// emitted configuration has to explain which of the two excused a repository
// from the pkgbase store. Below ReleaseSplit the name holds and the trust
// store still does not, and a file telling that operator their repository is
// not a base_release_<n> one sends them to move fingerprints onto a directory
// their host does not have.
//
// Measured with pkg 2.7.5 on 15.1-RELEASE, fetching
// FreeBSD:14:amd64/base_release_1 under each of the host's two stores with
// ABI and OSVERSION pinned to that release:
//
//	/usr/share/keys/pkg          525 packages processed, exit 0
//	/usr/share/keys/pkgbase-15   "No trusted public keys found", 0, exit 0
//
// So the name alone decides nothing, and the store that verifies a 14
// base_release repository is the same one that verifies ports.
func IsBaseRelease(upstream string) bool {
	return strings.HasPrefix(upstreamName(upstream), "base_release")
}

// upstreamName is what upstream calls a mirrored repository: the last segment
// of the URL, which is the repository root exactly as pkg.conf would spell
// it. Query and fragment are cut first, because a mirror configured through a
// URL carrying either still names its repository in the path.
func upstreamName(upstream string) string {
	name := upstream
	for _, cut := range []string{"?", "#"} {
		if i := strings.Index(name, cut); i >= 0 {
			name = name[:i]
		}
	}
	name = strings.TrimRight(name, "/")
	return strings.ToLower(name[strings.LastIndex(name, "/")+1:])
}

// UpstreamBootstrap reports what a proxied mirror of this upstream repository
// answers for the two paths pkg's own bootstrapper fetches,
// <repo>/Latest/pkg.pkg and its .sig (usr.sbin/pkg/pkg.c:870,881).
//
// Proxying is not the whole answer and claiming it is puts a command in the
// emitted file that cannot run. A proxy composes an upstream URL for any path
// outside the catalogue (internal/server/freebsd.go:127,155), so what the
// client sees is what upstream publishes, and upstream publishes a pkg
// package under the ports repositories and nowhere else. Every row measured
// with fetch(1) against pkg.FreeBSD.org on 2026-09-21, both paths per
// repository:
//
//	FreeBSD:15:aarch64  latest, quarterly                  both 200
//	FreeBSD:14:amd64    latest, quarterly                  both 200
//	FreeBSD:15:aarch64  release_0, release_1               both 200
//	FreeBSD:14:amd64    release_0, release_1               both 404
//	FreeBSD:15:aarch64  base_release_0                     pkg.pkg 200, .sig 403
//	FreeBSD:15:aarch64  base_release_1                     both 403
//	FreeBSD:15:aarch64  base_latest, base_weekly           both 404
//	FreeBSD:15:aarch64  kmods_{latest,quarterly}{,_0,_1}   both 404
//	FreeBSD:14:amd64    every base_* and kmods_*           both 404
//
// So the base and kmods repositories are absent on both releases, including
// the base_release_0 row where the package is there and the signature the
// bootstrapper checks it against is not. The release_<n> rows are why this
// answers from a measured list rather than from "it looks like a ports
// repository": the same name resolves on 15 and 404s on 14. An unrecognized
// name is BootstrapUnknown, which is the opposite default from the trust
// store's: there the wrong guess fails silently and here it prints a command
// that returns an HTTP error, so hedging costs a reader nothing.
func UpstreamBootstrap(upstream string) BootstrapAnswer {
	switch name := upstreamName(upstream); {
	case name == "latest", name == "quarterly":
		return BootstrapWorks
	case strings.HasPrefix(name, "base_"), strings.HasPrefix(name, "kmods_"):
		return BootstrapAbsent
	default:
		return BootstrapUnknown
	}
}

// Render produces the client configuration for one repository, or refuses.
//
// It refuses rather than picking a default in the cases where a stanza would
// install cleanly and fail later against something the operator cannot see
// from the file. An entry claiming to be both mirrored and generated has two
// different right answers for signature_type and the wrong one fails
// `pkg update` with an error naming the signature, which sends the reader to
// the key rather than to the manifest. A generated entry served in proxy mode
// is a repository the server answers 500 for on every path, so the stanza
// describes something that never replies. An entry claiming to be neither has
// no answer at all: nothing here knows who signed a catalogue bodega did not
// copy and did not build. A release nothing resolves means the override would
// disable a tag the host does not define, which fails nothing at all: the
// upstream repository stays enabled beside bodega's and nothing reports it.
//
// Generated and Upstream are independent, so they are four cases and not two,
// and the fourth is the one that reads worst. manifest.VersionEntry
// carries neither field as required, so an entry with no url and no generated
// flag loads, imports and routes; every switch below that keys off Generated
// alone would hand it the mirrored answer, which tells its reader FreeBSD
// signed bytes nobody mirrored and points fingerprints at a store that
// verifies whatever was uploaded only by luck. Refused here, Generated is a
// sound selector for the three arms below it, and each of them may say
// "upstream" and mean something.
//
// What this refuses is deliberately wider than what the server refuses to
// route, and the direction matters. A contradiction the server will not route
// and this renderer emits for is published as installable configuration with
// an empty refusal list beside it, and neither artifact says the repository
// answers 500: that set has to stay equal, and
// manifest.VersionEntry.FreeBSDGenerated is the other half of it. The reverse
// is not symmetrical, because the two answer different questions. The route
// asks whether it can serve these bytes and needs no url to do it: it reads
// the store and hands back what a mirror left there (internal/server/
// freebsd.go:110,155). This asks which trust store verifies them, and the url
// is the only authority for that. So an entry with neither field serves
// whatever was uploaded and gets a row in freebsd.refused[] rather than a
// stanza, which is the honest pair. Refusing it at the route as well would
// answer 500 for a repository that answers 200 today.
func Render(st State) (Repo, error) {
	if st.Generated && strings.TrimSpace(st.Upstream) != "" {
		return Repo{}, fmt.Errorf("freebsd %s@%s is marked generated and also records url %q, and the two want opposite client configuration: a mirrored repository verifies against %s and a generated one against bodega's own fingerprint. Drop the url to generate, or drop generated to mirror",
			st.Repo, st.ABI, st.Upstream, StockFingerprints)
	}
	if st.Generated && st.Proxy {
		return Repo{}, fmt.Errorf("freebsd %s@%s is marked generated and also served in proxy mode, and proxy keeps no snapshot for a generated catalogue to name: the server answers 500 on every path under it, so this stanza would configure a host for a repository that never replies. Drop the proxy mode to generate the catalogue here, or drop generated to proxy an upstream one",
			st.Repo, st.ABI)
	}
	if !st.Generated && strings.TrimSpace(st.Upstream) == "" {
		return Repo{}, fmt.Errorf("freebsd %s@%s records neither a url nor generated, so nothing here knows who signed its catalogue and a stanza would have to guess a trust store: a mirrored repository verifies against %s, a generated one against bodega's own fingerprint, and pkg reports the wrong guess as an empty repository rather than as a signature it could not check. Set url to the repository root this was mirrored from, or generated to build and sign the catalogue here from uploaded packages. To stop re-fetching a mirror while keeping the answer, set frozen rather than clearing the url",
			st.Repo, st.ABI, StockFingerprints)
	}

	release := st.Release
	if release <= 0 {
		var ok bool
		if release, ok = ReleaseFromABI(st.ABI); !ok {
			return Repo{}, fmt.Errorf("cannot tell which FreeBSD release %q names, so the override would disable a repository tag the host does not define and leave the upstream one enabled beside bodega's with nothing reporting it. Pass the target release, or name the ABI as FreeBSD:<release>:<arch>",
				st.ABI)
		}
	}

	repo := st.Repo
	if repo == "" {
		return Repo{}, fmt.Errorf("no repository name, so there is nothing to point a url at: a freebsd entry's name is the repository directory a client asks under, such as \"latest\"")
	}

	repoRelease := release
	if n, ok := ReleaseFromABI(st.ABI); ok {
		repoRelease = n
	}

	base := st.BaseURL()
	out := Repo{
		Tag:       TagPrefix + repo,
		ABI:       st.ABI,
		Repo:      repo,
		Release:   release,
		Generated: st.Generated,
		Proxy:     st.Proxy,
		// The repository's own release decides this, not the target host's:
		// the key that signed a catalogue is a property of the catalogue.
		// Release moves the overrides onto a host of another release and
		// cannot move a signature.
		Pkgbase:     !st.Generated && IsPkgbaseSigned(st.Upstream, repoRelease),
		BaseRelease: !st.Generated && IsBaseRelease(st.Upstream),
		// Two facts, not one. Whether a path outside the catalogue reaches
		// upstream at all is the first, and which upstream repository it
		// reaches decides whether there is anything there to fetch.
		UpstreamFallthrough: st.ReachesUpstream(),
		Bootstrap:           bootstrapAnswer(st),
		// ${ABI} stays literal. pkg substitutes the running host's own ABI,
		// which is what makes one file correct across a fleet of mixed
		// architectures, and it is the spelling every /etc/pkg/FreeBSD.conf
		// uses. The release above comes from the entry because that is what
		// the mirror was built for; the URL comes from the client because
		// that is what it is asking for.
		URL:      base + "/freebsd/${ABI}/" + repo,
		Disabled: UpstreamTags(release),
	}

	switch {
	case out.Pkgbase:
		out.SignatureType, out.Fingerprints = "fingerprints", PkgbaseFingerprints
	case !st.Generated:
		out.SignatureType, out.Fingerprints = "fingerprints", StockFingerprints
	case st.Fingerprint != "":
		out.SignatureType, out.Fingerprints = "fingerprints", BodegaFingerprints
	default:
		out.SignatureType = "none"
	}
	return finish(out), nil
}

// WithRelease re-renders this configuration for a different target release,
// which is what `bodega doctor --write-pkg-repo --release` asks for on a host
// that is not the one the repository is named for.
//
// It changes the override list and the release the comments name, and nothing
// else. Composing a fresh State from a rendered Repo is what the caller did
// before, and every fact the wire shape does not carry was silently lost in
// the trip: the upstream URL is one of them, so a mirror of a base repository
// came back out of that round trip pointed at the ports trust store. The
// trust half is the server's answer and is carried through verbatim here.
func (r Repo) WithRelease(release int) (Repo, error) {
	if release <= 0 {
		return Repo{}, fmt.Errorf("cannot render pkg configuration for FreeBSD release %d: the overrides have to name the tags that release defines, and a release that is not a positive major number names none", release)
	}
	r.Release, r.Disabled = release, UpstreamTags(release)
	return finish(r), nil
}

// finish fills in everything derived from the facts above it, so that Render
// and WithRelease cannot disagree about what a set of facts renders as.
func finish(r Repo) Repo {
	r.Notes = r.notes()
	r.Stanza = renderStanza(r)
	r.Conf = renderConf(r)
	return r
}

// notes lists the consequences of the form this repository rendered in.
func (r Repo) notes() []string {
	var out []string
	switch {
	case r.Pkgbase:
		out = append(out, PkgbaseMirroredNote, reachNote(r), bootstrapNote(r))
	case !r.Generated:
		out = append(out, MirroredNote, reachNote(r), bootstrapNote(r))
	case r.SignatureType != "none":
		out = append(out, FingerprintNote, reachNote(r), bootstrapNote(r))
	default:
		out = append(out, UnsignedNote, reachNote(r), bootstrapNote(r))
	}
	// The placeholder cannot occur in a URL anything reported: it carries
	// angle brackets, which no host may.
	if strings.Contains(r.URL, PlaceholderHost) {
		out = append(out, UnknownURLNote)
	}
	return out
}

// bootstrapAnswer decides what `pkg bootstrap` does here, from the facts that
// decide it rather than from the one that correlates with them.
//
// A repository no request falls out of publishes only the repopaths its
// catalogue names, so the pair is absent whatever upstream holds. One a
// request does fall out of answers with whatever upstream answers, which is
// the second fact and comes off the upstream name. A generated repository
// serves what the build tree uploaded, and poudriere publishes
// Latest/pkg.pkg as a symlink the upload skips
// (internal/builder/freebsd.go:632-644): usually absent, present if somebody
// put a real file there, and bodega cannot tell from here.
//
// The middle case is the predicate rather than the mode. Reading st.Proxy
// there called a hosted mirror with the proxy cache on absent while the route
// served both paths off pkg.FreeBSD.org, and reading it the other way told
// every proxied base mirror that bootstrap works.
func bootstrapAnswer(st State) BootstrapAnswer {
	switch {
	case st.Generated:
		return BootstrapUnknown
	case !st.ReachesUpstream():
		return BootstrapAbsent
	default:
		return UpstreamBootstrap(st.Upstream)
	}
}

// reachNote says how much of this repository leaves the host, from the two
// facts that decide it: whether anything falls through to upstream, and
// whether the catalogue is one of the paths that does.
//
// Neither fact alone answers it, which is how one text came to be printed for
// all three cases. A repository that falls through is not thereby proxied: a
// hosted mirror on a cache-enabled server serves its own catalogue and fetches
// everything else. A proxied one is not thereby reachable: with no url on the
// entry there is nothing to compose.
func reachNote(r Repo) string {
	switch {
	case !r.UpstreamFallthrough:
		return IsolatedNote
	case r.HoldsCatalogue():
		return MirrorReachNote
	default:
		return ProxyReachNote
	}
}

// bootstrapNote picks the true one. Five texts for three answers, because two
// of the answers have two reasons a reader acts on differently. Absent is
// bodega publishing no such path where nothing falls out of the repository,
// and upstream refusing it where something does. Unknown is an upstream
// repository nobody measured, and, where there is no upstream at all, a
// generated repository whose build tree decides. A note that is right half the
// time is worse than none: it reads as measured.
//
// The absent split reads UpstreamFallthrough rather than Proxy, which is the
// same term bootstrapAnswer decided on. Keyed off the mode, a hosted mirror of
// a base repository on a cache-enabled server got the text blaming bodega's
// catalogue while the request 502'd out of upstream.
func bootstrapNote(r Repo) string {
	switch r.Bootstrap {
	case BootstrapWorks:
		return BootstrapResolvesNote
	case BootstrapAbsent:
		if r.UpstreamFallthrough {
			return NoBootstrapUpstreamNote
		}
		return NoBootstrapNote
	default:
		if r.Generated {
			return GeneratedBootstrapNote
		}
		return BootstrapUnknownNote
	}
}

// renderStanza writes the repository definition. UCL accepts the trailing
// comma pkg's own files carry, and matching them is what makes a diff against
// /etc/pkg/FreeBSD.conf readable.
func renderStanza(r Repo) string {
	lines := []string{
		r.Tag + ": {",
		`  url: "` + r.URL + `",`,
		`  mirror_type: "none",`,
		`  signature_type: "` + r.SignatureType + `",`,
	}
	if r.Fingerprints != "" {
		lines = append(lines, `  fingerprints: "`+r.Fingerprints+`",`)
	}
	return strings.Join(append(lines, "  enabled: yes", "}"), "\n")
}

// writeReachComment writes the paragraph answering how much of this
// repository leaves the host, from the same two predicates reachNote reads.
//
// Both branches of renderConf call it, because the answer is not the mirror's
// alone and the generated branch used to print nothing at all. Render refuses
// a generated entry with a url and one served by proxy, so
// UpstreamFallthrough is false there by construction and the first arm is the
// one that fires. That makes a generated repository the one class this file
// can call isolated without qualifying it, and the class that was never told.
// Driving it off the predicate rather than writing that sentence into the arm
// is what keeps it true if either refusal is ever lifted.
func writeReachComment(b *strings.Builder, r Repo) {
	switch {
	case !r.UpstreamFallthrough:
		b.WriteString("# This repository publishes the paths its catalogue names and this server\n")
		b.WriteString("# fetches nothing under it from upstream: every request stops here, and a\n")
		b.WriteString("# package it does not hold is a 404 rather than a fetch from the internet.\n")
	case r.HoldsCatalogue():
		b.WriteString("# This catalogue is served from what was published here, and a miss on\n")
		b.WriteString("# meta.conf, packagesite.pkg or data.pkg is refused rather than fetched:\n")
		b.WriteString("# upstream's catalogue names packages this mirror has never held. Every\n")
		b.WriteString("# other path reaches the internet on a miss, because this server's proxy\n")
		b.WriteString("# cache is on: a package the mirror does not hold is fetched from upstream,\n")
		b.WriteString("# cached, and served under this repository's name, so an install can succeed\n")
		b.WriteString("# here against a package nobody mirrored.\n")
	default:
		b.WriteString("# Every request this repository answers may reach the internet, the\n")
		b.WriteString("# catalogue included. It is served in proxy mode: this server composes an\n")
		b.WriteString("# upstream URL for each path and fetches it whenever it holds no fresh\n")
		b.WriteString("# copy, so `pkg update` against this file contacts upstream. What is\n")
		b.WriteString("# stored here is whatever earlier requests cached, not a copy of the\n")
		b.WriteString("# repository.\n")
	}
}

// renderConf wraps the stanza in the overrides that disable upstream and the
// comments an operator reading the installed file needs.
//
// The comments are in the emitted file rather than in the docs because this
// file is what somebody opens at 03:00, six months after whoever installed it
// left. Each one answers a question the file provokes on its own: why the
// scheme is not the pkg+https next door, why there are disable blocks for
// repositories this file does not otherwise mention, which of the trust
// stores on the host this is and why, how much of this repository leaves the
// host, and why "pkg bootstrap" against this URL returns nothing.
func renderConf(r Repo) string {
	var b strings.Builder
	b.WriteString("# bodega pkg repository. Install as " + ClientConfPath + ".\n")
	b.WriteString("#\n")
	b.WriteString("# url carries a plain scheme with mirror_type: none, never the pkg+https\n")
	b.WriteString("# next door in /etc/pkg/FreeBSD.conf: pkg+ means SRV mirror discovery, where\n")
	b.WriteString("# the client resolves _https._tcp for the host and expects a record set, and\n")
	b.WriteString("# bodega is one host that publishes none.\n")
	b.WriteString("#\n")
	b.WriteString("# ${ABI} is literal. pkg substitutes the running host's own ABI, so this file\n")
	b.WriteString("# is correct on every architecture bodega mirrors. It was written for a\n")
	b.WriteString("# FreeBSD " + strconv.Itoa(r.Release) + " host, which is what the overrides below are named for.\n")
	b.WriteString("#\n")
	b.WriteString("# pkg merges repository definitions by tag across /etc/pkg/ and\n")
	b.WriteString("# " + ClientReposDir + "/, so the overrides have to name the tags this\n")
	b.WriteString("# release actually defines. One that names the wrong tag leaves the upstream\n")
	b.WriteString("# repository enabled beside this one, and nothing in `pkg update` output says\n")
	b.WriteString("# so: the host keeps fetching from the internet. Confirm with `pkg -vv`.\n")
	if r.Generated {
		b.WriteString("#\n")
		b.WriteString("# This catalogue is built here from the packages uploaded to this\n")
		b.WriteString("# repository rather than copied from upstream, so no signature of\n")
		b.WriteString("# FreeBSD's reaches a client under it and the stock trust store every\n")
		b.WriteString("# FreeBSD host ships verifies nothing in this path.\n")
		if r.SignatureType == "none" {
			b.WriteString("# This server holds no pkg signing key, so the catalogue carries no\n")
			b.WriteString("# signature at all and TLS is the only thing authenticating these\n")
			b.WriteString("# packages. `bodega freebsd key generate` on the server fixes that.\n")
		} else {
			b.WriteString("# bodega signs it with its own key, which is why fingerprints names\n")
			b.WriteString("# bodega's trust directory. Install the fingerprint out of band before\n")
			b.WriteString("# this file takes effect:\n")
			b.WriteString("#   bodega freebsd key export --fingerprint > " + BodegaFingerprints + "/trusted/bodega\n")
		}
		b.WriteString("#\n")
		writeReachComment(&b, r)
		b.WriteString("#\n")
		b.WriteString("# `pkg bootstrap` reaches this repository only if the build tree published\n")
		b.WriteString("# Latest/pkg.pkg under it as a real file. poudriere publishes that as a\n")
		b.WriteString("# symlink, which the upload skips to keep one package out of the catalogue\n")
		b.WriteString("# twice, so on an ordinary poudriere tree it is absent.\n")
	} else {
		b.WriteString("#\n")
		switch {
		case r.Pkgbase:
			b.WriteString("# fingerprints names the pkgbase trust store, not the ports one beside it\n")
			b.WriteString("# on the same host. Two things put it there: upstream calls this repository\n")
			b.WriteString("# base_release_<n>, which release engineering signs rather than the package\n")
			b.WriteString("# builders, and it is built for FreeBSD " + strconv.Itoa(ReleaseSplit) + " or later, whose base system\n")
			b.WriteString("# installs that second key set. It is not in " + StockFingerprints + ":\n")
			b.WriteString("# /etc/pkg/FreeBSD.conf gives FreeBSD-ports the ports store and FreeBSD-base\n")
			b.WriteString("# this one. Pointed at the wrong one, `pkg update` prints \"No trusted\n")
			b.WriteString("# public keys found\", exits 0 and processes no entries, and `pkg install`\n")
			b.WriteString("# then reports every package as missing rather than as unverifiable.\n")
			b.WriteString("# Confirm with `pkg -vv`, which prints the path after ${VERSION_MAJOR}\n")
			b.WriteString("# resolves.\n")
		case r.BaseRelease:
			b.WriteString("# fingerprints names the trust store every FreeBSD host already ships, and\n")
			b.WriteString("# this repository's name is not a reason to move it. Upstream calls it\n")
			b.WriteString("# base_release_<n>, which release engineering signs against the pkgbase\n")
			b.WriteString("# store on FreeBSD " + strconv.Itoa(ReleaseSplit) + " and later; this one is built for an older release,\n")
			b.WriteString("# whose base system installs no pkgbase directory to verify against, so its\n")
			b.WriteString("# catalogue comes off the package builders' key like ports. Measured with\n")
			b.WriteString("# pkg 2.7.5: FreeBSD:14:amd64/base_release_1 verifies under\n")
			b.WriteString("# " + StockFingerprints + " and not under /usr/share/keys/pkgbase-15. bodega\n")
			b.WriteString("# copies these bytes from upstream without transforming them, so FreeBSD's\n")
			b.WriteString("# own signature arrives inside the catalogue archive and no key of bodega's\n")
			b.WriteString("# is in this path.\n")
		default:
			b.WriteString("# fingerprints names the trust store every FreeBSD host already ships.\n")
			b.WriteString("# bodega copies these bytes from upstream without transforming them, so\n")
			b.WriteString("# FreeBSD's own signature arrives inside the catalogue archive and no key\n")
			b.WriteString("# of bodega's is in this path. The exception is a base_release_<n>\n")
			b.WriteString("# repository built for FreeBSD " + strconv.Itoa(ReleaseSplit) + " or later, which release engineering\n")
			b.WriteString("# signs against the pkgbase store; upstream calls this one something else.\n")
		}
		b.WriteString("#\n")
		writeReachComment(&b, r)
		b.WriteString("#\n")
		switch {
		case r.Bootstrap == BootstrapWorks:
			b.WriteString("# `pkg bootstrap` works here: this server fetches a path outside this\n")
			b.WriteString("# catalogue from the upstream the repository records, and upstream publishes\n")
			b.WriteString("# Latest/pkg.pkg and its .sig under it.\n")
		case r.Bootstrap == BootstrapAbsent && r.UpstreamFallthrough:
			b.WriteString("# `pkg bootstrap` does not work against this repository. It fetches\n")
			b.WriteString("# Latest/pkg.pkg and Latest/pkg.pkg.sig; this server fetches a path outside\n")
			b.WriteString("# the catalogue from the upstream the repository records, and upstream\n")
			b.WriteString("# publishes that pair under neither a base nor a kmods repository. A 404\n")
			b.WriteString("# passes through; where upstream answers 403 the client gets a 502 and the\n")
			b.WriteString("# refusing URL is in bodega's log, not in the error. Bootstrap the host from\n")
			b.WriteString("# a ports repository, then switch it over.\n")
		case r.Bootstrap == BootstrapAbsent:
			b.WriteString("# `pkg bootstrap` does not work against this repository. It fetches\n")
			b.WriteString("# Latest/pkg.pkg and Latest/pkg.pkg.sig and nothing else, a catalogue\n")
			b.WriteString("# never names that pair, and nothing here falls through to upstream to get\n")
			b.WriteString("# from. Install pkg from upstream before switching a host over.\n")
		default:
			b.WriteString("# `pkg bootstrap` may not work against this repository. It fetches\n")
			b.WriteString("# Latest/pkg.pkg and Latest/pkg.pkg.sig, upstream publishes that pair under\n")
			b.WriteString("# some repositories and not others, and nobody measured this one. Try it\n")
			b.WriteString("# rather than planning on it: a 404 or a 502 means bootstrapping the host\n")
			b.WriteString("# from a ports repository first.\n")
		}
	}
	b.WriteString("\n")
	for _, tag := range r.Disabled {
		b.WriteString(tag + ": { enabled: no }\n")
	}
	b.WriteString("\n")
	b.WriteString(r.Stanza)
	b.WriteString("\n")
	return b.String()
}
