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
	MirroredNote = `This repository is mirrored from upstream with its signature inside the catalogue archive, so pkg verifies it against ` + StockFingerprints + `, which every FreeBSD host already ships. Do not point fingerprints at a bodega key here: bodega signs nothing in this path, and the stanza would fail "pkg update" on a signature that is present and valid.`

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

	// NoBootstrapNote is what a hosted mirror costs. pkg's own bootstrapper
	// (usr.sbin/pkg/pkg.c) fetches <repo>/Latest/pkg.pkg and its .sig and
	// nothing else, and a hosted mirror publishes only the repopaths its
	// catalogue names, which never include that pair. A host with no pkg
	// installed cannot reach one through bodega.
	NoBootstrapNote = `"pkg bootstrap" does not work against this repository: it fetches Latest/pkg.pkg and Latest/pkg.pkg.sig, and a mirror publishes only the paths its catalogue names. Install pkg on the host from upstream first, then switch it over.`

	// BootstrapProxyNote is the other half of the same fact. A proxied
	// repository composes an upstream URL for any path outside the
	// catalogue, so both bootstrap paths resolve — at the cost of reaching
	// pkg.FreeBSD.org for them, which a host the operator believes is
	// isolated is not doing on any other path.
	BootstrapProxyNote = `"pkg bootstrap" works against this repository because it is proxied: bodega fetches Latest/pkg.pkg and Latest/pkg.pkg.sig from upstream on demand. That one path reaches the internet, unlike every other request this repository answers.`
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
	// from a finished mirror. It changes one thing a reader acts on: the
	// bootstrap paths resolve on a proxy and 404 on a hosted mirror, and
	// getting that backwards sends an operator to rebuild a repository that
	// was never going to answer. It also contradicts Generated, which is the
	// second pair Render refuses.
	Proxy bool
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
	Proxy     bool   `json:"proxy,omitempty"`
	URL       string `json:"url"`

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

// Render produces the client configuration for one repository, or refuses.
//
// It refuses rather than picking a default in the cases where a stanza would
// install cleanly and fail later against something the operator cannot see
// from the file. An entry claiming to be both mirrored and generated has two
// different right answers for signature_type and the wrong one fails
// `pkg update` with an error naming the signature, which sends the reader to
// the key rather than to the manifest. A generated entry served in proxy mode
// is a repository the server answers 500 for on every path, so the stanza
// describes something that never replies. A release nothing resolves means
// the override would disable a tag the host does not define, which fails
// nothing at all: the upstream repository stays enabled beside bodega's and
// nothing reports it.
//
// The contradictions are refused here as well as at
// manifest.VersionEntry.FreeBSDGenerated, which refuses them for the server's
// own routing, and the two sets have to stay equal: a contradiction the server
// refuses to route and this renderer emits for is published as installable
// configuration with an empty refusal list beside it, and neither artifact
// says the repository answers 500. Two refusals rather than one call because
// the artifacts outlive their producers differently: the server's decides a
// request, and this one is pasted onto a host and read again in a year.
func Render(st State) (Repo, error) {
	if st.Generated && strings.TrimSpace(st.Upstream) != "" {
		return Repo{}, fmt.Errorf("freebsd %s@%s is marked generated and also records url %q, and the two want opposite client configuration: a mirrored repository verifies against %s and a generated one against bodega's own fingerprint. Drop the url to generate, or drop generated to mirror",
			st.Repo, st.ABI, st.Upstream, StockFingerprints)
	}
	if st.Generated && st.Proxy {
		return Repo{}, fmt.Errorf("freebsd %s@%s is marked generated and also served in proxy mode, and proxy keeps no snapshot for a generated catalogue to name: the server answers 500 on every path under it, so this stanza would configure a host for a repository that never replies. Drop the proxy mode to generate the catalogue here, or drop generated to proxy an upstream one",
			st.Repo, st.ABI)
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

	base := st.BaseURL()
	out := Repo{
		Tag:       TagPrefix + repo,
		ABI:       st.ABI,
		Repo:      repo,
		Release:   release,
		Generated: st.Generated,
		Proxy:     st.Proxy,
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
	case !st.Generated:
		out.SignatureType, out.Fingerprints = "fingerprints", StockFingerprints
		out.Notes = append(out.Notes, MirroredNote, bootstrapNote(st.Proxy))
	case st.Fingerprint != "":
		out.SignatureType, out.Fingerprints = "fingerprints", BodegaFingerprints
		out.Notes = append(out.Notes, FingerprintNote)
	default:
		out.SignatureType = "none"
		out.Notes = append(out.Notes, UnsignedNote)
	}
	if strings.TrimRight(st.PublicURL, "/") == "" {
		out.Notes = append(out.Notes, UnknownURLNote)
	}

	out.Stanza = renderStanza(out)
	out.Conf = renderConf(out)
	return out, nil
}

// bootstrapNote picks the true one. Both are shipped because the answer is
// not a property of pkg or of bodega but of how this repository is served,
// and a note that is right half the time is worse than none: it reads as
// measured.
func bootstrapNote(proxy bool) string {
	if proxy {
		return BootstrapProxyNote
	}
	return NoBootstrapNote
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

// renderConf wraps the stanza in the overrides that disable upstream and the
// comments an operator reading the installed file needs.
//
// The comments are in the emitted file rather than in the docs because this
// file is what somebody opens at 03:00, six months after whoever installed it
// left. Each one answers a question the file provokes on its own: why the
// scheme is not the pkg+https next door, why there are disable blocks for
// repositories this file does not otherwise mention, and why "pkg bootstrap"
// against this URL returns nothing.
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
		b.WriteString("# This repository is generated and signed by bodega rather than mirrored, so\n")
		if r.SignatureType == "none" {
			b.WriteString("# it carries no signature at all and TLS is the only thing authenticating\n")
			b.WriteString("# these packages. `bodega freebsd key generate` on the server fixes that.\n")
		} else {
			b.WriteString("# fingerprints points at bodega's own trust directory rather than the stock\n")
			b.WriteString("# one. Install the fingerprint out of band before this file takes effect:\n")
			b.WriteString("#   bodega freebsd key export --fingerprint > " + BodegaFingerprints + "/trusted/bodega\n")
		}
		b.WriteString("#\n")
		b.WriteString("# `pkg bootstrap` reaches this repository only if the build tree published\n")
		b.WriteString("# Latest/pkg.pkg under it as a real file. poudriere publishes that as a\n")
		b.WriteString("# symlink, which the upload skips to keep one package out of the catalogue\n")
		b.WriteString("# twice, so on an ordinary poudriere tree it is absent.\n")
	} else if r.Proxy {
		b.WriteString("#\n")
		b.WriteString("# `pkg bootstrap` works here: this repository is proxied, so bodega fetches\n")
		b.WriteString("# Latest/pkg.pkg and its .sig from upstream on demand. That one path reaches\n")
		b.WriteString("# the internet, unlike every other request this repository answers.\n")
	} else {
		b.WriteString("#\n")
		b.WriteString("# `pkg bootstrap` does not work against this repository. It fetches\n")
		b.WriteString("# Latest/pkg.pkg and Latest/pkg.pkg.sig and nothing else, and a mirror\n")
		b.WriteString("# publishes only the paths its catalogue names. Install pkg from upstream\n")
		b.WriteString("# before switching a host over.\n")
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
