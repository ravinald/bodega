// Package aptsources renders the apt client configuration for a bodega
// instance: the deb822 stanza, its one-line equivalent, and the consequence of
// whichever form it chose.
//
// One renderer, because three of them produced three different wrong answers.
// The TUI derived the scheme from the local TLS pair and so printed http:// for
// a server behind a TLS-terminating proxy. The web page printed a literal
// "noble" at an instance serving jammy. Both printed [trusted=yes] at an
// instance that signs its index, which tells an operator to turn verification
// off permanently for that source.
//
// Each was guessing at something only the running server knows. State carries
// those facts, and nothing in the tree composes a sources line without one.
package aptsources

import (
	"fmt"
	"strings"
)

const (
	// ClientKeyringPath is where a client installs the dearmored keyring, and
	// therefore what Signed-By: names. It is a path on the client, not on the
	// server; KeyringRoute is where the bytes come from.
	ClientKeyringPath = "/etc/apt/keyrings/bodega-archive-keyring.gpg"

	// KeyringRoute serves the dearmored keyring that Signed-By: takes
	// directly, so a client needs no gpg binary to install it.
	KeyringRoute = "/apt/bodega-archive-keyring.gpg"

	// Component is the only component bodega generates, and the one a
	// mirrored stanza names by default. A mirrored suite serves whatever
	// components its upstream publishes — bodega proxies the path and parses
	// no index — so "restricted universe multiverse" can be appended to the
	// Components: line and will resolve.
	Component = "main"

	// PlaceholderHost stands in when nothing reported a public URL. A
	// placeholder the operator must replace beats a hostname the server
	// guessed at: behind a proxy the guess is wrong and reads as
	// authoritative, which is how http:// reached a TLS deployment.
	PlaceholderHost = "<bodega-host>:8080"

	// PlaceholderSuite stands in when no suite is served at all, which means
	// apt_codename resolved to nothing.
	PlaceholderSuite = "<suite>"

	// UnsignedNote is the consequence of the form Render emits with no key
	// loaded. It travels beside the line rather than in place of it: an
	// operator pasting [trusted=yes] into an Ansible template needs to read
	// this before the paste, not after the incident.
	UnsignedNote = `[trusted=yes] turns off signature verification for this source, permanently and silently, and it propagates into Ansible templates and cloud-init files that outlive whatever made it necessary. TLS is then the only thing authenticating the packages. Run "bodega apt key generate" to sign.`

	// SignedNote names what the first keyring fetch is authenticated by,
	// which is TLS alone. Comparing the fingerprint out of band is the only
	// thing that closes that hop.
	SignedNote = `Install the keyring from ` + KeyringRoute + ` first. That fetch is authenticated by TLS alone, so compare its fingerprint against "bodega apt key show".`

	// MirroredNote names what verifies a mirrored suite. bodega proxies the
	// upstream dists/ tree unchanged, so the archive's own InRelease reaches
	// the client with its signature intact and apt checks it against the
	// distro keyring already installed on the host. Neither Signed-By: nor
	// Trusted: belongs on the line: bodega's key does not sign these bytes,
	// and turning verification off would discard a signature that is right
	// there and valid.
	MirroredNote = `This suite is mirrored from upstream, signature included, so apt verifies it against the distro keyring already on the host. Do not add [trusted=yes] or Signed-By: here — bodega does not sign a mirrored suite, and either one would replace a working check with a worse one.`

	// TrustStoreNote fires on an https URI, which is every deployment that
	// terminates TLS anywhere. It is a fact about the client rather than the
	// server, and it belongs beside the stanza anyway: the operator pasting
	// this line is the one who decides what the client's sources are, and the
	// failure it prevents names the wrong subject. A minimal image ships no CA
	// bundle, apt cannot complete the handshake, apt-get update exits 0 having
	// ignored the index, and the install fails one command later at "Unable to
	// locate package" — the same terminal line an architecture mismatch
	// produces. The bundle comes from the image's own sources, so it is a step
	// before this stanza and cannot be one after it.
	TrustStoreNote = `Install ca-certificates on the client, from the sources it already has, before this line becomes its only one. A minimal image ships no CA bundle, so apt cannot complete the https handshake: "apt-get update" exits 0 having ignored the index and the install fails later as "Unable to locate package".`

	// UnknownURLNote fires whenever nothing reported a public URL, so the
	// host above is a placeholder rather than an address. Behind a reverse
	// proxy the server sees a loopback listener with no TLS and no hostname:
	// it cannot name the URL clients use, and the scheme it prints describes
	// its own back end.
	UnknownURLNote = `public_url is unset, so the host above is a placeholder and the scheme describes this server's own listener, not what a proxy publishes. Set public_url to the external base URL.`
)

// State is what the running server reports about how apt clients reach it.
// Every field is a fact the server holds and no emitter can derive on its own.
type State struct {
	// PublicURL is the base URL clients use, from the public_url chain or
	// from the request that asked. Empty renders PlaceholderHost.
	PublicURL string

	// LocalScheme is the scheme this server's own listener answers on. It
	// decides the placeholder's scheme when PublicURL is empty, and it is
	// wrong the moment a proxy terminates TLS in front — which is the case
	// public_url exists for. Empty means https.
	LocalScheme string

	// Suites go on the Suites: line in order. The one-line form carries only
	// one and takes the first.
	Suites []string

	// Signed reports that an index signature exists for a client to verify.
	Signed bool

	// Fingerprints are the loaded signing keys, uppercase hex, in load order.
	Fingerprints []string

	// Mirrored marks these suites as proxied from an upstream archive rather
	// than generated by bodega, which changes what authenticates them and
	// therefore the whole trust half of the stanza. Signed is not consulted
	// when it is set: bodega's key signs what bodega generates and nothing
	// else, so a signing instance still forwards upstream's signature here.
	Mirrored bool
}

// Sources is one rendered client configuration. The JSON tags are the wire
// shape of /api/v1/status: a second struct to carry the same five strings is
// how the copies started.
type Sources struct {
	Signed   bool     `json:"signed"`
	Mirrored bool     `json:"mirrored,omitempty"`
	Suite    string   `json:"suite"`
	URI      string   `json:"uri"`
	Deb822   string   `json:"deb822"`
	OneLine  string   `json:"one_line"`
	Notes    []string `json:"notes,omitempty"`
}

// Note joins the consequences of this form into one paragraph, for a consumer
// with a single line to spend on them.
func (s Sources) Note() string { return strings.Join(s.Notes, " ") }

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

// Render produces the sources block for one State.
//
// deb822 is the primary form: Signed-By: there is a path rather than a bracket
// option, and one stanza carries several suites. The one-line equivalent is
// rendered alongside for the panes that have room for a single line.
func Render(st State) Sources {
	uri := st.BaseURL() + "/apt/"

	suites := make([]string, 0, len(st.Suites))
	for _, s := range st.Suites {
		if s != "" {
			suites = append(suites, s)
		}
	}
	if len(suites) == 0 {
		suites = []string{PlaceholderSuite}
	}

	stanza := []string{
		"Types: deb",
		"URIs: " + uri,
		"Suites: " + strings.Join(suites, " "),
		"Components: " + Component,
	}

	out := Sources{Signed: st.Signed, Suite: suites[0], URI: uri, Mirrored: st.Mirrored}
	switch {
	case st.Mirrored:
		// No trust option at all. apt falls back to its configured trusted
		// keyrings, which is where the distro archive key already lives.
		out.Signed = true
		out.OneLine = fmt.Sprintf("deb %s %s %s", uri, suites[0], Component)
		out.Notes = append(out.Notes, MirroredNote)
	case st.Signed:
		stanza = append(stanza, "Signed-By: "+ClientKeyringPath)
		out.OneLine = fmt.Sprintf("deb [signed-by=%s] %s %s %s", ClientKeyringPath, uri, suites[0], Component)
		out.Notes = append(out.Notes, SignedNote)
	default:
		stanza = append(stanza, "Trusted: yes")
		out.OneLine = fmt.Sprintf("deb [trusted=yes] %s %s %s", uri, suites[0], Component)
		out.Notes = append(out.Notes, UnsignedNote)
	}
	if strings.TrimRight(st.PublicURL, "/") == "" {
		out.Notes = append(out.Notes, UnknownURLNote)
	}
	if strings.HasPrefix(uri, "https://") {
		out.Notes = append(out.Notes, TrustStoreNote)
	}
	out.Deb822 = strings.Join(stanza, "\n")
	return out
}
