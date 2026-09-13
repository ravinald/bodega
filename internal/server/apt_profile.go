package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- apt under a profile ---------------------------------------------------
//
// For the seven other types the request predicate is the control and the index
// filter is what makes a refusal legible. apt inverts that, and the inversion
// is the whole reason this file exists.
//
// apt clients decide what to request by reading a Packages index. A client
// refused at the pool has already resolved a transaction, so the 403 arrives
// mid-run: apt aborts the whole thing, and every security update in the same
// invocation is abandoned with it. The same package absent from the index
// instead produces "The following packages have been kept back", and the rest
// of the upgrade proceeds. Same policy, same verdict, opposite outcome, and
// the second one fails quietly in a cron log — so for apt the index filter is
// the enforcement and aptPoolGate is the backstop for a client that composed a
// URL without reading an index.
//
// Filtering Packages forces a matching Release, and Release is signed. Signing
// per profile on render would put a key operation on the hottest cached path
// and make InRelease uncacheable across hosts, so a profile that scopes apt is
// served under a codename of its own, generated and signed once per rebuild
// like any other generated suite.
//
// The boundary then lives in the client's sources.list, which the host can
// edit. It scopes what a correctly configured host is told exists; it
// authorizes nothing on its own. docs/THREAT_MODEL.md states that limit and
// the one below it: bodega re-signs an upstream index it fetched over TLS and
// did not verify against the distro keyring, so a filtered codename's chain of
// trust ends at the archive's certificate rather than at its signing key.

const (
	// aptProfileComponent is the only component a filtered codename carries.
	// Every generated suite serves main alone — handleAptPackages 404s the
	// rest — and a filtered view is a generated suite. A base whose packages
	// live in universe is named in the log rather than silently half-served.
	aptProfileComponent = "main"

	// aptProfileFetchTimeout bounds one upstream index fetch. A rebuild walks
	// (profile x architecture) and runs on a timer nothing waits on, so a slow
	// archive must cost a bounded amount rather than hold the rebuild until
	// aptRebuildTimeout fires and takes every suite's regeneration with it.
	aptProfileFetchTimeout = 2 * time.Minute
)

// aptProfileSuite is one profile's filtered codename: which upstream suite it
// derives from, what it is served as, and the predicate that decides its
// contents.
type aptProfileSuite struct {
	profile  string
	base     string
	codename string
	permit   *entitle.Profile
	index    *aptSuiteIndex
}

// aptProfileSuites resolves every profile that scopes apt into a suite this
// server can generate, dropping the ones it cannot with the reason.
//
// Read from the profile tables directly rather than from the binding set,
// because a codename exists whether or not a host is bound to it yet: an
// operator writes the profile, reads the sources line off `bodega doctor`, and
// binds the host afterwards. Requiring the binding first would mean the
// codename 404s during exactly the step that installs it.
func (s *Server) aptProfileSuites(ctx context.Context) (suites []aptProfileSuite, scoped bool) {
	if s.auditDB == nil {
		return nil, false
	}
	profiles, err := s.auditDB.ListProfiles(ctx)
	if err != nil {
		s.logger.Error("could not read the profiles, so no filtered apt codename was generated at this rebuild", "error", err)
		return nil, false
	}
	var out []aptProfileSuite
	for _, prof := range profiles {
		d, err := s.auditDB.GetProfile(ctx, prof.Name)
		if err != nil {
			s.logger.Error("could not read a profile to generate its filtered apt codename", "profile", prof.Name, "error", err)
			continue
		}
		p := entitle.New(d)
		base, refused := p.AptScope()
		if refused != "" {
			s.logger.Error("a profile names an apt base and has no filtered codename, because the filtered index would be the upstream document verbatim under bodega's signature; set the apt rule to membership closed with expansion block, or drop the base",
				"profile", prof.Name, "reason", refused)
			continue
		}
		if base == "" {
			continue
		}
		// Recorded here, ahead of every withdrawal below and of the ones
		// aptProfileIndexes makes after that. The pool predicate refuses this
		// profile's hosts whether or not a codename survives to be served, so
		// a cache directive that waits for one is right about the archive and
		// wrong about the refusal.
		scoped = true
		if !s.cfg.MirrorsAptCodename(base) {
			s.logger.Error("a profile names an apt base no upstream archive serves, so it has no filtered codename; add the base to apt_upstreams or move the profile onto one that is there",
				"profile", prof.Name, "base", base,
				"mirrored", strings.Join(s.cfg.MirroredAptCodenames(), " "))
			continue
		}
		codename := config.ProfileAptCodename(base, prof.Name)
		if err := s.cfg.ValidateProfileAptCodename(codename, base, prof.Name); err != nil {
			s.logger.Error("a profile's filtered apt codename cannot be served", "error", err)
			continue
		}
		out = append(out, aptProfileSuite{profile: prof.Name, base: base, codename: codename, permit: p})
	}
	return s.dropCollidingCodenames(out), scoped
}

// dropCollidingCodenames removes every profile whose derived codename another
// profile also derives, and names the group that lost.
//
// Neither is served rather than the last one written winning. ProfileAptCodename
// joins base and profile with a hyphen and both halves carry hyphens of their
// own, so "security-web" over noble and "web" over noble-security both derive
// noble-security-web on ordinary Ubuntu naming. Serving one of them hands the
// other profile's hosts an index filtered for a set they are not in: they are
// offered a package, request it, and aptPoolGate refuses them mid-transaction,
// which is the outcome this file exists to prevent. Dropping both instead
// fails `apt update` on both, and the log names the rename that fixes it.
//
// ValidateProfileAptCodename cannot catch this. It is handed one profile and
// checks it against the config, and the profile it collides with is in neither.
func (s *Server) dropCollidingCodenames(suites []aptProfileSuite) []aptProfileSuite {
	claims := map[string][]aptProfileSuite{}
	for _, ps := range suites {
		claims[ps.codename] = append(claims[ps.codename], ps)
	}
	out := make([]aptProfileSuite, 0, len(suites))
	for _, ps := range suites {
		group := claims[ps.codename]
		if len(group) == 1 {
			out = append(out, ps)
			continue
		}
		if group[0].profile != ps.profile {
			continue
		}
		pairs := make([]string, 0, len(group))
		for _, g := range group {
			pairs = append(pairs, g.profile+" over "+g.base)
		}
		s.logger.Error("two profiles derive one filtered apt codename, so neither is served and both hosts' apt update fails; rename a profile, or move one onto a base whose name does not overlap the other's",
			"codename", ps.codename, "profiles", strings.Join(pairs, ", "))
	}
	return out
}

// aptProfileIndexes generates and signs one filtered dists/ tree per profile
// that scopes apt, for the snapshot under construction.
//
// One fetch per (base, architecture) serves every profile over that base. Two
// profiles filtering noble read one upstream Packages between them, which is
// the difference between a linear cost in profiles and a linear cost in bases.
func (s *Server) aptProfileIndexes(ctx context.Context, date, validUntil time.Time) (served []aptProfileSuite, scoped bool) {
	suites, scoped := s.aptProfileSuites(ctx)
	if len(suites) == 0 {
		return nil, scoped
	}
	releases := map[string]map[string]string{}
	cache := map[string]aptIndexRead{}
	out := make([]aptProfileSuite, 0, len(suites))
	for _, ps := range suites {
		release, ok := releases[ps.base]
		if !ok {
			var err error
			if release, err = s.aptUpstreamRelease(ctx, ps.base); err != nil {
				s.logger.Error("could not read the upstream Release for a profile's apt base, so its filtered codename is not regenerated at this rebuild",
					"profile", ps.profile, "base", ps.base, "error", err)
				continue
			}
			releases[ps.base] = release
		}
		arches, err := s.aptUpstreamArches(ps.base, release)
		if err != nil {
			s.logger.Error("could not tell which architectures a profile's apt base publishes, so its filtered codename is not regenerated at this rebuild",
				"profile", ps.profile, "base", ps.base, "error", err)
			continue
		}
		packages, err := s.aptFilteredPackages(ctx, ps, arches, release, cache)
		if err != nil {
			s.logger.Error("a profile's filtered apt codename is not regenerated at this rebuild, so it stops being served until the read succeeds",
				"profile", ps.profile, "codename", ps.codename, "error", err)
			continue
		}
		ps.index = s.aptIndexFrom(ps.codename, packages, date, validUntil)
		out = append(out, ps)
	}
	return out, scoped
}

// aptIndexRead is one (base, architecture) upstream read, shared across every
// profile deriving from that base: the decompressed index, or the fact that
// this archive publishes no such architecture. The second is cached for the
// same reason as the first — without it, a base two profiles derive from
// spends one 404 per profile per rebuild on every architecture it does not
// carry.
type aptIndexRead struct {
	body []byte
	// notPublished is set when the fetch 404d, which is the archive saying it
	// does not carry that architecture rather than that its index is wrong.
	notPublished bool
}

// aptFilteredPackages filters one profile's view of every architecture its
// base publishes, dropping the ones the archive does not carry and failing the
// whole codename when one it does carry cannot be read or parsed.
//
// A filter that keeps nothing fails the same way, when the profile lists apt
// packages at all. Closed with nothing listed permits nothing deliberately and
// serves an empty index; closed with entries none of which match a paragraph is
// a misspelled source or an unsatisfiable pin, and the served result is
// identical — a signed empty Packages, every package on the host kept back, and
// one Info line carrying the counts.
//
// A 404 is a different class from every other failure and has to stay apart
// from it, because Ubuntu guarantees one. archive.ubuntu.com publishes a
// single Release per suite naming all seven architectures and a SHA256 for
// each, and then serves amd64 and i386 alone: the other five live on
// ports.ubuntu.com, and nothing in the Release records the split. Failing the
// codename on the first 404 means the canonical upstream — the one
// defaultConfigContent and docs/USAGE.md both print — filters amd64 correctly
// and serves it to nobody. The architecture is dropped instead, and
// aptIndexFrom builds Architectures: from what survived, so an arm64 host
// reading that archive is told the suite holds nothing for it, which is true
// of that archive.
//
// Everything else is all or nothing per codename: a digest mismatch, a
// decompression failure, a parse break, any non-404 status. A Release naming
// three architectures with two filtered bodies behind it is a signed document
// telling an amd64 host the suite holds nothing for it, and apt reports that
// as a suite that does not support the architecture — a bodega failure worded
// as an archive fact. Withdrawing the codename instead fails `apt update` on
// the line the operator installed, which names the instance that stopped
// answering. Withdrawing it when no architecture survives at all is the same
// rule: an empty Release is a suite with no architectures, which apt reads the
// same way.
func (s *Server) aptFilteredPackages(ctx context.Context, ps aptProfileSuite, arches []string, release map[string]string, cache map[string]aptIndexRead) (map[string][]byte, error) {
	out := make(map[string][]byte, len(arches))
	for _, arch := range arches {
		read, ok := cache[ps.base+"/"+arch]
		if !ok {
			body, err := s.aptUpstreamPackages(ctx, ps.base, arch, release)
			switch {
			case errors.Is(err, errUpstreamNotFound):
				read = aptIndexRead{notPublished: true}
				s.logger.Info("an apt base declares an architecture this archive does not serve, so filtered codenames over it carry the rest; the arch is served from another host (ports.ubuntu.com for Ubuntu's non-x86 ports) and reaching it needs its own apt_upstreams entry",
					"base", ps.base, "arch", arch)
			case err != nil:
				return nil, fmt.Errorf("read the upstream Packages for %s/%s: %w", ps.base, arch, err)
			default:
				read = aptIndexRead{body: body}
			}
			cache[ps.base+"/"+arch] = read
		}
		if read.notPublished {
			continue
		}
		filtered, kept, dropped, err := filterAptPackages(read.body, ps.permit)
		if err != nil {
			return nil, fmt.Errorf("filter the upstream Packages for %s/%s: %w", ps.base, arch, err)
		}
		if kept == 0 && ps.permit.Lists(manifest.TypeApt) {
			return nil, fmt.Errorf("the filter kept none of the %d paragraphs %s/%s publishes, and the profile lists apt packages: a name that matches no source in this base, or a pin no paragraph carries. Serving it would sign an empty Packages and report every package on the host as kept back",
				dropped, ps.base, arch)
		}
		s.logger.Info("filtered an upstream apt index for a profile",
			"profile", ps.profile, "codename", ps.codename, "arch", arch,
			"kept", kept, "dropped", dropped)
		out[arch] = filtered
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s publishes none of the %d architectures its Release names (%s); the filtered Release would name no architecture at all, which apt reads as a suite that does not support the host",
			ps.base, len(arches), strings.Join(arches, " "))
	}
	return out, nil
}

// filterAptPackages copies through the paragraphs a profile permits and drops
// the rest, returning the filtered index and the two counts.
//
// Membership is evaluated on the source package, not the binary. Ubuntu
// renames, splits and transitions binary packages within one stable source as
// ordinary maintenance — libfoo1 becomes libfoo1t64, a source ships a new -dev
// — and a set closed on binary names fires on every one of those until an
// operator sets the type to ignore, which is a control switched off by the
// noise it makes rather than by a decision.
//
// The kept paragraphs are the upstream's own bytes. deb822.ParseSingle answers
// with a map, so re-serializing from it would be a second grammar to get
// wrong, and it would get it wrong the way a re-serializer does: an index that
// still parses, carrying a Description that lost its continuation prefix.
// Filename is upstream's too and needs no rewrite, because it is relative to
// the archive root and bodega serves the pool at the same offset — which is
// also what keeps one pool object answering every profile.
//
// A paragraph that does not parse fails the whole filter. ParseStreamRaw stops
// where it could not read, so what the buffer holds at that point is every
// paragraph up to the break and none of the unbounded tail after it: a break
// at stanza 10 of 60,000 leaves a document the rest of this file would sign,
// serve, and log as kept=9 dropped=1, which is indistinguishable from a
// correct filter of a ten-stanza index. Every package past the break is then
// reported to the fleet as kept back, with one Info line as the only trace.
// docs/DESIGN.md names silent partial service as the reason not-signing lost;
// this is the same failure reached from the other side.
//
// The name is the source's and the version is the paragraph's own. They are
// different halves on purpose, because the version has to be the one the pool
// compares: aptPoolGate reads it off the .deb filename and has no index in
// hand, so a filter judging the source version would offer a binNMU's binary
// and let the backstop refuse it mid-transaction — the outcome the header
// above calls worse than no control. What that costs is stated where an
// operator meets it: an exact pin on a source that binNMU'd one of its
// binaries permits the binaries at that version and drops the rebuilt one, so
// apt reports the pair as kept back rather than installing half of it, and
// `bodega profile check` names the dropped binary at the write. A pin on the
// source version proper needs a capture recording ${source:Version}, which no
// catalog holds today.
func filterAptPackages(index []byte, p *entitle.Profile) (out []byte, kept, dropped int, err error) {
	var buf bytes.Buffer
	err = deb822.ParseStreamRaw(bytes.NewReader(index), func(raw []byte, fields map[string]string) error {
		source := deb822.SourceName(fields)
		if source == "" || !p.Permits(manifest.TypeApt, source, fields["Version"]).Permitted {
			dropped++
			return nil
		}
		kept++
		buf.Write(raw)
		buf.WriteByte('\n')
		return nil
	})
	if err != nil {
		return nil, kept, dropped, fmt.Errorf("paragraph %d does not parse, and everything after it would be missing from an index bodega signs: %w",
			kept+dropped+1, err)
	}
	return buf.Bytes(), kept, dropped, nil
}

// aptUpstreamArches reads the base codename's Release and returns the
// architectures it both names and publishes a digest for.
//
// The SHA256 block is the second half because an index with no digest beside
// it is one bodega would sign without having checked it against anything, and
// the digest is the only thing standing between a mirror mid-sync and a signed
// Release describing stanzas the pool no longer has.
//
// It is not a list of what the archive serves, and nothing in a Release is.
// Ubuntu's names seven architectures and publishes a digest for all seven
// while archive.ubuntu.com carries two, so the answer here is an upper bound
// and aptFilteredPackages drops what 404s out of it.
func (s *Server) aptUpstreamArches(base string, release map[string]string) ([]string, error) {
	declared := strings.Fields(release["Architectures"])
	if len(declared) == 0 {
		return nil, fmt.Errorf("the Release for %q names no Architectures", base)
	}
	published := aptReleaseDigests(release)
	var out []string
	for _, arch := range declared {
		if _, ok := published[aptPackagesPath(arch)+".gz"]; ok {
			out = append(out, arch)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the Release for %q publishes no %s/binary-*/Packages.gz for any of the architectures it names (%s)",
			base, aptProfileComponent, strings.Join(declared, " "))
	}
	if comps := strings.Fields(release["Components"]); len(comps) > 1 {
		s.logger.Info("a filtered apt codename carries one component; the base publishes more, and packages outside it are not served under the profile",
			"base", base, "served", aptProfileComponent, "upstream", strings.Join(comps, " "))
	}
	sort.Strings(out)
	return out, nil
}

// aptUpstreamRelease fetches and parses the Release for a mirrored codename.
//
// Release rather than InRelease: bodega has no distro keyring to check a
// signature against, so the clearsigned form would only add a wrapper to
// strip. What the document is used for is the digest list — see
// aptUpstreamPackages — and docs/THREAT_MODEL.md states what that does and
// does not buy.
func (s *Server) aptUpstreamRelease(ctx context.Context, base string) (map[string]string, error) {
	body, err := s.aptUpstreamFetch(ctx, base, "Release")
	if err != nil {
		return nil, err
	}
	return deb822.ParseSingle(body)
}

// aptUpstreamPackages fetches one architecture's compressed Packages index and
// returns it decompressed, after checking it against the digest the Release
// published for it.
//
// The digest check is not a signature and does not pretend to be one. It
// catches the failure a mirror produces on its own: a Packages body from one
// sync beside a Release from the next, which would have bodega sign an index
// whose stanzas name .deb digests the pool no longer has.
func (s *Server) aptUpstreamPackages(ctx context.Context, base, arch string, release map[string]string) ([]byte, error) {
	rest := aptPackagesPath(arch) + ".gz"
	want := aptReleaseDigests(release)[rest]
	body, err := s.aptUpstreamFetch(ctx, base, rest)
	if err != nil {
		return nil, err
	}
	if want != "" {
		if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != want {
			return nil, fmt.Errorf("the %s served for %s/%s does not match the SHA256 its own Release publishes: the archive's index and its digest list are from different syncs, and signing it would vouch for stanzas naming artifacts the pool no longer has",
				rest, base, arch)
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decompress %s for %s: %w", rest, base, err)
	}
	defer func() { _ = gz.Close() }()
	out, err := io.ReadAll(io.LimitReader(gz, maxUpstreamBody+1))
	if err != nil {
		return nil, fmt.Errorf("decompress %s for %s: %w", rest, base, err)
	}
	if int64(len(out)) > maxUpstreamBody {
		return nil, fmt.Errorf("%s for %s decompresses past bodega's %d-byte buffer", rest, base, maxUpstreamBody)
	}
	return out, nil
}

// aptUpstreamFetch reads one path under a mirrored codename's dists/ tree from
// the first archive configured for it, allow-list first.
//
// The first archive alone, matching handleAptMirrorDists: several archives can
// serve one codename and each publishes its own Release, so reading the digest
// list from one and the Packages from another is the hash mismatch the
// disjoint-namespace rule exists to prevent.
//
// The allow-list is checked before the request rather than after, for the
// reason aptResolvePoolUpstream states: a fetch that asks first and checks the
// answer later has already made the request the rule forbids. Nothing is
// recorded as discovery here — this is bodega reading its own index on a
// timer, not a host reaching for a package.
func (s *Server) aptUpstreamFetch(ctx context.Context, base, rest string) ([]byte, error) {
	key := base + "/" + rest
	if body, ok := s.aptUpstreamCached(key); ok {
		return body, nil
	}
	ups := s.cfg.AptUpstreams[base]
	if len(ups) == 0 {
		return nil, fmt.Errorf("no archive is configured for %q", base)
	}
	url := ups[0].URL + "/dists/" + base + "/" + rest
	if s.policy != nil {
		_, violation, err := s.upstreamPolicyVerdict(ctx, manifest.TypeApt, url)
		if err != nil {
			return nil, fmt.Errorf("policy check for %s: %w", url, err)
		}
		if violation {
			return nil, fmt.Errorf("%s is off the apt allow-list, so no filtered index can be generated from it: bodega policy add apt <host>", url)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, aptProfileFetchTimeout)
	defer cancel()
	body, _, err := fetchUpstream(ctx, url)
	if err != nil {
		return nil, err
	}
	s.aptUpstreamIdx.Store(key, aptUpstreamDoc{body: body, at: time.Now()})
	return body, nil
}

// aptUpstreamDoc is one cached upstream index document and when it was read.
type aptUpstreamDoc struct {
	body []byte
	at   time.Time
}

// aptUpstreamCached answers from the last read while it is inside
// metadata_ttl, which is the same clock the mirrored dists/ tree is served
// under: these are the same documents, reached by a different caller.
//
// A rebuild is triggered by the hourly tick and by every profile write, and
// the second one arrives in bursts — an operator listing a baseline writes one
// entry per package. Refetching tens of megabytes per write from an archive
// that republishes daily is the cost this bounds, and the staleness it trades
// for is bounded by the same setting an operator already tuned for the mirror.
func (s *Server) aptUpstreamCached(key string) ([]byte, bool) {
	ttl := s.cache.MetadataTTL
	if ttl <= 0 {
		return nil, false
	}
	v, ok := s.aptUpstreamIdx.Load(key)
	if !ok {
		return nil, false
	}
	doc, ok := v.(aptUpstreamDoc)
	if !ok || time.Since(doc.at) >= ttl {
		return nil, false
	}
	return doc.body, true
}

// aptPackagesPath is the Release-relative path of one architecture's Packages
// index, which is both what the digest list keys on and what the fetch asks
// for. One spelling, because a mismatch between the two reads as an archive
// that publishes no digest rather than as a typo.
func aptPackagesPath(arch string) string {
	return aptProfileComponent + "/binary-" + arch + "/Packages"
}

// aptReleaseDigests indexes a Release's SHA256 block by path. Each line is
// "<digest> <size> <path>", and deb822 hands the whole block over as one
// newline-joined value.
func aptReleaseDigests(release map[string]string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(release["SHA256"], "\n") {
		f := strings.Fields(line)
		if len(f) == 3 {
			out[f[2]] = f[0]
		}
	}
	return out
}

// ---- the backstop ----------------------------------------------------------

// aptPoolGate is the request predicate on /apt/pool/, and it answers true when
// the handler should carry on.
//
// It is the backstop rather than the control, which is the opposite of every
// other type: the filtered index has already decided what this host was told
// exists, and a request arriving here for something outside the profile came
// from a client that composed a URL without reading an index. Refusing it
// costs that client its transaction, which is the price of a request nothing
// offered.
//
// Which is also why it runs for a profile that scopes apt and for no other. A
// profile whose apt membership is open reads the mirrored codename unchanged
// and has no filtered index behind it, so a refusal here would be enforcement
// with no legible half — the 403 mid-transaction this whole shape exists to
// avoid, arriving on a package the index the client read said it could have.
//
// The source package comes from the pool path, with no index lookup: Debian
// lays the pool out as
// pool/<component>/<prefix>/<source>/<binary>_<version>_<arch>.deb, so segment
// four is the identity filterAptPackages closed the membership over, for every
// artifact mirrored out of an upstream archive.
//
// It is not that for a .deb bodega built. builder.PackageApt lays its pool out
// under ve.SourceName, which every importer fills with the name apt-get
// download needs — the binary's — while the real source sits in
// ve.SourcePackage. Segment four is then the binary name, so a profile listing
// sources refuses a generated-suite artifact whose two names differ. That
// fails closed and stays off the documented road: doctor --write-apt-sources
// installs the filtered stanza alone, so a host reaches those artifacts only
// after adding a generated-suite line by hand.
func (s *Server) aptPoolGate(w http.ResponseWriter, r *http.Request, poolPath string) bool {
	name, version := manifest.AptDebIdentity(path.Base(poolPath))
	if source := aptPoolSourceName(poolPath); source != "" {
		name = source
	}
	return s.entitleGate(w, r, manifest.TypeApt, name, version)
}

// aptGatesPool reports whether this request's own profile scopes apt, which is
// the one condition under which the pool route is a profile-decided one.
//
// It decides the predicate and nothing else. The cache directive is a server
// fact rather than a request one — see handleAptPool — because a route that
// refuses one host and ships `public` to the next has handed the refusal to a
// proxy to overturn, and the next host is an unidentified one on every
// instance.
func (s *Server) aptGatesPool(r *http.Request) bool {
	p := s.profileFor(r)
	if p == nil {
		return false
	}
	base, _ := p.AptScope()
	return base != ""
}

// aptScopedAnywhere reports whether any profile on this instance scopes apt,
// which is the server fact the pool route's cache directive turns on. See
// handleAptPool for why that directive cannot be a per-request one.
//
// Two sources, because each covers a window the other leaves open. The binding
// set is live from the moment a host is bound and is what aptGatesPool itself
// reads, so the two cannot disagree about a request in flight — including
// before the first rebuild has generated any codename at all. The snapshot
// answers for a profile written and not yet bound, which is the order bodega
// documents: write the profile, read the sources line off `bodega doctor`,
// bind the host. That profile's codename is already served, and a public copy
// cached during that window outlives the binding by a year.
func (s *Server) aptScopedAnywhere() bool {
	if s.profileNow().scopesApt() {
		return true
	}
	snap := s.aptSnap.Load()
	return snap == nil || snap.profilesScopeApt
}

// aptPoolSourceName reads the source package out of a pool path, and "" from
// a path that is not laid out as a pool. A caller falling back to the binary
// name is right to: a private archive free-forming its pool is a set closed on
// whatever the path carried, which is wrong in the direction of refusing too
// much and shows up as a refusal rather than as a leak.
func aptPoolSourceName(poolPath string) string {
	parts := strings.Split(poolPath, "/")
	if len(parts) != 5 || parts[0] != "pool" {
		return ""
	}
	return parts[3]
}
