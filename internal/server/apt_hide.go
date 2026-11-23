package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// ---- server-wide hide of a mirrored apt version -----------------------------
//
// `bodega pkg hide` withdraws a manifest entry by flagging it. A package served
// only from a mirrored codename has no entry to flag, and the index it appears
// in is the archive's own signed document, so withdrawing one version means
// rewriting that document and signing the result: the constraint the filtered
// codenames in apt_profile.go already work under.
//
// The unit rewritten is a mirrored base and every pocket of it this server
// mirrors, never one suite alone. A host reads the base and its pockets through
// one stanza (planApt), and Signed-By: applies to the whole stanza, so a
// rewritten base beside a proxied -security would leave one of the two
// verifying against a key that never signed it.
//
// A group with no hidden stanza in it is proxied byte-for-byte as before. The
// rewrite is the price of a hide, paid only where the hidden version is.
//
// The Release keeps the archive's Origin, Label, Suite, Codename and Version.
// apt refuses an update whose Origin or Label changed until the operator passes
// --allow-releaseinfo-change, so a Release stamped "bodega" would turn the hide
// into a fleet-wide apt update failure, and pin preferences written against
// o=Ubuntu would stop matching.

// aptMirrorHides is the set of hidden (binary name, version) pairs one rebuild
// read, keyed name then version.
type aptMirrorHides map[string]map[string]bool

// aptHidesByArchive is the hides one rebuild read, as each archive applies
// them, keyed by archive name with "" the default archive.
//
// A hide is recorded with the codenames its version was found in, and
// applies in the archives those codenames belong to. Two archives are two
// publishers, so a version withdrawn from a vendor's noble says nothing about
// Ubuntu's build of the same name; within one archive it reaches every
// codename, pockets included, as it always has. A hide naming no codename,
// or one this config no longer mirrors, applies in every archive: dropping a
// withdrawn version back into an index is the failure a hide exists to stop.
type aptHidesByArchive map[string]aptMirrorHides

// in is the hides applying in one archive.
func (h aptHidesByArchive) in(archive string) aptMirrorHides { return h[archive] }

// count is how many hides apply in some archive, each once.
func (h aptHidesByArchive) count() int {
	seen := map[string]bool{}
	for _, hides := range h {
		for name, versions := range hides {
			for version := range versions {
				seen[name+"\x00"+version] = true
			}
		}
	}
	return len(seen)
}

// aptHideArchives is the archives one hide applies in: those of the
// codenames it was found in, or every archive this config serves when any of
// them is no longer mirrored or none was recorded.
func aptHideArchives(cfg *config.Config, codenames []string) []string {
	every := append([]string{""}, cfg.AptArchiveNames()...)
	var out []string
	for _, c := range codenames {
		if !cfg.MirrorsAptCodename(c) {
			return every
		}
		if a := cfg.AptArchiveOf(c); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return every
	}
	return out
}

// hides reports whether a binary package's version is hidden.
func (h aptMirrorHides) hides(name, version string) bool {
	return h[name][version]
}

// poolHides reports which hide a pool filename's version falls under, and
// returns that hide's version as recorded, epoch included.
//
// A Debian pool filename drops the epoch: vim at 2:9.1.0016-1ubuntu7 lives at
// vim_9.1.0016-1ubuntu7_amd64.deb. A hide is keyed on the Packages version, so
// an exact lookup would miss every epoch'd version and serve the withdrawn
// .deb. Versions differing only in epoch name the same pool file, so matching
// on the version with its epoch removed is exact for the path. A filename that
// does carry one (spelled %3a, which AptDebIdentity decodes) is compared with
// the epoch, since there the path does tell the two apart.
func (h aptMirrorHides) poolHides(name, poolVersion string) (string, bool) {
	versions := h[name]
	if versions[poolVersion] {
		return poolVersion, true
	}
	if aptStripEpoch(poolVersion) != poolVersion {
		return "", false
	}
	var match string
	for v := range versions {
		if aptStripEpoch(v) == poolVersion && (match == "" || v < match) {
			match = v
		}
	}
	return match, match != ""
}

// aptStripEpoch removes a Debian version's "N:" epoch, when it has one.
func aptStripEpoch(version string) string {
	epoch, rest, found := strings.Cut(version, ":")
	if !found || epoch == "" || strings.Trim(epoch, "0123456789") != "" {
		return version
	}
	return rest
}

// permits is the filter predicate: a paragraph whose Package and Version an
// operator hid is dropped, and every other paragraph is kept.
func (h aptMirrorHides) permits(fields map[string]string) bool {
	return !h.hides(fields["Package"], fields["Version"])
}

// digest names the whole hide set, so a filtered index records which set it
// was filtered under. Any hide added or removed changes it, including one in
// a package the index never carried: telling those apart would mean parsing
// the index, which is the cost a reuse exists to skip.
func (h aptMirrorHides) digest() string {
	var pairs []string
	for name, versions := range h {
		for version, on := range versions {
			if on {
				pairs = append(pairs, name+"\x00"+version)
			}
		}
	}
	slices.Sort(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, "\n")))
	return hex.EncodeToString(sum[:])
}

// aptMirrorIndexKey is everything one filtered Packages of a rewritten group
// is a function of: the upstream bytes, named by the SHA256 their Release
// publishes, and the hide set. The archive and codename keep two codenames
// that publish an identical index from sharing a key across a config reload
// that moves one of them.
type aptMirrorIndexKey struct {
	archive, codename, path string
	upstreamSHA256          string
	hides                   string
}

// aptMirrorIndex is one filtered Packages as the snapshot serves it, and how
// many stanzas the filter dropped, which decides whether its group is
// rewritten at all.
//
// evidence is the full upstream membership the index was built from, held
// only while the audit database has no record of it. A reused index is never
// read again, so this is the one copy the age gate can still be told about;
// it is keyed by the immutable upstream digest through the index key, so a
// later or delayed read of the same mutable path cannot replace it.
type aptMirrorIndex struct {
	body     aptIndexBody
	dropped  int
	evidence *aptIndexEvidence
}

// aptIndexEvidence is the parsed membership of one upstream Packages whose
// record failed, shared by every snapshot that reuses an index built from it.
type aptIndexEvidence struct {
	codename, path, sum string
	entries             []audit.AptIndexEntry
	recorded            atomic.Bool
}

// pending returns e while its record is still owed, nil once it succeeded,
// so a reuse stops carrying membership nobody needs.
func (e *aptIndexEvidence) pending() *aptIndexEvidence {
	if e == nil || e.recorded.Load() {
		return nil
	}
	return e
}

// aptMirrorEvidence returns the membership of a freshly read upstream index
// when the audit database holds no record of its digest. The read that just
// happened already tried to record it; a database that refused that write
// usually refuses this lookup too, and either answer short of "recorded"
// keeps the membership, because losing it leaves new versions undated.
func (s *Server) aptMirrorEvidence(ctx context.Context, codename, path, sum string, body []byte) *aptIndexEvidence {
	if s.auditDB == nil || sum == "" {
		return nil
	}
	if seen, err := s.auditDB.AptIndexObserved(ctx, codename, sum); err == nil && seen {
		return nil
	}
	entries, err := aptIndexEntries(body)
	if err != nil || !aptEntriesNameAVersion(entries) {
		return nil
	}
	return &aptIndexEvidence{codename: codename, path: path, sum: sum, entries: entries}
}

// retryAptMirrorEvidence records every membership the published snapshot
// still owes the age gate. Each is tried once per rebuild; one that succeeds
// is marked so the indexes reusing it stop carrying it.
func (s *Server) retryAptMirrorEvidence(ctx context.Context, indexes map[aptMirrorIndexKey]aptMirrorIndex) {
	if s.auditDB == nil {
		return
	}
	tried := map[*aptIndexEvidence]bool{}
	for _, idx := range indexes {
		e := idx.evidence.pending()
		if e == nil || tried[e] {
			continue
		}
		tried[e] = true
		if s.recordAptIndexEntries(ctx, e.codename, e.path, e.sum, e.entries) == nil {
			e.recorded.Store(true)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// aptMirrorFilter is the filter a rewrite runs on an index it cannot reuse.
// A variable so a test can count the calls.
var aptMirrorFilter = filterAptParagraphs

// aptMirrorPass is what one rebuild's rewrites share: the hide set, the
// indexes the previous snapshot served, and the upstream reads made so far.
type aptMirrorPass struct {
	hidden  aptMirrorHides
	hideSet string
	prev    map[aptMirrorIndexKey]aptMirrorIndex
	reads   map[string]aptIndexRead
}

// reuse returns the previous snapshot's index for key. A key with no
// upstream digest names no particular bytes and is never reused.
func (p *aptMirrorPass) reuse(key aptMirrorIndexKey) (aptMirrorIndex, bool) {
	if key.upstreamSHA256 == "" {
		return aptMirrorIndex{}, false
	}
	idx, ok := p.prev[key]
	return idx, ok
}

// aptMirrorHidesFrom reads every hide. A read that fails returns the previous
// snapshot's set rather than none: an empty set would put a withdrawn version
// back in the index and open the pool to it over a transient database error.
func (s *Server) aptMirrorHidesFrom(ctx context.Context) aptHidesByArchive {
	if s.auditDB == nil {
		return nil
	}
	rows, err := s.auditDB.ListAptMirrorHides(ctx, "")
	if err != nil {
		var kept aptHidesByArchive
		if prev := s.aptSnap.Load(); prev != nil {
			kept = prev.hidden
		}
		s.logger.Error("could not read the mirrored apt hides, so this rebuild keeps the previous set",
			"error", err, "kept", kept.count())
		return kept
	}
	out := aptHidesByArchive{}
	for _, h := range rows {
		for _, archive := range aptHideArchives(s.cfg, h.Codenames) {
			if out[archive] == nil {
				out[archive] = aptMirrorHides{}
			}
			if out[archive][h.Name] == nil {
				out[archive][h.Name] = map[string]bool{}
			}
			out[archive][h.Name][h.Version] = true
		}
	}
	return out
}

// aptMirrorGroups lists every mirrored base with the pockets of it this server
// mirrors. A pocket whose base is not mirrored is a group of its own.
func (s *Server) aptMirrorGroups() [][]string {
	var out [][]string
	for _, codename := range s.cfg.MirroredAptCodenames() {
		if _, ok := s.aptPocketBase(codename); ok {
			continue
		}
		out = append(out, append([]string{codename}, s.aptMirroredPockets(codename)...))
	}
	return out
}

// aptMirrorRewrites generates a bodega-signed index for every mirrored group
// carrying a hidden version, keyed by codename.
//
// No signing key means no rewrite. An unsigned rewrite of a distro codename
// would need [trusted=yes] on the host, which replaces the archive's check
// with none, so the index stays the archive's and the pool refusal alone
// withholds the version.
//
// A group whose upstream read fails keeps the previous snapshot's rewrite when
// there was one. Falling back to the proxy would put the hidden stanza back in
// front of every host, and the pool refusal would then abort their apt runs
// mid-transaction, which is the outcome apt_profile.go explains the index
// filter exists to prevent.
//
// The second map is every filtered Packages the returned rewrites serve, for
// the next rebuild to reuse: an index whose upstream SHA256 and hide set are
// unchanged is the same bytes, and filtering, compressing and hashing it again
// is what made each rebuild cost the size of the archive rather than the size
// of the change. A carried group carries its entries with it; a group that
// goes back to proxy has none to keep.
//
// A reused index is never read, so it never reaches the age gate observer
// that a read feeds. Each index whose record failed carries the membership it
// was built from, and the previous snapshot's are retried first, so a
// database that recovers between rebuilds still gets the evidence.
func (s *Server) aptMirrorRewrites(ctx context.Context, hidden aptHidesByArchive, date, validUntil time.Time) (map[string]*aptSuiteIndex, map[aptMirrorIndexKey]aptMirrorIndex) {
	if len(hidden) == 0 {
		return nil, nil
	}
	if s.aptSign.Load() == nil {
		s.logger.Error("mirrored apt versions are hidden and no apt signing key is installed, so the mirrored indexes still list them and only the pool refuses them; run bodega apt key generate and reload",
			"hidden", hidden.count())
		return nil, nil
	}
	prev := s.aptSnap.Load()
	reads := map[string]aptIndexRead{}
	var prevIndexes map[aptMirrorIndexKey]aptMirrorIndex
	if prev != nil {
		prevIndexes = prev.mirrorIndexes
	}
	s.retryAptMirrorEvidence(ctx, prevIndexes)
	out := map[string]*aptSuiteIndex{}
	reusable := map[aptMirrorIndexKey]aptMirrorIndex{}
	for _, group := range s.aptMirrorGroups() {
		groupHidden := hidden.in(s.cfg.AptArchiveOf(group[0]))
		pass := &aptMirrorPass{hidden: groupHidden, hideSet: groupHidden.digest(), reads: reads, prev: prevIndexes}
		indexes := make(map[string]*aptSuiteIndex, len(group))
		built := map[aptMirrorIndexKey]aptMirrorIndex{}
		dropped, refiltered := 0, 0
		var failed error
		for _, codename := range group {
			idx, d, n, err := s.aptMirrorRewrite(ctx, codename, pass, built, date, validUntil)
			if err != nil {
				failed = fmt.Errorf("%s: %w", codename, err)
				break
			}
			indexes[codename] = idx
			dropped += d
			refiltered += n
		}
		switch {
		case failed != nil:
			carried := prev.mirrorGroup(group)
			s.logger.Error("could not rewrite a mirrored apt group to drop its hidden versions; the previous rewrite keeps serving if there was one, otherwise the archive's index is proxied and the pool refuses the hidden versions",
				"group", strings.Join(group, " "), "carried", carried != nil, "error", failed)
			for codename, idx := range carried {
				out[codename] = idx
			}
			if carried != nil {
				for key, idx := range pass.prev {
					if slices.Contains(group, key.codename) {
						reusable[key] = idx
					}
				}
			}
		case dropped > 0:
			s.logger.Info("rewrote and re-signed a mirrored apt group to drop hidden versions",
				"group", strings.Join(group, " "), "dropped", dropped, "refiltered", refiltered)
			for codename, idx := range indexes {
				out[codename] = idx
			}
			maps.Copy(reusable, built)
		}
	}
	return out, reusable
}

// mirrorGroup returns this snapshot's rewrite of every codename in group, or
// nil when any of them was proxied. Nil-safe, for the first rebuild.
func (snap *aptSnapshot) mirrorGroup(group []string) map[string]*aptSuiteIndex {
	if snap == nil {
		return nil
	}
	out := make(map[string]*aptSuiteIndex, len(group))
	for _, codename := range group {
		if !snap.mirrorRewritten[codename] || snap.suites[codename] == nil {
			return nil
		}
		out[codename] = snap.suites[codename]
	}
	return out
}

// aptMirrorRewrite builds one mirrored codename's index with the hidden
// stanzas dropped, records each filtered Packages it serves in built, and
// returns how many stanzas it dropped and how many indexes it had to filter
// rather than reuse.
func (s *Server) aptMirrorRewrite(ctx context.Context, codename string, pass *aptMirrorPass, built map[aptMirrorIndexKey]aptMirrorIndex, date, validUntil time.Time) (*aptSuiteIndex, int, int, error) {
	release, err := s.aptUpstreamRelease(ctx, codename)
	if err != nil {
		return nil, 0, 0, err
	}
	layout, err := s.aptUpstreamComponents(codename, release)
	if err != nil {
		return nil, 0, 0, err
	}
	digests := aptReleaseDigests(release)
	archive := s.cfg.AptArchiveOf(codename)
	bodies := map[string]map[string]aptIndexBody{}
	var components []string
	dropped, refiltered := 0, 0
	for _, comp := range layout {
		for _, arch := range comp.arches {
			key := aptMirrorIndexKey{
				archive: archive, codename: codename, path: comp.index[arch],
				upstreamSHA256: digests[comp.index[arch]], hides: pass.hideSet,
			}
			idx, ok := pass.reuse(key)
			if !ok {
				read, err := s.aptUpstreamRead(ctx, codename, comp, arch, release, pass.reads)
				if err != nil {
					return nil, 0, 0, err
				}
				if read.notPublished {
					continue
				}
				body, _, d, err := aptMirrorFilter(read.body, pass.hidden.permits)
				if err != nil {
					return nil, 0, 0, fmt.Errorf("filter the upstream Packages for %s/%s/%s: %w", codename, comp.name, arch, err)
				}
				idx = aptMirrorIndex{
					body: newAptIndexBody(body), dropped: d,
					evidence: s.aptMirrorEvidence(ctx, codename, key.path, key.upstreamSHA256, read.body),
				}
				refiltered++
			}
			idx.evidence = idx.evidence.pending()
			if key.upstreamSHA256 != "" {
				built[key] = idx
			}
			dropped += idx.dropped
			if bodies[comp.name] == nil {
				bodies[comp.name] = map[string]aptIndexBody{}
				components = append(components, comp.name)
			}
			bodies[comp.name][arch] = idx.body
		}
	}
	if len(bodies) == 0 {
		return nil, 0, 0, fmt.Errorf("%s publishes none of the architectures its Release names in any component bodega mirrors", codename)
	}
	header := aptReleaseHeader{
		origin:   release["Origin"],
		label:    release["Label"],
		suite:    release["Suite"],
		codename: release["Codename"],
		version:  release["Version"],

		notAutomatic:         release["NotAutomatic"],
		butAutomaticUpgrades: release["ButAutomaticUpgrades"],
	}
	if header.suite == "" {
		header.suite = config.AptCodenameOf(codename)
	}
	if header.codename == "" {
		header.codename = config.AptCodenameOf(codename)
	}
	return s.aptIndexWithBodies(header, components, bodies, date, validUntil), dropped, refiltered, nil
}

// aptMirrorRewritten reports whether the loaded snapshot serves this mirrored
// codename from a bodega-signed rewrite rather than by proxy.
func (s *Server) aptMirrorRewritten(codename string) bool {
	snap := s.aptSnap.Load()
	return snap != nil && snap.mirrorRewritten[codename]
}

// aptPoolHidden refuses a pool request for a hidden mirrored version and
// answers true when it did.
//
// 403 where a hidden manifest entry answers 404. This version exists upstream
// and every archive a client might try next still serves it, so "absent" would
// be a claim about the world that is false; the refusal says this server
// withheld it. Checked before every other gate, because a hide is the
// operator's verdict on the bytes whoever asks.
func (s *Server) aptPoolHidden(w http.ResponseWriter, r *http.Request, archive, poolPath string) bool {
	snap := s.aptSnap.Load()
	if snap == nil || len(snap.hidden) == 0 {
		return false
	}
	name, poolVersion := manifest.AptDebIdentity(path.Base(poolPath))
	version, hidden := snap.hidden.in(archive).poolHides(name, poolVersion)
	if !hidden {
		return false
	}
	f := newRefusal(checkHidden, manifest.TypeApt, name, version, http.StatusForbidden)
	f.reason = "an operator has withdrawn this version from every host this server answers."
	f.next = fmt.Sprintf("install a version the index lists; if this one should be served again, `bodega pkg hide apt %s %s` toggles the hide off.", name, version)
	s.logger.Info("refused a hidden mirrored apt version at the pool",
		"pool_path", poolPath, "package", name, "version", version, "incident", f.incident)
	recordDenialFor(s.auditDB, r, manifest.TypeApt, name, version, audit.DenialHidden,
		map[string]string{"incident": f.incident, "pool_path": poolPath})
	f.write(w, r)
	return true
}

// LocateMirroredAptVersion names the mirrored codenames whose upstream Packages
// carry a binary package at a version, reading each the way the index rebuild
// does: the first archive configured for the codename, allow-list first when
// db is open, digests checked against the Release.
//
// It answers `bodega pkg hide` before a hide is recorded, so a typo in the
// version is refused at the command rather than recorded as a hide that drops
// nothing. A codename that cannot be read is named in the error rather than
// skipped, because "not found" would then be a claim about an archive nobody
// read.
func LocateMirroredAptVersion(ctx context.Context, cfg *config.Config, db *audit.DB, name, version string) ([]string, error) {
	s := &Server{cfg: cfg, logger: slog.New(slog.DiscardHandler), auditDB: db}
	if db != nil {
		s.policy = policy.NewChecker(db)
	}
	return s.locateMirroredAptVersion(ctx, name, version)
}

func (s *Server) locateMirroredAptVersion(ctx context.Context, name, version string) ([]string, error) {
	searched := s.cfg.MirroredAptCodenames()
	if len(searched) == 0 {
		return nil, fmt.Errorf("apt/%s is in no manifest and this server mirrors no apt codename, so there is no index to hide %s from", name, version)
	}
	var found, unread []string
	for _, codename := range searched {
		hit, err := s.mirroredCodenameCarries(ctx, codename, name, version)
		switch {
		case err != nil:
			unread = append(unread, fmt.Sprintf("%s (%v)", codename, err))
		case hit:
			found = append(found, codename)
		}
	}
	if len(found) > 0 {
		return found, nil
	}
	if len(unread) > 0 {
		return nil, fmt.Errorf("apt/%s %s is in no manifest and was not found in the mirrored codenames read (searched %s); these could not be read: %s",
			name, version, strings.Join(searched, " "), strings.Join(unread, "; "))
	}
	return nil, fmt.Errorf("apt/%s %s is in no manifest and in no mirrored codename's Packages (searched %s); check the version against apt-cache madison %s on a host",
		name, version, strings.Join(searched, " "), name)
}

// mirroredCodenameCarries reports whether any component and architecture of
// one mirrored codename lists the binary package at the version.
func (s *Server) mirroredCodenameCarries(ctx context.Context, codename, name, version string) (bool, error) {
	release, err := s.aptUpstreamRelease(ctx, codename)
	if err != nil {
		return false, err
	}
	layout, err := s.aptUpstreamComponents(codename, release)
	if err != nil {
		return false, err
	}
	cache := map[string]aptIndexRead{}
	for _, comp := range layout {
		for _, arch := range comp.arches {
			read, err := s.aptUpstreamRead(ctx, codename, comp, arch, release, cache)
			if err != nil {
				return false, err
			}
			if read.notPublished {
				continue
			}
			if hit, err := aptIndexCarries(read.body, name, version); err != nil || hit {
				return hit, err
			}
		}
	}
	return false, nil
}

// errAptFound stops a Packages walk at the first match.
var errAptFound = errors.New("found")

func aptIndexCarries(index []byte, name, version string) (bool, error) {
	err := deb822.ParseStreamRaw(bytes.NewReader(index), func(_ []byte, fields map[string]string) error {
		if fields["Package"] == name && fields["Version"] == version {
			return errAptFound
		}
		return nil
	})
	if errors.Is(err, errAptFound) {
		return true, nil
	}
	return false, err
}
