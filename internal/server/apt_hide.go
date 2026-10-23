package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
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

// aptMirrorHidesFrom reads every hide. A read that fails returns the previous
// snapshot's set rather than none: an empty set would put a withdrawn version
// back in the index and open the pool to it over a transient database error.
func (s *Server) aptMirrorHidesFrom(ctx context.Context) aptMirrorHides {
	if s.auditDB == nil {
		return nil
	}
	rows, err := s.auditDB.ListAptMirrorHides(ctx, "")
	if err != nil {
		var kept aptMirrorHides
		if prev := s.aptSnap.Load(); prev != nil {
			kept = prev.hidden
		}
		s.logger.Error("could not read the mirrored apt hides, so this rebuild keeps the previous set",
			"error", err, "kept", len(kept))
		return kept
	}
	out := aptMirrorHides{}
	for _, h := range rows {
		if out[h.Name] == nil {
			out[h.Name] = map[string]bool{}
		}
		out[h.Name][h.Version] = true
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
func (s *Server) aptMirrorRewrites(ctx context.Context, hidden aptMirrorHides, date, validUntil time.Time) map[string]*aptSuiteIndex {
	if len(hidden) == 0 {
		return nil
	}
	if s.aptSign.Load() == nil {
		s.logger.Error("mirrored apt versions are hidden and no apt signing key is installed, so the mirrored indexes still list them and only the pool refuses them; run bodega apt key generate and reload",
			"hidden", len(hidden))
		return nil
	}
	prev := s.aptSnap.Load()
	cache := map[string]aptIndexRead{}
	out := map[string]*aptSuiteIndex{}
	for _, group := range s.aptMirrorGroups() {
		indexes := make(map[string]*aptSuiteIndex, len(group))
		dropped := 0
		var failed error
		for _, codename := range group {
			idx, d, err := s.aptMirrorRewrite(ctx, codename, hidden, cache, date, validUntil)
			if err != nil {
				failed = fmt.Errorf("%s: %w", codename, err)
				break
			}
			indexes[codename] = idx
			dropped += d
		}
		switch {
		case failed != nil:
			carried := prev.mirrorGroup(group)
			s.logger.Error("could not rewrite a mirrored apt group to drop its hidden versions; the previous rewrite keeps serving if there was one, otherwise the archive's index is proxied and the pool refuses the hidden versions",
				"group", strings.Join(group, " "), "carried", carried != nil, "error", failed)
			for codename, idx := range carried {
				out[codename] = idx
			}
		case dropped > 0:
			s.logger.Info("rewrote and re-signed a mirrored apt group to drop hidden versions",
				"group", strings.Join(group, " "), "dropped", dropped)
			for codename, idx := range indexes {
				out[codename] = idx
			}
		}
	}
	return out
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
// stanzas dropped, and returns how many it dropped.
func (s *Server) aptMirrorRewrite(ctx context.Context, codename string, hidden aptMirrorHides, cache map[string]aptIndexRead, date, validUntil time.Time) (*aptSuiteIndex, int, error) {
	release, err := s.aptUpstreamRelease(ctx, codename)
	if err != nil {
		return nil, 0, err
	}
	layout, err := s.aptUpstreamComponents(codename, release)
	if err != nil {
		return nil, 0, err
	}
	packages := map[string]map[string][]byte{}
	var components []string
	dropped := 0
	for _, comp := range layout {
		for _, arch := range comp.arches {
			read, err := s.aptUpstreamRead(ctx, codename, comp, arch, release, cache)
			if err != nil {
				return nil, 0, err
			}
			if read.notPublished {
				continue
			}
			body, _, d, err := filterAptParagraphs(read.body, hidden.permits)
			if err != nil {
				return nil, 0, fmt.Errorf("filter the upstream Packages for %s/%s/%s: %w", codename, comp.name, arch, err)
			}
			dropped += d
			if packages[comp.name] == nil {
				packages[comp.name] = map[string][]byte{}
				components = append(components, comp.name)
			}
			packages[comp.name][arch] = body
		}
	}
	if len(packages) == 0 {
		return nil, 0, fmt.Errorf("%s publishes none of the architectures its Release names in any component bodega mirrors", codename)
	}
	header := aptReleaseHeader{
		origin:   release["Origin"],
		label:    release["Label"],
		suite:    release["Suite"],
		codename: release["Codename"],
		version:  release["Version"],
	}
	if header.suite == "" {
		header.suite = codename
	}
	if header.codename == "" {
		header.codename = codename
	}
	return s.aptIndexWithHeader(header, components, packages, date, validUntil), dropped, nil
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
func (s *Server) aptPoolHidden(w http.ResponseWriter, r *http.Request, poolPath string) bool {
	snap := s.aptSnap.Load()
	if snap == nil || len(snap.hidden) == 0 {
		return false
	}
	name, poolVersion := manifest.AptDebIdentity(path.Base(poolPath))
	version, hidden := snap.hidden.poolHides(name, poolVersion)
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
	s := &Server{cfg: cfg, logger: slog.New(slog.DiscardHandler)}
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
