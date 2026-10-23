package provenance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// Covered are the types the check verifies anything for: npm, and git and
// binary entries fetched from GitHub releases. Every other type records
// unavailable with the reason uncoveredReason gives.
var Covered = []string{manifest.TypeBinary, manifest.TypeGit, manifest.TypeNpm}

// uncoveredReason names, per ecosystem, why no provenance is read, so the gap
// is stated in every admission row rather than inferred from an absence.
var uncoveredReason = map[string]string{
	manifest.TypePypi:      "PyPI publishes PEP 740 attestations, which bodega does not verify yet",
	manifest.TypeGomod:     "Go modules carry no publisher signature; the checksum database proves every client sees the same bytes, not who published them",
	manifest.TypeCargo:     "crates.io publishes no provenance bodega can verify",
	manifest.TypeRubygems:  "bodega does not verify the Sigstore attestations RubyGems.org publishes yet",
	manifest.TypeHelm:      "a chart's .prov file is a PGP signature with no key bodega is configured to trust, and is not verified yet",
	manifest.TypeApt:       "a .deb carries no publisher provenance; the archive's Release signature covers the index, not who built the package",
	manifest.TypeFreeBSD:   "the pkg repository signature covers the catalogue, not who built the package",
	manifest.TypeDistfiles: "a distfile carries no publisher provenance; its digest comes from the ports tree's distinfo",
}

// Store is what the check reads and writes in the audit database.
type Store interface {
	GetProvenancePolicy(ctx context.Context, ecosystem string) (audit.ProvenancePolicy, error)
	GetProvenancePin(ctx context.Context, pkgType, pkgName string) (audit.ProvenancePin, error)
	PinProvenance(ctx context.Context, p audit.ProvenancePin) (audit.ProvenancePin, bool, error)
}

// Checker is the upstream_provenance admission check. One Checker judges one
// admission: Check compares each verified version with the package's pin and
// writes nothing, and Commit takes the pin once the admission is decided, so
// a version another check refuses never becomes the anchor every later
// version is held to.
type Checker struct {
	Store    Store
	Verifier *Verifier

	// pending is the pin this admission takes if it is admitted: the first
	// verified version's identity, when the package holds no pin yet. Later
	// versions of the same admission are compared with it.
	pending *audit.ProvenancePin
	// judged is every version compared with pending, for Commit to judge
	// again should the stored pin turn out to be another one.
	judged []judgement
}

type judgement struct {
	ve     *manifest.VersionEntry
	pm     *manifest.PackageManifest
	ev     Evidence
	action string
	// unpinned is a version without provenance checked before this
	// admission had any pin to hold it to, judged only once Commit knows one.
	unpinned bool
}

// Action returns the configured action for an ecosystem: warn when none is
// set.
func Action(ctx context.Context, store Store, ecosystem string) (string, error) {
	if store == nil {
		return policy.ActionWarn, nil
	}
	p, err := store.GetProvenancePolicy(ctx, ecosystem)
	if errors.Is(err, audit.ErrProvenancePolicyNotFound) {
		return policy.ActionWarn, nil
	}
	if err != nil {
		return "", err
	}
	return p.Action, nil
}

// Check verifies ve's upstream provenance and turns the outcome into a
// verdict. invalid, unknown and mismatch fail under warn and block;
// unavailable fails under block only; ignore records the outcome and fails
// nothing.
func (c *Checker) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) policy.Result {
	r := policy.Result{Check: audit.CheckUpstreamProvenance, Action: policy.ActionPass}
	if pm == nil || ve == nil {
		return r
	}
	action, err := Action(ctx, c.Store, pm.Type)
	if err != nil {
		r.Action = policy.ActionWarn
		r.Reason = "load upstream provenance policy: " + err.Error()
		return r
	}
	if pm.Type == manifest.TypeNpm && policy.UndatableVersion(pm.Type, ve.Version) {
		r.Action = policy.ActionNotEvaluated
		r.Reason = "version " + strings.TrimSpace(ve.Version) + " names no single release; checked when a fetch resolves one"
		return r
	}

	key := strings.Join([]string{audit.CheckUpstreamProvenance, pm.Type, pm.Name, ve.Version, ve.URL, ve.Ref,
		entrySHA256(ve), fmt.Sprint(ve.IsRelease())}, "\x00")
	ev := policy.SharedLookup(ctx, key, func() Evidence { return c.evaluate(ctx, pm, ve) })
	if ev.Outcome == audit.ProvenanceVerified || (ev.Outcome == audit.ProvenanceUnavailable && pm.Type == manifest.TypeNpm) {
		ev = c.compare(ctx, pm, ve, ev, action)
	}
	return verdict(ev, action)
}

// Commit takes the pending pin, once the admission Check judged has been
// decided admitted, and returns a fresh verdict for every version whose
// verdict the stored pin changes. That is none, unless another admission
// pinned a different identity between Check and Commit, or the write failed:
// a version is then judged against what the package actually holds, which is
// what the pin's read-back exists for. Commit on a refused admission is never
// called, so it writes nothing.
func (c *Checker) Commit(ctx context.Context) map[*manifest.VersionEntry]policy.Result {
	if c.pending == nil || c.Store == nil {
		c.judged = nil
		return nil
	}
	want := *c.pending
	judged := c.judged
	c.pending, c.judged = nil, nil
	held, created, err := c.Store.PinProvenance(ctx, want)
	settled := err == nil && (created || samePin(held, want))
	var out map[*manifest.VersionEntry]policy.Result
	for _, j := range judged {
		if settled && !j.unpinned {
			continue
		}
		ev := j.ev
		if err != nil {
			ev = pinFailed(ev, "written", err)
		} else {
			ev = judge(j.pm, ev, held)
		}
		if j.unpinned && ev.Outcome == j.ev.Outcome {
			continue
		}
		if out == nil {
			out = make(map[*manifest.VersionEntry]policy.Result, len(judged))
		}
		out[j.ve] = verdict(ev, j.action)
	}
	return out
}

// compare judges a verified version, or an npm version without provenance,
// against the package's stored pin, or, when it holds none, against the pin
// this admission would take. A verified version with neither becomes that
// pin; one without provenance and with neither stays unavailable.
func (c *Checker) compare(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry, ev Evidence, action string) Evidence {
	if c.Store == nil {
		return ev
	}
	held, err := c.Store.GetProvenancePin(ctx, pm.Type, pm.Name)
	switch {
	case err == nil:
		return judge(pm, ev, held)
	case !errors.Is(err, audit.ErrProvenancePinNotFound):
		return pinFailed(ev, "read", err)
	}
	unpinned := c.pending == nil && ev.Outcome != audit.ProvenanceVerified
	c.judged = append(c.judged, judgement{ve: ve, pm: pm, ev: ev, action: action, unpinned: unpinned})
	if c.pending != nil {
		return judge(pm, ev, *c.pending)
	}
	if unpinned {
		return ev
	}
	version := strings.TrimSpace(ve.Version)
	if version == "" {
		version = ve.Ref
	}
	c.pending = &audit.ProvenancePin{
		PkgType: pm.Type, PkgName: pm.Name,
		SourceRepositoryURI: ev.SourceRepositoryURI,
		BuilderID:           PinnedBuilder(ev.BuilderID),
		WorkflowRef:         ev.WorkflowRef,
		PinnedVersion:       version,
	}
	ev.Detail += "; the package's first verified version, pinned once admitted"
	return ev
}

// judge holds ev against held: a verified version by who built it, one
// without provenance by when it was published.
func judge(pm *manifest.PackageManifest, ev Evidence, held audit.ProvenancePin) Evidence {
	if ev.Outcome == audit.ProvenanceUnavailable {
		return stopped(pm, ev, held)
	}
	return against(pm, ev, held)
}

// stopped is an npm version without provenance judged against held. A
// version published after the pinned one is a mismatch: the project
// published provenance and then a version arrived without it, which is what
// a publish from a stolen token on a machine other than the project's CI
// looks like. One published before the pinned version predates the
// project's adoption of provenance and stays unavailable. With either time
// unknown no comparison ran, and saying unavailable would pass it under warn.
// A maintainer publishing by hand leaves the same trace, so a mismatch names
// who published each version for the operator to take to the project; it
// does not decide between the two.
func stopped(pm *manifest.PackageManifest, ev Evidence, held audit.ProvenancePin) Evidence {
	pinnedAt, ok := ev.Published[held.PinnedVersion]
	var missing []string
	if ev.PublishedAt == nil {
		missing = append(missing, "this version's")
	}
	if !ok {
		missing = append(missing, "pinned version "+held.PinnedVersion+"'s")
	}
	if len(missing) > 0 {
		ev.Outcome = audit.ProvenanceUnknown
		ev.Detail = fmt.Sprintf("%s; %s/%s is pinned to %s from %s, and the packument's time map has no publish time for %s, so whether this version came after the pin is unknown",
			ev.Detail, pm.Type, pm.Name, held.BuilderID, held.SourceRepositoryURI, strings.Join(missing, " or "))
		return ev
	}
	at := ev.PublishedAt.UTC().Format(time.RFC3339)
	pinned := pinnedAt.UTC().Format(time.RFC3339)
	if ev.PublishedAt.Before(pinnedAt) {
		ev.Detail = fmt.Sprintf("%s; published %s, before pinned version %s (%s), so it predates the pin", ev.Detail, at, held.PinnedVersion, pinned)
		return ev
	}
	ev.Outcome = audit.ProvenanceMismatch
	if p, ok := ev.Publishers[held.PinnedVersion]; ok {
		ev.PinnedPublisher = &p
	}
	ev.Detail = fmt.Sprintf("published %s by %s with no provenance; pinned version %s was published by %s (%s), and %s/%s is pinned to %s from %s since then. A maintainer publishing by hand and a publish from a stolen token look the same from the registry; if the project confirms this release, 'bodega pkg trust reset %s %s' clears the pin",
		at, ev.Publisher, held.PinnedVersion, ev.PinnedPublisher, pinned, pm.Type, pm.Name, held.BuilderID, held.SourceRepositoryURI, pm.Type, pm.Name)
	return ev
}

// against is a verified version judged against held: unchanged when it was
// built by the pinned builder from the pinned repository, a mismatch when not.
func against(pm *manifest.PackageManifest, ev Evidence, held audit.ProvenancePin) Evidence {
	builder := PinnedBuilder(ev.BuilderID)
	if held.SourceRepositoryURI == ev.SourceRepositoryURI && held.BuilderID == builder {
		return ev
	}
	ev.Outcome = audit.ProvenanceMismatch
	ev.Detail = fmt.Sprintf("built by %s from %s, but %s/%s is pinned to %s from %s (first verified at %s); 'bodega pkg trust reset %s %s' clears the pin if the move is legitimate",
		builder, ev.SourceRepositoryURI, pm.Type, pm.Name, held.BuilderID, held.SourceRepositoryURI, held.PinnedVersion, pm.Type, pm.Name)
	return ev
}

// pinFailed is a version whose pin could not be read or written. Whether a
// verified version matches an earlier one, or whether one without provenance
// came after a version that had it, is unknown, and reporting the outcome
// verification reached would claim a comparison that never ran.
func pinFailed(ev Evidence, verb string, err error) Evidence {
	was := "verified"
	if ev.Outcome == audit.ProvenanceUnavailable {
		was = "no provenance published"
	}
	ev.Outcome = audit.ProvenanceUnknown
	ev.Detail = was + ", but the trust-on-first-use pin could not be " + verb + ": " + err.Error()
	return ev
}

func samePin(a, b audit.ProvenancePin) bool {
	return a.SourceRepositoryURI == b.SourceRepositoryURI && a.BuilderID == b.BuilderID
}

// verdict turns an outcome into the check's result under action.
func verdict(ev Evidence, action string) policy.Result {
	prov := ev.UpstreamProvenance
	r := policy.Result{Check: audit.CheckUpstreamProvenance, Action: policy.ActionPass,
		Provenance: &prov, Reason: ev.Outcome + ": " + ev.Detail}
	failed := false
	switch ev.Outcome {
	case audit.ProvenanceInvalid, audit.ProvenanceUnknown, audit.ProvenanceMismatch:
		failed = action != policy.ActionIgnore
	case audit.ProvenanceUnavailable:
		failed = action == policy.ActionBlock
	}
	if failed {
		r.Action = action
		r.Details = map[string]any{"outcome": ev.Outcome}
		if prov.SourceRepositoryURI != "" {
			r.Details["source_repository_uri"] = prov.SourceRepositoryURI
			r.Details["builder_id"] = prov.BuilderID
		}
		if ev.NoTrustedRoot {
			r.Details[audit.DetailNoTrustedRoot] = true
		}
		if ev.Outcome == audit.ProvenanceMismatch && prov.SourceRepositoryURI == "" {
			r.Details["publisher"] = publisherName(ev.Publisher)
			r.Details["pinned_publisher"] = publisherName(ev.PinnedPublisher)
		}
	}
	return r
}

// publisherName is a publisher for Details: its name, or nil (JSON null)
// when the registry did not name one, so a reader never mistakes an
// unnamed publisher for one called "".
func publisherName(p *Publisher) any {
	if p == nil {
		return nil
	}
	return p.Name
}

func (c *Checker) evaluate(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Evidence {
	v := c.Verifier
	switch pm.Type {
	case manifest.TypeNpm:
		return v.Npm(ctx, ve.URL, pm.Name, strings.TrimSpace(ve.Version))
	case manifest.TypeBinary:
		rel, ok := v.ParseReleaseAsset(ve.URL)
		if !ok {
			return unavailable("%s is not a GitHub release asset, and binaries from anywhere else carry no provenance bodega reads", ve.URL)
		}
		digest := entrySHA256(ve)
		if digest == "" {
			var err error
			if digest, err = v.ReleaseAssetDigest(ctx, rel); err != nil {
				return unknown("the release lookup for %s/%s@%s failed, so %s's digest and its attestations are unknown: %v", rel.Owner, rel.Repo, rel.Tag, rel.Asset, err)
			}
		}
		if digest == "" {
			return unavailable("neither the entry nor release %s/%s@%s records a sha256 for %s, so no attestation can be looked up before the fetch", rel.Owner, rel.Repo, rel.Tag, rel.Asset)
		}
		return v.GitHubAttestations(ctx, rel.Owner, rel.Repo, digest)
	case manifest.TypeGit:
		owner, repo, ok := v.ParseRepo(ve.URL)
		if !ok {
			return unavailable("%s is not a GitHub repository, and git sources from anywhere else carry no provenance bodega reads", ve.URL)
		}
		if !ve.IsRelease() {
			return unavailable("a bare clone of %s/%s is not a release asset; provenance is checked for release archives only", owner, repo)
		}
		asset := ve.Ref + ".tar.gz"
		digest := entrySHA256(ve)
		if digest == "" {
			var err error
			if digest, err = v.PublishedSHA256(ctx, owner, repo, ve.Ref, asset); err != nil {
				return unknown("reading the SHA256SUMS release %s/%s@%s publishes failed, so %s's digest and its attestations are unknown: %v", owner, repo, ve.Ref, asset, err)
			}
		}
		if digest == "" {
			return unavailable("release %s/%s@%s publishes no sha256 for %s, so no attestation can be looked up before the fetch", owner, repo, ve.Ref, asset)
		}
		return v.GitHubAttestations(ctx, owner, repo, digest)
	}
	if why, ok := uncoveredReason[pm.Type]; ok {
		return unavailable("%s", why)
	}
	return unavailable("%s has no provenance mechanism bodega reads", pm.Type)
}

// entrySHA256 is the sha256 the manifest entry already pins, if any.
func entrySHA256(ve *manifest.VersionEntry) string {
	if ve.SHA256 != "" {
		return strings.ToLower(ve.SHA256)
	}
	if ve.Checksum != nil && strings.EqualFold(ve.Checksum.Algorithm, "sha256") {
		return strings.ToLower(ve.Checksum.Value)
	}
	return ""
}

// IsCovered reports whether the check verifies anything for typ.
func IsCovered(typ string) bool { return slices.Contains(Covered, typ) }

// UncoveredReason says why typ records unavailable on every version.
func UncoveredReason(typ string) string { return uncoveredReason[typ] }
