// Package entitle answers one question: may this profile fetch this package at
// this version. The request path and the index generators are the same
// two-caller shape that grew two copies of one sequence and drifted before
// internal/admit existed, so the answer is computed here and nowhere else.
package entitle

import (
	"fmt"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

// Decision is the predicate's answer with the reasoning that produced it.
//
// Governed separates "permitted because the profile says so" from "permitted
// because the profile states no rule for this type". They are the same boolean
// and different facts: a caller enforcing profiles needs the first to log an
// admission and the second to fall through to the fleet-wide controls, and a
// bare bool would make those indistinguishable.
type Decision struct {
	Permitted bool
	Governed  bool
	Reason    string

	// Refusal names which rule said no: RefusalMembership or
	// RefusalConstraint, and "" on a permit. An operator reading a denial has
	// two opposite repairs available — widen the set, or move a pin — and a
	// single "profile refused this" leaves them guessing which.
	Refusal string

	// Outside reports a package the profile does not list under a closed type,
	// whichever expansion action followed. It is what tells Permits to skip
	// the version rule — a package the profile does not carry has no entry
	// naming a version, and holding it to the type default would turn warn
	// into block through the back door. Reportable is the narrower question of
	// whether to record it.
	Outside bool

	// Rule and Entry are the levels that decided, when one did. Entry is nil
	// when the type's default answered alone.
	Rule  *audit.ProfileTypeRule
	Entry *audit.ProfileEntry
}

// Refusal kinds. They are the response body's vocabulary as well as the audit
// row's, so a client reading an error and an operator reading a row are
// looking at the same word.
const (
	RefusalMembership = "membership"
	RefusalConstraint = "constraint"
)

// Reportable reports whether a decision is a reach outside the host's class
// that the caller should record. Every Outside decision is one except under
// ExpansionIgnore, which is the operator saying not to hear about this type.
//
// A method rather than a second boolean, so the one place that knows what
// ignore means is the package that defines it.
func (d Decision) Reportable() bool {
	return d.Outside && d.Rule != nil && d.Rule.Expansion != audit.ExpansionIgnore
}

// Profile is a profile resolved for lookup: the per-type markers and the
// entries indexed by the keys the predicate reads them with.
type Profile struct {
	name    string
	types   map[string]audit.ProfileTypeRule
	entries map[string]map[string]audit.ProfileEntry
}

// New indexes a stored profile for the predicate. A nil detail yields a nil
// Profile, which is the unprofiled host: see Permits.
func New(d *audit.ProfileDetail) *Profile {
	if d == nil {
		return nil
	}
	p := &Profile{
		name:    d.Profile.Name,
		types:   make(map[string]audit.ProfileTypeRule, len(d.Types)),
		entries: make(map[string]map[string]audit.ProfileEntry, len(d.Types)),
	}
	for _, r := range d.Types {
		p.types[r.Type] = r
	}
	for _, e := range d.Entries {
		if p.entries[e.Type] == nil {
			p.entries[e.Type] = map[string]audit.ProfileEntry{}
		}
		p.entries[e.Type][Key(e.Type, e.Name)] = e
	}
	return p
}

// Key is the form both sides of the membership comparison are held in: New
// indexes the entries with it and Covers looks one up with it, so no caller
// has to normalize a name before asking.
//
// It is exported because the CLI compares the same two sides outside the gate.
// A duplicate check, a drift report or a lookup by typed name that compares
// raw disagrees with what the server will decide, and disagrees silently.
//
// pypi needs it because the two sides carry different spellings of one
// project. An operator writes the normalized name, and the gate is handed
// whatever the URL or the filename carried: pypi publishes
// Django-4.2.11-py3-none-any.whl with the capital, and PEP 625 writes every
// sdist with underscores. Compared raw, a listed distribution is refused and a
// pin is never reached, because Permits returns at membership.
//
// Every other type is identity. gomod module paths and git namespaces are
// case-sensitive by specification, and collapsing '.' to '-' there would merge
// github.com/foo.bar/x with github.com/foo-bar/x into one entry; cargo already
// refuses a crate name that is not lowercase.
func Key(typ, name string) string {
	if typ != manifest.TypePypi {
		return name
	}
	// PEP 503: lowercase, and every run of [-_.] becomes one hyphen.
	name = strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(name))
	sep := false
	for i := 0; i < len(name); i++ {
		if c := name[i]; c == '-' || c == '_' || c == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteByte(name[i])
	}
	return b.String()
}

// AptScope is the mirrored codename this profile's filtered apt index derives
// from, and "" for a profile that does not scope apt.
//
// Both halves are required. A base with an open membership admits every
// package the archive publishes, so the filtered view would be the same
// document under a second name — signed by bodega instead of the archive,
// which is strictly worse: it replaces a signature the host already trusts
// with one covering identical bytes. A closed membership with no base has
// nothing to filter, because bodega's own manifest entries are already served
// under the generated suites.
func (p *Profile) AptScope() string {
	if p == nil {
		return ""
	}
	r, ok := p.types[manifest.TypeApt]
	if !ok || r.Membership != audit.MembershipClosed {
		return ""
	}
	return r.AptBase
}

// Name returns the profile's name, empty for the nil profile.
func (p *Profile) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}

// Covers answers the first two levels alone: does p govern typ, and is name
// inside the set it governs. It is what an index generator asks, because a
// listing decides which packages appear before any version is in hand, and it
// is the first half of Permits so the two cannot drift.
//
//  1. The type marker. Absent, the profile states no rule for typ and the
//     decision is ungoverned: fleet-wide controls decide it alone, exactly as
//     they did before any profile existed.
//  2. Membership. Closed admits only the packages the profile lists, so a
//     closed marker with no entries covers nothing of that type. Open admits
//     every package of that type in the catalog.
//
// A package outside a closed set is answered by the type's expansion action
// rather than by membership alone: block refuses it, warn serves it and leaves
// the decision Reportable so the caller records the reach, ignore serves it
// and reports nothing. warn is the default because a new transitive dependency
// is ordinary upstream maintenance and refusing it leaves the host unpatched.
//
// A nil profile is the host nothing binds, and it covers everything
// ungoverned. That is the state every host is in before an operator writes a
// profile, and making it a refusal would turn the first `bodega profile
// create` into a fleet-wide outage.
func (p *Profile) Covers(typ, name string) Decision {
	if p == nil {
		return Decision{Permitted: true, Reason: "no profile is bound to this host"}
	}
	rule, ok := p.types[typ]
	if !ok {
		return Decision{
			Permitted: true,
			Reason:    fmt.Sprintf("profile %q states no rule for %s", p.name, typ),
		}
	}

	if _, listed := p.entries[typ][Key(typ, name)]; listed || rule.Membership != audit.MembershipClosed {
		return Decision{Permitted: true, Governed: true, Rule: &rule}
	}

	d := Decision{Governed: true, Rule: &rule}
	switch rule.Expansion {
	case audit.ExpansionBlock:
		d.Refusal = RefusalMembership
		d.Outside = true
		d.Reason = fmt.Sprintf("profile %q is closed for %s and does not list %s",
			p.name, typ, name)
	case audit.ExpansionIgnore:
		d.Permitted = true
		d.Outside = true
		d.Reason = fmt.Sprintf("profile %q is closed for %s and ignores packages it does not list", p.name, typ)
	default:
		// Empty as well as "warn": a marker written before expansion existed
		// carries no value, and the column default says what that means.
		d.Permitted = true
		d.Outside = true
		d.Reason = fmt.Sprintf("profile %q is closed for %s and does not list %s, permitted because %s expansion is %s",
			p.name, typ, name, typ, audit.ExpansionWarn)
	}
	return d
}

// Permits reports whether p allows typ/name at version.
//
// Covers answers the first two levels; the third is the version rule, where a
// per-entry constraint overrides the type's version default in both
// directions: one pinned package inside a floating type, and one floating
// package inside a pinned type.
//
// A package Covers permitted by expansion skips the version rule entirely. It
// is outside the set, so no entry names a version for it and the type default
// is a rule about the profile's own packages; applying a pinned default to a
// package the profile does not list would turn warn into block through the
// back door.
func (p *Profile) Permits(typ, name, version string) Decision {
	d := p.Covers(typ, name)
	if !d.Permitted || !d.Governed || d.Outside {
		return d
	}

	rule := *d.Rule
	entry, listed := p.entries[typ][Key(typ, name)]

	kind, base := versionRule(rule, entry, listed)
	if kind == audit.VersionPinned {
		// Reachable only through an open type whose default is pinned: the
		// profile pins every version and named none for this package, so there
		// is nothing to compare against.
		return Decision{
			Governed: true,
			Rule:     d.Rule,
			Refusal:  RefusalConstraint,
			Reason: fmt.Sprintf("profile %q pins every %s version and names none for %s",
				p.name, typ, name),
		}
	}

	out := Decision{Governed: true, Rule: d.Rule}
	if listed {
		out.Entry = &entry
	}
	out.Permitted, out.Reason = matches(kind, base, version)
	if out.Permitted {
		out.Reason = fmt.Sprintf("profile %q permits %s/%s at %s (%s)", p.name, typ, name, version, out.Reason)
	} else {
		out.Refusal = RefusalConstraint
		out.Reason = fmt.Sprintf("profile %q does not permit %s/%s at %s: %s", p.name, typ, name, version, out.Reason)
	}
	return out
}

// versionRule resolves the third level against the first. It returns a
// manifest.Constraint* kind and the version to match it against, or
// audit.VersionPinned to signal a pin with nothing to pin to.
func versionRule(rule audit.ProfileTypeRule, entry audit.ProfileEntry, listed bool) (kind, base string) {
	if listed && entry.Constraint != "" {
		return entry.Constraint, entry.Version
	}
	if rule.VersionDefault == audit.VersionFloating {
		return manifest.ConstraintAny, ""
	}
	if listed && entry.Version != "" {
		return manifest.ConstraintExact, entry.Version
	}
	return audit.VersionPinned, ""
}

// matches applies one constraint kind, returning the reason either way.
//
// exact and any are string work on purpose: an apt version carries an epoch
// and a Debian revision, and a git entry carries a ref, so parsing either as
// semver to decide equality would refuse versions that are equal. compatible
// and patch have no such shortcut and go through builder.FilterVersions, which
// is the one implementation of what "^" and "~" mean here.
func matches(kind, base, version string) (bool, string) {
	switch kind {
	case manifest.ConstraintAny:
		return true, "any version"
	case manifest.ConstraintExact, "":
		if version == base {
			return true, "pinned to " + base
		}
		return false, "pinned to " + base
	case manifest.ConstraintCompatible, manifest.ConstraintPatch:
		if _, ok := builder.ParseSemVer(base); !ok {
			return false, fmt.Sprintf("constraint %s needs a semantic version to compare against and %q is not one", kind, base)
		}
		if _, ok := builder.ParseSemVer(version); !ok {
			return false, fmt.Sprintf("constraint %s cannot place %q, which is not a semantic version", kind, version)
		}
		if len(builder.FilterVersions([]string{version}, kind, base)) == 1 {
			return true, fmt.Sprintf("%s %s", kind, base)
		}
		return false, fmt.Sprintf("outside %s %s", kind, base)
	}
	return false, fmt.Sprintf("unknown constraint %q", kind)
}
