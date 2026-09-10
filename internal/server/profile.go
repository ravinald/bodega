package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// profileSet is the binding table and every profile it names, resolved once
// and swapped whole. Held behind an atomic pointer on the same TTL as the ACL
// and identity sets, because the handler chain is built at Start and an
// operator writing `bodega profile add` against a running server has nothing
// to rebuild it.
//
// Whole matters as much as atomic: a request that read one host's binding from
// the incoming generation and another host's entries from the outgoing one
// would be answered by a profile nobody wrote.
type profileSet struct {
	byIdentity map[string]*entitle.Profile
}

// profileFor returns the profile bound to the host this request resolved to,
// or nil when nothing binds it. A nil *entitle.Profile is the unprofiled host
// and permits everything ungoverned, so every caller can use the answer
// without a nil check of its own.
func (p *profileSet) profileFor(identity string) *entitle.Profile {
	if p == nil || identity == "" {
		return nil
	}
	return p.byIdentity[identity]
}

func (s *Server) profileNow() *profileSet {
	if set := s.profileCached(); set != nil {
		return set
	}
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	if set := s.profileCached(); set != nil {
		return set
	}
	return s.storeProfiles(s.resolveProfiles(context.Background()))
}

func (s *Server) profileCached() *profileSet {
	set := s.profiles.Load()
	if set == nil {
		return nil
	}
	if time.Since(time.Unix(0, s.profilesAt.Load())) >= aclCacheTTL {
		return nil
	}
	return set
}

func (s *Server) storeProfiles(set *profileSet) *profileSet {
	s.profiles.Store(set)
	s.profilesAt.Store(time.Now().UnixNano())
	return set
}

// refreshProfiles re-reads the bindings regardless of cache age, so SIGHUP
// lands a profile change at once rather than within the TTL.
func (s *Server) refreshProfiles(ctx context.Context) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	s.storeProfiles(s.resolveProfiles(ctx))
}

// resolveProfiles reads every binding and the profiles they name.
//
// A read that fails keeps the last good set rather than emptying. Emptying
// would unprofile the fleet on one query timeout, which is the same failure
// the identity table's read guards against and is worse here: this set decides
// admission, so losing it silently relaxes every control it carries.
func (s *Server) resolveProfiles(ctx context.Context) *profileSet {
	empty := &profileSet{byIdentity: map[string]*entitle.Profile{}}
	if s.auditDB == nil {
		return empty
	}
	bindings, err := s.auditDB.ListProfileBindings(ctx, "")
	if err != nil {
		s.logger.Error("could not read the profile bindings; keeping the last set", "error", err)
		if set := s.profiles.Load(); set != nil {
			return set
		}
		return empty
	}
	set := &profileSet{byIdentity: make(map[string]*entitle.Profile, len(bindings))}
	resolved := map[string]*entitle.Profile{}
	for _, b := range bindings {
		p, ok := resolved[b.Profile]
		if !ok {
			d, err := s.auditDB.GetProfile(ctx, b.Profile)
			if err != nil {
				// A binding naming a profile that no longer exists resolves to
				// nothing rather than to a refusal: the host is in the state it
				// was in before anyone bound it.
				s.logger.Error("a profile binding names a profile that could not be read; the host is served unprofiled",
					"identity", b.Identity, "profile", b.Profile, "error", err)
				resolved[b.Profile] = nil
				continue
			}
			p = entitle.New(d)
			resolved[b.Profile] = p
		}
		if p != nil {
			set.byIdentity[b.Identity] = p
		}
	}
	return set
}

// profileFor is the whole of the read path's profile lookup: which host is
// this, and what may it fetch.
func (s *Server) profileFor(r *http.Request) *entitle.Profile {
	return s.profileNow().profileFor(Identity(r))
}

// entitleGate is the request predicate on a package route. It answers true
// when the handler should carry on.
//
// version is empty on a route that names a package without naming a version —
// a git namespace, a packument, an index. Those are decided at the membership
// level alone, because there is no version yet to hold to a constraint.
//
// apt does not reach here and is deliberately excluded: refusing an apt fetch
// at the pool costs the client a half-applied transaction, and the control
// there belongs at the index. See docs/DESIGN.md.
func (s *Server) entitleGate(w http.ResponseWriter, r *http.Request, typ, name, version string) bool {
	p := s.profileFor(r)
	if p == nil {
		return true
	}
	var d entitle.Decision
	if version == "" {
		d = p.Covers(typ, name)
	} else {
		d = p.Permits(typ, name, version)
	}
	if d.Reportable() {
		s.recordProfileReach(r, p, typ, name, version)
	}
	if d.Permitted {
		return true
	}
	s.recordProfileRefusal(r, p, typ, name, version, d)
	http.Error(w, profileRefusalText(p, typ, name, version, d), http.StatusForbidden)
	return false
}

// profileRefusalText is the body a refused client reads. It names the profile,
// the package, the rule that refused and the repair, because the two refusals
// call for opposite fixes: a membership refusal is widened by adding the
// package, a constraint refusal by moving the pin. A client that prints only
// "403 Forbidden" leaves the operator with the audit row, and the row is not
// what the person running the install is looking at.
func profileRefusalText(p *entitle.Profile, typ, name, version string, d entitle.Decision) string {
	subject := typ + "/" + name
	if version != "" {
		subject += " at " + version
	}
	switch d.Refusal {
	case entitle.RefusalMembership:
		return fmt.Sprintf("%s: profile %q does not list %s.\n"+
			"  Add it:      bodega profile add %s %s %s\n"+
			"  Or open it:  bodega profile set %s %s --membership open\n",
			entitle.RefusalMembership, p.Name(), subject, p.Name(), typ, name, p.Name(), typ)
	case entitle.RefusalConstraint:
		return fmt.Sprintf("%s: %s.\n"+
			"  Move the pin:  bodega profile pin %s %s %s <version> --reason <why>\n"+
			"  Or float it:   bodega profile add %s %s %s --constraint any\n",
			entitle.RefusalConstraint, d.Reason, p.Name(), typ, name, p.Name(), typ, name)
	}
	return fmt.Sprintf("profile %q refused %s: %s\n", p.Name(), subject, d.Reason)
}

// recordProfileRefusal writes the denial row. The status column carries which
// rule refused rather than one "profile" value for both, so `bodega audit
// events` answers "widen the set or move the pin" without anyone decoding the
// details blob.
func (s *Server) recordProfileRefusal(r *http.Request, p *entitle.Profile, typ, name, version string, d entitle.Decision) {
	reason := audit.DenialProfileMembership
	if d.Refusal == entitle.RefusalConstraint {
		reason = audit.DenialProfileConstraint
	}
	extra := map[string]string{
		"profile": p.Name(),
		"rule":    d.Refusal,
		"detail":  d.Reason,
	}
	if d.Rule != nil {
		extra["membership"] = d.Rule.Membership
		extra["version_default"] = d.Rule.VersionDefault
		extra["expansion"] = d.Rule.Expansion
	}
	if d.Entry != nil {
		extra["entry_constraint"] = d.Entry.Constraint
		extra["entry_version"] = d.Entry.Version
	}
	recordDenialFor(s.auditDB, r, typ, name, version, reason, extra)
}

// recordProfileReach writes the discovery row for a fetch outside a closed
// profile's set, under warn as well as under block.
//
// decision is `denied`, which is the value the existing promote flow already
// reads: the row means "this host reached outside its class", which is the
// same shape of finding as "this host reached an upstream the allow-list
// refuses" and belongs in the same table an operator already watches. Recording
// it as no_manifest instead would read as a catalog gap and send someone to add
// a package the profile deliberately does not list.
func (s *Server) recordProfileReach(r *http.Request, p *entitle.Profile, typ, name, version string) {
	s.recordDiscoveryRaw(r.Context(), r, typ, "", profileReachHint(p, typ, name), name, version,
		audit.DecisionDenied, "")
}

// profileReachHint is the pattern_hint for a reach outside a profile. The
// upstream allow-list hint has no meaning here — nothing about this row is
// promoted into a policy rule — so the column carries the command that closes
// the finding instead.
func profileReachHint(p *entitle.Profile, typ, name string) string {
	return fmt.Sprintf("bodega profile add %s %s %s", p.Name(), typ, name)
}

// profileIndexKey scopes a cached index to the profile whose view of it is
// being served.
//
// An index filtered for one host class and cached under the shared key is
// served to every other class from that cache, with no error anywhere: the
// second host gets a document that is valid, parseable and wrong about what it
// may install. The npm packument path avoided that by refusing to cache a
// filtered document at all; the profile in the key is the version of that
// answer which still caches.
//
// An unidentified request, and an identified one whose profile states no rule
// for the type, both get the key they get today. An install with no profiles
// pays nothing, and neither does a profile that governs apt alone.
//
// The prefix is deliberately outside every type tree. manifest.ParseKey reads
// a type out of a key's leading segment, and a scoped key must not answer as
// one of the eight: the checksum table is keyed by object key, and the same
// bytes acquiring a second identity is what migration 014 refused to do.
// Indexes are mutable and so are never checksummed, which is what keeps this
// safe rather than merely unobserved.
func profileIndexKey(profile, key string) string {
	if profile == "" {
		return key
	}
	return "profiles/" + manifest.SafeName(profile) + "/" + key
}

// profileIndexScope reports the profile name a filtered index for typ/name
// should be cached under, and the profile to filter with. An empty name means
// nothing is filtered and today's key stands.
func (s *Server) profileIndexScope(r *http.Request, typ, name string) (*entitle.Profile, string) {
	p := s.profileFor(r)
	if p == nil {
		return nil, ""
	}
	if !p.Covers(typ, name).Governed {
		return nil, ""
	}
	return p, p.Name()
}

// profileVersionFilter is the per-version predicate an index filter applies.
// It is Permits with the type and package already bound, so an index generator
// and the request predicate cannot disagree about one version.
//
// nil when the profile does not govern the type, which is the signal to leave
// the document as it is rather than to run a filter that permits everything.
func profileVersionFilter(p *entitle.Profile, typ, name string) func(string) bool {
	if p == nil {
		return nil
	}
	if d := p.Covers(typ, name); !d.Governed || d.Outside {
		// Outside a closed set and permitted by expansion: the profile lists
		// no version rule for a package it does not carry, so filtering its
		// versions would invent one.
		return nil
	}
	return func(version string) bool { return p.Permits(typ, name, version).Permitted }
}
