package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// Identity returns the host an identity binding resolved this request to, or
// "" when nothing bound it. Never a substitute for ClientIP: the deny list
// matched on the address, and an audit row that dropped it would lose which of
// an identity's addresses asked.
func Identity(r *http.Request) string {
	if id, ok := r.Context().Value(identityKey).(string); ok {
		return id
	}
	return ""
}

// credentialForm names how a request carried its credential. It is recorded on
// nothing and returned for the sake of the tests and error text: eight clients
// reach this server through three header shapes, and knowing which one arrived
// is how a support question about "apt sends no credential" gets answered.
type credentialForm string

const (
	formNone   credentialForm = ""
	formBearer credentialForm = "bearer" // npm _authToken, curl -H, helm --pass-credentials over Bearer
	formBasic  credentialForm = "basic"  // apt auth.conf.d, pip index URL, go .netrc, helm --username, git, curl --netrc
	formRaw    credentialForm = "raw"    // cargo: the registry token verbatim, no scheme
)

// credentialFrom pulls the candidate token out of a request's Authorization
// header. It is deliberately protocol-blind: the eight clients bodega serves
// reach it through three header shapes, and which route the request landed on
// says nothing about which shape its client chose.
//
//	Bearer <token>          npm writes _authToken; curl and helm can be told to
//	Basic  <base64 u:p>     apt, pip, go, helm, git, wget — every netrc-shaped path
//	<token>                 cargo, which sends the registry token with no scheme
//
// On Basic, the password wins and the username is the fallback. Both spellings
// are in the field: apt's auth.conf.d, go's .netrc and git's credential store
// all carry a login plus the secret, while a pip index URL of the form
// https://<token>@host/pypi/simple/ has only the user half to put it in.
func credentialFrom(r *http.Request) (string, credentialForm) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return "", formNone
	}
	// Cut before trimming the remainder, so "Bearer " is a scheme with an
	// empty value rather than a bare word that looks like cargo's token.
	scheme, rest, _ := strings.Cut(h, " ")
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(scheme) {
	case "bearer", "token":
		if rest == "" {
			return "", formNone
		}
		return rest, formBearer
	case "basic":
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return "", formNone
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			return "", formNone
		}
		if pass != "" {
			return pass, formBasic
		}
		if user != "" {
			return user, formBasic
		}
		return "", formNone
	}
	if rest == "" && !knownScheme(scheme) {
		// One word, no scheme bodega recognizes. Cargo sends its registry
		// token exactly this way and nothing else bodega speaks to does.
		return scheme, formRaw
	}
	// Digest, Negotiate and anything else with a scheme bodega does not speak.
	// Reading the remainder as a token would attribute a request to whichever
	// identity happened to collide with a base64 blob.
	return "", formNone
}

// knownScheme names the HTTP auth schemes that mean "the value follows", so a
// scheme with nothing after it is a malformed header rather than cargo's
// credential. Digest and Negotiate are here for that reason alone: bodega
// speaks neither, and both must yield no credential either way.
func knownScheme(s string) bool {
	switch strings.ToLower(s) {
	case "bearer", "token", "basic", "digest", "negotiate", "ntlm":
		return true
	}
	return false
}

// cidrBinding is one CIDR binding parsed for matching, kept alongside the
// prefix length resolution sorts on.
type cidrBinding struct {
	prefix   netip.Prefix
	identity string
}

// identitySet is one resolved answer for the whole binding table, plus the
// token hashes a token binding is keyed through. Swapped whole for the same
// reason aclSet is: a request must never see a token binding from one
// generation and a CIDR binding from the next.
//
// cidr is sorted longest prefix first, so the first match is the answer.
type identitySet struct {
	byToken map[string]string // token id -> identity
	cidr    []cidrBinding
	tokens  []audit.TokenHash
}

// newIdentitySet parses the table into the shape the read path matches
// against. An unparseable CIDR row is skipped rather than emptying the set: a
// binding table that loses every row on one bad entry would attribute the
// whole fleet to nobody, silently.
func newIdentitySet(bindings []audit.IdentityBinding, tokens []audit.TokenHash) *identitySet {
	set := &identitySet{byToken: make(map[string]string, len(bindings)), tokens: tokens}
	for _, b := range bindings {
		switch b.Kind {
		case audit.BindToken:
			set.byToken[b.Key] = b.Identity
		case audit.BindCIDR:
			p, err := netip.ParsePrefix(b.Key)
			if err != nil {
				continue
			}
			set.cidr = append(set.cidr, cidrBinding{prefix: p.Masked(), identity: b.Identity})
		}
	}
	sort.SliceStable(set.cidr, func(i, j int) bool {
		return set.cidr[i].prefix.Bits() > set.cidr[j].prefix.Bits()
	})
	return set
}

// resolve answers "which host is this", in the order token, longest-prefix
// CIDR, unidentified.
//
// The token wins because it is the precise answer: an operator who issued a
// credential to one host said more about that host than the subnet it happens
// to sit in. A credential that resolves to no token, or to a token nothing is
// bound to, falls through to the CIDR rather than refusing — this path adds
// attribution, never admission, and a request that would have been served
// yesterday is served today.
//
// cidrTrusted is the caller's answer to "may an address name a host here",
// which is false while trusted_proxies is still the built-in default. See
// Server.cidrBindingsTrusted.
func (s *identitySet) resolve(cred, clientIP, pepper string, now time.Time, cidrTrusted bool) string {
	if s == nil {
		return ""
	}
	if cred != "" && len(s.byToken) > 0 {
		if id := s.identityForToken(cred, pepper, now); id != "" {
			return id
		}
	}
	if !cidrTrusted {
		return ""
	}
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	for _, b := range s.cidr {
		if b.prefix.Contains(addr) {
			return b.identity
		}
	}
	return ""
}

// identityForToken hashes the presented credential and returns the identity
// bound to the token it matches. An expired token identifies nobody: the row
// that revoked it is the operator saying this host is no longer that host.
func (s *identitySet) identityForToken(cred, pepper string, now time.Time) string {
	incoming := audit.HashToken(cred, pepper)
	for i := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(incoming), []byte(s.tokens[i].Hash)) != 1 {
			continue
		}
		if exp := s.tokens[i].ExpiresAt; exp != nil && exp.Before(now) {
			return ""
		}
		return s.byToken[s.tokens[i].ID]
	}
	return ""
}

// IdentityMiddleware stashes the resolved identity in the request context, so
// every audit and discovery write downstream names the host rather than only
// the address it came from.
//
// resolve is called per request rather than per chain build, on the same rule
// the ACL lists follow: a binding written on a running server takes effect
// without the chain being rebuilt.
//
// It admits nothing and refuses nothing. A request with no credential, an
// unknown credential or an expired one reaches the next handler exactly as it
// did before this middleware existed; all that changes is what the row says.
func IdentityMiddleware(resolve func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if resolve == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := resolve(r)
			if id == "" {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
		})
	}
}

// identityNow returns the current binding set, refreshing it when the cache
// has aged out. Same TTL and same double-check as aclNow, so a `bodega
// identity bind` and a `bodega acl` issued in the same minute land together.
func (s *Server) identityNow() *identitySet {
	if set := s.identityCached(); set != nil {
		return set
	}
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if set := s.identityCached(); set != nil {
		return set
	}
	return s.storeIdentities(s.resolveIdentities(context.Background()))
}

func (s *Server) identityCached() *identitySet {
	set := s.identity.Load()
	if set == nil {
		return nil
	}
	if time.Since(time.Unix(0, s.identityAt.Load())) >= aclCacheTTL {
		return nil
	}
	return set
}

func (s *Server) storeIdentities(set *identitySet) *identitySet {
	s.identity.Store(set)
	s.identityAt.Store(time.Now().UnixNano())
	s.logInertCIDRBindings(set)
	return set
}

// logInertCIDRBindings reports the state guardCIDRBindings refuses to start in,
// once on entering it and once on leaving. Only a bind against a running server
// reaches it, so the startup refusal never printed and the one stderr line
// `identity bind` writes is all the operator got — from a command that commonly
// runs under config management with its output discarded. Error level, because
// log_level defaults to Error and anything quieter is written for nobody.
func (s *Server) logInertCIDRBindings(set *identitySet) {
	inert := len(set.cidr) > 0 && !s.aclNow().trustedSet
	if s.cidrInert.Swap(inert) == inert {
		return
	}
	if !inert {
		s.logger.Info("trusted_proxies is answered; CIDR identity bindings resolve again")
		return
	}
	s.logger.Error("CIDR identity bindings are inert while trusted_proxies is still the built-in default; requests from a bound network are recorded unidentified",
		"bindings", len(set.cidr),
		"remedy", "bodega acl proxies add <proxy-cidr>, or \"trusted_proxies\": [] to trust no forwarded header")
}

// refreshIdentities re-reads the binding table regardless of cache age, so
// SIGHUP lands a binding change at once rather than within the TTL.
func (s *Server) refreshIdentities(ctx context.Context) {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	s.storeIdentities(s.resolveIdentities(ctx))
}

// resolveIdentities reads the binding table and the token hashes it keys on.
// A read that fails keeps the last good set rather than emptying: attributing
// the fleet to nobody because one query timed out would read in the audit
// trail as a fleet that stopped identifying itself.
func (s *Server) resolveIdentities(ctx context.Context) *identitySet {
	if s.auditDB == nil {
		return newIdentitySet(nil, nil)
	}
	bindings, err := s.auditDB.ListIdentityBindings(ctx)
	if err != nil {
		s.logger.Error("could not read the identity bindings; keeping the last set",
			"error", err)
		if set := s.identity.Load(); set != nil {
			return set
		}
		return newIdentitySet(nil, nil)
	}
	var tokens []audit.TokenHash
	if hasTokenBinding(bindings) {
		tokens, err = s.auditDB.GetTokenHashes(ctx)
		if err != nil {
			s.logger.Error("could not read token hashes for identity resolution; token bindings are inert until this clears",
				"error", err)
		}
	}
	return newIdentitySet(bindings, tokens)
}

func hasTokenBinding(bindings []audit.IdentityBinding) bool {
	for _, b := range bindings {
		if b.Kind == audit.BindToken {
			return true
		}
	}
	return false
}

// identityFunc hands the middleware a live view of the binding table.
func (s *Server) identityFunc() func(*http.Request) string {
	return func(r *http.Request) string {
		set := s.identityNow()
		if len(set.byToken) == 0 && len(set.cidr) == 0 {
			return ""
		}
		cred, _ := credentialFrom(r)
		return set.resolve(cred, ClientIP(r), s.pepper, time.Now(), s.cidrBindingsTrusted())
	}
}

// cidrBindingsTrusted reports whether an address may name a host on this
// request. It is the same predicate guardCIDRBindings refuses to start on, read
// where the binding is consumed rather than only where the process boots.
//
// Startup is not the only way into that state, and it is the rarer one. An
// operator binds on a server that is already running: guardCIDRBindings ran at
// boot with no bindings and passed, SIGHUP and the cache TTL then install the
// new binding with nothing between them and the read path. The instance ends up
// serving the arrangement it would have refused to start carrying.
//
// So with trusted_proxies unanswered the CIDR half resolves as absent. Token
// bindings still resolve, because a credential is a claim the caller had to
// hold; an address is a claim any RFC 1918 peer can make with a header. The
// request is served either way and the row simply names nobody.
func (s *Server) cidrBindingsTrusted() bool { return s.aclNow().trustedSet }

// guardCIDRBindings refuses to start an instance where a CIDR binding is
// assertable by whoever sends a header.
//
// trusted_proxies defaults to loopback plus RFC 1918, and a peer inside that
// set has its X-Real-IP believed verbatim. So on a default-configured
// instance, any RFC 1918 peer can name itself 10.1.2.3 and collect whatever
// identity 10.1.0.0/16 is bound to. A token binding has no such hole: the
// credential is the claim.
//
// A refusal rather than a warning, on the same rule as the empty
// admin_permit_cidr refusal: log_level defaults to Error, so a warning here
// is written for nobody and the instance runs anyway.
func (s *Server) guardCIDRBindings(ctx context.Context) error {
	if s.auditDB == nil {
		return nil
	}
	if s.aclNow().trustedSet {
		return nil // the operator answered, whichever way
	}
	n, err := s.auditDB.CIDRBindingCount(ctx)
	if err != nil || n == 0 {
		return err
	}
	return &cidrBindingTrustError{bindings: n}
}

// cidrBindingTrustError is the startup refusal. A type rather than a string so
// a test can assert the condition without matching prose.
type cidrBindingTrustError struct{ bindings int }

func (e *cidrBindingTrustError) Error() string {
	noun, verb := "CIDR identity bindings", "exist"
	if e.bindings == 1 {
		noun, verb = "CIDR identity binding", "exists"
	}
	return fmt.Sprintf("refusing to serve: %d %s %s while trusted_proxies is still the built-in default (loopback + RFC 1918).\n"+
		"  Every peer in that range has its X-Real-IP believed verbatim, so any of them can claim\n"+
		"  an address inside a bound network and collect that identity. Answer trusted_proxies\n"+
		"  either way:\n"+
		"    bodega acl proxies add <proxy-cidr>     name the proxy that terminates for clients\n"+
		"    \"trusted_proxies\": [] in %s\n"+
		"                                            trust no forwarded header from anyone\n"+
		"  Leaving the default is what is not accepted.\n"+
		"  The live list:  bodega acl proxies list\n"+
		"  The bindings:   bodega identity list", e.bindings, noun, verb, config.ConfigPath())
}
