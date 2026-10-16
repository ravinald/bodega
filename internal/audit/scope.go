package audit

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/ravinald/bodega/internal/manifest"
)

// Scope names. read reaches the serving routes, write the package mutation
// routes, admin the policy, audit and configuration surface. read and write
// may be narrowed to package types. approve casts the votes on an override
// and resolves a refusal-queue row; superadmin mints, lists and revokes
// tokens. Each is granted only by naming it: admin implies neither, so the
// operator who sets policy does not also approve exceptions to it or mint a
// second voter. inventory reaches the push routes inventory sources
// register, plus reads, and combines with nothing: it is the credential a
// host holds to report what it installed, and its reads are that same host
// fetching packages.
const (
	ScopeRead       = "read"
	ScopeWrite      = "write"
	ScopeAdmin      = "admin"
	ScopeApprove    = "approve"
	ScopeSuperadmin = "superadmin"
	ScopeInventory  = "inventory"

	// ScopeFull is every scope but inventory with no type restriction: what a
	// token minted before scopes existed holds after migrations 036 and 037.
	ScopeFull = "read,write,admin,approve,superadmin"

	// scopeLegacyFull is the stored value migration 036 rewrote. A store
	// opened read-only is never migrated, so the parser still reads it, as
	// ScopeFull: what 036 and 037 together would have made it.
	scopeLegacyFull = "full"
)

// Grant is one scope a token holds. Types empty means every package type.
type Grant struct {
	Name  string
	Types []string
}

func (g Grant) String() string {
	if len(g.Types) == 0 {
		return g.Name
	}
	return g.Name + ":" + strings.Join(g.Types, ",")
}

// Scopes is a token's grants in canonical order (scopeOrder), each at most
// once, types sorted.
type Scopes []Grant

var scopeOrder = []string{ScopeRead, ScopeWrite, ScopeAdmin, ScopeApprove, ScopeSuperadmin, ScopeInventory}

// ParseScopes reads a scope list. Grants are separated by commas or spaces,
// and a grant's types follow a colon with commas between them, so
// "read,write:npm,pypi,admin" is read, write narrowed to npm and pypi, and
// admin. That is unambiguous because no package type is named like a scope.
func ParseScopes(s string) (Scopes, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(fields) == 0 {
		return nil, fmt.Errorf("no scope given: want one or more of read, write (each optionally :<type>,...), admin, approve, superadmin, or inventory")
	}
	byName := map[string]*Grant{}
	untyped := map[string]bool{}
	var current *Grant
	for _, f := range fields {
		if f == scopeLegacyFull {
			for _, n := range []string{ScopeRead, ScopeWrite, ScopeAdmin, ScopeApprove, ScopeSuperadmin} {
				untyped[n] = true
				byName[n] = &Grant{Name: n}
			}
			current = nil
			continue
		}
		name, typ, typed := strings.Cut(f, ":")
		if !typed && !isScopeName(name) {
			if current == nil || untyped[current.Name] {
				return nil, fmt.Errorf("unknown scope %q: want read, write (each optionally :<type>,...), admin, approve, superadmin, or inventory", f)
			}
			typ, name, typed = f, current.Name, true
		}
		if !isScopeName(name) {
			return nil, fmt.Errorf("unknown scope %q: want read, write (each optionally :<type>,...), admin, approve, superadmin, or inventory", name)
		}
		g := byName[name]
		if g == nil {
			g = &Grant{Name: name}
			byName[name] = g
		}
		current = g
		if !typed {
			untyped[name] = true
			continue
		}
		if name != ScopeRead && name != ScopeWrite {
			return nil, fmt.Errorf("scope %q takes no package types: the routes it reaches are not per type", name)
		}
		if !manifest.IsKnownType(typ) {
			return nil, fmt.Errorf("unknown package type %q in scope %s: want one of %s", typ, name, strings.Join(manifest.AllTypes, ", "))
		}
		if !slices.Contains(g.Types, typ) {
			g.Types = append(g.Types, typ)
		}
	}
	if byName[ScopeInventory] != nil && len(byName) > 1 {
		return nil, fmt.Errorf("scope inventory combines with no other scope: mint a second token for anything else")
	}
	var out Scopes
	for _, n := range scopeOrder {
		g := byName[n]
		if g == nil {
			continue
		}
		if untyped[n] {
			g.Types = nil
		}
		slices.Sort(g.Types)
		out = append(out, *g)
	}
	return out, nil
}

func isScopeName(s string) bool { return slices.Contains(scopeOrder, s) }

// CanonicalScopes parses s and renders it back in canonical order.
func CanonicalScopes(s string) (string, error) {
	sc, err := ParseScopes(s)
	if err != nil {
		return "", err
	}
	return sc.String(), nil
}

func (s Scopes) String() string {
	parts := make([]string, len(s))
	for i, g := range s {
		parts[i] = g.String()
	}
	return strings.Join(parts, ",")
}

// Allows reports whether the scopes reach a route needing name for pkgType.
// An empty pkgType is a route not tied to one type, which any grant of name
// reaches, narrowed or not. inventory reads as read: an inventory token is
// also the credential its host fetches packages with.
func (s Scopes) Allows(name, pkgType string) bool {
	for _, g := range s {
		if g.Name == ScopeInventory && name == ScopeRead {
			return true
		}
		if g.Name != name {
			continue
		}
		if len(g.Types) == 0 || pkgType == "" || slices.Contains(g.Types, pkgType) {
			return true
		}
	}
	return false
}

// Has reports whether s holds a grant named name, narrowed or not.
func (s Scopes) Has(name string) bool {
	return slices.ContainsFunc(s, func(g Grant) bool { return g.Name == name })
}

// HoldsAll reports whether s carries read, write and admin with no type
// restriction on any of them: the scope a pre-scope token migrated to.
func (s Scopes) HoldsAll() bool {
	n := 0
	for _, g := range s {
		if len(g.Types) == 0 && (g.Name == ScopeRead || g.Name == ScopeWrite || g.Name == ScopeAdmin) {
			n++
		}
	}
	return n == 3
}

// ValidTokenScope reports whether s is a scope list api_tokens accepts.
func ValidTokenScope(s string) bool {
	_, err := ParseScopes(s)
	return err == nil
}

// Principal is who an OIDC-exchanged token acts for: the ID token's subject
// and issuer. Every audit row a request carrying such a token writes names
// the subject as its actor and the issuer as its identity, so the trail
// reads as a person or a workflow rather than a token id.
type Principal struct {
	Subject string
	Issuer  string
}

// Identity is the name the override quorum counts this principal under:
// the issuer, "#", then the subject. It is distinct per (issuer, subject),
// so every workflow one provider vouches for is its own voter, and stable
// across exchanges, so a subject exchanging twice is still one voter. An
// OIDC issuer is a URL with no fragment, so the first "#" splits the two.
func (p Principal) Identity() string {
	return p.Issuer + "#" + p.Subject
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p, for Record to stamp on every row
// written under it.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal ctx carries, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.Subject != ""
}
