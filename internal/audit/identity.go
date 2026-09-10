package audit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Binding kinds. A token binding names the credential a request presented; a
// CIDR binding names the network its resolved address falls in.
const (
	BindToken = "token"
	BindCIDR  = "cidr"
)

// BindKinds returns the two kinds in a stable order, for error text and the
// CLI's own listing.
func BindKinds() []string { return []string{BindToken, BindCIDR} }

// ValidBindKind reports whether kind is one of the two.
func ValidBindKind(kind string) bool { return kind == BindToken || kind == BindCIDR }

// ErrUnknownBindKind is returned for a kind outside the two above.
var ErrUnknownBindKind = errors.New("unknown binding kind")

// IdentityBinding maps one observable request attribute to a name. Key is a
// token id for BindToken and a masked CIDR for BindCIDR.
type IdentityBinding struct {
	Kind      string
	Key       string
	Identity  string
	Comment   string
	Actor     string
	CreatedAt time.Time
}

// BindingConflict is the refusal that keeps ambiguity out of the read path. It
// names the binding already in the table, because "conflict" without the other
// side of it leaves an operator running a second command to find out what they
// collided with.
//
// Reason distinguishes the two ways a write is ambiguous: the same key already
// naming a different identity, and a second CIDR of the same prefix length
// covering an address the first already covers. Every write through
// AddIdentityBinding is the first, because NormalizeBindCIDR makes the key the
// address set; the second is there for a row that reached the table some other
// way.
type BindingConflict struct {
	Existing IdentityBinding
	Want     IdentityBinding
	Reason   string
}

func (e *BindingConflict) Error() string {
	return fmt.Sprintf(
		"refusing to bind %s %s to %q: %s.\n"+
			"  Already bound: %s %s -> %s\n"+
			"  Remove it first (bodega identity unbind %s %s), or bind to the same identity",
		e.Want.Kind, e.Want.Key, e.Want.Identity, e.Reason,
		e.Existing.Kind, e.Existing.Key, e.Existing.Identity,
		e.Existing.Kind, e.Existing.Key)
}

// IsBindingConflict reports whether err is a write refused for ambiguity, so a
// caller can print the store's own explanation rather than wrapping it.
func IsBindingConflict(err error) bool {
	var c *BindingConflict
	return errors.As(err, &c)
}

// NormalizeBindCIDR renders a CIDR in the one form the table stores: masked,
// and with an IPv4-mapped IPv6 prefix folded back to IPv4. A bare address
// becomes a host route.
//
// Both normalizations exist so that equality of the key is equality of the
// address set. Without masking, 10.0.0.5/8 and 10.0.0.0/8 are two rows naming
// one network; without unmapping, ::ffff:10.0.0.0/104 is a third.
func NormalizeBindCIDR(in string) (netip.Prefix, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return netip.Prefix{}, errors.New("empty CIDR")
	}
	if !strings.Contains(in, "/") {
		addr, err := netip.ParseAddr(in)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is neither a CIDR nor an address: %w", in, err)
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(in)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR: %w", in, err)
	}
	if addr := p.Addr(); addr.Is4In6() {
		// A /104 over ::ffff:10.0.0.0 is a /8 over 10.0.0.0. Rebase the bit
		// count on the unmapped address so the two spellings share a key.
		bits := p.Bits() - (addr.BitLen() - addr.Unmap().BitLen())
		if bits < 0 {
			return netip.Prefix{}, fmt.Errorf("%q covers more than the IPv4-mapped range it names", in)
		}
		p = netip.PrefixFrom(addr.Unmap(), bits)
	}
	return p.Masked(), nil
}

// AddIdentityBinding writes one binding, refusing anything the read path would
// otherwise have to disambiguate. Two refusals, both at write time:
//
//   - the key is already bound to a different identity
//   - a CIDR of the same prefix length already covers an address this one does
//
// Normalizing the CIDR first collapses the second into the first: masked and
// with the IPv4-mapped spelling folded back, two prefixes of equal length are
// either the same key or disjoint. So ::ffff:10.0.0.0/104 against 10.0.0.0/8
// is refused as the key collision it is, and the overlap check below only ever
// fires on a row written around this function.
//
// Rebinding a key to the identity it already has is a no-op reporting false.
func (a *DB) AddIdentityBinding(ctx context.Context, b IdentityBinding) (bool, error) {
	if !ValidBindKind(b.Kind) {
		return false, fmt.Errorf("%w: %q (want one of: %s)", ErrUnknownBindKind, b.Kind, strings.Join(BindKinds(), ", "))
	}
	b.Key = strings.TrimSpace(b.Key)
	b.Identity = strings.TrimSpace(b.Identity)
	if b.Key == "" {
		return false, fmt.Errorf("a %s binding needs a key", b.Kind)
	}
	if b.Identity == "" {
		return false, errors.New("a binding needs an identity to bind to")
	}
	if b.Kind == BindCIDR {
		p, err := NormalizeBindCIDR(b.Key)
		if err != nil {
			return false, err
		}
		b.Key = p.String()
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}

	existing, err := a.ListIdentityBindings(ctx)
	if err != nil {
		return false, err
	}
	if conflict := findBindingConflict(existing, b); conflict != nil {
		return false, conflict
	}
	for _, e := range existing {
		if e.Kind == b.Kind && e.Key == b.Key {
			return false, nil // same key, same identity
		}
	}

	_, err = a.db.ExecContext(ctx,
		`INSERT INTO identity_bindings (kind, bind_key, identity, comment, actor) VALUES (?, ?, ?, ?, ?)`,
		b.Kind, b.Key, b.Identity, b.Comment, b.Actor)
	if err != nil {
		return false, err
	}
	return true, nil
}

// findBindingConflict returns the refusal want would produce against existing,
// or nil. Split out from AddIdentityBinding so the rule is testable without a
// database and so the CLI can preview it.
func findBindingConflict(existing []IdentityBinding, want IdentityBinding) *BindingConflict {
	for _, e := range existing {
		if e.Kind == want.Kind && e.Key == want.Key && e.Identity != want.Identity {
			return &BindingConflict{Existing: e, Want: want,
				Reason: fmt.Sprintf("that %s is already bound to %q", e.Kind, e.Identity)}
		}
	}
	if want.Kind != BindCIDR {
		return nil
	}
	// Unreachable for anything NormalizeBindCIDR touched, and kept for what it
	// did not: a row inserted straight into the table can carry an unmasked
	// key like 10.0.0.5/8, which the loop above does not match against
	// 10.0.0.0/8 and which Overlaps does.

	wp, err := netip.ParsePrefix(want.Key)
	if err != nil {
		return nil
	}
	for _, e := range existing {
		if e.Kind != BindCIDR || e.Key == want.Key {
			continue
		}
		ep, err := netip.ParsePrefix(e.Key)
		if err != nil || ep.Bits() != wp.Bits() {
			continue
		}
		if ep.Overlaps(wp) {
			return &BindingConflict{Existing: e, Want: want,
				Reason: fmt.Sprintf("%s covers the same addresses at the same prefix length, so longest-prefix resolution could not choose between them", e.Key)}
		}
	}
	return nil
}

// ListIdentityBindings returns every binding, ordered by kind then key.
func (a *DB) ListIdentityBindings(ctx context.Context) ([]IdentityBinding, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT kind, bind_key, identity, comment, actor, created_at FROM identity_bindings ORDER BY kind, bind_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IdentityBinding
	for rows.Next() {
		var b IdentityBinding
		var ts string
		if err := rows.Scan(&b.Kind, &b.Key, &b.Identity, &b.Comment, &b.Actor, &ts); err != nil {
			return nil, err
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, b)
	}
	return out, rows.Err()
}

// CIDRBindingCount reports how many CIDR bindings exist. `bodega serve` asks
// this before it binds a listener: a CIDR binding on an instance that believes
// X-Real-IP from every RFC 1918 peer is assertable by any of them.
func (a *DB) CIDRBindingCount(ctx context.Context) (int, error) {
	var n int
	err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM identity_bindings WHERE kind = ?`, BindCIDR).Scan(&n)
	return n, err
}

// RemoveIdentityBinding deletes one binding, reporting whether it was there.
func (a *DB) RemoveIdentityBinding(ctx context.Context, kind, key string) (bool, error) {
	if !ValidBindKind(kind) {
		return false, fmt.Errorf("%w: %q (want one of: %s)", ErrUnknownBindKind, kind, strings.Join(BindKinds(), ", "))
	}
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	if kind == BindCIDR {
		p, err := NormalizeBindCIDR(key)
		if err != nil {
			return false, err
		}
		key = p.String()
	}
	res, err := a.db.ExecContext(ctx,
		`DELETE FROM identity_bindings WHERE kind = ? AND bind_key = ?`, kind, key)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
