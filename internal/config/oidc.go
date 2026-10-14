package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

// DefaultOIDCTokenTTL is oidc_token_ttl when unset: the lifetime of a bodega
// token an OIDC exchange mints.
const DefaultOIDCTokenTTL = 15 * time.Minute

// OIDCProvider is one identity provider whose ID tokens bodega exchanges for
// its own. audience is what a CI job requests its token for (GitHub Actions
// and GitLab CI both let the job choose it); client_id is the OAuth client a
// person signs in through with `bodega login`. An ID token is accepted when
// its aud names either. Rules map the token's claims onto bodega scopes, and
// the first rule whose every claim matches decides.
type OIDCProvider struct {
	Name     string     `json:"name,omitempty"`
	Issuer   string     `json:"issuer"`
	ClientID string     `json:"client_id,omitempty"`
	Audience string     `json:"audience,omitempty"`
	Rules    []OIDCRule `json:"rules"`
}

// OIDCRule grants Scopes to an ID token whose claims match every entry of
// Claims. A value matches a string claim exactly, or as a glob where * spans
// any run of characters including "/"; against a list claim (groups) it
// matches when any element does.
type OIDCRule struct {
	Claims map[string]string `json:"claims"`
	Scopes string            `json:"scopes"`
}

// DisplayName is the provider's name, or its issuer's host when it has none.
func (p OIDCProvider) DisplayName() string {
	if p.Name != "" {
		return p.Name
	}
	if u, err := url.Parse(p.Issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return p.Issuer
}

// Audiences are the aud values an ID token from p may carry.
func (p OIDCProvider) Audiences() []string {
	var out []string
	for _, a := range []string{p.Audience, p.ClientID} {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// ResolveOIDCTokenTTL returns oidc_token_ttl, or the default when unset. Load
// has already refused a value that does not parse.
func (c *Config) ResolveOIDCTokenTTL() time.Duration {
	if c == nil || c.OIDCTokenTTL == "" {
		return DefaultOIDCTokenTTL
	}
	d, err := time.ParseDuration(c.OIDCTokenTTL)
	if err != nil || d <= 0 {
		return DefaultOIDCTokenTTL
	}
	return d
}

// validateOIDC refuses a provider list the exchange could only misread. Every
// failure here would otherwise surface as a 401 on a CI job, far from the
// config line that caused it.
func (c *Config) validateOIDC() error {
	if c.OIDCTokenTTL != "" {
		if d, err := time.ParseDuration(c.OIDCTokenTTL); err != nil || d <= 0 {
			return fmt.Errorf("invalid oidc_token_ttl %q (want a positive Go duration, e.g. \"15m\")", c.OIDCTokenTTL)
		}
	}
	names := map[string]bool{}
	issuers := map[string]bool{}
	for i, p := range c.OIDCProviders {
		where := fmt.Sprintf("oidc_providers[%d]", i)
		if err := validateIssuer(p.Issuer); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if issuers[p.Issuer] {
			return fmt.Errorf("%s: issuer %s is configured twice; one provider per issuer, with all its rules", where, p.Issuer)
		}
		issuers[p.Issuer] = true
		n := p.DisplayName()
		if names[n] {
			return fmt.Errorf("%s: name %q is taken by another provider; set name on one of them", where, n)
		}
		names[n] = true
		if len(p.Audiences()) == 0 {
			return fmt.Errorf("%s (%s): set audience (what CI jobs request their token for) or client_id (the OAuth client bodega login uses), or both", where, p.Issuer)
		}
		if len(p.Rules) == 0 {
			return fmt.Errorf("%s (%s): no rules, so every token it issues would be refused; add a rule mapping claims to scopes", where, p.Issuer)
		}
		for j, r := range p.Rules {
			if len(r.Claims) == 0 {
				return fmt.Errorf("%s.rules[%d]: no claims to match, which would grant its scopes to every token %s issues; name at least one claim (repository, ref, job_workflow_ref, sub, email, groups)", where, j, p.Issuer)
			}
			for k, v := range r.Claims {
				if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" || strings.Trim(v, "*") == "" {
					return fmt.Errorf("%s.rules[%d]: claim %q matches anything; give it a value that names something", where, j, k)
				}
			}
			sc, err := audit.ParseScopes(r.Scopes)
			if err != nil {
				return fmt.Errorf("%s.rules[%d]: %w", where, j, err)
			}
			if sc.Has(audit.ScopeInventory) {
				return fmt.Errorf("%s.rules[%d]: an exchange cannot grant inventory: inventory tokens are bound to a host with bodega identity bind", where, j)
			}
		}
	}
	return nil
}

// validateIssuer requires https. An issuer over http hands its signing keys to
// anything on the path, which then mints tokens bodega accepts. Loopback is
// the exception, for a test issuer on the same host.
func validateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return fmt.Errorf("issuer %q is not a URL", issuer)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("issuer %q must be https: its signing keys are fetched from it, and over http anything on the path could substitute its own", issuer)
}
