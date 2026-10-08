// Package policy implements the upstream allow-list. Operators declare which
// upstream sources are trusted per registry type (apt hosts, git orgs, pypi
// package names, etc.); bodega enforces those rules at every fetch/import
// point. An empty policy table means no enforcement — the feature is opt-in.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// Rule kinds. Each registry type accepts exactly one kind (see RuleKindForType).
const (
	KindHost    = "host"    // apt: match URL hostname
	KindOrg     = "org"     // git: HasPrefix after stripping scheme
	KindPackage = "package" // pypi/npm: match normalized package name
	KindPrefix  = "prefix"  // gomod/helm/binary: HasPrefix
)

// Rule is an alias for the audit-package type so the policy package owns the
// matcher semantics while audit owns persistence.
type Rule = audit.PolicyInfo

// RuleKindForType returns the rule kind a given registry type uses. Returns
// empty string for unknown types.
func RuleKindForType(registryType string) string {
	switch registryType {
	case manifest.TypeApt, manifest.TypeFreeBSD, manifest.TypeDistfiles:
		// All three are archive mirrors: what an operator trusts is the
		// archive host, not a package name, because the request that reaches
		// upstream carries a pool path, a repopath or a distinfo name and no
		// package identity at all. A distfile's digest says the bytes are
		// right; it does not say the operator agreed to contact the host.
		return KindHost
	case manifest.TypeGit:
		return KindOrg
	case manifest.TypePypi, manifest.TypeNpm, manifest.TypeCargo:
		return KindPackage
	case manifest.TypeGomod, manifest.TypeHelm, manifest.TypeBinary:
		return KindPrefix
	}
	return ""
}

// ValidateType returns an error if registryType is not one of the supported
// manifest types.
func ValidateType(registryType string) error {
	if slices.Contains(manifest.AllTypes, registryType) {
		return nil
	}
	return fmt.Errorf("unknown registry type %q (expected one of: %s)",
		registryType, strings.Join(manifest.AllTypes, ", "))
}

// Store is the persistence interface used by the Checker. *audit.DB satisfies
// this interface; tests can substitute fakes.
type Store interface {
	GetPoliciesByType(ctx context.Context, registryType string) ([]Rule, error)
}

// DefaultCacheTTL is the in-memory cache duration for loaded rules. Mirrors
// the token-hash cache in server/middleware.go.
const DefaultCacheTTL = 30 * time.Second

// Checker loads rules from a Store on demand and evaluates candidate URLs or
// package names against them. Concurrent callers share a read-through cache
// keyed by registry type.
type Checker struct {
	store    Store
	cacheTTL time.Duration

	mu     sync.RWMutex
	cache  map[string][]Rule
	loaded map[string]time.Time
}

// CheckerFor returns a Checker reading rules from db, or nil when db is nil.
// The nil has to be dropped before it becomes a Store: a nil *audit.DB wrapped
// in the interface is a non-nil Store whose every rule load panics, so the
// callers that pass an optional audit database go through here.
func CheckerFor(db *audit.DB) *Checker {
	if db == nil {
		return nil
	}
	return NewChecker(db)
}

// NewChecker returns a Checker backed by store.
func NewChecker(store Store) *Checker {
	return &Checker{
		store:    store,
		cacheTTL: DefaultCacheTTL,
		cache:    make(map[string][]Rule),
		loaded:   make(map[string]time.Time),
	}
}

// Invalidate clears the cache. Call after policy add/remove so the next Check
// sees fresh rules without waiting for TTL expiry.
func (c *Checker) Invalidate() {
	c.mu.Lock()
	c.cache = make(map[string][]Rule)
	c.loaded = make(map[string]time.Time)
	c.mu.Unlock()
}

// Check returns nil if candidate is permitted under the current allow-list for
// registryType. Empty rule set for a type means "allow" (opt-in feature).
// Non-matching candidate returns a *ViolationError suitable for
// errors.As / IsViolation.
//
// What to pass as `candidate` per type:
//   - apt:    upstream URL (hostname is extracted internally)
//   - git:    upstream URL
//   - pypi:   package name (not URL)
//   - npm:    package name (not URL), e.g. "lodash" or "@example-cloud/client-storage"
//   - gomod:  module path, e.g. "example.com/example-corp/widget-sdk"
//   - helm:   upstream URL
//   - binary: upstream URL
//   - distfiles: upstream URL (hostname is extracted internally)
func (c *Checker) Check(ctx context.Context, registryType, candidate string) error {
	if c == nil {
		return nil // nil checker = policy disabled entirely (test/dev convenience)
	}
	rules, err := c.rulesFor(ctx, registryType)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}
	if len(rules) == 0 {
		return nil
	}
	for _, r := range rules {
		if matchRule(registryType, r, candidate) {
			return nil
		}
	}
	return &ViolationError{
		RegistryType: registryType,
		Candidate:    candidate,
	}
}

func (c *Checker) rulesFor(ctx context.Context, registryType string) ([]Rule, error) {
	c.mu.RLock()
	if ts, ok := c.loaded[registryType]; ok && time.Since(ts) < c.cacheTTL {
		rules := c.cache[registryType]
		c.mu.RUnlock()
		return rules, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check after acquiring write lock — another goroutine may have loaded.
	if ts, ok := c.loaded[registryType]; ok && time.Since(ts) < c.cacheTTL {
		return c.cache[registryType], nil
	}
	rules, err := c.store.GetPoliciesByType(ctx, registryType)
	if err != nil {
		return nil, err
	}
	c.cache[registryType] = rules
	c.loaded[registryType] = time.Now()
	return rules, nil
}

func matchRule(registryType string, r Rule, candidate string) bool {
	switch registryType {
	case manifest.TypeApt, manifest.TypeFreeBSD, manifest.TypeDistfiles:
		return strings.EqualFold(hostFromURL(candidate), r.Pattern)
	case manifest.TypeGit:
		return strings.HasPrefix(stripScheme(candidate), stripScheme(r.Pattern))
	case manifest.TypePypi:
		return manifest.CanonicalPypiName(candidate) == manifest.CanonicalPypiName(r.Pattern)
	case manifest.TypeNpm:
		return matchNpm(candidate, r.Pattern)
	case manifest.TypeCargo:
		return candidate == r.Pattern
	case manifest.TypeGomod, manifest.TypeHelm, manifest.TypeBinary:
		return strings.HasPrefix(candidate, r.Pattern)
	}
	return false
}

// CandidateFor picks the string a caller should pass to Check based on type.
// For pypi/npm/gomod the package name is checked (the URL is a registry
// endpoint, not the thing being declared trusted); for everything else the
// upstream URL is checked directly.
func CandidateFor(registryType, packageName, entryURL string) string {
	switch registryType {
	case manifest.TypePypi, manifest.TypeNpm, manifest.TypeGomod, manifest.TypeCargo:
		return packageName
	}
	return entryURL
}

// matchNpm handles exact package names plus the `@scope/*` wildcard form.
func matchNpm(candidate, pattern string) bool {
	if candidate == pattern {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(candidate, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// HasRules reports whether any allow-list rules exist for registryType. The
// discovery hook calls this to distinguish "allowed by an explicit rule" from
// "no rules configured for this type" — both of which make Check return nil.
// Result respects the same TTL cache as Check.
func (c *Checker) HasRules(ctx context.Context, registryType string) (bool, error) {
	if c == nil {
		return false, nil
	}
	rules, err := c.rulesFor(ctx, registryType)
	if err != nil {
		return false, err
	}
	return len(rules) > 0, nil
}

// SuggestPattern returns the pattern a `policy add` call would use if an
// operator wanted to allow the given observation. The shape matches the rule
// kind for the type (see RuleKindForType): a hostname for apt, an org prefix
// for git, a package name for pypi/npm, a path prefix for gomod, and a full
// URL prefix for helm/binary.
//
// Inputs:
//   - host     : URL hostname (may be empty for name-scoped types)
//   - fullPath : URL path including the leading slash (may be empty)
//   - pkgName  : the package/module name; for gomod this is the module path
//
// The returned string is safe to feed directly into audit.InsertPolicy with
// RuleKindForType(regType).
func SuggestPattern(regType, host, fullPath, pkgName string) string {
	switch regType {
	case manifest.TypeApt, manifest.TypeFreeBSD, manifest.TypeDistfiles:
		return host
	case manifest.TypeGit:
		return host + "/" + firstSegment(fullPath) + "/"
	case manifest.TypePypi:
		return manifest.CanonicalPypiName(pkgName)
	case manifest.TypeNpm:
		if strings.HasPrefix(pkgName, "@") {
			if idx := strings.IndexByte(pkgName, '/'); idx > 0 {
				return pkgName[:idx] + "/*"
			}
		}
		return pkgName
	case manifest.TypeCargo:
		return pkgName
	case manifest.TypeGomod:
		// Module paths look like host/org/repo... — propose host+org/.
		parts := strings.SplitN(pkgName, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1] + "/"
		}
		return pkgName
	case manifest.TypeHelm, manifest.TypeBinary:
		seg := firstSegment(fullPath)
		if seg == "" {
			return "https://" + host + "/"
		}
		return "https://" + host + "/" + seg + "/"
	}
	return ""
}

// firstSegment returns the first non-empty `/`-separated segment of p. Returns
// "" for an empty path or "/".
func firstSegment(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	if idx := strings.IndexByte(p, '/'); idx >= 0 {
		return p[:idx]
	}
	return p
}

// DigestStore is what Digest reads: every row of the four tables an
// admission decision is judged against. *audit.DB satisfies it.
type DigestStore interface {
	ListPolicies(ctx context.Context) ([]audit.PolicyInfo, error)
	ListAgePolicies(ctx context.Context) ([]audit.AgePolicy, error)
	ListOSVPolicies(ctx context.Context) ([]audit.OSVPolicy, error)
	ListOSVMalwarePolicies(ctx context.Context) ([]audit.OSVMalwarePolicy, error)
}

// Digest returns "sha256:<hex>" over a canonical serialization of the
// allow-list rules and the age_policy, osv_policy and osv_malware_policy rows,
// which is what an admission row cites as the policy it was decided under.
// The malware rows are in it because the OSV check refuses on them too, with
// a default of block that an absent osv_policy row does not turn off.
//
// Only the fields that change a verdict are hashed. A rule's id, comment,
// author and timestamp are left out, so removing a rule and adding it back is
// the same policy, while editing a pattern, an action or a minimum age is not.
// Rows are sorted first so the digest does not depend on the order a query
// happens to return them in.
func Digest(ctx context.Context, store DigestStore) (string, error) {
	rules, err := store.ListPolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list allow-list rules: %w", err)
	}
	ages, err := store.ListAgePolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list age policies: %w", err)
	}
	osvs, err := store.ListOSVPolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list osv policies: %w", err)
	}
	malware, err := store.ListOSVMalwarePolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list osv malware policies: %w", err)
	}

	type rule struct {
		Type    string `json:"type"`
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
	}
	type age struct {
		Ecosystem     string `json:"ecosystem"`
		MinAgeSeconds int64  `json:"min_age_seconds"`
		Action        string `json:"action"`
	}
	type osv struct {
		Ecosystem string `json:"ecosystem"`
		Action    string `json:"action"`
	}
	canon := struct {
		Version   int    `json:"v"`
		AllowList []rule `json:"allowlist"`
		Age       []age  `json:"age"`
		OSV       []osv  `json:"osv"`
		Malware   []osv  `json:"osv_malware"`
	}{Version: 1, AllowList: []rule{}, Age: []age{}, OSV: []osv{}, Malware: []osv{}}
	for _, r := range rules {
		canon.AllowList = append(canon.AllowList, rule{r.RegistryType, r.RuleKind, r.Pattern})
	}
	for _, a := range ages {
		canon.Age = append(canon.Age, age{a.Ecosystem, a.MinAgeSeconds, a.Action})
	}
	for _, o := range osvs {
		canon.OSV = append(canon.OSV, osv{o.Ecosystem, o.Action})
	}
	for _, m := range malware {
		canon.Malware = append(canon.Malware, osv{m.Ecosystem, m.Action})
	}
	slices.SortFunc(canon.AllowList, func(a, b rule) int {
		return strings.Compare(a.Type+"\x00"+a.Kind+"\x00"+a.Pattern, b.Type+"\x00"+b.Kind+"\x00"+b.Pattern)
	})
	slices.SortFunc(canon.Age, func(a, b age) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	slices.SortFunc(canon.OSV, func(a, b osv) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	slices.SortFunc(canon.Malware, func(a, b osv) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })

	blob, err := json.Marshal(canon)
	if err != nil {
		return "", fmt.Errorf("policy digest: %w", err)
	}
	sum := sha256.Sum256(blob)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
