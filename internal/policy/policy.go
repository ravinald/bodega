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
	"errors"
	"fmt"
	"maps"
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
	case manifest.TypePypi, manifest.TypeNpm, manifest.TypeCargo, manifest.TypeMaven:
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

// ModeStore is the store half that holds the admission mode an operator set.
// *audit.DB satisfies it. A Store without it has no set modes, so every type
// takes the mode its rules imply.
type ModeStore interface {
	GetAdmissionMode(ctx context.Context, ecosystem string) (audit.AdmissionMode, error)
}

// Mode is how a type decides which names it admits, and whether an operator
// set that or the allow-list implied it.
type Mode struct {
	Mode string // audit.ModeListed or audit.ModeOpen
	// Set is true when an operator chose Mode with `policy mode set`. False
	// means it follows the rules: listed with any, open with none.
	Set bool
	// Rules is how many allow-list rules the type has.
	Rules int
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
	modes  map[string]string
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
		modes:    make(map[string]string),
		loaded:   make(map[string]time.Time),
	}
}

// Invalidate clears the cache. Call after policy add/remove so the next Check
// sees fresh rules without waiting for TTL expiry.
func (c *Checker) Invalidate() {
	c.mu.Lock()
	c.cache = make(map[string][]Rule)
	c.modes = make(map[string]string)
	c.loaded = make(map[string]time.Time)
	c.mu.Unlock()
}

// Check returns nil if candidate is permitted under the current allow-list for
// registryType. A type in open mode admits every name, which is what a type
// with no rules and no mode set is; a type in listed mode admits only a name
// a rule matches, none at all when it has no rules. A non-matching candidate
// returns a *ViolationError suitable for errors.As / IsViolation.
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
	rules, mode, err := c.load(ctx, registryType)
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}
	if mode.Mode == audit.ModeOpen {
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

// load returns the type's rules and its mode, through the cache.
func (c *Checker) load(ctx context.Context, registryType string) ([]Rule, Mode, error) {
	c.mu.RLock()
	if ts, ok := c.loaded[registryType]; ok && time.Since(ts) < c.cacheTTL {
		rules, set := c.cache[registryType], c.modes[registryType]
		c.mu.RUnlock()
		return rules, modeOf(rules, set), nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check after acquiring write lock — another goroutine may have loaded.
	if ts, ok := c.loaded[registryType]; ok && time.Since(ts) < c.cacheTTL {
		rules, set := c.cache[registryType], c.modes[registryType]
		return rules, modeOf(rules, set), nil
	}
	rules, err := c.store.GetPoliciesByType(ctx, registryType)
	if err != nil {
		return nil, Mode{}, err
	}
	set := ""
	if ms, ok := c.store.(ModeStore); ok {
		m, err := ms.GetAdmissionMode(ctx, registryType)
		switch {
		case err == nil:
			set = m.Mode
		case !errors.Is(err, audit.ErrAdmissionModeNotFound):
			return nil, Mode{}, fmt.Errorf("load admission mode: %w", err)
		}
	}
	c.cache[registryType] = rules
	c.modes[registryType] = set
	c.loaded[registryType] = time.Now()
	return rules, modeOf(rules, set), nil
}

// modeOf resolves a type's mode from the mode set for it, empty when none
// was, and its rules.
func modeOf(rules []Rule, set string) Mode {
	m := Mode{Mode: set, Set: set != "", Rules: len(rules)}
	if !m.Set {
		m.Mode = audit.ModeOpen
		if len(rules) > 0 {
			m.Mode = audit.ModeListed
		}
	}
	return m
}

// ModeFor returns the admission mode registryType is in. A nil checker is
// open: there is no allow-list to list anything.
func (c *Checker) ModeFor(ctx context.Context, registryType string) (Mode, error) {
	if c == nil {
		return Mode{Mode: audit.ModeOpen}, nil
	}
	_, m, err := c.load(ctx, registryType)
	return m, err
}

// Listed reports whether the allow-list decides which names registryType
// admits: true in listed mode, false in open mode. It is what an admission
// row's allow-list action and a discovery row's no_policy turn on.
func (c *Checker) Listed(ctx context.Context, registryType string) (bool, error) {
	if c == nil {
		return false, nil
	}
	m, err := c.ModeFor(ctx, registryType)
	if err != nil {
		return false, err
	}
	return m.Mode == audit.ModeListed, nil
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
	case manifest.TypeMaven:
		return matchMaven(candidate, r.Pattern)
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
	if KeysByName(registryType) {
		return packageName
	}
	return entryURL
}

// KeysByName reports whether the allow-list for registryType rules on the
// package name rather than on an upstream URL.
func KeysByName(registryType string) bool {
	switch registryType {
	case manifest.TypePypi, manifest.TypeNpm, manifest.TypeGomod, manifest.TypeCargo, manifest.TypeMaven:
		return true
	}
	return false
}

// matchMaven handles an exact <groupId>:<artifactId> plus <groupId>:*, which
// admits every artifact of one groupId and no groupId nested under it: a JVM
// framework publishes dozens of artifacts under one groupId, and
// org.springframework:* is not a claim about org.springframework.boot.
func matchMaven(candidate, pattern string) bool {
	if candidate == pattern {
		return true
	}
	group, ok := strings.CutSuffix(pattern, ":*")
	if !ok {
		return false
	}
	candGroup, _, found := strings.Cut(candidate, ":")
	return found && candGroup == group
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
	case manifest.TypeCargo, manifest.TypeMaven:
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

// DigestStore is what Digest reads: every row of the tables an admission
// decision is judged against. *audit.DB satisfies it.
type DigestStore interface {
	ListPolicies(ctx context.Context) ([]audit.PolicyInfo, error)
	ListAgePolicies(ctx context.Context) ([]audit.AgePolicy, error)
	ListOSVPolicies(ctx context.Context) ([]audit.OSVPolicy, error)
	ListOSVMalwarePolicies(ctx context.Context) ([]audit.OSVMalwarePolicy, error)
	ListProvenancePolicies(ctx context.Context) ([]audit.ProvenancePolicy, error)
	ListSimilarityPolicies(ctx context.Context) ([]audit.SimilarityPolicy, error)
	ListPopularLists(ctx context.Context) ([]audit.PopularList, error)
	ListIntegrationPolicies(ctx context.Context) ([]audit.IntegrationPolicy, error)
}

// Digest returns "sha256:<hex>" over a canonical serialization of the
// allow-list rules, the age_policy, osv_policy, osv_malware_policy,
// upstream_provenance_policy, name_similarity_policy and integration_policy
// rows, and the SHA-256 of the popular-name list in force for each ecosystem,
// which is what an admission row cites as the policy it was decided under.
// The malware rows are in it because the OSV check refuses on them too, with
// a default of block that an absent osv_policy row does not turn off. The
// popular lists are in it because loading one changes which names fail.
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
	provenance, err := store.ListProvenancePolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list upstream provenance policies: %w", err)
	}
	similarity, err := store.ListSimilarityPolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list name similarity policies: %w", err)
	}
	loaded, err := store.ListPopularLists(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list popular-name lists: %w", err)
	}
	integrations, err := store.ListIntegrationPolicies(ctx)
	if err != nil {
		return "", fmt.Errorf("policy digest: list integration policies: %w", err)
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
	type integration struct {
		Instance  string `json:"instance"`
		Ecosystem string `json:"ecosystem"`
		Action    string `json:"action"`
	}
	canon := struct {
		Version   int    `json:"v"`
		AllowList []rule `json:"allowlist"`
		Age       []age  `json:"age"`
		OSV       []osv  `json:"osv"`
		Malware   []osv  `json:"osv_malware"`
		// Provenance reuses osv's two fields: an ecosystem and an action.
		Provenance []osv `json:"upstream_provenance"`
		Similarity []osv `json:"name_similarity"`
		// Popular reuses osv's fields too: an ecosystem and the list's hash.
		Popular []osv `json:"popular_lists"`
		// Integrations is omitted when empty, so an install with no
		// integration_policy row cites the digest it cited before the table
		// existed.
		Integrations []integration `json:"integrations,omitempty"`
	}{Version: 1, AllowList: []rule{}, Age: []age{}, OSV: []osv{}, Malware: []osv{}, Provenance: []osv{}, Similarity: []osv{}}
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
	for _, p := range provenance {
		canon.Provenance = append(canon.Provenance, osv{p.Ecosystem, p.Action})
	}
	for _, p := range similarity {
		canon.Similarity = append(canon.Similarity, osv{p.Ecosystem, p.Action})
	}
	for _, p := range integrations {
		canon.Integrations = append(canon.Integrations, integration{p.Instance, p.Ecosystem, p.Action})
	}
	slices.SortFunc(canon.Integrations, func(a, b integration) int {
		return strings.Compare(a.Instance+"\x00"+a.Ecosystem, b.Instance+"\x00"+b.Ecosystem)
	})
	lists := map[string]string{}
	for _, eco := range SimilarityEcosystems() {
		if p, ok := EmbeddedPopularNames(eco); ok {
			lists[eco] = p.SHA256
		}
	}
	for _, l := range loaded {
		lists[l.Ecosystem] = l.SHA256
	}
	for _, eco := range slices.Sorted(maps.Keys(lists)) {
		canon.Popular = append(canon.Popular, osv{eco, lists[eco]})
	}
	slices.SortFunc(canon.AllowList, func(a, b rule) int {
		return strings.Compare(a.Type+"\x00"+a.Kind+"\x00"+a.Pattern, b.Type+"\x00"+b.Kind+"\x00"+b.Pattern)
	})
	slices.SortFunc(canon.Age, func(a, b age) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	slices.SortFunc(canon.OSV, func(a, b osv) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	slices.SortFunc(canon.Malware, func(a, b osv) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	slices.SortFunc(canon.Provenance, func(a, b osv) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })
	slices.SortFunc(canon.Similarity, func(a, b osv) int { return strings.Compare(a.Ecosystem, b.Ecosystem) })

	blob, err := json.Marshal(canon)
	if err != nil {
		return "", fmt.Errorf("policy digest: %w", err)
	}
	sum := sha256.Sum256(blob)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
