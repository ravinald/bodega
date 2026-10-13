package policy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// MaxSimilarityDistance is the furthest a candidate may be from a popular
// name and still count as near it. One or two edits covers the squats seen in
// the wild (a dropped, doubled, swapped or substituted character, or a
// separator added or removed) without reaching far enough to make every short
// name near every other.
const MaxSimilarityDistance = 2

//go:embed popular/*.txt
var popularFS embed.FS

// SimilarityEcosystems are the types the name-similarity check compares:
// the ones whose packages are named by whoever publishes them, on a registry
// anyone can publish to.
func SimilarityEcosystems() []string {
	return []string{manifest.TypeCargo, manifest.TypeNpm, manifest.TypePypi}
}

// NormalizeName is the form two names are compared in. pypi applies PEP 503,
// so `Py_Yaml` and `py-yaml` are one name; cargo lowercases and treats `_` as
// `-`, because crates.io refuses a crate differing from an existing one only
// in those ways; every other type lowercases.
func NormalizeName(typ, name string) string {
	name = strings.TrimSpace(name)
	switch typ {
	case manifest.TypePypi:
		return manifest.CanonicalPypiName(name)
	case manifest.TypeCargo:
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	}
	return strings.ToLower(name)
}

// PopularNames is the list one ecosystem's candidates are compared with.
type PopularNames struct {
	Ecosystem string
	// Names are as listed, most popular first; keys are their normalized
	// forms, index for index.
	Names []string
	keys  []string
	set   map[string]bool
	// Source and Date come from the list's header; Loaded says an operator
	// replaced the embedded list.
	Source string
	Date   string
	Loaded bool
	SHA256 string
}

// ParsePopularNames reads a list: one name per line, `#` comments, and the
// header keys `# source:` and `# date:` when present. A name repeated after
// normalization is kept once, at its first (most popular) position.
func ParsePopularNames(ecosystem string, data []byte) (PopularNames, error) {
	sum := sha256.Sum256(data)
	p := PopularNames{Ecosystem: ecosystem, set: map[string]bool{}, SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		if c, ok := strings.CutPrefix(text, "#"); ok {
			k, v, _ := strings.Cut(c, ":")
			switch strings.TrimSpace(k) {
			case "source":
				p.Source = strings.TrimSpace(v)
			case "date":
				p.Date = strings.TrimSpace(v)
			}
			continue
		}
		if strings.ContainsAny(text, " \t") {
			return PopularNames{}, fmt.Errorf("line %d: %q is not a package name: one name per line", line, text)
		}
		key := NormalizeName(ecosystem, text)
		if p.set[key] {
			continue
		}
		p.set[key] = true
		p.Names = append(p.Names, text)
		p.keys = append(p.keys, key)
	}
	if err := sc.Err(); err != nil {
		return PopularNames{}, err
	}
	if len(p.Names) == 0 {
		return PopularNames{}, errors.New("the list names no package")
	}
	return p, nil
}

var (
	embeddedOnce    sync.Once
	embeddedPopular map[string]PopularNames
)

// EmbeddedPopularNames is the list bodega ships for ecosystem, and false for
// an ecosystem it ships none for.
func EmbeddedPopularNames(ecosystem string) (PopularNames, bool) {
	embeddedOnce.Do(func() {
		embeddedPopular = map[string]PopularNames{}
		for _, eco := range SimilarityEcosystems() {
			data, err := popularFS.ReadFile("popular/" + eco + ".txt")
			if err != nil {
				panic("embedded popular list " + eco + ": " + err.Error())
			}
			p, err := ParsePopularNames(eco, data)
			if err != nil {
				panic("embedded popular list " + eco + ": " + err.Error())
			}
			embeddedPopular[eco] = p
		}
	})
	p, ok := embeddedPopular[ecosystem]
	return p, ok
}

// Contains reports whether name is itself on the list.
func (p PopularNames) Contains(name string) bool {
	return p.set[NormalizeName(p.Ecosystem, name)]
}

// Nearest returns the popular name closest to name and its distance. Ties go
// to the more popular. ok is false for an empty list.
func (p PopularNames) Nearest(name string) (popular string, distance int, ok bool) {
	key := NormalizeName(p.Ecosystem, name)
	best := -1
	for i, k := range p.keys {
		if best >= 0 && lengthGap(key, k) >= best {
			continue
		}
		d := nameDistance(p.Ecosystem, key, k)
		if best < 0 || d < best {
			best, popular = d, p.Names[i]
		}
	}
	return popular, best, best >= 0
}

// Near returns the popular name within MaxSimilarityDistance of name that
// name is not equal to, and the distance; ok is false when there is none, or
// when name is itself popular.
func (p PopularNames) Near(name string) (popular string, distance int, ok bool) {
	if p.Contains(name) {
		return "", 0, false
	}
	popular, distance, ok = p.Nearest(name)
	if !ok || distance > MaxSimilarityDistance {
		return "", 0, false
	}
	return popular, distance, true
}

// Label says which list this is, for a detail an operator reads.
func (p PopularNames) Label() string {
	origin := "embedded"
	if p.Loaded {
		origin = "loaded"
	}
	if p.Date != "" {
		return fmt.Sprintf("%s list of %d, %s", origin, len(p.Names), p.Date)
	}
	return fmt.Sprintf("%s list of %d", origin, len(p.Names))
}

// nameDistance is Damerau-Levenshtein over normalized names. An npm scope is
// compared with the other name's scope and the bare name with the bare name,
// and the two distances added, so an edit never pairs a character of the
// scope with one of the name, and `@types/node` is 1 from `@typess/node` and
// 1 from `@types/nodes`.
func nameDistance(ecosystem, a, b string) int {
	if ecosystem == manifest.TypeNpm {
		as, an := splitNpmScope(a)
		bs, bn := splitNpmScope(b)
		return damerauLevenshtein(as, bs) + damerauLevenshtein(an, bn)
	}
	return damerauLevenshtein(a, b)
}

// splitNpmScope splits "@scope/name" into "scope" and "name"; an unscoped
// name has an empty scope.
func splitNpmScope(name string) (scope, bare string) {
	if rest, ok := strings.CutPrefix(name, "@"); ok {
		if s, n, ok := strings.Cut(rest, "/"); ok {
			return s, n
		}
	}
	return "", name
}

// lengthGap is a lower bound on the distance between a and b, for skipping a
// name that cannot beat the best found so far.
func lengthGap(a, b string) int {
	d := len([]rune(a)) - len([]rune(b))
	if d < 0 {
		return -d
	}
	return d
}

// damerauLevenshtein is the edit distance counting insertion, deletion,
// substitution and transposition of adjacent characters, each as one edit.
// It is the unrestricted form (Lowrance-Wagner), so "ca" to "abc" is 2; the
// restricted form most libraries ship calls that 3, because it never edits a
// substring twice.
func damerauLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	inf := la + lb
	d := make([][]int, la+2)
	for i := range d {
		d[i] = make([]int, lb+2)
	}
	d[0][0] = inf
	for i := 0; i <= la; i++ {
		d[i+1][0] = inf
		d[i+1][1] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j+1] = inf
		d[1][j+1] = j
	}
	last := map[rune]int{}
	for i := 1; i <= la; i++ {
		db := 0
		for j := 1; j <= lb; j++ {
			i1, j1 := last[rb[j-1]], db
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost, db = 0, j
			}
			d[i+1][j+1] = min(
				d[i][j]+cost,
				d[i+1][j]+1,
				d[i][j+1]+1,
				d[i1][j1]+(i-i1-1)+1+(j-j1-1),
			)
		}
		last[ra[i-1]] = i
	}
	return d[la+1][lb+1]
}

// SimilarityStore is what the name-similarity check reads. *audit.DB
// satisfies it.
type SimilarityStore interface {
	GetSimilarityPolicy(ctx context.Context, ecosystem string) (audit.SimilarityPolicy, error)
	GetPopularList(ctx context.Context, ecosystem string) (audit.PopularList, error)
	GetPoliciesByType(ctx context.Context, registryType string) ([]Rule, error)
	NameBaseline(ctx context.Context) (audit.NameBaselineState, error)
	InNameBaseline(ctx context.Context, pkgType, key string) (bool, error)
}

// SimilarityAction returns the configured action for an ecosystem: warn when
// none is set.
func SimilarityAction(ctx context.Context, store SimilarityStore, ecosystem string) (string, error) {
	if store == nil {
		return ActionWarn, nil
	}
	p, err := store.GetSimilarityPolicy(ctx, ecosystem)
	if errors.Is(err, audit.ErrSimilarityPolicyNotFound) {
		return ActionWarn, nil
	}
	if err != nil {
		return "", err
	}
	return p.Action, nil
}

// LoadPopularNames returns the list in force for ecosystem: the one an
// operator loaded, or the embedded one. false means the ecosystem has none.
func LoadPopularNames(ctx context.Context, store SimilarityStore, ecosystem string) (PopularNames, bool, error) {
	if store != nil {
		l, err := store.GetPopularList(ctx, ecosystem)
		switch {
		case err == nil:
			p, perr := ParsePopularNames(ecosystem, []byte(l.Names))
			if perr != nil {
				return PopularNames{}, false, fmt.Errorf("loaded %s popular list: %w", ecosystem, perr)
			}
			p.Loaded = true
			return p, true, nil
		case !errors.Is(err, audit.ErrPopularListNotFound):
			return PopularNames{}, false, fmt.Errorf("load %s popular list: %w", ecosystem, err)
		}
	}
	p, ok := EmbeddedPopularNames(ecosystem)
	return p, ok, nil
}

// ExactRule reports whether an allow-list rule names one package rather than
// a family of them. pypi and cargo rules are always exact; an npm rule is
// unless it is the `@scope/*` wildcard. Every other kind is a host or a
// prefix, which names no package at all.
func ExactRule(typ, pattern string) bool {
	switch typ {
	case manifest.TypePypi, manifest.TypeCargo:
		return true
	case manifest.TypeNpm:
		return !strings.HasSuffix(pattern, "/*")
	}
	return false
}

// TakeNameBaseline records every package the manifest store holds, and every
// name with an admitted row in the audit database, as a name in use before
// the check, the first time it is called against a database, and reports
// whether this call took it. all is manifest.Store.AllPackages.
func TakeNameBaseline(ctx context.Context, adb *audit.DB, all map[string][]string) (bool, error) {
	if adb == nil {
		return false, nil
	}
	var keys []audit.NameBaselineKey
	for typ, names := range all {
		for _, n := range names {
			keys = append(keys, audit.NameBaselineKey{PkgType: typ, PkgKey: NormalizeName(typ, n)})
		}
	}
	slices.SortFunc(keys, func(a, b audit.NameBaselineKey) int {
		return strings.Compare(a.PkgType+"\x00"+a.PkgKey, b.PkgType+"\x00"+b.PkgKey)
	})
	return adb.TakeNameBaseline(ctx, keys, func(typ, name string) string {
		return NormalizeName(typ, manifest.SafeName(name))
	})
}

// NameSimilarityChecker is the name_similarity admission check. Every
// version of one package gets the same verdict, so it is computed once per
// name and reused for the rest of the admission.
type NameSimilarityChecker struct {
	Store SimilarityStore
	seen  map[string]Result
}

// NewNameSimilarityChecker returns the check reading store, which may be nil.
func NewNameSimilarityChecker(store SimilarityStore) *NameSimilarityChecker {
	return &NameSimilarityChecker{Store: store}
}

// Check compares pm's name with the ecosystem's popular names. A name within
// MaxSimilarityDistance of one it is not equal to fails under the configured
// action, unless an exact allow-list rule names it or the store held it when
// the baseline was taken.
func (c *NameSimilarityChecker) Check(ctx context.Context, pm *manifest.PackageManifest, _ *manifest.VersionEntry) Result {
	r := Result{Check: audit.CheckNameSimilarity, Action: ActionPass}
	if pm == nil {
		return r
	}
	key := pm.Type + "\x00" + pm.Name
	if prev, ok := c.seen[key]; ok {
		return prev
	}
	r = c.check(ctx, pm.Type, pm.Name)
	if c.seen == nil {
		c.seen = map[string]Result{}
	}
	c.seen[key] = r
	return r
}

func (c *NameSimilarityChecker) check(ctx context.Context, typ, name string) Result {
	r := Result{Check: audit.CheckNameSimilarity, Action: ActionPass}
	if !slices.Contains(SimilarityEcosystems(), typ) {
		r.Action = ActionNotEvaluated
		r.Reason = "no popular-name list for " + typ + ": " + typ + " packages are not named by whoever publishes them on an open registry"
		return r
	}
	if c.Store == nil {
		r.Action = ActionNotEvaluated
		r.Reason = "not run: no audit database to read the policy and the name baseline from"
		return r
	}
	action, err := SimilarityAction(ctx, c.Store, typ)
	if err != nil {
		r.Action, r.Reason = ActionWarn, "load name similarity policy: "+err.Error()
		return r
	}
	list, ok, err := LoadPopularNames(ctx, c.Store, typ)
	if err != nil {
		r.Action, r.Reason = ActionWarn, err.Error()
		return r
	}
	if !ok {
		r.Action, r.Reason = ActionNotEvaluated, "no popular-name list for "+typ
		return r
	}
	if list.Contains(name) {
		r.Reason = name + " is itself on the popular " + typ + " list (" + list.Label() + ")"
		return r
	}
	popular, distance, near := list.Near(name)
	if !near {
		r.Reason = fmt.Sprintf("no popular %s name within distance %d (%s)", typ, MaxSimilarityDistance, list.Label())
		return r
	}
	hit := fmt.Sprintf("%s is distance %d from the popular %s name %s (%s)", name, distance, typ, popular, list.Label())
	r.Details = map[string]any{"nearest": popular, "distance": distance}

	exempt, err := c.exemption(ctx, typ, name)
	if err != nil {
		r.Action, r.Reason = ActionWarn, hit+"; exemptions could not be read: "+err.Error()
		return r
	}
	if exempt != "" {
		r.Reason = "exempt, " + exempt + ": " + hit
		return r
	}
	switch action {
	case ActionBlock:
		r.Action = ActionBlock
	case ActionIgnore:
		r.Action = ActionIgnore
	default:
		r.Action = ActionWarn
	}
	r.Reason = hit
	return r
}

// exemption says why a near name is exempt, or "" when it is not. An exact
// allow-list rule is an operator having named this package on purpose; the
// baseline is a name already in use when the check arrived, which refusing
// now would break rather than protect.
func (c *NameSimilarityChecker) exemption(ctx context.Context, typ, name string) (string, error) {
	rules, err := c.Store.GetPoliciesByType(ctx, typ)
	if err != nil {
		return "", err
	}
	for _, rule := range rules {
		if ExactRule(typ, rule.Pattern) && NormalizeName(typ, rule.Pattern) == NormalizeName(typ, name) {
			return "allow-listed by an exact rule", nil
		}
	}
	baseline, err := c.Store.NameBaseline(ctx)
	if err != nil {
		return "", err
	}
	if !baseline.Taken {
		return "", nil
	}
	in, err := c.Store.InNameBaseline(ctx, typ, NormalizeName(typ, manifest.SafeName(name)))
	if err != nil {
		return "", err
	}
	if in {
		return "in use (in the manifest store or admitted) when the name baseline was taken on " + baseline.TakenAt.UTC().Format("2006-01-02"), nil
	}
	return "", nil
}

// NearPopularName runs the check's comparison alone, for `bodega policy add`:
// the popular name an exact rule for name would sit within
// MaxSimilarityDistance of, and the distance. ok is false when there is none.
func NearPopularName(ctx context.Context, store SimilarityStore, typ, name string) (popular string, distance int, ok bool, err error) {
	if !slices.Contains(SimilarityEcosystems(), typ) || !ExactRule(typ, name) {
		return "", 0, false, nil
	}
	list, has, err := LoadPopularNames(ctx, store, typ)
	if err != nil || !has {
		return "", 0, false, err
	}
	popular, distance, ok = list.Near(name)
	return popular, distance, ok, nil
}
