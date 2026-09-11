package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// OSVStore is the subset of audit.DB the OSV checker needs.
type OSVStore interface {
	GetOSVPolicy(ctx context.Context, ecosystem string) (audit.OSVPolicy, error)
}

// osvEcosystemFor maps bodega's registry types to OSV's ecosystem identifiers.
// Ecosystems without an OSV equivalent short-circuit to pass, so `bodega
// policy osv set` refuses to write a row for one; see OSVEcosystems.
//
// apt is covered and is deliberately not in here. One identifier per registry
// type is the assumption this table encodes, and apt breaks it: Ubuntu and
// Debian backport a fix without moving the upstream version, so the records
// that settle a version live in the export for its own release. See
// osvLookupFor and OSVExportsFor.
var osvEcosystemFor = map[string]string{
	manifest.TypeNpm:   "npm",
	manifest.TypePypi:  "PyPI",
	manifest.TypeGomod: "Go",
	manifest.TypeCargo: "crates.io",
}

// OSVEcosystemFor returns OSV's identifier for a registry type, or "" when
// the type has no single OSV equivalent. `policy osv sync` needs the mapping
// to name the export it fetches, and a second copy of the table is how the two
// drift. apt returns "" here and is still covered; ask OSVExportsFor, which
// answers for every type.
func OSVEcosystemFor(registryType string) string {
	return osvEcosystemFor[registryType]
}

// OSVCovers reports whether the gate can query a registry type at all. It is
// the question `show pkg` asks before printing "unchecked" rather than "n/a",
// and OSVEcosystemFor is the wrong one to ask now that apt has no single
// identifier.
func OSVCovers(registryType string) bool {
	return registryType == manifest.TypeApt || osvEcosystemFor[registryType] != ""
}

// OSVEcosystems returns the registry types the OSV gate can query, sorted.
func OSVEcosystems() []string {
	out := make([]string, 0, len(osvEcosystemFor)+1)
	for eco := range osvEcosystemFor {
		out = append(out, eco)
	}
	out = append(out, manifest.TypeApt)
	sort.Strings(out)
	return out
}

type OSVChecker struct {
	store OSVStore

	Endpoint string // defaults to https://api.osv.dev/v1/query
	HTTP     *http.Client

	// LocalDB is the synced OSV mirror the gate answers from. Nil means no
	// osv_db_dir is configured, which is not the same as an empty database:
	// both produce a warn, and neither produces a pass.
	LocalDB *OSVDatabase

	// AllowAPIFallback authorizes a live query when the local database cannot
	// answer. Off by default: on a restricted network every version would
	// otherwise stall for the client timeout against a host that never
	// answers, and a bulk import pays that per version.
	AllowAPIFallback bool

	// MaxAge is how old a synced ecosystem may be before a clean answer from
	// it warns instead of passing. Zero means DefaultOSVMaxAge.
	MaxAge time.Duration

	// DefaultAptSuite is the suite an apt entry naming none is served under,
	// which is the server's apt_codename. Empty leaves such an entry
	// unanswerable, which is what a test or a tool holding no Config gets.
	DefaultAptSuite string

	// ServedAptSuites is apt_suites, and it bounds DefaultAptSuite rather than
	// widening it: an apt entry naming no suite is answered from the codename
	// only while the codename is the one release this bodega serves. Two
	// releases and nothing on the entry says which of them its version string
	// came from, so the gate warns instead of choosing. Empty leaves the
	// fallback unbounded, which is the single-release install and every caller
	// holding no Config.
	ServedAptSuites []string

	Now func() time.Time
}

func NewOSVChecker(store OSVStore) *OSVChecker {
	return &OSVChecker{
		store:    store,
		Endpoint: "https://api.osv.dev/v1/query",
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		MaxAge:   DefaultOSVMaxAge,
		Now:      time.Now,
	}
}

func (c *OSVChecker) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result {
	if pm == nil || ve == nil {
		return Result{Check: "osv", Action: ActionPass}
	}
	if !OSVCovers(pm.Type) {
		return Result{Check: "osv", Action: ActionPass}
	}
	// An apt entry with no version is a stub whose .deb nothing has resolved
	// yet, and a stub is exactly what the gate must not wave through: see the
	// warn below, once the policy row says the gate is on at all.
	if ve.Version == "" && pm.Type != manifest.TypeApt {
		return Result{Check: "osv", Action: ActionPass}
	}

	policy, err := c.store.GetOSVPolicy(ctx, pm.Type)
	if errors.Is(err, audit.ErrOSVPolicyNotFound) {
		return Result{Check: "osv", Action: ActionPass}
	}
	if err != nil {
		return Result{Check: "osv", Action: ActionWarn, Reason: "load osv policy: " + err.Error()}
	}
	if policy.Action == ActionIgnore {
		return Result{Check: "osv", Action: ActionPass}
	}
	if ve.Version == "" {
		return Result{Check: "osv", Action: ActionWarn,
			Reason: fmt.Sprintf("apt entry %s carries no version, so no advisory can be evaluated against it", pm.Name)}
	}
	lk := osvLookupFor(pm, ve, c.DefaultAptSuite, c.ServedAptSuites)
	if lk.reason != "" {
		return Result{Check: "osv", Action: ActionWarn, Reason: lk.reason}
	}

	ans := c.answerFor(ctx, lk, ve)
	if ans.err != nil {
		return Result{Check: "osv", Action: ActionWarn,
			Reason: fmt.Sprintf("osv lookup failed for %s/%s@%s: %v", pm.Type, pm.Name, ve.Version, ans.err)}
	}
	vulns := ans.vulns
	if len(vulns) == 0 {
		// A gate that could not answer must not report a clean result.
		if !ans.conclusive() {
			return Result{Check: "osv", Action: ActionWarn, Reason: ans.degraded}
		}
		if reason := lk.emptyAnswerReason(vulns); reason != "" {
			return Result{Check: "osv", Action: ActionWarn, Reason: reason}
		}
		// Dating a clean result is what stops it reading, a year later, like
		// a version nobody ever looked at.
		stampOSV(ve, nil, c.now(), lk.queried)
		return Result{Check: "osv", Action: ActionPass}
	}

	// Stamp onto VersionEntry.Metadata so the knowledge follows the version.
	// Records found in stale data are still records, so they are stamped
	// without a date rather than dropped.
	checkedAt := time.Time{}
	if ans.conclusive() {
		checkedAt = c.now()
	}
	stampOSV(ve, vulns, checkedAt, lk.queried)

	ids := vulnIDs(vulns)
	details := map[string]any{
		"vulns": ids,
		"count": len(vulns),
	}
	if sev := vulnSeverities(vulns); len(sev) > 0 {
		details["severity"] = sev
	}
	if lk.queried != "" {
		details["queried"] = lk.queried
	}

	reason := fmt.Sprintf("%s@%s has %d OSV record(s): %s",
		pm.Name, ve.Version, len(vulns), strings.Join(ids, ", "))
	if lk.queried != "" {
		reason += ", queried as " + lk.queried
	}
	if ans.degraded != "" {
		reason += " (" + ans.degraded + ")"
	}
	return Result{
		Check:   "osv",
		Action:  policy.Action,
		Reason:  reason,
		Details: details,
	}
}

// osvAnswer is one lookup's evidence. degraded names why the answer cannot be
// trusted to be complete — no local database, or one too old to have seen a
// recent advisory — and turns an empty vuln list into a warn instead of a
// pass. err means nothing answered at all.
//
// answered separates the two shapes degraded covers: current data with a
// caveat, versus no verdict at all. A rescan stamps a check date only on the
// first, because dating a clean result against a database synced in March
// asserts the thing the date exists to prove.
type osvAnswer struct {
	vulns    []osvVuln
	degraded string
	answered bool
	err      error
}

// conclusive reports whether the answer is one the gate acts on: current data,
// and nothing left unread that could still cover this version. Anything else
// leaves the check date alone, because "clean" and "nobody could tell" are the
// two states the date exists to keep apart.
//
// Matching a record is not a substitute for reading the rest of them. One hit
// beside an unread record is still an incomplete answer, and dating it makes
// the version indistinguishable from one whose whole database was read; the
// same version with no hits and the same unread record is already reported
// unanswered.
func (a osvAnswer) conclusive() bool {
	return a.err == nil && a.answered && a.degraded == ""
}

// answerFor is the lookup both admission and rescan go through.
//
// An entry resolves to several targets when it is published to several apt
// suites, and the same .deb is offered to every one of them: a record against
// any of those releases is a finding on this version. The answers fold into
// one, and one target that could not be read leaves the whole entry
// inconclusive: a union built from half the sources is a clean answer about a
// question nobody finished asking.
//
// A version entry whose constraint is not exact does not name one version: the
// server resolves the range against upstream and serves releases the manifest
// never lists, so a point lookup on the base version answers a question nobody
// asked. Marking that inconclusive keeps the range out of the check date while
// still carrying any record found against the base version itself, which is
// the same shape as an answer read from stale data.
func (c *OSVChecker) answerFor(ctx context.Context, lk osvLookup, ve *manifest.VersionEntry) osvAnswer {
	out := osvAnswer{answered: true}
	seen := map[string]bool{}
	var degraded []string
	if lk.note != "" {
		out.answered = false
		degraded = append(degraded, lk.note)
	}
	for _, t := range lk.targets {
		ans := c.lookup(ctx, t.ecosystem, t.name, ve.Version)
		if ans.err != nil {
			// Whole, not just the error: a caller reads the ids off an
			// answer it could not act on, and lookup builds this one.
			return ans
		}
		for _, v := range ans.vulns {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			out.vulns = append(out.vulns, v)
		}
		if !ans.answered {
			out.answered = false
		}
		if ans.degraded != "" {
			degraded = append(degraded, ans.degraded)
		}
	}
	if reason := constraintUnevaluatedReason(queryName(lk), ve); reason != "" {
		out.answered = false
		degraded = append(degraded, reason)
	}
	out.degraded = strings.Join(degraded, "; ")
	return out
}

// queryName is the name the entry was looked up under, for a reason that has
// to name something the operator can find in the manifest.
func queryName(lk osvLookup) string {
	if len(lk.targets) == 0 {
		return ""
	}
	return lk.targets[0].name
}

// OSVDatable reports whether one point lookup can date this entry. Anything
// other than exact and the empty default is a range, including a value this
// build does not recognize: guessing at an unknown constraint is how a version
// gets dated against a query that never covered it.
//
// Exported because the writer and the renderer have to agree. A stamp written
// under one constraint outlives an edit to that constraint, and an imported
// manifest carries whatever date its source wrote, so `show pkg` has to ask
// the question again at render time rather than trust the bytes.
func OSVDatable(ve manifest.VersionEntry) bool {
	switch ve.VersionConstraint {
	case "", manifest.ConstraintExact:
		return true
	}
	return false
}

// constraintUnevaluatedReason names a constraint no point lookup can settle.
func constraintUnevaluatedReason(name string, ve *manifest.VersionEntry) string {
	if OSVDatable(*ve) {
		return ""
	}
	return fmt.Sprintf("%s is stored under the %q version constraint, so the versions served are resolved upstream and only %s was queried",
		name, ve.VersionConstraint, ve.Version)
}

// lookup answers from the local database, and reaches api.osv.dev only when
// the local copy cannot answer and osv_api_fallback authorizes it.
func (c *OSVChecker) lookup(ctx context.Context, osvEco, name, version string) osvAnswer {
	unusable := ""
	switch meta, err := c.LocalDB.Meta(osvEco); {
	case err == nil:
		vulns, skipped, matchErr := c.LocalDB.Match(osvEco, name, version)
		if matchErr != nil {
			unusable = fmt.Sprintf("local OSV database for %s is unreadable (%v); run `bodega policy osv sync`", osvEco, matchErr)
			break
		}
		degraded := unevaluatedReason(name, version, skipped)
		age := meta.Age(c.now())
		if age <= c.maxAge() {
			return osvAnswer{vulns: vulns, degraded: degraded, answered: true}
		}
		stale := fmt.Sprintf("local OSV database for %s is %s old (synced %s); run `bodega policy osv sync`",
			osvEco, ShortDuration(age), meta.FetchedAt.UTC().Format(time.RFC3339))
		if c.AllowAPIFallback {
			if fresh, apiErr := c.query(ctx, osvEco, name, version); apiErr == nil {
				return osvAnswer{vulns: fresh, answered: true}
			}
		}
		if degraded != "" {
			stale += "; " + degraded
		}
		return osvAnswer{vulns: vulns, degraded: stale}
	case errors.Is(err, ErrOSVDBMissing):
		if c.LocalDB == nil {
			unusable = "no local OSV database configured (set osv_db_dir); run `bodega policy osv sync`"
		} else {
			unusable = fmt.Sprintf("no local OSV database for %s in %s; run `bodega policy osv sync`", osvEco, c.LocalDB.Dir())
		}
	default:
		unusable = fmt.Sprintf("local OSV database for %s is unreadable (%v); run `bodega policy osv sync`", osvEco, err)
	}

	if !c.AllowAPIFallback {
		return osvAnswer{degraded: unusable + "; osv_api_fallback is off, so nothing was queried"}
	}
	vulns, err := c.query(ctx, osvEco, name, version)
	if err != nil {
		return osvAnswer{err: fmt.Errorf("%s; api fallback failed: %w", unusable, err)}
	}
	return osvAnswer{vulns: vulns, answered: true}
}

// unevaluatedReason names the records that mention the package but carry a
// version bound no ordering can place, so a version they might cover never
// reports clean without the operator being told which records nobody read.
// api.osv.dev drops the same ranges and says nothing, which is why the reason
// carries the bound: it is upstream data, not a local misconfiguration, and
// the only way to settle it is to read the record.
func unevaluatedReason(name, version string, skipped []string) string {
	if len(skipped) == 0 {
		return ""
	}
	shown, extra := skipped, ""
	if len(shown) > osvSkipListLimit {
		extra = fmt.Sprintf(" and %d more", len(shown)-osvSkipListLimit)
		shown = shown[:osvSkipListLimit]
	}
	return fmt.Sprintf("%d OSV record(s) for %s were not evaluated against %s: %s%s",
		len(skipped), name, version, strings.Join(shown, ", "), extra)
}

// osvSkipListLimit caps the ids one reason carries. A package whose own
// version string cannot be ordered skips every record naming it, and torch
// alone carries 30-odd.
const osvSkipListLimit = 5

func (c *OSVChecker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *OSVChecker) maxAge() time.Duration {
	if c.MaxAge <= 0 {
		return DefaultOSVMaxAge
	}
	return c.MaxAge
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
}

// osvAPIBodyLimit caps what one api.osv.dev response may cost in memory. A
// distro ecosystem gets an order of magnitude more than a language one because
// a USN enumerates every version it covers: measured 2026-09-11, one query for
// linux 5.15.0-91.101 in Ubuntu:22.04:LTS answers with 32.8 MB.
func osvAPIBodyLimit(ecosystem string) int64 {
	if isDistroEcosystem(ecosystem) {
		return 64 << 20
	}
	return 4 << 20
}

func (c *OSVChecker) query(ctx context.Context, ecosystem, name, version string) ([]osvVuln, error) {
	body, _ := json.Marshal(map[string]any{
		"package": map[string]string{"name": name, "ecosystem": ecosystem},
		"version": version,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: HTTP %d", c.Endpoint, resp.StatusCode)
	}
	// One byte past the cap, so a body that reaches it is reported as too
	// large rather than as the truncated JSON it would otherwise parse as.
	limit := osvAPIBodyLimit(ecosystem)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("osv response for %s %s@%s is larger than the %d MiB cap; run `bodega policy osv sync` and answer from the local database",
			ecosystem, name, version, limit>>20)
	}
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse osv response: %w", err)
	}
	return out.Vulns, nil
}

// vulnSeverities keys each record's severity entries by its OSV id. A version
// carrying several records at different severities keeps them apart, and
// json.Marshal sorts the keys, so the stamped value is stable across runs.
// Records OSV scored no severity for are absent; vetting.osv.vulns is the
// list of what was queried.
func vulnSeverities(vs []osvVuln) map[string][]osvSeverity {
	out := make(map[string][]osvSeverity, len(vs))
	for _, v := range vs {
		if v.ID == "" || len(v.Severity) == 0 {
			continue
		}
		out[v.ID] = v.Severity
	}
	return out
}

func vulnIDs(vs []osvVuln) []string {
	ids := make([]string, 0, len(vs))
	for _, v := range vs {
		if v.ID != "" {
			ids = append(ids, v.ID)
		}
	}
	sort.Strings(ids)
	return ids
}
