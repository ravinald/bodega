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
	GetOSVMalwarePolicy(ctx context.Context, ecosystem string) (audit.OSVMalwarePolicy, error)
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

// Check evaluates one version under two actions. An advisory is a version
// with a known flaw and answers to the osv_policy row, which is off until an
// operator sets it. A malware record is a package someone published to do
// harm and answers to the malware action, which is block until an operator
// says otherwise; that default is why a fresh install looks anything up.
func (c *OSVChecker) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result {
	return c.check(ctx, pm, ve, false)
}

// CheckMalware evaluates the malware action alone. It is the proxy fill's
// question: that path does not run the advisory gate, and a client fetching
// through the proxy still must not receive a package OSV says is malicious.
func (c *OSVChecker) CheckMalware(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result {
	return c.check(ctx, pm, ve, true)
}

func (c *OSVChecker) check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry, malwareOnly bool) Result {
	if pm == nil || ve == nil {
		return Result{Check: "osv", Action: ActionPass}
	}
	if !OSVCovers(pm.Type) {
		return Result{Check: "osv", Action: ActionPass}
	}
	// An apt entry with no version is a stub whose .deb nothing has resolved
	// yet, and a stub is exactly what the gate must not wave through: see the
	// warn below, once the actions say the gate is on at all.
	if ve.Version == "" && pm.Type != manifest.TypeApt {
		return Result{Check: "osv", Action: ActionPass}
	}

	acts := c.actions(ctx, pm.Type)
	if malwareOnly {
		acts.advisory = ActionIgnore
	}
	if acts.advisory == ActionIgnore && acts.malware == ActionIgnore {
		return acts.pass()
	}
	if ve.Version == "" {
		return Result{Check: "osv", Action: ActionWarn,
			Reason: acts.qualify(fmt.Sprintf("apt entry %s carries no version, so no advisory can be evaluated against it", pm.Name))}
	}
	lk := osvLookupFor(pm, ve, c.DefaultAptSuite, c.ServedAptSuites)
	if lk.reason != "" {
		return Result{Check: "osv", Action: ActionWarn, Reason: acts.qualify(lk.reason)}
	}

	ans := c.answerFor(ctx, lk, ve)
	if ans.err != nil {
		reason := fmt.Sprintf("osv lookup failed for %s/%s@%s: %v", pm.Type, pm.Name, ve.Version, ans.err)
		if r, ok := priorMalware(pm, ve, acts.malware, reason); ok {
			return r
		}
		return Result{Check: "osv", Action: ActionWarn, Reason: acts.qualify(reason)}
	}
	malware, advisories := splitMalware(ans.vulns)
	if acts.malware == ActionIgnore {
		malware = nil
	}
	if acts.advisory == ActionIgnore {
		advisories = nil
	}
	if len(malware) == 0 && len(advisories) == 0 {
		// A gate that could not answer must not report a clean result, and
		// one that could not answer today still knows what an earlier answer
		// found.
		if !ans.conclusive() {
			if r, ok := priorMalware(pm, ve, acts.malware, ans.degraded); ok {
				return r
			}
			return Result{Check: "osv", Action: ActionWarn, Reason: acts.qualify(ans.degraded)}
		}
		if reason := lk.emptyAnswerReason(ans.vulns); reason != "" {
			return Result{Check: "osv", Action: ActionWarn, Reason: acts.qualify(reason)}
		}
		// Dating a clean result is what stops it reading, a year later, like
		// a version nobody ever looked at. Records under an ignored action
		// are stamped too: whether a version carries them is the same fact
		// whatever the gate does about it.
		stampOSV(ve, ans.vulns, c.now(), lk.queried)
		return acts.pass()
	}

	// Stamp onto VersionEntry.Metadata so the knowledge follows the version.
	// Records found in stale data are still records, so they are stamped
	// without a date rather than dropped.
	checkedAt := time.Time{}
	if ans.conclusive() {
		checkedAt = c.now()
	}
	stampOSV(ve, ans.vulns, checkedAt, lk.queried)

	details := map[string]any{}
	if sev := vulnSeverities(ans.vulns); len(sev) > 0 {
		details["severity"] = sev
	}
	if lk.queried != "" {
		details["queried"] = lk.queried
	}

	// Malware is named record by record and never counted with the
	// advisories: "3 OSV record(s)" reads as three CVEs to triage, and one of
	// them being a package built to steal credentials is not a triage item.
	action := ActionPass
	var parts []string
	if len(malware) > 0 {
		action = acts.malware
		details["malware"] = vulnIDs(malware)
		parts = append(parts, fmt.Sprintf("%s@%s is known malware: %s",
			pm.Name, ve.Version, describeMalware(malware)))
	}
	if len(advisories) > 0 {
		action = stricter(action, acts.advisory)
		ids := vulnIDs(advisories)
		details["vulns"] = ids
		details["count"] = len(advisories)
		parts = append(parts, fmt.Sprintf("%s@%s has %d OSV record(s): %s",
			pm.Name, ve.Version, len(advisories), strings.Join(ids, ", ")))
	}

	reason := strings.Join(parts, "; ")
	if lk.queried != "" {
		reason += ", queried as " + lk.queried
	}
	if ans.degraded != "" {
		reason += " (" + ans.degraded + ")"
	}
	return Result{
		Check:   "osv",
		Action:  action,
		Reason:  acts.qualify(reason),
		Details: details,
	}
}

// osvActions is what the gate does with each kind of record for one
// ecosystem, plus anything that went wrong reading those settings.
type osvActions struct {
	advisory string
	malware  string
	notes    []string
}

// actions reads both settings. An unreadable advisory row warns, as it always
// has; an unreadable malware row blocks, because the alternative is that a
// database fault turns off the one check that runs with no configuration.
// Neither stops the lookup: a malware hit is still worth refusing while the
// advisory row is unreadable.
func (c *OSVChecker) actions(ctx context.Context, registryType string) osvActions {
	out := osvActions{advisory: ActionIgnore}
	if c.store == nil {
		out.malware = ActionBlock
		return out
	}
	switch p, err := c.store.GetOSVPolicy(ctx, registryType); {
	case errors.Is(err, audit.ErrOSVPolicyNotFound):
	case err != nil:
		out.advisory = ActionWarn
		out.notes = append(out.notes, "load osv policy: "+err.Error())
	default:
		out.advisory = p.Action
	}
	var err error
	out.malware, err = c.MalwareAction(ctx, registryType)
	if err != nil {
		out.notes = append(out.notes, "load osv malware policy: "+err.Error())
	}
	return out
}

// pass is the clean verdict, which a settings read that failed turns into a
// warn: the operator has to learn that the gate ran on a default it did not
// choose.
func (a osvActions) pass() Result {
	if len(a.notes) > 0 {
		return Result{Check: "osv", Action: ActionWarn, Reason: strings.Join(a.notes, "; ")}
	}
	return Result{Check: "osv", Action: ActionPass}
}

func (a osvActions) qualify(reason string) string {
	if len(a.notes) == 0 {
		return reason
	}
	return reason + "; " + strings.Join(a.notes, "; ")
}

// MalwareAction is the action for malware records in one registry type: the
// stored row, or block when there is none. An unreadable row also answers
// block, with the error beside it for the caller to report.
func (c *OSVChecker) MalwareAction(ctx context.Context, registryType string) (string, error) {
	if c.store == nil {
		return ActionBlock, nil
	}
	p, err := c.store.GetOSVMalwarePolicy(ctx, registryType)
	switch {
	case errors.Is(err, audit.ErrOSVMalwarePolicyNotFound):
		return ActionBlock, nil
	case err != nil:
		return ActionBlock, err
	}
	return p.Action, nil
}

// priorMalware applies the malware action to what an earlier lookup stamped,
// for a lookup that could not answer today. A version with no such stamp is
// the caller's to warn on: refusing every version while OSV is unreachable
// would stop every install over an outage, which is the wrong trade for a
// list that only holds malware someone has already reported.
func priorMalware(pm *manifest.PackageManifest, ve *manifest.VersionEntry, action, degraded string) (Result, bool) {
	if action == ActionIgnore || ve.Metadata[OSVMetaMalware] == "" {
		return Result{}, false
	}
	ids := splitIDs(ve.Metadata[OSVMetaMalware])
	return Result{
		Check:  "osv",
		Action: action,
		Reason: fmt.Sprintf("%s@%s is known malware: %s, found by an earlier check; this one could not confirm it (%s)",
			pm.Name, ve.Version, strings.Join(ids, ", "), degraded),
		Details: map[string]any{"malware": ids},
	}, true
}

// stricter returns the more restrictive of two actions.
func stricter(a, b string) string {
	rank := map[string]int{ActionPass: 0, ActionIgnore: 0, ActionWarn: 1, ActionBlock: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
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

// OSVSeverity is one score OSV published for one advisory: the scoring
// system it came from and the vector or value itself. Exported because the
// stamp it is persisted into is read outside this package — `bodega profile
// pins` renders it and the pins endpoint returns it — and a severity a caller
// has to re-query OSV to read is a severity nothing will read.
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []OSVSeverity `json:"severity"`
	// Malicious is what database_specific said, decoded at sync or at query
	// time; see osvDatabaseSpecific.
	Malicious bool `json:"-"`
}

// isMalware reports whether the record describes a malicious package rather
// than a vulnerable one. OpenSSF's malicious-packages feed publishes under
// MAL- ids; a record from another database that describes malware says so in
// database_specific instead.
func (v osvVuln) isMalware() bool {
	return strings.HasPrefix(v.ID, "MAL-") || v.Malicious
}

// osvDatabaseSpecific is the part of a record's database_specific block that
// marks malware. The OpenSSF feed carries malicious-packages-origins on every
// record it exports, whatever id the record goes by downstream, and GitHub
// files a malware advisory under CWE-506, "Embedded Malicious Code".
type osvDatabaseSpecific struct {
	MaliciousOrigins json.RawMessage `json:"malicious-packages-origins"`
	CWEIDs           []string        `json:"cwe_ids"`
}

func (d osvDatabaseSpecific) malicious() bool {
	if len(d.MaliciousOrigins) > 0 && string(d.MaliciousOrigins) != "null" {
		return true
	}
	for _, id := range d.CWEIDs {
		if id == "CWE-506" {
			return true
		}
	}
	return false
}

func splitMalware(vs []osvVuln) (malware, advisories []osvVuln) {
	for _, v := range vs {
		if v.isMalware() {
			malware = append(malware, v)
		} else {
			advisories = append(advisories, v)
		}
	}
	return malware, advisories
}

// describeMalware names each record with its summary, sorted by id. The
// summary is what tells an operator what the package did, and the id is what
// they search for.
func describeMalware(vs []osvVuln) string {
	sorted := append([]osvVuln(nil), vs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	parts := make([]string, 0, len(sorted))
	for _, v := range sorted {
		if v.Summary == "" {
			parts = append(parts, v.ID)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", v.ID, v.Summary))
	}
	return strings.Join(parts, ", ")
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
		Vulns []struct {
			osvVuln
			DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse osv response: %w", err)
	}
	vulns := make([]osvVuln, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		v.Malicious = v.DatabaseSpecific.malicious()
		vulns = append(vulns, v.osvVuln)
	}
	return vulns, nil
}

// vulnSeverities keys each record's severity entries by its OSV id. A version
// carrying several records at different severities keeps them apart, and
// json.Marshal sorts the keys, so the stamped value is stable across runs.
// Records OSV scored no severity for are absent; vetting.osv.vulns is the
// list of what was queried.
func vulnSeverities(vs []osvVuln) map[string][]OSVSeverity {
	out := make(map[string][]OSVSeverity, len(vs))
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
