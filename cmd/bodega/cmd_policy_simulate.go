package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// policyRemove is the action word that proposes deleting an ecosystem's row,
// as `bodega policy <gate> remove <ecosystem>` would.
const policyRemove = "remove"

// policyOverlay answers the policy reads every check makes, with a proposed
// change laid over the rows on record. It never writes: the one write a check
// can make, the provenance pin, is refused here as well as never committed.
type policyOverlay struct {
	*audit.DB
	allow      map[string][]audit.PolicyInfo
	age        map[string]*audit.AgePolicy
	osv        map[string]*audit.OSVPolicy
	provenance map[string]*audit.ProvenancePolicy
	similarity map[string]*audit.SimilarityPolicy
}

func newPolicyOverlay(adb *audit.DB) *policyOverlay {
	return &policyOverlay{DB: adb,
		allow: map[string][]audit.PolicyInfo{}, age: map[string]*audit.AgePolicy{}, osv: map[string]*audit.OSVPolicy{},
		provenance: map[string]*audit.ProvenancePolicy{}, similarity: map[string]*audit.SimilarityPolicy{}}
}

// types lists every ecosystem the change touches. A version of any other type
// reads exactly the rows it reads today, so its decision cannot move.
func (o *policyOverlay) types() []string {
	var out []string
	add := func(t string) {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	for t := range o.allow {
		add(t)
	}
	for t := range o.age {
		add(t)
	}
	for t := range o.osv {
		add(t)
	}
	for t := range o.provenance {
		add(t)
	}
	for t := range o.similarity {
		add(t)
	}
	sort.Strings(out)
	return out
}

func (o *policyOverlay) GetPoliciesByType(ctx context.Context, t string) ([]audit.PolicyInfo, error) {
	if rules, ok := o.allow[t]; ok {
		return rules, nil
	}
	return o.DB.GetPoliciesByType(ctx, t)
}

func (o *policyOverlay) GetAgePolicy(ctx context.Context, eco string) (audit.AgePolicy, error) {
	if p, ok := o.age[eco]; ok {
		if p == nil {
			return audit.AgePolicy{}, audit.ErrAgePolicyNotFound
		}
		return *p, nil
	}
	return o.DB.GetAgePolicy(ctx, eco)
}

func (o *policyOverlay) GetOSVPolicy(ctx context.Context, eco string) (audit.OSVPolicy, error) {
	if p, ok := o.osv[eco]; ok {
		if p == nil {
			return audit.OSVPolicy{}, audit.ErrOSVPolicyNotFound
		}
		return *p, nil
	}
	return o.DB.GetOSVPolicy(ctx, eco)
}

func (o *policyOverlay) GetProvenancePolicy(ctx context.Context, eco string) (audit.ProvenancePolicy, error) {
	if p, ok := o.provenance[eco]; ok {
		if p == nil {
			return audit.ProvenancePolicy{}, audit.ErrProvenancePolicyNotFound
		}
		return *p, nil
	}
	return o.DB.GetProvenancePolicy(ctx, eco)
}

func (o *policyOverlay) GetSimilarityPolicy(ctx context.Context, eco string) (audit.SimilarityPolicy, error) {
	if p, ok := o.similarity[eco]; ok {
		if p == nil {
			return audit.SimilarityPolicy{}, audit.ErrSimilarityPolicyNotFound
		}
		return *p, nil
	}
	return o.DB.GetSimilarityPolicy(ctx, eco)
}

func (o *policyOverlay) PinProvenance(context.Context, audit.ProvenancePin) (audit.ProvenancePin, bool, error) {
	return audit.ProvenancePin{}, false, errors.New("a policy simulation writes no provenance pin")
}

// readOnlyVerdict is what evaluateReadOnly concluded about one version.
type readOnlyVerdict struct {
	Decision string
	Reason   string
	Checks   []audit.AdmissionCheck
}

// evaluateReadOnly decides on pm's one version the way admission would, in the
// same order, and writes nothing: no admission row, no audit event, no pin.
// admit.Admit with no checker and no database is the structural half alone,
// which writes nothing by construction; the policy half runs the checkers
// here without ever calling Commit.
func evaluateReadOnly(ctx context.Context, cfg *config.Config, checker *policy.Checker, checkers []policy.VersionChecker, pm *manifest.PackageManifest) readOnlyVerdict {
	if res := admit.Admit(ctx, nil, nil, cfg, pm, ""); res.Decision == admit.Invalid {
		return readOnlyVerdict{Decision: audit.AdmissionInvalid, Reason: res.Reason}
	}
	ve := &pm.Versions[0]
	candidate := policy.CandidateFor(pm.Type, pm.Name, ve.URL)
	listed, _ := checker.Listed(ctx, pm.Type)
	var allowErr error
	if candidate != "" {
		allowErr = checker.Check(ctx, pm.Type, candidate)
	}
	v := readOnlyVerdict{Decision: audit.AdmissionAdmitted,
		Checks: []audit.AdmissionCheck{admit.AllowListCheck(listed, candidate, allowErr)}}
	if allowErr != nil {
		v.Decision, v.Reason = audit.AdmissionPolicyBlocked, allowErr.Error()
		return v
	}
	for _, c := range checkers {
		r := c.Check(ctx, pm, ve)
		status, action := audit.CheckPass, audit.ActionNone
		switch r.Action {
		case policy.ActionWarn:
			status, action = audit.CheckWarn, policy.ActionWarn
		case policy.ActionBlock:
			status, action = audit.CheckBlock, policy.ActionBlock
		case policy.ActionNotEvaluated:
			status = audit.CheckNotEvaluated
		}
		v.Checks = append(v.Checks, audit.AdmissionCheck{Check: r.Check, Action: action, Status: status, Detail: r.Reason})
		if status == audit.CheckBlock && v.Decision == audit.AdmissionAdmitted {
			v.Decision, v.Reason = audit.AdmissionPolicyBlocked, r.Check+": "+r.Reason
		}
	}
	return v
}

type checkChange struct {
	Check  string `json:"check"`
	Before string `json:"before"`
	After  string `json:"after"`
	Detail string `json:"detail,omitempty"`
}

type simulatedChange struct {
	Type    string        `json:"type"`
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Before  string        `json:"before"`
	After   string        `json:"after"`
	Checks  []checkChange `json:"checks"`
}

type simulation struct {
	Types     []string          `json:"types"`
	Evaluated int               `json:"evaluated"`
	Changes   []simulatedChange `json:"changes"`
}

func newPolicySimulateCmd(gf *globalFlags) *cobra.Command {
	var (
		osvFlags, ageFlags, provFlags, simFlags []string
		allowFile                               string
		asJSON                                  bool
	)
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Show which admitted versions a policy change would block or admit",
		Long: `simulate evaluates every admitted version of the ecosystems a proposed
change touches, once against the policy on record and once against that
policy with the change applied, and lists the versions whose decision would
move, with the check responsible. It writes nothing: no policy row, no
admission row, no provenance pin.

Admitted versions are every version in the manifest store plus every version
the proxy admitted that the store does not list, read from the admission
decisions table.

The change uses the words the policy commands use, as ecosystem=value:
  --osv npm=block               bodega policy osv set npm block
  --age pypi=14d:block          bodega policy age set pypi 14d block
  --provenance npm=block        bodega policy provenance set npm block
  --similarity cargo=block      bodega policy similarity set cargo block
  --osv npm=remove              bodega policy osv remove npm
  --allow-file rules.json       replace the allow-list of every type the file names

The allow-file is a JSON object from type to the complete list of patterns
that type would have, in 'bodega policy add' syntax:
  {"npm": ["lodash", "@example/*"], "pypi": []}
An empty list proposes no rules for the type, which switches enforcement off.

The age gate and the upstream provenance check read their registries, so a
simulation over many versions makes as many reads.`,
		Example: `  bodega policy simulate --osv npm=block
  bodega policy simulate --age pypi=14d:block --json
  bodega policy simulate --allow-file rules.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			adb, err := openAuditDBErr(gf)
			if err != nil {
				return err
			}
			if adb == nil {
				return errors.New("simulate needs the audit database: the policy it compares against lives there")
			}
			defer adb.Close()
			proposed, err := parsePolicyChange(adb, osvFlags, ageFlags, provFlags, simFlags, allowFile)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			sim, err := simulatePolicy(cmd.Context(), cfg, adb, store, proposed)
			if err != nil {
				return err
			}
			return printSimulation(cmd.OutOrStdout(), sim, asJSON)
		},
	}
	cmd.Flags().StringArrayVar(&osvFlags, "osv", nil, "Proposed OSV action, ecosystem=warn|block|ignore|remove (repeatable)")
	cmd.Flags().StringArrayVar(&ageFlags, "age", nil, "Proposed age gate, ecosystem=<min-age>:warn|block|ignore or ecosystem=remove (repeatable)")
	cmd.Flags().StringArrayVar(&provFlags, "provenance", nil, "Proposed upstream provenance action, ecosystem=warn|block|ignore|remove (repeatable)")
	cmd.Flags().StringArrayVar(&simFlags, "similarity", nil, "Proposed name similarity action, ecosystem=warn|block|ignore|remove (repeatable)")
	cmd.Flags().StringVar(&allowFile, "allow-file", "", "JSON file of proposed allow-list rules per type")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the result as JSON")
	return cmd
}

// parsePolicyChange turns the flags into an overlay, refusing what the
// matching set command would refuse.
func parsePolicyChange(adb *audit.DB, osvFlags, ageFlags, provFlags, simFlags []string, allowFile string) (*policyOverlay, error) {
	o := newPolicyOverlay(adb)
	type gate struct {
		flag    string
		values  []string
		covered []string
		set     func(eco, action string)
	}
	gates := []gate{
		{"--osv", osvFlags, policy.OSVEcosystems(), func(eco, a string) {
			o.osv[eco] = nil
			if a != policyRemove {
				o.osv[eco] = &audit.OSVPolicy{Ecosystem: eco, Action: a}
			}
		}},
		{"--provenance", provFlags, manifest.AllTypes, func(eco, a string) {
			o.provenance[eco] = nil
			if a != policyRemove {
				o.provenance[eco] = &audit.ProvenancePolicy{Ecosystem: eco, Action: a}
			}
		}},
		{"--similarity", simFlags, policy.SimilarityEcosystems(), func(eco, a string) {
			o.similarity[eco] = nil
			if a != policyRemove {
				o.similarity[eco] = &audit.SimilarityPolicy{Ecosystem: eco, Action: a}
			}
		}},
	}
	for _, g := range gates {
		for _, v := range g.values {
			eco, action, err := splitPolicyFlag(g.flag, v, g.covered)
			if err != nil {
				return nil, err
			}
			if err := checkAction(g.flag, action, true); err != nil {
				return nil, err
			}
			g.set(eco, action)
		}
	}
	for _, v := range ageFlags {
		eco, rest, err := splitPolicyFlag("--age", v, policy.AgeEcosystems())
		if err != nil {
			return nil, err
		}
		if rest == policyRemove {
			o.age[eco] = nil
			continue
		}
		rawDur, action, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("--age %s: want ecosystem=<min-age>:<action>, like pypi=14d:block", v)
		}
		dur, err := parseAgeDuration(rawDur)
		if err != nil {
			return nil, fmt.Errorf("--age %s: %w", v, err)
		}
		action = strings.ToLower(action)
		if err := checkAction("--age", action, false); err != nil {
			return nil, err
		}
		o.age[eco] = &audit.AgePolicy{Ecosystem: eco, MinAgeSeconds: int64(dur.Seconds()), Action: action}
	}
	if allowFile != "" {
		if err := readAllowFile(o, allowFile); err != nil {
			return nil, err
		}
	}
	if len(o.types()) == 0 {
		return nil, errors.New("no change proposed: pass at least one of --osv, --age, --provenance, --similarity or --allow-file")
	}
	return o, nil
}

func splitPolicyFlag(flag, v string, covered []string) (eco, value string, err error) {
	eco, value, ok := strings.Cut(v, "=")
	if !ok || eco == "" || value == "" {
		return "", "", fmt.Errorf("%s %q: want ecosystem=value", flag, v)
	}
	if !slices.Contains(covered, eco) {
		return "", "", fmt.Errorf("%s %q: %s is not an ecosystem this gate covers; one of %s", flag, v, eco, strings.Join(covered, ", "))
	}
	return eco, strings.ToLower(value), nil
}

func checkAction(flag, action string, removable bool) error {
	switch action {
	case policy.ActionWarn, policy.ActionBlock, policy.ActionIgnore:
		return nil
	case policyRemove:
		if removable {
			return nil
		}
	}
	return fmt.Errorf("%s: action must be warn|block|ignore, or remove on its own, got %q", flag, action)
}

func readAllowFile(o *policyOverlay, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read --allow-file: %w", err)
	}
	var rules map[string][]string
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("--allow-file %s: want an object from type to a list of patterns: %w", path, err)
	}
	for t, patterns := range rules {
		if err := policy.ValidateType(t); err != nil {
			return fmt.Errorf("--allow-file %s: %w", path, err)
		}
		kind := policy.RuleKindForType(t)
		list := make([]audit.PolicyInfo, 0, len(patterns))
		for i, p := range patterns {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("--allow-file %s: %s pattern %d is empty", path, t, i+1)
			}
			list = append(list, audit.PolicyInfo{ID: fmt.Sprintf("simulated-%s-%d", t, i), RegistryType: t, RuleKind: kind, Pattern: p})
		}
		o.allow[t] = list
	}
	return nil
}

// simulatePolicy evaluates every admitted version of the touched types twice
// and keeps the ones whose decision moved.
func simulatePolicy(ctx context.Context, cfg *config.Config, adb *audit.DB, store *manifest.Store, proposed *policyOverlay) (simulation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	current := newPolicyOverlay(adb)
	curChecker, newChecker := policy.NewChecker(current), policy.NewChecker(proposed)
	sim := simulation{Types: proposed.types(), Changes: []simulatedChange{}}
	for _, t := range sim.Types {
		pms, err := admittedVersions(ctx, adb, store, t)
		if err != nil {
			return sim, err
		}
		for _, pm := range pms {
			for _, ve := range pm.Versions {
				one := *pm
				one.Versions = []manifest.VersionEntry{ve}
				before := evaluateReadOnly(ctx, cfg, curChecker, admit.VersionCheckersFrom(cfg, current), &one)
				after := evaluateReadOnly(ctx, cfg, newChecker, admit.VersionCheckersFrom(cfg, proposed), &one)
				sim.Evaluated++
				if before.Decision == after.Decision {
					continue
				}
				sim.Changes = append(sim.Changes, simulatedChange{Type: t, Name: pm.Name, Version: ve.Version,
					Before: before.Decision, After: after.Decision, Checks: responsibleChecks(before.Checks, after.Checks)})
			}
		}
	}
	return sim, nil
}

// admittedVersions is every version of type t that stands admitted: the
// manifest store's entries, then the versions the proxy admitted that the
// store does not list, each at its newest decision.
func admittedVersions(ctx context.Context, adb *audit.DB, store *manifest.Store, t string) ([]*manifest.PackageManifest, error) {
	var out []*manifest.PackageManifest
	listed := map[string]bool{}
	for _, name := range store.ListPackages(t) {
		pm, err := store.GetPackage(ctx, t, name)
		if err != nil {
			return nil, fmt.Errorf("load %s/%s: %w", t, name, err)
		}
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			listed[pm.Name+"\x00"+ve.Version] = true
		}
		out = append(out, pm)
	}
	// One decision per version is wanted and the table holds every decision
	// ever made; there is no cap that is both small and complete.
	rows, err := adb.Admissions(ctx, audit.AdmissionFilter{PkgType: t, Limit: 1 << 30})
	if err != nil {
		return nil, fmt.Errorf("read %s admission decisions: %w", t, err)
	}
	seen := map[string]bool{}
	byName := map[string]*manifest.PackageManifest{}
	for _, r := range rows {
		k := r.PkgName + "\x00" + r.PkgVersion
		if seen[k] {
			continue
		}
		seen[k] = true
		if listed[k] || r.Decision != audit.AdmissionAdmitted || !r.Evaluated() {
			continue
		}
		pm := byName[r.PkgName]
		if pm == nil {
			pm = &manifest.PackageManifest{Type: t, Name: r.PkgName}
			byName[r.PkgName] = pm
			out = append(out, pm)
		}
		pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: r.PkgVersion, Mode: manifest.ModeProxy})
	}
	return out, nil
}

// responsibleChecks names the checks whose verdict moved into or out of a
// block, which is what moved the decision.
func responsibleChecks(before, after []audit.AdmissionCheck) []checkChange {
	statusOf := func(list []audit.AdmissionCheck, name string) (audit.AdmissionCheck, bool) {
		for _, c := range list {
			if c.Check == name {
				return c, true
			}
		}
		return audit.AdmissionCheck{}, false
	}
	var out []checkChange
	for _, a := range after {
		b, ok := statusOf(before, a.Check)
		if !ok {
			b.Status = audit.CheckNotEvaluated
		}
		if a.Status == b.Status || (a.Status != audit.CheckBlock && b.Status != audit.CheckBlock) {
			continue
		}
		detail := a.Detail
		if a.Status != audit.CheckBlock {
			detail = b.Detail
		}
		out = append(out, checkChange{Check: a.Check, Before: b.Status, After: a.Status, Detail: detail})
	}
	for _, b := range before {
		if _, ok := statusOf(after, b.Check); !ok && b.Status == audit.CheckBlock {
			out = append(out, checkChange{Check: b.Check, Before: b.Status, After: audit.CheckNotEvaluated, Detail: b.Detail})
		}
	}
	return out
}

func printSimulation(out io.Writer, sim simulation, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(sim)
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, c := range sim.Changes {
		var why []string
		for _, ch := range c.Checks {
			why = append(why, fmt.Sprintf("%s %s->%s: %s", ch.Check, ch.Before, ch.After, ch.Detail))
		}
		fmt.Fprintf(w, "%s\t%s@%s\t%s -> %s\t%s\n", c.Type, c.Name, c.Version, c.Before, c.After, strings.Join(why, "; "))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d version(s) of %s evaluated; %d would change\n", sim.Evaluated, strings.Join(sim.Types, ", "), len(sim.Changes))
	return nil
}
