package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
)

// Metadata keys the OSV gate writes onto a VersionEntry. OSVMetaCheckedAt is
// the one that makes the other two readable: without it a version with no
// findings and a version nobody ever queried carry the same absent key, and a
// report cannot tell "no known vulnerabilities" from "nobody looked".
const (
	OSVMetaVulns     = "vetting.osv.vulns"
	OSVMetaSeverity  = "vetting.osv.severity"
	OSVMetaCheckedAt = "vetting.osv.checked_at"
	// OSVMetaQueried names what was actually asked: for apt that is the
	// source package, under the OSV ecosystem of the entry's own suite, and
	// neither is the name or the version string on the manifest. A finding an
	// operator cannot trace back to the package they installed is a finding
	// they will not act on.
	OSVMetaQueried = "vetting.osv.queried"
	// OSVMetaMalware lists the stamped ids that are malware records. It is
	// what admission falls back on when OSV cannot answer, and what a rescan
	// compares against to tell a newly published record from one an operator
	// already saw. The ids alone cannot say it: a record GitHub marks as
	// malware goes by a GHSA- id like any advisory.
	OSVMetaMalware = "vetting.osv.malware"
)

// stampOSV records one conclusive lookup on the version. A zero checkedAt
// drops the date rather than leaving the previous one: the caller found
// records in data too old to date a verdict against, and a date written by an
// earlier clean check would then sit beside the new ids as if it had produced
// them. The ids are worth keeping; the claim "clean as of that day" is not.
//
// An empty vulns list clears the previous findings. That is the point of a
// rescan against an advisory OSV withdrew, and it is why the caller must not
// call this at all when the database could not answer — a blank stamp and a
// clean stamp are the same bytes.
func stampOSV(ve *manifest.VersionEntry, vulns []osvVuln, checkedAt time.Time, queried string) {
	if ve == nil {
		return
	}
	if ve.Metadata == nil {
		ve.Metadata = map[string]string{}
	}
	// Empty for the language ecosystems, where the registry type and the
	// package name already say everything a lookup used.
	if queried == "" {
		delete(ve.Metadata, OSVMetaQueried)
	} else {
		ve.Metadata[OSVMetaQueried] = queried
	}
	if checkedAt.IsZero() {
		delete(ve.Metadata, OSVMetaCheckedAt)
	} else {
		ve.Metadata[OSVMetaCheckedAt] = checkedAt.UTC().Format(time.RFC3339)
	}
	if malware, _ := splitMalware(vulns); len(malware) > 0 {
		ve.Metadata[OSVMetaMalware] = strings.Join(vulnIDs(malware), ",")
	} else {
		delete(ve.Metadata, OSVMetaMalware)
	}
	ids := vulnIDs(vulns)
	if len(ids) == 0 {
		delete(ve.Metadata, OSVMetaVulns)
		delete(ve.Metadata, OSVMetaSeverity)
		return
	}
	ve.Metadata[OSVMetaVulns] = strings.Join(ids, ",")
	if sev := vulnSeverities(vulns); len(sev) > 0 {
		blob, _ := json.Marshal(sev)
		ve.Metadata[OSVMetaSeverity] = string(blob)
	} else {
		delete(ve.Metadata, OSVMetaSeverity)
	}
}

// OSVRescanChange is what a rescan learned about one version.
//
// Answered false means the stamp was left exactly as it was found. Rescan
// records and never decides: nothing here hides, freezes, blocks or deletes a
// version, because an OSV data refresh that flags a base image would otherwise
// take a fleet offline without an operator in the loop. NewMalware is the one
// finding the caller acts on, under the malware action; see
// OSVChecker.MalwareAction.
type OSVRescanChange struct {
	Answered bool
	// Vulns are the ids the lookup matched, reported whether or not the run
	// could answer for the version: a range entry is not stamped and not
	// counted, and a record found against its base version is still worth
	// naming in the row.
	Vulns []string
	// Flagged is the transition into findings: unchecked or clean before,
	// carrying ids now. Cleared is the reverse, which is what an OSV
	// withdrawal looks like from here.
	Flagged bool
	Cleared bool
	// Malware are the ids among Vulns that are malware records, and
	// NewMalware the ones no earlier stamp on this version named. Both are
	// set whether or not the run could answer: a MAL- record matched in
	// stale data is still a package built to do harm.
	Malware    []string
	NewMalware []string
	// Reason names why nothing was learned, or what limits what was. Empty on
	// an unqualified answer.
	Reason string
}

// Rescan re-runs the OSV lookup for one stored version and re-stamps it.
//
// It reads no policy row; the caller applies the malware action to NewMalware. The per-ecosystem action decides what admission does
// with a finding; whether a version is vulnerable today is the same fact under
// warn, block and ignore, and an operator who has not configured the gate
// still gets the report.
func (c *OSVChecker) Rescan(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) OSVRescanChange {
	if pm == nil || ve == nil || ve.Version == "" {
		return OSVRescanChange{Reason: "no version to look up"}
	}
	lk := osvLookupFor(pm, ve, c.DefaultAptSuite, c.ServedAptSuites)
	if lk.reason != "" {
		return OSVRescanChange{Reason: lk.reason}
	}

	ans := c.answerFor(ctx, lk, ve)
	if reason := lk.emptyAnswerReason(ans.vulns); ans.err == nil && reason != "" {
		return OSVRescanChange{Reason: reason}
	}
	if !ans.conclusive() {
		reason := ans.degraded
		if ans.err != nil {
			reason = ans.err.Error()
		}
		// A record matched against the base version is a real record, and
		// admission names it on the same entry against the same database.
		// The version stays unanswered and unstamped, because the range it
		// stands for was never queried, but dropping the ids would leave the
		// verb built for the late-published advisory silent on the case it
		// exists for.
		ch := OSVRescanChange{Vulns: vulnIDs(ans.vulns), Reason: reason}
		ch.Malware, ch.NewMalware = malwareSince(ve, ans.vulns)
		return ch
	}

	ids := vulnIDs(ans.vulns)
	had := ve.Metadata[OSVMetaVulns] != ""
	ch := OSVRescanChange{
		Answered: true,
		Vulns:    ids,
		Flagged:  len(ids) > 0 && !had,
		Cleared:  len(ids) == 0 && had,
		Reason:   ans.degraded,
	}
	ch.Malware, ch.NewMalware = malwareSince(ve, ans.vulns)
	stampOSV(ve, ans.vulns, c.now(), lk.queried)
	return ch
}

// malwareSince splits the malware records in vulns into all of them and the
// ones the version's current stamp does not name. Read before the re-stamp:
// after it, every record is one the stamp already names.
//
// Any stamped id counts as seen, not only the malware list, because a stamp
// written before that list existed carries a MAL- id among the advisories. A
// record an operator already looked at and left served is theirs to decide,
// and hiding it again on every rescan would overrule them.
func malwareSince(ve *manifest.VersionEntry, vulns []osvVuln) (all, fresh []string) {
	malware, _ := splitMalware(vulns)
	if len(malware) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, key := range []string{OSVMetaVulns, OSVMetaMalware} {
		for _, id := range splitIDs(ve.Metadata[key]) {
			seen[id] = true
		}
	}
	all = vulnIDs(malware)
	for _, id := range all {
		if !seen[id] {
			fresh = append(fresh, id)
		}
	}
	return all, fresh
}

// OSVRescanSummary accumulates one rescan run. Report is the only reader; the
// counters are exported so a caller can assert on them.
type OSVRescanSummary struct {
	Walked   int
	Answered int
	Flagged  int
	Cleared  int

	reasons     map[string]int
	reasonOrder []string
}

// Add folds one version's result in. Every version the walk considered is
// counted, so Walked minus Answered is the population whose stamp is now older
// than the run that just finished.
func (s *OSVRescanSummary) Add(ch OSVRescanChange) {
	s.Walked++
	if ch.Answered {
		s.Answered++
		if ch.Flagged {
			s.Flagged++
		}
		if ch.Cleared {
			s.Cleared++
		}
	}
	if ch.Reason == "" {
		return
	}
	if s.reasons == nil {
		s.reasons = map[string]int{}
	}
	if _, seen := s.reasons[ch.Reason]; !seen {
		s.reasonOrder = append(s.reasonOrder, ch.Reason)
	}
	s.reasons[ch.Reason]++
}

// Unanswered is the count of versions whose stamp the run left untouched.
func (s *OSVRescanSummary) Unanswered() int { return s.Walked - s.Answered }

// Report writes the run's outcome. The unanswered block is what separates a
// rescan that found nothing from a rescan that could not read the database:
// both print zero newly flagged, and only one of them names a reason.
func (s *OSVRescanSummary) Report(w io.Writer) {
	fmt.Fprintf(w, "Rescanned %d version(s): %d answered, %d newly flagged, %d newly cleared.\n",
		s.Walked, s.Answered, s.Flagged, s.Cleared)
	if s.Unanswered() > 0 {
		fmt.Fprintf(w, "%d version(s) unanswered; their previous stamp is unchanged.\n", s.Unanswered())
	}
	for _, reason := range s.reasonOrder {
		fmt.Fprintf(w, "  %d x %s\n", s.reasons[reason], reason)
	}
}

// OSVStamp is one version's recorded OSV state, as `show pkg` and the API
// render it. Checked zero means no run has ever answered for this version:
// versions checked before the check date existed cannot be backfilled, and
// dating them from the manifest's mtime would invent the fact the field
// carries.
type OSVStamp struct {
	Checked time.Time
	Vulns   []string
	// Severity is the per-advisory score B34 persisted and nothing read until
	// now, keyed by OSV id. An id present in Vulns and absent here is one OSV
	// scored nothing for, which is not the same as a score of zero.
	Severity map[string][]OSVSeverity
}

// Flagged reports whether the version carries findings.
func (s OSVStamp) Flagged() bool { return len(s.Vulns) > 0 }

// State names the version's OSV state in one word for a table column.
func (s OSVStamp) State() string {
	switch {
	case s.Flagged():
		return fmt.Sprintf("%d vuln(s)", len(s.Vulns))
	case s.Checked.IsZero():
		return "unchecked"
	default:
		return "clean"
	}
}

// OSVStampOf reads the OSV metadata off a version. An unparsable check date
// reads as unchecked, which is the honest answer for a value nothing can date.
func OSVStampOf(ve manifest.VersionEntry) OSVStamp {
	var st OSVStamp
	st.Vulns = splitIDs(ve.Metadata[OSVMetaVulns])
	if raw := ve.Metadata[OSVMetaSeverity]; raw != "" {
		// A blob that does not parse is dropped rather than reported. The ids
		// beside it are the finding; a score bodega could not read is a
		// rendering detail, and failing the whole stamp over one would hide
		// the advisory list that matters.
		var sev map[string][]OSVSeverity
		if err := json.Unmarshal([]byte(raw), &sev); err == nil && len(sev) > 0 {
			st.Severity = sev
		}
	}
	if raw := ve.Metadata[OSVMetaCheckedAt]; raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			st.Checked = t
		}
	}
	return st
}

// splitIDs reads a stamped id list back, sorted, with blanks dropped.
func splitIDs(raw string) []string {
	var ids []string
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
