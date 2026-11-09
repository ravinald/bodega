package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

func readDoc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// docSection is doc from heading to the next heading of the same level.
func docSection(t *testing.T, doc, heading string) string {
	t.Helper()
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		t.Fatalf("no %q heading; it moved", heading)
	}
	rest := doc[i+1+len(heading):]
	level := heading[:strings.IndexByte(heading, ' ')+1]
	if j := strings.Index(rest, "\n"+level); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// tableRow is the first line of doc that is a table row whose first cell is
// cell, or "".
func tableRow(doc, cell string) string {
	re := regexp.MustCompile(`(?m)^\|\s*` + regexp.QuoteMeta(cell) + `\s*\|.*$`)
	return re.FindString(doc)
}

// The checksum_database check's keys, outcomes and operator steps are where
// an operator reads them: the configuration table and the Go proxy section of
// docs/usage.md, and the proof boundary in design.md and threat-model.md.
func TestUsageDocumentsChecksumDatabase(t *testing.T) {
	usage := readDoc(t, "usage.md")
	cfg := loadFrom(t, `{}`)

	sumdbURL := strings.Index(usage, tableRow(usage, "`gomod_sumdb_url`"))
	for key, def := range map[string]string{"`gomod_sumdb_key`": cfg.GomodSumdbKey, "`gomod_nosumdb`": "empty"} {
		row := tableRow(usage, key)
		if row == "" {
			t.Errorf("docs/usage.md has no configuration row for %s", key)
			continue
		}
		if !strings.Contains(row, def) {
			t.Errorf("%s row does not give the default %q: %s", key, def, row)
		}
		if at := strings.Index(usage, row); sumdbURL < 0 || at < sumdbURL || at-sumdbURL > 4*len(row)+2000 {
			t.Errorf("%s row is not beside the gomod_sumdb_url row", key)
		}
	}
	if cfg.GomodSumdbKey != config.DefaultGomodSumdbKey {
		t.Fatalf("loaded default %q is not DefaultGomodSumdbKey", cfg.GomodSumdbKey)
	}

	outcomes := map[string]string{"`verified`": "`pass`", "`invalid`": "`block`", "`unknown`": "`block`", "`unavailable`": "`pass`"}
	goSection := usage[strings.Index(usage, "The checksum database comes through the same `GOPROXY`"):]
	goSection = goSection[:strings.Index(goSection, "\n#")]
	for outcome, status := range outcomes {
		row := tableRow(goSection, outcome)
		if row == "" || !strings.Contains(row, status) {
			t.Errorf("the Go proxy section's outcome table has no %s row with status %s: %q", outcome, status, row)
		}
	}
	for _, want := range []string{
		"fails closed",
		"--check checksum_database",
		"`gomod_nosumdb`",
		"`checksum_database_tree`",
		"before this check existed are not re-checked",
	} {
		if !strings.Contains(goSection, want) {
			t.Errorf("the Go proxy section does not say %q", want)
		}
	}

	for name, doc := range map[string]string{
		"design.md":       docSection(t, readDoc(t, "design.md"), "### Attestations"),
		"threat-model.md": strings.Join(strings.Fields(readDoc(t, "threat-model.md")), " "),
	} {
		flat := strings.Join(strings.Fields(doc), " ")
		for _, want := range []string{"`checksum_database`", "public", "who published them", "safe"} {
			if !strings.Contains(flat, want) {
				t.Errorf("docs/%s does not say %q about a verified checksum_database outcome", name, want)
			}
		}
	}
}

// docs/slsa.md names the Go checksum database as met at Level 2's integrity
// row and no longer lists it, or #274, as a publisher-evidence gap.
func TestSLSADocumentsChecksumDatabase(t *testing.T) {
	slsa := readDoc(t, "slsa.md")

	row := tableRow(slsa, "L2: integrity verified at ingestion; a failure is refused")
	if row == "" {
		t.Fatal("docs/slsa.md has no Level 2 integrity row; it moved")
	}
	for _, want := range []string{"Go module", "checksum database", "`checksum_database`", "refused"} {
		if !strings.Contains(row, want) {
			t.Errorf("the Level 2 integrity row does not say %q: %s", want, row)
		}
	}

	gaps := docSection(t, slsa, "### Gaps")
	bullet := regexp.MustCompile(`(?m)^- \*\*Publisher signatures.*$`).FindString(gaps)
	if bullet == "" {
		return
	}
	for _, banned := range []string{"checksum database", "#274", "issues/274"} {
		if strings.Contains(strings.ToLower(bullet), strings.ToLower(banned)) {
			t.Errorf("the publisher-signature gap still names %q: %s", banned, bullet)
		}
	}
	if !strings.HasPrefix(bullet, "- **Publisher signatures are verified for npm, PyPI, GitHub releases and classic Helm charts only.**") {
		t.Errorf("the gap's bold sentence does not list the ecosystems bodega verifies publisher evidence for: %s", bullet)
	}
	if !strings.Contains(bullet, "served over OCI") {
		t.Errorf("the gap names no remaining gap and should be removed: %s", bullet)
	}
}

// usage.md has to describe FreeBSD as covered by VuXML, with pkg's version
// order, and no longer list it among the types no advisory source covers.
func TestUsageDoc_FreeBSDAdvisoriesComeFromVuXML(t *testing.T) {
	doc := readDoc(t, "usage.md")
	row := tableRow(docSection(t, doc, "### `bodega policy osv <sync|set|list|remove|rescan|malware>`"), "freebsd")
	if !strings.Contains(row, "VuXML") || !strings.Contains(row, "pkg-version(8)") {
		t.Errorf("the OSV ecosystem table's freebsd row must name VuXML and pkg-version(8) ordering: %q", row)
	}
	section := docSection(t, doc, "#### FreeBSD (VuXML)")
	for _, want := range []string{"`3.0.15_1,1` sorts above `3.0.15,1` and below `3.0.16,1`", "epoch after the comma first", "port revision after the underscore", "case-sensitively"} {
		if !strings.Contains(section, want) {
			t.Errorf("FreeBSD (VuXML) section lacks %q", want)
		}
	}
	for _, stale := range []string{
		"`binary`, `git`, `helm`, `freebsd`, `distfiles` and `oci` have no OSV identifier",
		"Those five have no OSV ecosystem identifier",
		"proxied helm, binary, git and freebsd fetches are not checked at all",
	} {
		if strings.Contains(doc, stale) {
			t.Errorf("usage.md still says FreeBSD has no advisory source: %q", stale)
		}
	}
}
