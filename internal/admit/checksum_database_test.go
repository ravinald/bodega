package admit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

// sumdbConfig points the checksum_database check at log.
func sumdbConfig(base *config.Config, log *sumdbtest.Log) *config.Config {
	cfg := *base
	cfg.GomodSumdbURL = log.URL
	cfg.GomodSumdbKey = log.Key.Verifier
	return &cfg
}

func TestChecksumDatabaseOnGomodRowsOnly(t *testing.T) {
	f := newAdmissionFixture(t)
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "x")
	log.AddModule(m)
	cfg := sumdbConfig(f.synced, log)

	gomod := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: m.Path,
		Versions: []manifest.VersionEntry{{Version: m.Version, URL: "https://proxy.golang.org"}}}
	res := AdmitAs(t.Context(), nil, f.adb, cfg, gomod, Who{Actor: "ravi"})
	if !res.OK() || len(res.Admissions) != 1 {
		t.Fatalf("gomod admission: %+v", res)
	}
	row := res.Admissions[0]
	c := checkOf(t, row, audit.CheckChecksumDatabase)
	if c.Status != audit.CheckPass || c.Action != policy.ActionBlock || c.ChecksumDatabase == nil ||
		c.ChecksumDatabase.Outcome != audit.ProvenanceVerified || c.ChecksumDatabase.ZipHash != m.ZipHash || c.ChecksumDatabase.ModHash != m.ModHash {
		t.Errorf("gomod checksum_database entry = %+v %+v", c, c.ChecksumDatabase)
	}
	at := -1
	for i, c := range row.Checks {
		if c.Check == audit.CheckChecksumDatabase {
			at = i
		}
	}
	if at < 1 || row.Checks[at-1].Check != audit.CheckUpstreamProvenance {
		t.Errorf("checksum_database is not ordered right after upstream_provenance: %+v", row.Checks)
	}

	npm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad", Versions: []manifest.VersionEntry{{Version: "1.3.0"}}}
	res = AdmitAs(t.Context(), nil, f.adb, cfg, npm, Who{Actor: "ravi"})
	if len(res.Admissions) != 1 {
		t.Fatalf("npm admission wrote %d rows: %+v", len(res.Admissions), res)
	}
	for _, c := range res.Admissions[0].Checks {
		if c.Check == audit.CheckChecksumDatabase {
			t.Errorf("npm row carries checksum_database: %+v", res.Admissions[0].Checks)
		}
	}
}

// An override names the version and the check: one admits a version the
// database could not answer for, and none admits one it disagrees with.
func TestChecksumDatabaseOverrides(t *testing.T) {
	f := newAdmissionFixture(t)
	now := time.Now()
	key := sumdbtest.NewKey(t)
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "x")

	silent := sumdbtest.New(t, key) // holds nothing: every lookup 404s
	forged := sumdbtest.New(t, sumdbtest.NewKey(t))
	forged.AddModule(m)
	for _, tc := range []struct {
		name    string
		log     *sumdbtest.Log
		outcome string
		applies bool
	}{
		{"unknown", silent, audit.ProvenanceUnknown, true},
		{"invalid", forged, audit.ProvenanceInvalid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *f.synced
			cfg.GomodSumdbURL, cfg.GomodSumdbKey = tc.log.URL, key.Verifier
			version := map[bool]string{true: "v1.2.3", false: "v1.2.4"}[tc.applies]
			if !tc.applies {
				forged.AddModule(sumdbtest.NewModule(t, m.Path, version, "y"))
			}
			o := request(t, f.adb, f.synced, OverrideRequest{Type: manifest.TypeGomod, Name: m.Path, Version: version,
				Check: audit.CheckChecksumDatabase, Reason: "INC-7", Expires: "7d"}, now)
			vote(t, f.adb, o.ID, "bob", true, now)

			got := Fetch(t.Context(), f.adb, []policy.VersionChecker{ChecksumDatabaseChecker(&cfg, f.adb)}, manifest.TypeGomod, m.Path,
				manifest.VersionEntry{Version: version}, AllowListCheck(false, m.Path, nil), Who{}, "")
			c := checkOf(t, got.Admission, audit.CheckChecksumDatabase)
			if c.ChecksumDatabase == nil || c.ChecksumDatabase.Outcome != tc.outcome {
				t.Fatalf("outcome %+v, want %s: %s", c.ChecksumDatabase, tc.outcome, c.Detail)
			}
			if tc.applies {
				if got.Block != nil || got.Admission.Decision != audit.AdmissionAdmitted || c.Status != audit.CheckOverridden || c.Override != o.ID {
					t.Errorf("override did not admit an unknown outcome: %+v", got.Admission)
				}
				return
			}
			if got.Block == nil || got.Admission.Decision != audit.AdmissionPolicyBlocked || c.Status != audit.CheckBlock {
				t.Fatalf("an override admitted past an invalid outcome: %+v", got.Admission)
			}
			if c.Unwaivable != ChecksumDatabaseInvalidReason || !strings.Contains(c.Detail, "override "+o.ID+" does not apply: "+ChecksumDatabaseInvalidReason) {
				t.Errorf("refusal does not say why the override does not apply: unwaivable %q detail %q", c.Unwaivable, c.Detail)
			}
		})
	}
}

// Evaluate previews an admission and writes nothing, the stored tree head
// included.
func TestEvaluateWritesNoTreeHead(t *testing.T) {
	f := newAdmissionFixture(t)
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	first := sumdbtest.NewModule(t, "example.com/widget", "v1.0.0", "x")
	second := sumdbtest.NewModule(t, "example.com/widget", "v1.1.0", "y")
	log.AddModule(first)
	log.AddModule(second)
	cfg := sumdbConfig(f.synced, log)

	// One admission that writes, so there is a head for Evaluate to read.
	pm := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: first.Path, Versions: []manifest.VersionEntry{{Version: first.Version}}}
	if res := AdmitAs(t.Context(), nil, f.adb, cfg, pm, Who{Actor: "ravi"}); !res.OK() {
		t.Fatalf("admit: %+v", res)
	}
	before, err := f.adb.GetChecksumDatabaseTree(t.Context(), sumdbtest.Name)
	if err != nil || len(before) == 0 {
		t.Fatalf("no tree head stored: %q %v", before, err)
	}

	// The second version grows the log, so a checker that wrote would move
	// the head.
	pm = &manifest.PackageManifest{Type: manifest.TypeGomod, Name: second.Path, Versions: []manifest.VersionEntry{{Version: second.Version}}}
	v := Evaluate(t.Context(), cfg, nil, f.adb, nil, pm, time.Now())
	var c *audit.AdmissionCheck
	for i := range v.Checks {
		if v.Checks[i].Check == audit.CheckChecksumDatabase {
			c = &v.Checks[i]
		}
	}
	if v.Decision != Admitted || c == nil || c.ChecksumDatabase == nil || c.ChecksumDatabase.Outcome != audit.ProvenanceVerified || c.ChecksumDatabase.TreeSize != 2 {
		t.Fatalf("Evaluate: %+v, checksum_database %+v", v, c)
	}
	after, _ := f.adb.GetChecksumDatabaseTree(t.Context(), sumdbtest.Name)
	if !bytes.Equal(after, before) {
		t.Errorf("Evaluate moved the stored tree head:\n%s\nwas\n%s", after, before)
	}
}
