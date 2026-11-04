package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A fetch admitted under one checksum database outcome pins under a row
// carrying that outcome, never under a newer admission that verified bytes
// this fetch did not compare; with nothing matching it declines, writing no row.
func TestPinKeepsTheFetchsChecksumEvidence(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	gomod := func(at time.Time, outcome, status string) Admission {
		a := passed("v1.2.3", at)
		a.PkgType, a.PkgName = "gomod", "example.com/widget"
		a.Checks = append(a.Checks, AdmissionCheck{Check: CheckChecksumDatabase, Action: "block", Status: status,
			Detail: outcome, ChecksumDatabase: &ChecksumDatabase{Outcome: outcome, ZipHash: "h1:zip", ModHash: "h1:mod"}})
		return a
	}
	pin := func(key string, admitted *Admission) AdmissionPin {
		return AdmissionPin{PkgType: "gomod", PkgName: "example.com/widget", PkgVersion: "v1.2.3", ObjectKey: key, Admitted: admitted}
	}
	keyOf := func(t *testing.T, db *DB, outcome string) []string {
		t.Helper()
		rows, err := db.Admissions(t.Context(), AdmissionFilter{PkgType: "gomod", PkgName: "example.com/widget"})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, r := range rows {
			for _, c := range r.Checks {
				if c.ChecksumDatabase != nil && c.ChecksumDatabase.Outcome == outcome {
					keys = append(keys, r.ObjectKey)
				}
			}
		}
		return keys
	}
	for name, open := range admissionStores(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			unknown := gomod(t0, ProvenanceUnknown, CheckOverridden)
			verified := gomod(t0.Add(time.Second), ProvenanceVerified, CheckPass)
			for _, a := range []Admission{unknown, verified} {
				if err := db.RecordAdmission(t.Context(), a); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := db.PinAdmission(t.Context(), pin("gomod/zip", &unknown)); err != nil || got != PinAttached {
				t.Fatalf("PinAdmission = %v, %v", got, err)
			}
			if got := keyOf(t, db, ProvenanceUnknown); len(got) != 1 || got[0] != "gomod/zip" {
				t.Errorf("unknown fetch pinned under %v, want its own row", got)
			}
			if got := keyOf(t, db, ProvenanceVerified); len(got) != 1 || got[0] != "" {
				t.Errorf("the verified row took a key it never compared: %v", got)
			}

			if got, err := db.PinAdmission(t.Context(), pin("gomod/mod", &verified)); err != nil || got != PinAttached {
				t.Fatalf("PinAdmission = %v, %v", got, err)
			}
			if got := keyOf(t, db, ProvenanceVerified); len(got) != 1 || got[0] != "gomod/mod" {
				t.Errorf("verified fetch pinned under %v, want the newest row", got)
			}

			countRows := func(t *testing.T) int {
				t.Helper()
				rows, err := db.Admissions(t.Context(), AdmissionFilter{PkgType: "gomod", PkgName: "example.com/widget"})
				if err != nil {
					t.Fatal(err)
				}
				return len(rows)
			}
			before := countRows(t)
			stranger := gomod(t0, ProvenanceUnavailable, CheckPass)
			if _, err := db.PinAdmission(t.Context(), pin("gomod/info", &stranger)); !errors.Is(err, ErrAdmissionNotLocated) {
				t.Fatalf("PinAdmission with no matching decision: %v; want ErrAdmissionNotLocated", err)
			}
			if got := countRows(t); got != before {
				t.Errorf("a declined pin wrote %d rows; a fetch that was decided gets no new decision", got-before)
			}
		})
	}
}

// A pin naming no admission never attaches a new object to a row whose
// checksum_database outcome is verified, by setting its key or by copying it
// for a second key; an object that row already carries still pins.
func TestUnboundPinCannotTakeVerifiedChecksumEvidence(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	for name, open := range admissionStores(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			verified := passed("v1.2.3", t0)
			verified.PkgType, verified.PkgName = "gomod", "example.com/widget"
			verified.Checks = append(verified.Checks, AdmissionCheck{Check: CheckChecksumDatabase, Action: "block", Status: CheckPass,
				Detail: "verified", ChecksumDatabase: &ChecksumDatabase{Outcome: ProvenanceVerified, ZipHash: "h1:zip", ModHash: "h1:mod"}})
			if err := db.RecordAdmission(t.Context(), verified); err != nil {
				t.Fatal(err)
			}
			pin := func(key string, admitted *Admission) AdmissionPin {
				return AdmissionPin{PkgType: "gomod", PkgName: "example.com/widget", PkgVersion: "v1.2.3", ObjectKey: key, Admitted: admitted}
			}
			keys := func() []string {
				rows, err := db.Admissions(t.Context(), AdmissionFilter{PkgType: "gomod", PkgName: "example.com/widget"})
				if err != nil {
					t.Fatal(err)
				}
				var out []string
				for _, r := range rows {
					out = append(out, r.ObjectKey)
				}
				return out
			}

			if _, err := db.PinAdmission(t.Context(), pin("gomod/zip", nil)); !errors.Is(err, ErrUnboundChecksumEvidence) {
				t.Fatalf("unbound pin on an unkeyed verified row: err = %v, want ErrUnboundChecksumEvidence", err)
			}
			if got := keys(); len(got) != 1 || got[0] != "" {
				t.Fatalf("refused pin changed the rows: %q", got)
			}

			if got, err := db.PinAdmission(t.Context(), pin("gomod/zip", &verified)); err != nil || got != PinAttached {
				t.Fatalf("bound pin = %v, %v", got, err)
			}
			if got, err := db.PinAdmission(t.Context(), pin("gomod/zip", nil)); err != nil || got != PinAttached {
				t.Fatalf("unbound re-pin of the row's own object = %v, %v", got, err)
			}
			if _, err := db.PinAdmission(t.Context(), pin("gomod/mod", nil)); !errors.Is(err, ErrUnboundChecksumEvidence) {
				t.Fatalf("unbound pin copying a keyed verified row: err = %v, want ErrUnboundChecksumEvidence", err)
			}
			if got := keys(); len(got) != 1 || got[0] != "gomod/zip" {
				t.Fatalf("refused copy changed the rows: %q", got)
			}
		})
	}
}

type fixedAdmissions []Admission

func (f fixedAdmissions) Admissions(context.Context, AdmissionFilter) ([]Admission, error) {
	return append([]Admission(nil), f...), nil
}

// A signer reading through ComparedAdmissions sees a verified checksum
// database row only when the caller compared the digest it signs under that
// row's evidence; every other row passes through, a newer denial carrying
// verified evidence included.
func TestComparedAdmissionsWithholdsVerifiedRowsNoComparisonVouchesFor(t *testing.T) {
	sumdb := func(outcome, zip string) []AdmissionCheck {
		return []AdmissionCheck{{Check: CheckChecksumDatabase, Status: CheckPass,
			ChecksumDatabase: &ChecksumDatabase{Outcome: outcome, ZipHash: zip}}}
	}
	verified := Admission{ID: 2, Decision: AdmissionAdmitted, Checks: sumdb(ProvenanceVerified, "h1:a")}
	other := Admission{ID: 3, Decision: AdmissionAdmitted, Checks: sumdb(ProvenanceVerified, "h1:b")}
	excluded := Admission{ID: 1, Decision: AdmissionAdmitted, Checks: sumdb(ProvenanceUnavailable, "")}
	denied := Admission{ID: 4, Decision: AdmissionPolicyBlocked, Checks: sumdb(ProvenanceVerified, "h1:b")}
	rows := fixedAdmissions{denied, other, verified, excluded}
	for _, tc := range []struct {
		name     string
		sha      string
		compared *ChecksumComparison
		want     []int64
	}{
		{"no comparison", "aa", nil, []int64{4, 1}},
		{"compared other bytes", "aa", &ChecksumComparison{SHA256: "bb", Checks: verified.Checks}, []int64{4, 1}},
		{"compared under other evidence", "aa", &ChecksumComparison{SHA256: "aa", Checks: excluded.Checks}, []int64{4, 1}},
		{"compared these bytes", "AA", &ChecksumComparison{SHA256: "aa", Checks: verified.Checks}, []int64{4, 2, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ComparedAdmissions{Reader: rows, SHA256: tc.sha, Compared: tc.compared}.Admissions(t.Context(), AdmissionFilter{})
			if err != nil {
				t.Fatal(err)
			}
			var ids []int64
			for _, r := range got {
				ids = append(ids, r.ID)
			}
			if len(ids) != len(tc.want) {
				t.Fatalf("rows %v, want %v", ids, tc.want)
			}
			for i := range ids {
				if ids[i] != tc.want[i] {
					t.Fatalf("rows %v, want %v", ids, tc.want)
				}
			}
		})
	}
}

// A pin holding its fetch's admission writes no not_evaluated row when no
// admitted row is on record: that row would be a new admission, newer than
// the refusal that is.
func TestPinHoldingAnAdmissionNeverRecordsANewOne(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	for name, open := range admissionStores(t) {
		t.Run(name, func(t *testing.T) {
			db := open(t)
			fetch := passed("v1.2.3", t0)
			fetch.PkgType, fetch.PkgName = "gomod", "example.com/widget"
			denied := fetch
			denied.Decision, denied.DecidedAt = AdmissionPolicyBlocked, t0.Add(time.Second)
			if err := db.RecordAdmission(t.Context(), denied); err != nil {
				t.Fatal(err)
			}
			_, err := db.PinAdmission(t.Context(), AdmissionPin{PkgType: "gomod", PkgName: "example.com/widget", PkgVersion: "v1.2.3", ObjectKey: "gomod/zip", Admitted: &fetch})
			if !errors.Is(err, ErrAdmissionNotLocated) {
				t.Fatalf("PinAdmission: %v; want ErrAdmissionNotLocated", err)
			}
			rows, err := db.Admissions(t.Context(), AdmissionFilter{PkgType: "gomod", PkgName: "example.com/widget"})
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Decision != AdmissionPolicyBlocked {
				t.Errorf("rows after a declined pin: %+v; want the refusal alone", rows)
			}
		})
	}
}
