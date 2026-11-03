package audit

import (
	"testing"
	"time"
)

// A fetch admitted under one checksum database outcome pins under a row
// carrying that outcome, never under a newer admission that verified bytes
// this fetch did not compare; with nothing matching it pins under no decision.
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

			stranger := gomod(t0, ProvenanceUnavailable, CheckPass)
			if got, err := db.PinAdmission(t.Context(), pin("gomod/info", &stranger)); err != nil || got != PinUnadmitted {
				t.Fatalf("PinAdmission with no matching decision = %v, %v; want PinUnadmitted", got, err)
			}
		})
	}
}
