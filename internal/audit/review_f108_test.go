package audit

import (
	"path/filepath"
	"testing"
)

func TestReviewUnadmittedGomodPinCarriesChecksumDatabase(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, typ := range []string{"gomod", "npm"} {
		pin := AdmissionPin{PkgType: typ, PkgName: "example.com/widget", PkgVersion: "v1.2.3", ObjectKey: typ + "/test"}
		if _, err := db.PinAdmission(t.Context(), pin); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Admissions(t.Context(), AdmissionFilter{PkgType: typ})
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows=%v err=%v", rows, err)
		}
		found := false
		for i, c := range rows[0].Checks {
			if c.Check != CheckChecksumDatabase {
				continue
			}
			found = true
			if c.Status != CheckNotEvaluated || i == 0 || rows[0].Checks[i-1].Check != CheckUpstreamProvenance {
				t.Errorf("bad checksum_database entry: %+v", rows[0].Checks)
			}
		}
		if found != (typ == "gomod") {
			t.Errorf("%s fallback row checksum_database present=%v: %+v", typ, found, rows[0].Checks)
		}
	}
}
