package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// admissionStores opens a *DB per queryable sink, so the pin rules are held
// against the postgres sink as well as the embedded one. They are one shared
// pinTx in two dialects, and a dialect is exactly where they would drift.
func admissionStores(t *testing.T) map[string]func(t *testing.T) *DB {
	return map[string]func(t *testing.T) *DB{
		SinkSQLite: func(t *testing.T) *DB {
			db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			return db
		},
		SinkPostgres: func(t *testing.T) *DB {
			dsn := os.Getenv("BODEGA_TEST_POSTGRES_DSN")
			if dsn == "" {
				t.Skip("set BODEGA_TEST_POSTGRES_DSN to run the postgres sink against a live server")
			}
			db, err := OpenWithSink(filepath.Join(t.TempDir(), "audit.db"), SinkConfig{Kind: SinkPostgres, DSN: dsn})
			if err != nil {
				t.Fatalf("OpenWithSink: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if _, err := db.sink.(*postgresSink).db.Exec("DELETE FROM admissions"); err != nil {
				t.Fatalf("clear admissions: %v", err)
			}
			return db
		},
	}
}

func passed(version string, at time.Time) Admission {
	return Admission{
		PkgType: "pypi", PkgName: "requests", PkgVersion: version,
		Decision: AdmissionAdmitted, PolicyDigest: "sha256:aa", DecidedAt: at,
		Checks: []AdmissionCheck{
			{Check: CheckAllowList, Action: "block", Status: CheckPass},
			{Check: CheckAge, Action: ActionNone, Status: CheckPass},
			{Check: CheckOSV, Action: ActionNone, Status: CheckPass},
		},
	}
}

func TestPinAdmission(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	pin := func(version, key string) AdmissionPin {
		return AdmissionPin{PkgType: "pypi", PkgName: "requests", PkgVersion: version, ObjectKey: key}
	}

	for name, open := range admissionStores(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("attaches_to_the_newest_admitted_decision", func(t *testing.T) {
				db := open(t)
				older := passed("2.31.0", t0)
				blocked := passed("2.31.0", t0.Add(2*time.Hour))
				blocked.Decision = AdmissionPolicyBlocked
				newer := passed("2.31.0", t0.Add(time.Hour))
				newer.Actor = "newer"
				for _, a := range []Admission{older, blocked, newer} {
					if err := db.RecordAdmission(ctx, a); err != nil {
						t.Fatalf("RecordAdmission: %v", err)
					}
				}
				got, err := db.PinAdmission(ctx, pin("2.31.0", "pypi/wheels/requests-2.31.0-py3-none-any.whl"))
				if err != nil || got != PinAttached {
					t.Fatalf("PinAdmission = %v, %v; want PinAttached", got, err)
				}
				rows, err := db.Admissions(ctx, AdmissionFilter{PkgType: "pypi", PkgName: "requests"})
				if err != nil {
					t.Fatalf("Admissions: %v", err)
				}
				if len(rows) != 3 {
					t.Fatalf("pin changed the row count to %d", len(rows))
				}
				// Newest first: the blocked row, then the one pinned.
				if rows[0].Decision != AdmissionPolicyBlocked || rows[0].ObjectKey != "" {
					t.Errorf("a blocked decision took the key: %+v", rows[0])
				}
				if rows[1].Actor != "newer" || rows[1].ObjectKey == "" {
					t.Errorf("the key did not land on the newest admitted decision: %+v", rows[1])
				}
				if rows[2].ObjectKey != "" {
					t.Errorf("an older decision took the key as well: %+v", rows[2])
				}
			})

			t.Run("a_repeat_pin_changes_nothing_and_a_second_object_copies_the_decision", func(t *testing.T) {
				db := open(t)
				if err := db.RecordAdmission(ctx, passed("2.31.0", t0)); err != nil {
					t.Fatalf("RecordAdmission: %v", err)
				}
				for _, key := range []string{"k/one.whl", "k/one.whl", "k/two.whl", "k/one.whl"} {
					if got, err := db.PinAdmission(ctx, pin("2.31.0", key)); err != nil || got != PinAttached {
						t.Fatalf("PinAdmission(%s) = %v, %v", key, got, err)
					}
				}
				rows, err := db.Admissions(ctx, AdmissionFilter{PkgVersion: "2.31.0"})
				if err != nil {
					t.Fatalf("Admissions: %v", err)
				}
				keys := map[string]int{}
				for _, r := range rows {
					keys[r.ObjectKey]++
					if r.PolicyDigest != "sha256:aa" || !r.Evaluated() || !r.DecidedAt.Equal(t0) {
						t.Errorf("the copy for a second object is not the same decision: %+v", r)
					}
				}
				if len(rows) != 2 || keys["k/one.whl"] != 1 || keys["k/two.whl"] != 1 {
					t.Errorf("want one row per object key, got %v", keys)
				}
			})

			t.Run("a_pin_with_no_decision_writes_not_evaluated", func(t *testing.T) {
				db := open(t)
				blocked := passed("2.32.0", t0)
				blocked.Decision = AdmissionPolicyBlocked
				if err := db.RecordAdmission(ctx, blocked); err != nil {
					t.Fatalf("RecordAdmission: %v", err)
				}
				got, err := db.PinAdmission(ctx, pin("2.32.0", "k/three.whl"))
				if err != nil || got != PinUnadmitted {
					t.Fatalf("PinAdmission = %v, %v; want PinUnadmitted", got, err)
				}
				rows, err := db.Admissions(ctx, AdmissionFilter{PkgVersion: "2.32.0"})
				if err != nil {
					t.Fatalf("Admissions: %v", err)
				}
				if len(rows) != 2 {
					t.Fatalf("want the blocked row and one written by the pin, got %d", len(rows))
				}
				row := rows[0]
				if row.ObjectKey != "k/three.whl" || row.PolicyDigest != "" || row.Evaluated() {
					t.Errorf("the pin's row claims an evaluation: %+v", row)
				}
				for _, c := range row.Checks {
					if c.Status != CheckNotEvaluated {
						t.Errorf("check %s = %s on a row nothing evaluated", c.Check, c.Status)
					}
				}
				// The second pin of the same key finds that row and stays quiet.
				if got, err := db.PinAdmission(ctx, pin("2.32.0", "k/three.whl")); err != nil || got != PinAttached {
					t.Errorf("repeat pin = %v, %v; want PinAttached", got, err)
				}
				// A second object of the same unevaluated version is still unevaluated.
				if got, err := db.PinAdmission(ctx, pin("2.32.0", "k/four.whl")); err != nil || got != PinUnadmitted {
					t.Errorf("second object of an unevaluated version = %v, %v; want PinUnadmitted", got, err)
				}
			})
		})
	}
}

// audit_events selects which event types an operator keeps, and an admission
// is not an event: a decision dropped by that list is a version no
// attestation can cite.
func TestRecordAdmissionIgnoresTheEventFilter(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	db.SetEventFilter([]string{string(EventDenied)})
	if err := db.RecordAdmission(context.Background(), passed("1.0", time.Time{})); err != nil {
		t.Fatalf("RecordAdmission: %v", err)
	}
	rows, err := db.Admissions(context.Background(), AdmissionFilter{})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	if len(rows) != 1 || rows[0].DecidedAt.IsZero() {
		t.Fatalf("filtered store kept %d admissions (want 1, stamped): %+v", len(rows), rows)
	}
	if err := db.RecordAdmission(context.Background(), Admission{PkgType: "npm", PkgName: "x", Decision: "allowed"}); err == nil {
		t.Error("a decision outside the set was accepted")
	}
}

// Under a write-only sink there is no table to look a decision up in, so a
// pin is emitted for the consumer to join and reported as unverified rather
// than as attached or as unadmitted.
func TestPinAdmissionOnAWriteOnlySink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	db, err := OpenWithSink(filepath.Join(t.TempDir(), "audit.db"), SinkConfig{Kind: SinkJSONL, DSN: path})
	if err != nil {
		t.Fatalf("OpenWithSink: %v", err)
	}
	defer db.Close()
	got, err := db.PinAdmission(context.Background(), AdmissionPin{PkgType: "npm", PkgName: "x", PkgVersion: "1.0", ObjectKey: "npm/x/-/x-1.0.tgz"})
	if err != nil || got != PinUnverified {
		t.Fatalf("PinAdmission = %v, %v; want PinUnverified", got, err)
	}
	b, _ := os.ReadFile(path) //nolint:gosec // G304: this test's own temp file.
	recs := parseWireLines(t, []string{string(b)})
	if len(recs) != 1 || recs[0].Kind != "admission_pin" {
		t.Fatalf("want one admission_pin record, got %+v", recs)
	}
	if _, err := db.Admissions(context.Background(), AdmissionFilter{}); !IsUnqueryable(err) {
		t.Errorf("Admissions on a write-only sink = %v, want the unqueryable refusal", err)
	}
}
