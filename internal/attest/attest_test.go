package attest

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// The example in the DSSE protocol specification
// (secure-systems-lab/dsse, protocol.md), as the bytes it publishes.
func TestPAEMatchesTheSpecExample(t *testing.T) {
	got := PAE("http://example.com/HelloWorld", []byte("hello world"))
	wantHex := "44 53 53 45 76 31 20 32 39 20 68 74 74 70 3a 2f 2f 65 78 61 6d 70 6c 65 2e 63 6f 6d 2f 48 65 6c 6c 6f 57 6f 72 6c 64 20 31 31 20 68 65 6c 6c 6f 20 77 6f 72 6c 64"
	wantBytes, err := hex.DecodeString(strings.ReplaceAll(wantHex, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantBytes) {
		t.Errorf("PAE = %q, want %q", got, wantBytes)
	}
	if string(got) != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Errorf("PAE = %q", got)
	}
}

func TestPURL(t *testing.T) {
	for _, tc := range []struct{ typ, name, version, key, want string }{
		{manifest.TypeNpm, "@example-corp/widget-cli", "1.5.0", "", "pkg:npm/%40example-corp/widget-cli@1.5.0"},
		{manifest.TypeNpm, "lodash", "4.17.21", "", "pkg:npm/lodash@4.17.21"},
		{manifest.TypePypi, "Example_SDK", "1.35.0", manifest.PypiWheelKey("example_sdk-1.35.0-py3-none-any.whl"),
			"pkg:pypi/example-sdk@1.35.0?file_name=example_sdk-1.35.0-py3-none-any.whl"},
		{manifest.TypeGomod, "example.com/example-corp/sdk", "v1.30.0", "", "pkg:golang/example.com/example-corp/sdk@v1.30.0"},
		{manifest.TypeCargo, "serde", "1.0.200", "", "pkg:cargo/serde@1.0.200"},
		{manifest.TypeApt, "hello", "2.10-3build1+x", "", "pkg:generic/apt/hello@2.10-3build1%2Bx"},
		{manifest.TypeDistfiles, "sub/zsh-5.9.tar.xz", "", "", "pkg:generic/distfiles/sub%2Fzsh-5.9.tar.xz"},
	} {
		if got := PURL(tc.typ, tc.name, tc.version, tc.key); got != tc.want {
			t.Errorf("PURL(%s, %s, %s) = %s, want %s", tc.typ, tc.name, tc.version, got, tc.want)
		}
	}
	if got := PURLBase("pkg:pypi/x@1?file_name=x.whl"); got != "pkg:pypi/x@1" {
		t.Errorf("PURLBase = %s", got)
	}
}

func newSigner(t *testing.T) attestsign.Signer {
	t.Helper()
	kr, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kr.Signer()
}

func trusted(t *testing.T, s attestsign.Signer) map[string]ed25519.PublicKey {
	t.Helper()
	pub := s.Public().(ed25519.PublicKey)
	id, err := KeyIDOf(pub)
	if err != nil || id != s.KeyID() {
		t.Fatalf("KeyIDOf = %s, %v; signer says %s", id, err, s.KeyID())
	}
	return map[string]ed25519.PublicKey{id: pub}
}

func openAudit(t *testing.T) *audit.DB {
	t.Helper()
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func emitter(db *audit.DB, s attestsign.Signer) *Emitter {
	return &Emitter{
		Signer:     func() attestsign.Signer { return s },
		Admissions: db,
		PlatformID: "https://bodega.example",
		Now:        func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) },
	}
}

func admit(t *testing.T, db *audit.DB, version, decision string, checks []audit.AdmissionCheck) {
	t.Helper()
	if err := db.RecordAdmission(context.Background(), audit.Admission{
		PkgType: manifest.TypeNpm, PkgName: "lodash", PkgVersion: version, Decision: decision,
		Checks: checks, PolicyDigest: "sha256:" + strings.Repeat("ab", 32), Actor: "ci",
	}); err != nil {
		t.Fatal(err)
	}
}

func pin(t *testing.T, db *audit.DB, version, key string) Pin {
	t.Helper()
	out, err := db.PinAdmission(context.Background(), audit.AdmissionPin{PkgType: manifest.TypeNpm, PkgName: "lodash", PkgVersion: version, ObjectKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return Pin{Type: manifest.TypeNpm, Name: "lodash", Version: version, ObjectKey: key, SHA256: digest, Outcome: out}
}

var passing = []audit.AdmissionCheck{
	{Check: audit.CheckAllowList, Action: "block", Status: audit.CheckPass},
	{Check: audit.CheckAge, Action: "warn", Status: audit.CheckPass},
}

func TestEmitSignsWhatTheRowSaysAndVerifies(t *testing.T) {
	ctx := context.Background()
	db := openAudit(t)
	s := newSigner(t)
	store := storage.NewMemory()
	key := manifest.NpmTarballKey("lodash", "4.17.21")

	admit(t, db, "4.17.21", audit.AdmissionAdmitted, passing)
	p := pin(t, db, "4.17.21", key)
	p.RequiredBy = []string{"widget"}
	ek, err := emitter(db, s).Emit(ctx, store, p)
	if err != nil || ek == "" {
		t.Fatalf("Emit = %q, %v", ek, err)
	}
	if !strings.HasPrefix(ek, manifest.AttestationDir(key)) {
		t.Errorf("envelope key %s is not under %s", ek, manifest.AttestationDir(key))
	}
	data, _ := store.Get(ctx, ek)
	env, st, err := ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	pr := st.Predicate
	if pr.IngestionPlatform.ID != "https://bodega.example" || pr.PolicyEvaluations.PolicyDigest["sha256"] != strings.Repeat("ab", 32) ||
		len(pr.ResolvedFrom) != 1 || pr.ResolvedFrom[0].Name != "widget" ||
		pr.UpstreamProvenance.Status != StatusUnavailable || pr.PublisherSignature.Status != StatusUnavailable {
		t.Errorf("predicate = %+v", pr)
	}
	// The row lacks an OSV entry, so the statement says so rather than
	// leaving it out.
	if last := pr.PolicyEvaluations.Evaluations[len(pr.PolicyEvaluations.Evaluations)-1]; last.Check != audit.CheckOSV || last.Status != audit.CheckNotEvaluated {
		t.Errorf("missing check rendered as %+v", last)
	}

	in := VerifyInput{Trusted: trusted(t, s), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}
	for _, r := range Verify(env, st, in) {
		if !r.OK {
			t.Errorf("%s failed: expected %s, observed %s", r.Check, r.Expected, r.Observed)
		}
	}

	// A repeat pin under the same decision lands on the same key; a
	// re-admission writes a second envelope and keeps the first.
	if again, err := emitter(db, s).Emit(ctx, store, pin(t, db, "4.17.21", key)); err != nil || again != ek {
		t.Errorf("repeat Emit = %q, %v; want %q", again, err, ek)
	}
	time.Sleep(2 * time.Millisecond)
	admit(t, db, "4.17.21", audit.AdmissionAdmitted, passing)
	second, err := emitter(db, s).Emit(ctx, store, pin(t, db, "4.17.21", key))
	if err != nil || second == ek {
		t.Fatalf("re-admission Emit = %q, %v", second, err)
	}
	if n, _ := store.List(ctx, manifest.AttestationDir(key)); len(n) != 2 {
		t.Errorf("envelopes after a re-admission = %v, want 2", n)
	}
	if newest, _ := Newest(ctx, store, []string{key}); newest != second {
		t.Errorf("Newest = %s, want %s", newest, second)
	}
}

func TestVerifyNamesEachFailure(t *testing.T) {
	ctx := context.Background()
	db := openAudit(t)
	s := newSigner(t)
	store := storage.NewMemory()
	key := manifest.NpmTarballKey("lodash", "4.17.21")
	admit(t, db, "4.17.21", audit.AdmissionAdmitted, passing)
	ek, err := emitter(db, s).Emit(ctx, store, pin(t, db, "4.17.21", key))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := store.Get(ctx, ek)
	env, st, _ := ParseEnvelope(data)
	good := VerifyInput{Trusted: trusted(t, s), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}

	failed := func(in VerifyInput) []string {
		var out []string
		for _, r := range Verify(env, st, in) {
			if !r.OK {
				out = append(out, r.Check)
			}
		}
		return out
	}
	other := good
	other.Trusted = trusted(t, newSigner(t))
	if got := failed(other); len(got) != 1 || got[0] != CheckSignature {
		t.Errorf("wrong key fails %v, want [signature]", got)
	}
	other = good
	other.ArtifactSHA256 = strings.Repeat("0", 64)
	if got := failed(other); len(got) != 1 || got[0] != CheckSubjectDigest {
		t.Errorf("changed artifact fails %v, want [subject-digest]", got)
	}
	other = good
	other.WantPURL = "pkg:npm/lodash@4.17.20"
	if got := failed(other); len(got) != 1 || got[0] != CheckSubjectName {
		t.Errorf("other version fails %v, want [subject-name]", got)
	}

	// A payload edited after signing breaks the signature even though every
	// claim in it still matches what the verifier asked for.
	st.Subject[0].Name = "pkg:npm/lodash@4.17.21"
	tampered := *env
	tampered.Payload = env.Payload[:len(env.Payload)-4] + "AAAA"
	if r := Verify(&tampered, st, good)[0]; r.OK {
		t.Error("a changed payload still verifies")
	}
}

func TestEmitRefuses(t *testing.T) {
	ctx := context.Background()
	key := manifest.NpmTarballKey("lodash", "1.0.0")
	for _, tc := range []struct {
		name  string
		setup func(*audit.DB) Pin
		want  string
	}{
		{"no row", func(db *audit.DB) Pin {
			return Pin{Type: manifest.TypeNpm, Name: "lodash", Version: "1.0.0", ObjectKey: key, SHA256: digest}
		}, "no admission row"},
		{"newest is blocked", func(db *audit.DB) Pin {
			admit(t, db, "1.0.0", audit.AdmissionAdmitted, passing)
			p := pin(t, db, "1.0.0", key)
			time.Sleep(2 * time.Millisecond)
			admit(t, db, "1.0.0", audit.AdmissionPolicyBlocked, []audit.AdmissionCheck{{Check: audit.CheckOSV, Action: "block", Status: audit.CheckBlock}})
			return p
		}, "policy_blocked"},
		{"row names another object", func(db *audit.DB) Pin {
			admit(t, db, "1.0.0", audit.AdmissionAdmitted, passing)
			pin(t, db, "1.0.0", "npm/lodash/other.tgz")
			return Pin{Type: manifest.TypeNpm, Name: "lodash", Version: "1.0.0", ObjectKey: key, SHA256: digest}
		}, "names object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openAudit(t)
			store := storage.NewMemory()
			got, err := emitter(db, newSigner(t)).Emit(ctx, store, tc.setup(db))
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Emit = %q, %v; want ErrRefused mentioning %q", got, err, tc.want)
			}
			if keys := store.Keys(); len(keys) != 0 {
				t.Errorf("a refusal wrote %v", keys)
			}
		})
	}
}

// A pin no decision preceded is signed with the not_evaluated checks the row
// records, never as a pass.
func TestEmitUnadmittedPinSignsNotEvaluated(t *testing.T) {
	ctx := context.Background()
	db := openAudit(t)
	store := storage.NewMemory()
	key := manifest.NpmTarballKey("lodash", "2.0.0")
	p := pin(t, db, "2.0.0", key)
	if p.Outcome != audit.PinUnadmitted {
		t.Fatalf("outcome = %v, want PinUnadmitted", p.Outcome)
	}
	ek, err := emitter(db, newSigner(t)).Emit(ctx, store, p)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := store.Get(ctx, ek)
	_, st, _ := ParseEnvelope(data)
	evals := st.Predicate.PolicyEvaluations.Evaluations
	if len(evals) == 0 {
		t.Fatal("no evaluations")
	}
	for _, e := range evals {
		if e.Status != audit.CheckNotEvaluated {
			t.Errorf("evaluation %+v on an unadmitted pin", e)
		}
	}
}

func TestEmitNothingWithoutAKeyOrATable(t *testing.T) {
	ctx := context.Background()
	db := openAudit(t)
	store := storage.NewMemory()
	e := emitter(db, nil)
	e.Signer = func() attestsign.Signer { return nil }
	if k, err := e.Emit(ctx, store, Pin{ObjectKey: "x", SHA256: digest}); k != "" || err != nil {
		t.Errorf("no key: Emit = %q, %v", k, err)
	}
	if k, err := emitter(db, newSigner(t)).Emit(ctx, store, Pin{ObjectKey: "x", SHA256: digest, Outcome: audit.PinUnverified}); k != "" || err != nil {
		t.Errorf("unverified pin: Emit = %q, %v", k, err)
	}
	if keys := store.Keys(); len(keys) != 0 {
		t.Errorf("wrote %v", keys)
	}
}
