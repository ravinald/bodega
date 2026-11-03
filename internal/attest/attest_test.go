package attest

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
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
		{manifest.TypeRubygems, "concurrent-ruby", "1.3.4", "", "pkg:gem/concurrent-ruby@1.3.4"},
		{manifest.TypeRubygems, "nokogiri", "1.16.7-x86_64-linux", "", "pkg:gem/nokogiri@1.16.7?platform=x86_64-linux"},
		{manifest.TypeMaven, "org.slf4j:slf4j-api", "2.0.13", "", "pkg:maven/org.slf4j/slf4j-api@2.0.13"},
		{manifest.TypeMaven, "org.slf4j:slf4j-api", "2.0.13", manifest.MavenKey("org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar"),
			"pkg:maven/org.slf4j/slf4j-api@2.0.13"},
		{manifest.TypeMaven, "io.netty:netty-transport-native-epoll", "4.1.100.Final",
			manifest.MavenKey("io/netty/netty-transport-native-epoll/4.1.100.Final/netty-transport-native-epoll-4.1.100.Final-linux-x86_64.jar"),
			"pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?classifier=linux-x86_64"},
		{manifest.TypeMaven, "org.springframework.boot:spring-boot-dependencies", "3.3.0",
			manifest.MavenKey("org/springframework/boot/spring-boot-dependencies/3.3.0/spring-boot-dependencies-3.3.0.pom"),
			"pkg:maven/org.springframework.boot/spring-boot-dependencies@3.3.0?type=pom"},
		{manifest.TypeMaven, "com.example:webapp", "1.0", manifest.MavenKey("com/example/webapp/1.0/webapp-1.0-classes@x.war"),
			"pkg:maven/com.example/webapp@1.0"},
		{manifest.TypeMaven, "androidx.core:core", "1.13.1", manifest.MavenKey("androidx/core/core/1.13.1/core-1.13.1-sources.aar"),
			"pkg:maven/androidx.core/core@1.13.1?classifier=sources&type=aar"},
		{manifest.TypeComposer, "symfony/console", "v7.1.5", "composer/dist/symfony/console/v7.1.5/abc", "pkg:composer/symfony/console@v7.1.5"},
		{manifest.TypeOCI, "docker.io/library/nginx", "sha256:abababababababababababababababababababababababababababababababab", manifest.OCIBlobKey("sha256:abababababababababababababababababababababababababababababababab"),
			"pkg:oci/nginx@sha256:abababababababababababababababababababababababababababababababab?repository_url=docker.io/library/nginx"},
		{manifest.TypeOCI, "ghcr.io/example-corp/tools/cli", "1.2", manifest.OCIManifestKey("ghcr.io", "example-corp/tools/cli", "sha256:abababababababababababababababababababababababababababababababab"),
			"pkg:oci/cli@sha256:abababababababababababababababababababababababababababababababab?repository_url=ghcr.io/example-corp/tools/cli&tag=1.2"},
		{manifest.TypeRpm, "nginx", "2:1.20.1-20.el9", manifest.RpmPackageKey("rocky-baseos", "9", "x86_64", "nginx", "2:1.20.1-20.el9", "nginx-1.20.1-20.el9.x86_64.rpm"),
			"pkg:rpm/nginx@1.20.1-20.el9?arch=x86_64&epoch=2"},
		{manifest.TypeRpm, "httpd", "2.4.57-5.el9", "", "pkg:rpm/httpd@2.4.57-5.el9"},
		{manifest.TypeApt, "hello", "2.10-3build1+x", "", "pkg:generic/apt/hello@2.10-3build1%2Bx"},
		{manifest.TypeDistfiles, "sub/zsh-5.9.tar.xz", "", "", "pkg:generic/distfiles/sub%2Fzsh-5.9.tar.xz"},
	} {
		if got := PURL(tc.typ, tc.name, tc.version, tc.key); got != tc.want {
			t.Errorf("PURL(%s, %s, %s) = %s, want %s", tc.typ, tc.name, tc.version, got, tc.want)
		}
	}
	if got := PURLBase(PURL(manifest.TypeRubygems, "nokogiri", "1.16.7-java", "")); got != "pkg:gem/nokogiri@1.16.7" {
		t.Errorf("PURLBase of a platform gem = %s, want the release without the build", got)
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
		pr.ResolvedFrom != nil || len(pr.RequiredBy) != 1 || pr.RequiredBy[0].Ref != "widget" ||
		pr.RequiredBy[0].Unavailable != noChecksumTable || pr.RequiredBy[0].Digest != nil ||
		pr.UpstreamProvenance.Result != ResultNotAttempted || pr.PublisherSignature.Result != ResultUnverified {
		t.Errorf("predicate = %+v", pr)
	}
	raw := rawPredicate(t, env)
	if got, _ := json.Marshal(raw["integrity"]); string(got) != `{"method":"hash","result":"verified"}` {
		t.Errorf("integrity = %s, want {\"method\":\"hash\",\"result\":\"verified\"}", got)
	}
	// The row lacks OSV and upstream provenance entries, so the statement
	// says so rather than leaving them out.
	for _, name := range []string{audit.CheckOSV, audit.CheckUpstreamProvenance} {
		var found *Evaluation
		for i, e := range pr.PolicyEvaluations.Evaluations {
			if e.Check == name {
				found = &pr.PolicyEvaluations.Evaluations[i]
			}
		}
		if found == nil || found.Status != audit.CheckNotEvaluated {
			t.Errorf("missing %s check rendered as %+v", name, found)
		}
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

// rawPredicate decodes the signed payload of env as untyped JSON, so a test
// sees the keys a consumer reads rather than what the Go struct tolerates.
func rawPredicate(t *testing.T, env *Envelope) map[string]any {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	pr, ok := st["predicate"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no predicate object: %s", payload)
	}
	return pr
}

// The emitter maps the row's upstream_provenance outcome onto the draft's
// vocabulary, and a check that never ran says not-attempted (unverified in
// publisherSignature) whatever its entry holds.
func TestEmitCarriesTheUpstreamProvenanceOfTheRow(t *testing.T) {
	ctx := context.Background()
	verified := audit.UpstreamProvenance{
		Outcome:             audit.ProvenanceVerified,
		SourceRepositoryURI: "https://github.com/lodash/lodash",
		WorkflowRef:         "https://github.com/lodash/lodash/.github/workflows/release.yml@refs/tags/4.17.21",
		BuilderID:           "https://github.com/actions/runner/github-hosted",
		BundleDigest:        "sha256:" + strings.Repeat("cd", 32),
	}
	mismatched := verified
	mismatched.Outcome = audit.ProvenanceMismatch
	mismatched.SourceRepositoryURI = "https://github.com/someone-else/lodash"
	identity := map[string]any{
		"sourceRepositoryUri": verified.SourceRepositoryURI, "workflowRef": verified.WorkflowRef,
		"builderId": verified.BuilderID, "bundleDigest": map[string]any{"sha256": strings.Repeat("cd", 32)},
	}
	with := func(base map[string]any, id map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range id {
			out[k] = v
		}
		return out
	}
	prov := func(outcome string) *audit.UpstreamProvenance { return &audit.UpstreamProvenance{Outcome: outcome} }
	entry := func(status string, p *audit.UpstreamProvenance) []audit.AdmissionCheck {
		return []audit.AdmissionCheck{{Check: audit.CheckUpstreamProvenance, Action: "warn", Status: status, Provenance: p}}
	}
	mismatchID := with(identity, map[string]any{"sourceRepositoryUri": mismatched.SourceRepositoryURI})
	cases := []struct {
		name                string
		checks              []audit.AdmissionCheck
		upstream, publisher map[string]any
	}{
		{"verified", entry(audit.CheckPass, &verified),
			with(map[string]any{"result": "verified"}, identity), with(map[string]any{"result": "verified"}, identity)},
		{"invalid", entry(audit.CheckWarn, prov(audit.ProvenanceInvalid)),
			map[string]any{"result": "failed"}, map[string]any{"result": "failed"}},
		{"unavailable", entry(audit.CheckWarn, prov(audit.ProvenanceUnavailable)),
			map[string]any{"availability": "unavailable"}, map[string]any{"availability": "unavailable"}},
		{"unknown", entry(audit.CheckWarn, prov(audit.ProvenanceUnknown)),
			map[string]any{"result": "not-attempted"}, map[string]any{"result": "unverified"}},
		{"mismatch with a verified bundle", entry(audit.CheckWarn, &mismatched),
			with(map[string]any{"result": "verified"}, mismatchID), with(map[string]any{"result": "verified"}, mismatchID)},
		{"npm mismatch with no bundle", entry(audit.CheckWarn, prov(audit.ProvenanceMismatch)),
			map[string]any{"availability": "unavailable"}, map[string]any{"availability": "unavailable"}},
		{"not evaluated", entry(audit.CheckNotEvaluated, &verified),
			map[string]any{"result": "not-attempted"}, map[string]any{"result": "unverified"}},
		{"no entry", nil,
			map[string]any{"result": "not-attempted"}, map[string]any{"result": "unverified"}},
		{"unrecognized outcome", entry(audit.CheckWarn, prov("missing")),
			map[string]any{"result": "not-attempted"}, map[string]any{"result": "unverified"}},
	}
	for i, tc := range cases {
		db := openAudit(t)
		store := storage.NewMemory()
		version := "4.17." + string(rune('0'+i))
		key := manifest.NpmTarballKey("lodash", version)
		admit(t, db, version, audit.AdmissionAdmitted, append(append([]audit.AdmissionCheck(nil), passing...), tc.checks...))
		ek, err := emitter(db, newSigner(t)).Emit(ctx, store, pin(t, db, version, key))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		data, _ := store.Get(ctx, ek)
		env, _, err := ParseEnvelope(data)
		if err != nil {
			t.Fatal(err)
		}
		raw := rawPredicate(t, env)
		for field, want := range map[string]map[string]any{"upstreamProvenance": tc.upstream, "publisherSignature": tc.publisher} {
			got, _ := json.Marshal(raw[field])
			exp, _ := json.Marshal(want)
			if string(got) != string(exp) {
				t.Errorf("%s: %s = %s, want %s", tc.name, field, got, exp)
			}
		}
	}
}

// No statement NewStatement builds carries the pre-E27 status key, whatever
// the row's outcome, in either provenance object.
func TestEmitNeverWritesALegacyStatus(t *testing.T) {
	for _, outcome := range []string{audit.ProvenanceVerified, audit.ProvenanceInvalid, audit.ProvenanceUnavailable,
		audit.ProvenanceUnknown, audit.ProvenanceMismatch, "missing", ""} {
		checks := []audit.AdmissionCheck{{Check: audit.CheckUpstreamProvenance, Action: "warn", Status: audit.CheckWarn,
			Provenance: &audit.UpstreamProvenance{Outcome: outcome, SourceRepositoryURI: "https://github.com/lodash/lodash"}}}
		st := NewStatement(Pin{Type: manifest.TypeNpm, Name: "lodash", Version: "4.17.21", ObjectKey: "k", SHA256: digest},
			audit.Admission{Decision: audit.AdmissionAdmitted, Checks: checks}, "https://bodega.example", time.Now())
		data, err := Sign(newSigner(t), st)
		if err != nil {
			t.Fatal(err)
		}
		env, _, err := ParseEnvelope(data)
		if err != nil {
			t.Fatal(err)
		}
		raw := rawPredicate(t, env)
		for _, field := range []string{"upstreamProvenance", "publisherSignature"} {
			obj, ok := raw[field].(map[string]any)
			if !ok {
				t.Fatalf("outcome %q: %s is not an object: %v", outcome, field, raw[field])
			}
			if _, has := obj["status"]; has {
				t.Errorf("outcome %q: %s carries a status key: %v", outcome, field, obj)
			}
		}
	}
}

// stubChecksums answers ListChecksums from fixed rows, filtered the way the
// audit table filters them, or fails with err.
type stubChecksums struct {
	rows []audit.StoredChecksum
	err  error
}

func (s stubChecksums) ListChecksums(_ context.Context, pkgType, pkgName string) ([]audit.StoredChecksum, error) {
	if s.err != nil {
		return nil, s.err
	}
	var out []audit.StoredChecksum
	for _, r := range s.rows {
		if (pkgType == "" || r.PkgType == pkgType) && (pkgName == "" || r.PkgName == pkgName) {
			out = append(out, r)
		}
	}
	return out, nil
}

func sumRow(typ, name, version, value string) audit.StoredChecksum {
	return audit.StoredChecksum{PkgType: typ, PkgName: name, PkgVersion: version, Algorithm: "sha256", Value: value,
		ObjectKey: typ + "/" + name + "/" + version + "/" + value[:4]}
}

// Each catalog reference resolves to its parent's pinned sha256 at signing
// time, and the first one that does is what resolvedFrom carries. A reference
// that resolves to nothing, or to more than one digest, is kept in requiredBy
// with the reason, and the envelope is signed either way.
func TestEmitResolvesTheDirectDependencyDigest(t *testing.T) {
	d1, d2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	sha := func(d string) map[string]string { return map[string]string{"sha256": d} }
	cases := []struct {
		name     string
		refs     []string
		parents  []Parent
		src      ChecksumLister
		wantFrom string
		want     []RequiredByRef // Unavailable is a substring of the reason
	}{
		{"versioned reference with one pin", []string{"git/widget@v1.0.0"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1.0.0", d1), sumRow("git", "widget", "v2.0.0", d2)}},
			d1, []RequiredByRef{{Ref: "git/widget@v1.0.0", Digest: sha(d1)}}},
		{"bare name reads as git", []string{"widget"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1.0.0", d1), sumRow("npm", "widget", "1.0.0", d2)}},
			d1, []RequiredByRef{{Ref: "widget", Digest: sha(d1)}}},
		{"bare name with two pins", []string{"widget"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1.0.0", d1), sumRow("git", "widget", "v2.0.0", d2)}},
			"", []RequiredByRef{{Ref: "widget", Unavailable: `"widget" matches 2 distinct`}}},
		{"type and name over every version", []string{"apt/libpq-dev"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("apt", "libpq-dev", "14.9", d2)}},
			d2, []RequiredByRef{{Ref: "apt/libpq-dev", Digest: sha(d2)}}},
		{"no pin", []string{"git/widget@v1.0.0"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v2.0.0", d2)}},
			"", []RequiredByRef{{Ref: "git/widget@v1.0.0", Unavailable: `no sha256 is pinned for "git/widget@v1.0.0"`}}},
		{"two resolvable references", []string{"git/widget@v1.0.0", "git/gadget"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1.0.0", d1), sumRow("git", "gadget", "v3", d2)}},
			d1, []RequiredByRef{{Ref: "git/widget@v1.0.0", Digest: sha(d1)}, {Ref: "git/gadget", Digest: sha(d2)}}},
		{"first reference unresolved", []string{"git/missing", "git/gadget"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "gadget", "v3", d2)}},
			d2, []RequiredByRef{{Ref: "git/missing", Unavailable: "no sha256 is pinned"}, {Ref: "git/gadget", Digest: sha(d2)}}},
		{"checksum table error", []string{"widget"}, nil,
			stubChecksums{err: errors.New("database is locked")},
			"", []RequiredByRef{{Ref: "widget", Unavailable: "database is locked"}}},
		{"malformed references", []string{"", "/widget", "git/"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1", d1)}},
			"", []RequiredByRef{{Ref: "", Unavailable: "names no package type and name"},
				{Ref: "/widget", Unavailable: "names no package type and name"}, {Ref: "git/", Unavailable: "names no package type and name"}}},
		{"empty name before a version", []string{"git/@v1", "@v1", "pypi/@1.0", "npm/@1.0"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "@v1", "x", d1), sumRow("git", "", "v1", d1), sumRow("pypi", "", "1.0", d1), sumRow("npm", "", "1.0", d1)}},
			"", []RequiredByRef{{Ref: "git/@v1", Unavailable: `"git/@v1" names no package`}, {Ref: "@v1", Unavailable: `"@v1" names no package`},
				{Ref: "pypi/@1.0", Unavailable: `"pypi/@1.0" names no package`}, {Ref: "npm/@1.0", Unavailable: `"npm/@1.0" names no package`}}},
		{"empty version or broken npm scope", []string{"git/widget@", "npm/@/pkg", "npm/@scope/", "npm/@scope/pkg@"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "", d1), sumRow("npm", "@/pkg", "1", d1), sumRow("npm", "@scope/", "1", d1), sumRow("npm", "@scope/pkg", "", d1)}},
			"", []RequiredByRef{{Ref: "git/widget@", Unavailable: "names no package"}, {Ref: "npm/@/pkg", Unavailable: "names no package"},
				{Ref: "npm/@scope/", Unavailable: "names no package"}, {Ref: "npm/@scope/pkg@", Unavailable: "names no package"}}},
		{"npm scoped package with and without a version", []string{"npm/@scope/pkg@1.0", "npm/@scope/other"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("npm", "@scope/pkg", "1.0", d1), sumRow("npm", "@scope/pkg", "2.0", d2), sumRow("npm", "@scope/other", "3.0", d2)}},
			d1, []RequiredByRef{{Ref: "npm/@scope/pkg@1.0", Digest: sha(d1)}, {Ref: "npm/@scope/other", Digest: sha(d2)}}},
		{"caller-held parents after catalog references, sorted, repeats dropped", []string{"git/missing"},
			[]Parent{{Ref: "pypi/zeta@2", SHA256: d2}, {Ref: "pypi/alpha@1", SHA256: d1}, {Ref: "pypi/zeta@2", SHA256: d2}},
			stubChecksums{},
			d1, []RequiredByRef{{Ref: "git/missing", Unavailable: "no sha256 is pinned"},
				{Ref: "pypi/alpha@1", Digest: sha(d1)}, {Ref: "pypi/zeta@2", Digest: sha(d2)}}},
		{"repeated catalog reference", []string{"widget", "widget"}, nil,
			stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1", d1)}},
			d1, []RequiredByRef{{Ref: "widget", Digest: sha(d1)}}},
		{"no references and no parents", nil, nil, stubChecksums{rows: []audit.StoredChecksum{sumRow("git", "widget", "v1", d1)}},
			"", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := openAudit(t)
			s := newSigner(t)
			store := storage.NewMemory()
			key := manifest.NpmTarballKey("lodash", "4.17.21")
			admit(t, db, "4.17.21", audit.AdmissionAdmitted, passing)
			p := pin(t, db, "4.17.21", key)
			p.RequiredBy, p.Parents = tc.refs, tc.parents
			e := emitter(db, s)
			e.Checksums = tc.src
			ek, err := e.Emit(ctx, store, p)
			if err != nil || ek == "" {
				t.Fatalf("Emit = %q, %v", ek, err)
			}
			data, _ := store.Get(ctx, ek)
			env, st, err := ParseEnvelope(data)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range Verify(env, st, VerifyInput{Trusted: trusted(t, s), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}) {
				if !r.OK {
					t.Errorf("%s failed: expected %s, observed %s", r.Check, r.Expected, r.Observed)
				}
			}
			payload, _ := base64.StdEncoding.DecodeString(env.Payload)
			raw := rawPredicate(t, env)
			if tc.wantFrom == "" {
				if strings.Contains(string(payload), `"resolvedFrom"`) || st.Predicate.ResolvedFrom != nil {
					t.Errorf("resolvedFrom present with no parent digest: %s", payload)
				}
			} else {
				got, _ := json.Marshal(raw["resolvedFrom"])
				if want := `{"subject":{"sha256":"` + tc.wantFrom + `"}}`; string(got) != want {
					t.Errorf("resolvedFrom = %s, want %s", got, want)
				}
			}
			if tc.want == nil && strings.Contains(string(payload), `"requiredBy"`) {
				t.Errorf("requiredBy present with nothing to list: %s", payload)
			}
			got := st.Predicate.RequiredBy
			if len(got) != len(tc.want) {
				t.Fatalf("requiredBy = %+v, want %+v", got, tc.want)
			}
			for i, w := range tc.want {
				g := got[i]
				if g.Ref != w.Ref || (g.Digest == nil) != (w.Digest == nil) || g.Digest["sha256"] != w.Digest["sha256"] ||
					(g.Unavailable == "") != (w.Unavailable == "") || !strings.Contains(g.Unavailable, w.Unavailable) {
					t.Errorf("requiredBy[%d] = %+v, want %+v", i, g, w)
				}
			}
			if entries, _ := raw["requiredBy"].([]any); len(entries) > 0 {
				for _, e := range entries {
					obj := e.(map[string]any)
					_, hasDigest := obj["digest"]
					_, hasReason := obj["unavailable"]
					if hasDigest == hasReason {
						t.Errorf("requiredBy entry %v carries both or neither of digest and unavailable", obj)
					}
				}
			}
		})
	}
}

// An envelope signed while resolvedFrom was an array of name-only
// descriptors, under either provenance vocabulary, still parses and passes
// every check, and keeps the names it carried.
func TestPreE29EnvelopeStillVerifies(t *testing.T) {
	for _, tc := range []struct{ name, provenance string }{
		{"pre-E27 status", `"upstreamProvenance":{"status":"unavailable"},"publisherSignature":{"status":"unavailable"}`},
		{"E27 fields", `"upstreamProvenance":{"result":"not-attempted"},"publisherSignature":{"result":"unverified"},` +
			`"integrity":{"method":"hash","result":"verified"}`},
	} {
		s := newSigner(t)
		payload := `{"_type":"` + StatementType + `","subject":[{"name":"pkg:npm/lodash@4.17.21","digest":{"sha256":"` + digest + `"}}],` +
			`"predicateType":"` + PredicateType + `","predicate":{"ingestionPlatform":{"id":"https://bodega.example"},` +
			`"ingestedAt":"2026-10-10T12:00:00Z","policyEvaluations":{"policyDigest":{},"decision":"admitted","decidedAt":"2026-10-10T12:00:00Z",` +
			`"evaluations":[{"check":"allowlist","action":"none","status":"pass"}]},` +
			`"resolvedFrom":[{"name":"widget"}],` + tc.provenance + `}}`
		sig, err := s.Sign(rand.Reader, PAE(PayloadType, []byte(payload)), crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(payload)),
			Signatures: []Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}}}
		data, _ := json.Marshal(env)
		pe, st, err := ParseEnvelope(data)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := st.Predicate.LegacyResolvedFrom; len(got) != 1 || got[0] != "widget" || st.Predicate.ResolvedFrom != nil {
			t.Errorf("%s: legacy resolvedFrom = %v, ResolvedFrom = %+v", tc.name, got, st.Predicate.ResolvedFrom)
		}
		for _, r := range Verify(pe, st, VerifyInput{Trusted: trusted(t, s), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}) {
			if !r.OK {
				t.Errorf("%s: %s failed: expected %s, observed %s", tc.name, r.Check, r.Expected, r.Observed)
			}
		}
		// Re-signing what was parsed never puts the array back on the wire.
		resigned, err := Sign(s, *st)
		if err != nil {
			t.Fatal(err)
		}
		renv, _, err := ParseEnvelope(resigned)
		if err != nil {
			t.Fatal(err)
		}
		if raw := rawPredicate(t, renv); raw["resolvedFrom"] != nil {
			t.Errorf("%s: re-signed statement carries resolvedFrom %v", tc.name, raw["resolvedFrom"])
		}
	}
}

// An envelope signed before upstreamProvenance carried anything but a status
// still parses and passes every check.
func TestPreF38EnvelopeStillVerifies(t *testing.T) {
	s := newSigner(t)
	payload := `{"_type":"` + StatementType + `","subject":[{"name":"pkg:npm/lodash@4.17.21","digest":{"sha256":"` + digest + `"}}],` +
		`"predicateType":"` + PredicateType + `","predicate":{"ingestionPlatform":{"id":"https://bodega.example"},` +
		`"ingestedAt":"2026-10-10T12:00:00Z","policyEvaluations":{"policyDigest":{},"decision":"admitted","decidedAt":"2026-10-10T12:00:00Z",` +
		`"evaluations":[{"check":"allowlist","action":"none","status":"pass"}]},` +
		`"upstreamProvenance":{"status":"unavailable"},"publisherSignature":{"status":"unavailable"}}}`
	sig, err := s.Sign(rand.Reader, PAE(PayloadType, []byte(payload)), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(payload)),
		Signatures: []Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}}}
	data, _ := json.Marshal(env)
	pe, st, err := ParseEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.UpstreamProvenance.LegacyStatus != AvailabilityUnavailable || st.Predicate.UpstreamProvenance.SourceRepositoryURI != "" {
		t.Errorf("upstreamProvenance = %+v", st.Predicate.UpstreamProvenance)
	}
	for _, r := range Verify(pe, st, VerifyInput{Trusted: trusted(t, s), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}) {
		if !r.OK {
			t.Errorf("%s failed: expected %s, observed %s", r.Check, r.Expected, r.Observed)
		}
	}
}

// An envelope signed under the pre-E27 vocabulary, a single status per
// provenance object, still verifies, and its status and identity stay
// readable.
func TestPreE27EnvelopeStillVerifies(t *testing.T) {
	for _, tc := range []struct {
		name, object, status, source, builder string
	}{
		{"mismatch with identity",
			`{"status":"mismatch","sourceRepositoryUri":"https://github.com/lodash/lodash","builderId":"https://github.com/actions/runner/github-hosted"}`,
			"mismatch", "https://github.com/lodash/lodash", "https://github.com/actions/runner/github-hosted"},
		{"invalid", `{"status":"invalid"}`, "invalid", "", ""},
	} {
		s := newSigner(t)
		payload := `{"_type":"` + StatementType + `","subject":[{"name":"pkg:npm/lodash@4.17.21","digest":{"sha256":"` + digest + `"}}],` +
			`"predicateType":"` + PredicateType + `","predicate":{"ingestionPlatform":{"id":"https://bodega.example"},` +
			`"ingestedAt":"2026-10-10T12:00:00Z","policyEvaluations":{"policyDigest":{},"decision":"admitted","decidedAt":"2026-10-10T12:00:00Z",` +
			`"evaluations":[{"check":"allowlist","action":"none","status":"pass"}]},` +
			`"upstreamProvenance":` + tc.object + `,"publisherSignature":` + tc.object + `}}`
		sig, err := s.Sign(rand.Reader, PAE(PayloadType, []byte(payload)), crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(payload)),
			Signatures: []Signature{{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}}}
		data, _ := json.Marshal(env)
		pe, st, err := ParseEnvelope(data)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for field, got := range map[string]Availability{"upstreamProvenance": st.Predicate.UpstreamProvenance, "publisherSignature": st.Predicate.PublisherSignature} {
			if got.LegacyStatus != tc.status || got.SourceRepositoryURI != tc.source || got.BuilderID != tc.builder || got.Result != "" || got.Availability != "" {
				t.Errorf("%s: %s = %+v", tc.name, field, got)
			}
		}
		for _, r := range Verify(pe, st, VerifyInput{Trusted: trusted(t, s), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}) {
			if !r.OK {
				t.Errorf("%s: %s failed: expected %s, observed %s", tc.name, r.Check, r.Expected, r.Observed)
			}
		}
	}
}

func TestE27LegacyStatusIsDecodeOnly(t *testing.T) {
	for _, status := range []string{"mismatch", "invalid"} {
		payload := `{"predicate":{"upstreamProvenance":{"status":"` + status + `"},"publisherSignature":{"status":"` + status + `"}}}`
		encoded, err := json.Marshal(Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(payload))})
		if err != nil {
			t.Fatal(err)
		}
		_, st, err := ParseEnvelope(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if st.Predicate.UpstreamProvenance.LegacyStatus != status || st.Predicate.PublisherSignature.LegacyStatus != status {
			t.Fatal("legacy status was not decoded")
		}
		signed, err := Sign(newSigner(t), *st)
		if err != nil {
			t.Fatal(err)
		}
		env, _, err := ParseEnvelope(signed)
		if err != nil {
			t.Fatal(err)
		}
		raw := rawPredicate(t, env)
		for _, field := range []string{"upstreamProvenance", "publisherSignature"} {
			object, ok := raw[field].(map[string]any)
			if !ok {
				t.Fatalf("%s is not an object", field)
			}
			if value, exists := object["status"]; exists {
				t.Errorf("%s re-emitted decode-only status %q", field, value)
			}
		}
	}
}

// constDoc returns the doc comment of the package-level constant name in
// attest.go, so a test can hold the comment to what it promises.
func constDoc(t *testing.T, name string) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "attest.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			for _, n := range spec.(*ast.ValueSpec).Names {
				if n.Name == name {
					return g.Doc.Text()
				}
			}
		}
	}
	t.Fatalf("attest.go declares no constant %s", name)
	return ""
}

func TestE27DraftRevisionIsPinned(t *testing.T) {
	if DraftRevision != "https://github.com/slsa-framework/slsa/blob/4d3f9d44a803aaa52eef08fdafd04a7409c263e7/spec/dependency-provenance.md" {
		t.Errorf("DraftRevision = %q", DraftRevision)
	}
	if PredicateType != "https://slsa.dev/dependency/v1" {
		t.Errorf("PredicateType = %q", PredicateType)
	}
	if doc := constDoc(t, "DraftRevision"); !strings.Contains(doc, "2026-11-02") || !strings.Contains(doc, "#277") {
		t.Errorf("DraftRevision comment names neither the read date nor issue #277: %q", doc)
	}
	if doc := constDoc(t, "PredicateType"); !strings.Contains(doc, "DraftRevision") {
		t.Errorf("PredicateType comment does not name DraftRevision: %q", doc)
	}
}

// The admission row's outcomes are stored values with override rules keyed on
// them; the predicate maps them, it never renames them.
func TestE27AuditVocabularyIsUnchanged(t *testing.T) {
	for got, want := range map[string]string{
		audit.ProvenanceVerified:    "verified",
		audit.ProvenanceUnavailable: "unavailable",
		audit.ProvenanceInvalid:     "invalid",
		audit.ProvenanceUnknown:     "unknown",
		audit.ProvenanceMismatch:    "mismatch",
	} {
		if got != want {
			t.Errorf("audit provenance outcome %q, want %q", got, want)
		}
	}
	if len(map[string]bool{audit.ProvenanceVerified: true, audit.ProvenanceUnavailable: true, audit.ProvenanceInvalid: true,
		audit.ProvenanceUnknown: true, audit.ProvenanceMismatch: true}) != 5 {
		t.Error("audit provenance outcomes are no longer five distinct values")
	}
}

// readDoc returns a docs page with its whitespace collapsed, so a guard over
// hard-wrapped prose does not break on a rewrap.
func readDoc(t *testing.T, name string) (raw, flat string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b), strings.Join(strings.Fields(string(b)), " ")
}

func requireAll(t *testing.T, page, text string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("%s does not say %q", page, w)
		}
	}
}

func TestE27DesignDocumentsTheDraftVocabulary(t *testing.T) {
	raw, flat := readDoc(t, "design.md")
	requireAll(t, "design.md", flat,
		"[Dependency track](https://slsa.dev/spec/draft/dependency-track)",
		"(https://slsa.dev/spec/draft/dependency-provenance)",
		DraftRevision, "4d3f9d44", "read on 2026-11-02",
		"`availability: unavailable` when the publisher published nothing",
		"`integrity`, always `{\"method\": \"hash\", \"result\": \"verified\"}`",
		"`mismatch` therefore shows in the `upstream_provenance` entry of `policyEvaluations`")
	rows := map[string][2]string{
		"`verified`":                         {"`result: verified`, with the identity fields", "`result: verified`, with the identity fields"},
		"`invalid`":                          {"`result: failed`", "`result: failed`"},
		"`unavailable`":                      {"`availability: unavailable`", "`availability: unavailable`"},
		"`unknown`":                          {"`result: not-attempted`", "`result: unverified`"},
		"`mismatch`, a bundle that verified": {"`result: verified`, with the identity fields", "`result: verified`, with the identity fields"},
		"`mismatch`, no bundle after a pinned one":        {"`availability: unavailable`", "`availability: unavailable`"},
		"`not_evaluated`, no entry, or any other outcome": {"`result: not-attempted`", "`result: unverified`"},
	}
	found := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) != 5 {
			continue
		}
		outcome := strings.TrimSpace(cells[1])
		want, ok := rows[outcome]
		if !ok {
			continue
		}
		found[outcome] = true
		if up, pub := strings.TrimSpace(cells[2]), strings.TrimSpace(cells[3]); up != want[0] || pub != want[1] {
			t.Errorf("design.md row %s maps to %q / %q, want %q / %q", outcome, up, pub, want[0], want[1])
		}
	}
	for outcome := range rows {
		if !found[outcome] {
			t.Errorf("design.md mapping table has no row for %s", outcome)
		}
	}
}

func TestE27ThreatModelReportsMismatchInPolicyEvaluations(t *testing.T) {
	_, flat := readDoc(t, "threat-model.md")
	requireAll(t, "threat-model.md", flat,
		"`result` is `verified`, `failed`, or `not-attempted` (`unverified` in `publisherSignature`), or `availability` is `unavailable` when the publisher published nothing",
		"A `verified` there means only that the publisher's bundle verified cryptographically.",
		"A `mismatch` against the pinned publisher is reported in the `upstream_provenance` entry of `policyEvaluations`, not in `publisherSignature`.")
}

// section returns the body of the ## heading in page, up to the next ## heading.
func section(t *testing.T, page, raw, heading string) string {
	t.Helper()
	_, body, ok := strings.Cut(raw, "\n"+heading+"\n")
	if !ok {
		t.Fatalf("%s has no %q section", page, heading)
	}
	body, _, _ = strings.Cut(body, "\n## ")
	return body
}

func tableRows(body string) []string {
	var rows []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "|") {
			rows = append(rows, line)
		}
	}
	return rows
}

func TestE27SlsaPageNamesTheRevision(t *testing.T) {
	raw, _ := readDoc(t, "slsa.md")
	_, opening, _ := strings.Cut(raw, "The Dependency track is a working draft")
	opening, _, _ = strings.Cut(opening, "\n")
	requireAll(t, "slsa.md opening paragraph", opening, DraftRevision, "November 2, 2026")
	if strings.Contains(opening, "October 5, 2026") {
		t.Error("slsa.md opening paragraph still names the October 5, 2026 reading")
	}
	if drift := tableRows(section(t, "slsa.md", raw, "## Spec drift")); len(drift) != 0 {
		t.Errorf("slsa.md Spec drift still lists a difference from the draft:\n%s", strings.Join(drift, "\n"))
	}
	level3 := tableRows(section(t, "slsa.md", raw, "## What Level 3 requires that bodega does not provide"))
	if len(level3) == 0 {
		t.Fatal("slsa.md Level 3 table missing")
	}
	if last := level3[len(level3)-1]; strings.Contains(last, "vocabulary") || strings.Contains(last, "differ") {
		t.Errorf("slsa.md Level 3 last row still says the vocabulary differs: %s", last)
	}
}

// Every Emitter the binaries build hands it the audit checksum table it
// already passes as Admissions, so no construction path signs every parent
// reference as unavailable.
func TestEveryEmitterResolvesParents(t *testing.T) {
	fset := token.NewFileSet()
	var found []string
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Emitter" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "attest" {
					return true
				}
				fields := map[string]string{}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					fields[kv.Key.(*ast.Ident).Name] = types.ExprString(kv.Value)
				}
				pos := fset.Position(lit.Pos())
				found = append(found, pos.String())
				if fields["Checksums"] == "" || fields["Checksums"] != fields["Admissions"] {
					t.Errorf("%s: attest.Emitter sets Checksums %q, want the Admissions value %q", pos, fields["Checksums"], fields["Admissions"])
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) != 4 {
		t.Errorf("found %d attest.Emitter literals, want 4: %v", len(found), found)
	}
}

// The pages describing resolvedFrom say what it is now, how a parent is
// resolved, and when it is absent.
func TestE29DocsDescribeResolvedFrom(t *testing.T) {
	_, design := readDoc(t, "design.md")
	if strings.Contains(design, "the version's `required_by`)") {
		t.Error("design.md still says resolvedFrom is the version's required_by")
	}
	requireAll(t, "design.md", design,
		"`ResolvedFromRef` object, `{\"subject\": {\"sha256\": \"<hex>\"}}`",
		"`requiredBy` is a bodega field outside the draft",
		"exactly one of `digest` (`{\"sha256\": \"<hex>\"}`) or `unavailable`",
		"`<type>/<name>@<version>` matches the SHA-256 rows for that type, name and version",
		"`<type>/<name>`, the form apt discovery records, matches every version",
		"a reference with no `/` reads as `git/<name>`",
		"`resolvedFrom` is the digest of the first `requiredBy` entry that carries one")

	_, usage := readDoc(t, "usage.md")
	requireAll(t, "usage.md", usage,
		"A statement carries no `resolvedFrom` when:",
		"proxy fill of a version with no manifest entry",
		"no SHA-256 pinned at the moment the child was signed",
		"`bodega attest backfill` skips an object that already has an envelope",
		"more than one distinct pinned SHA-256",
		"only parents are source distributions or requirements carrying an environment marker",
		"signed before bodega recorded parent digests")

	_, threat := readDoc(t, "threat-model.md")
	requireAll(t, "threat-model.md", threat,
		"`resolvedFrom` and `requiredBy` are bodega's record of the relationship",
		"An absent `resolvedFrom` does not prove the artifact was a top-level dependency",
		"has to refuse statements lacking it")

	raw, _ := readDoc(t, "slsa.md")
	gaps := section(t, "slsa.md", raw, "## Dependency track Level 2")
	if strings.Contains(gaps, "names the parent, not its digest") {
		t.Error("slsa.md Gaps still says resolvedFrom names the parent")
	}
	requireAll(t, "slsa.md Gaps", strings.Join(strings.Fields(gaps), " "),
		"**`resolvedFrom` is absent where bodega cannot establish the parent's digest.**",
		"proxy fill of a version with no manifest entry",
		"`bodega attest backfill` skips an object that already has one",
		"more than one distinct pinned SHA-256",
		"source distributions or marker-conditioned requirements",
		"every statement signed before parent digests were recorded")
}

func TestReviewE29EmptyVersionedNameNeverResolves(t *testing.T) {
	for _, typ := range []string{"git", "apt", "pypi"} {
		t.Run(typ, func(t *testing.T) {
			ctx := context.Background()
			db := openAudit(t)
			signer := newSigner(t)
			store := storage.NewMemory()
			key := manifest.NpmTarballKey("lodash", "4.17.21")
			admit(t, db, "4.17.21", audit.AdmissionAdmitted, passing)
			p := pin(t, db, "4.17.21", key)
			ref := typ + "/@v1"
			p.RequiredBy = []string{ref}
			e := emitter(db, signer)
			e.Checksums = stubChecksums{rows: []audit.StoredChecksum{
				sumRow(typ, "@v1", "other", strings.Repeat("1", 64)),
			}}
			ek, err := e.Emit(ctx, store, p)
			if err != nil || ek == "" {
				t.Fatalf("Emit = %q, %v", ek, err)
			}
			data, err := store.Get(ctx, ek)
			if err != nil {
				t.Fatal(err)
			}
			env, st, err := ParseEnvelope(data)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range Verify(env, st, VerifyInput{Trusted: trusted(t, signer), ArtifactSHA256: digest, WantPURL: "pkg:npm/lodash@4.17.21"}) {
				if !r.OK {
					t.Fatalf("Verify failed: %+v", r)
				}
			}
			rb := st.Predicate.RequiredBy
			if len(rb) != 1 || rb[0].Ref != ref || rb[0].Digest != nil || rb[0].Unavailable == "" || !strings.Contains(rb[0].Unavailable, ref) || st.Predicate.ResolvedFrom != nil {
				t.Fatalf("empty name in %q produced requiredBy=%+v resolvedFrom=%+v; want unavailable and no digest", ref, rb, st.Predicate.ResolvedFrom)
			}
		})
	}
}
