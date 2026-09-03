package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// ctxStore records the context every List was handed and can be made to
// honor cancellation, which storage.Local does not and storage.S3 does.
type ctxStore struct {
	*storage.Memory
	lastListErr atomic.Value // error or nil
	honorCtx    atomic.Bool
	failList    atomic.Bool
	listCalls   atomic.Int64
}

func (c *ctxStore) List(ctx context.Context, prefix string) ([]string, error) {
	c.listCalls.Add(1)
	err := ctx.Err()
	c.lastListErr.Store(errBox{err})
	if c.honorCtx.Load() && err != nil {
		return nil, err
	}
	if c.failList.Load() {
		return nil, errors.New("AccessDenied: user is not authorized to perform s3:ListBucket")
	}
	return c.Memory.List(ctx, prefix)
}

type errBox struct{ err error }

func (c *ctxStore) listErr() error {
	v, _ := c.lastListErr.Load().(errBox)
	return v.err
}

// refreshTestServer builds a Server over a real manifest directory on disk, so
// a test can edit a manifest out of band the way an operator does.
func refreshTestServer(t *testing.T) (*Server, *ctxStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	ctx := t.Context()
	if err := store.AddVersion(ctx, manifest.TypeApt, "hello", manifest.VersionEntry{
		Version:      "1.0.0",
		SourceName:   "hello",
		ArtifactSize: 10,
		Description:  "original",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/h/hello/hello_1.0.0_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	cs := &ctxStore{Memory: storage.NewMemory()}
	cs.Seed("packages/apt/pool/main/h/hello/hello_1.0.0_amd64.deb", "\x00deb")

	cfg := &config.Config{ManifestDir: dir, AptCodename: "noble", MetadataTTL: "1h"}
	s := newServer(cfg, store, storage.NewSingle(cs), ":0", nil)
	return s, cs, dir
}

// TestRebuildAfterWriteOutlivesTheRequest covers the mutation path: the write
// has already committed when the rebuild starts, so a client that hangs up
// must not be able to cancel the index update and leave a 201 describing state
// the index does not show.
func TestRebuildAfterWriteOutlivesTheRequest(t *testing.T) {
	s, cs, _ := refreshTestServer(t)
	cs.honorCtx.Store(true)

	// Drop the cached pool listing: with it, the rebuild never reaches List
	// and the test would pass against the defect.
	s.aptPool.Store(nil)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	s.rebuildAptIndexAfterWrite(canceled, manifest.TypeApt)

	if err := cs.listErr(); err != nil {
		t.Errorf("pool listing ran on a canceled context (%v); the rebuild must detach from the request", err)
	}
	if snap := s.aptSnap.Load(); snap == nil || snap.suites["noble"] == nil {
		t.Fatal("no snapshot after the post-write rebuild")
	}
}

// TestRefreshReloadsManifestsFromDisk is the hourly tick's contract: an edit
// made outside the process has to reach the index. Without the reload the
// tick re-stamps Valid-Until over an unchanged in-memory cache forever.
func TestRefreshReloadsManifestsFromDisk(t *testing.T) {
	s, _, dir := refreshTestServer(t)

	path := filepath.Join(dir, "apt", "hello", "manifest.json")
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temp dir
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var pm map[string]any
	if err := json.Unmarshal(raw, &pm); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	versions, _ := pm["versions"].([]any)
	if len(versions) == 0 {
		t.Fatalf("manifest has no versions: %s", raw)
	}
	v, _ := versions[0].(map[string]any)
	v["description"] = "EDITED-BY-HAND"
	edited, err := json.Marshal(pm)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	ctx := t.Context()
	s.reloadManifests(ctx)
	s.rebuildAptSnapshot(ctx)

	snap := s.aptSnap.Load()
	if snap == nil || snap.suites["noble"] == nil {
		t.Fatal("no snapshot after refresh")
	}
	packages := string(snap.suites["noble"].packages["amd64"])
	if !strings.Contains(packages, "EDITED-BY-HAND") {
		t.Errorf("out-of-band manifest edit did not reach the index:\n%s", packages)
	}
}

// TestTickIntervalShortensWithoutASnapshot covers the 503 window: with no
// snapshot every apt request fails, and the failures that put it there
// (credentials, a network that was not up at unit start) are usually over in
// seconds rather than in an hour. It also pins the two ends of the backoff:
// the first retry stays short, and a snapshot puts the loop straight back on
// the refresh interval however far the retry had walked.
func TestTickIntervalShortensWithoutASnapshot(t *testing.T) {
	s, _, _ := refreshTestServer(t)

	if got := s.aptNextInterval(aptRetryInterval); got != aptRefreshInterval {
		t.Errorf("interval with a snapshot = %v, want %v", got, aptRefreshInterval)
	}
	s.aptSnap.Store(nil)
	if got := s.aptNextInterval(0); got != aptRetryInterval {
		t.Errorf("first interval with no snapshot = %v, want %v", got, aptRetryInterval)
	}
	if got := s.aptNextInterval(aptRetryInterval); got != aptRetryInterval*aptRetryFactor {
		t.Errorf("second interval = %v, want %v", got, aptRetryInterval*aptRetryFactor)
	}
	if got := s.aptNextInterval(aptRefreshInterval); got != aptRefreshInterval {
		t.Errorf("interval is not capped at the refresh interval: %v", got)
	}
}

// TestRetryIsCappedAgainstAPermanentFailure drives a simulated hour of the
// refresh loop over an object store whose List never succeeds — a wrong
// bucket, revoked credentials, a role without s3:ListBucket. Each attempt
// costs a full manifest reload, a pool listing and an ERROR line, so the
// assertion is on how many the backend was made to serve, not on the interval
// the loop happens to be holding.
func TestRetryIsCappedAgainstAPermanentFailure(t *testing.T) {
	s, cs, _ := refreshTestServer(t)
	seedFallbackEntry(t, s) // an entry with no _pool_path, so the listing runs
	s.aptSnap.Store(nil)
	s.aptPool.Store(nil)
	cs.failList.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A virtual clock: every wait the loop takes advances it, and the hour
	// mark cancels. Called only from the loop, which this test runs inline,
	// so the counters need no synchronization.
	var elapsed time.Duration
	after := func(d time.Duration) <-chan time.Time {
		if elapsed+d > time.Hour {
			cancel()
			return make(chan time.Time) // never fires; ctx.Done wins the select
		}
		elapsed += d
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	s.aptRefreshLoopClock(ctx, after)

	attempts := cs.listCalls.Load()
	flat := int64(time.Hour / aptRetryInterval)
	if attempts >= flat {
		t.Fatalf("%d listings in a simulated hour; a flat %v retry is %d, so nothing is capping it",
			attempts, aptRetryInterval, flat)
	}
	if attempts > 10 {
		t.Errorf("%d listings in a simulated hour against a permanently failing backend, want no more than 10", attempts)
	}
	if attempts < 3 {
		t.Errorf("%d listings in a simulated hour; the first retries have to stay quick enough to catch a transient failure", attempts)
	}
}

// TestRetryReturnsToRefreshIntervalOnRecovery is the other half: the backoff
// exists to stop a storm, not to punish a backend that arrives late. Once a
// snapshot builds, the loop is back on the hourly interval.
func TestRetryReturnsToRefreshIntervalOnRecovery(t *testing.T) {
	s, cs, _ := refreshTestServer(t)
	s.aptSnap.Store(nil)
	s.aptPool.Store(nil)
	cs.failList.Store(true)

	ctx := t.Context()
	interval := s.aptNextInterval(0)
	for range 4 {
		s.rebuildAptSnapshot(ctx)
		interval = s.aptNextInterval(interval)
	}
	if interval <= aptRetryInterval {
		t.Fatalf("interval after four failures = %v, want more than %v", interval, aptRetryInterval)
	}

	cs.failList.Store(false)
	s.rebuildAptSnapshot(ctx)
	if got := s.aptNextInterval(interval); got != aptRefreshInterval {
		t.Errorf("interval after recovery = %v, want %v", got, aptRefreshInterval)
	}
}

// seedFallbackEntry adds an apt entry with no _pool_path, the shape 'pkg
// create' and the mutation API both accept and the only one that makes the
// index depend on a pool listing.
func seedFallbackEntry(t *testing.T, s *Server) {
	t.Helper()
	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "late", manifest.VersionEntry{
		Version:    "2.0.0",
		SourceName: "late",
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := s.store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
}

// TestNoListingWhenEveryEntryCarriesPoolPath is the cost bound. An index built
// entirely from _pool_path never reads the listing, so walking the whole pool
// on every rebuild, once per configured backend, buys nothing.
func TestNoListingWhenEveryEntryCarriesPoolPath(t *testing.T) {
	s, cs, _ := refreshTestServer(t)
	s.aptPool.Store(nil)
	cs.listCalls.Store(0)

	s.rebuildAptSnapshot(t.Context())

	if n := cs.listCalls.Load(); n != 0 {
		t.Errorf("%d pool listings for an index every entry addresses directly, want 0", n)
	}
	snap := s.aptSnap.Load()
	if snap == nil || !strings.Contains(string(snap.suites["noble"].packages["amd64"]), "Package: hello") {
		t.Error("the entry with _pool_path did not reach the index")
	}
}

// TestLateDebIsNotHiddenByTheCachedListing is the freshness half. A .deb that
// reached the pool after the cached listing was taken used to stay out of the
// index for the whole metadata_ttl, and stay out silently.
func TestLateDebIsNotHiddenByTheCachedListing(t *testing.T) {
	s, cs, _ := refreshTestServer(t)
	seedFallbackEntry(t, s)

	// A listing taken before the .deb landed, still well inside the TTL.
	s.aptPool.Store(&aptPoolListing{keys: []string{}, at: time.Now()})
	cs.Seed("packages/apt/pool/main/l/late/late_2.0.0_amd64.deb", "\x00deb")

	s.rebuildAptSnapshot(t.Context())

	snap := s.aptSnap.Load()
	if snap == nil {
		t.Fatal("no snapshot")
	}
	packages := string(snap.suites["noble"].packages["amd64"])
	if !strings.Contains(packages, "Package: late") {
		t.Errorf("a .deb uploaded after the cached listing stayed out of the index:\n%s", packages)
	}
}

// TestPoolListFailureStillLeavesAnErrorPath pins the 503 the operator sees
// when the very first snapshot cannot be built, message included: it names
// what failed and where to look, which the retry loop then works to clear.
func TestPoolListFailureStillLeavesAnErrorPath(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	s.aptSnap.Store(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/apt/dists/noble/Release", nil)
	s.handleAptRelease(w, r, "noble")

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 with no snapshot", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no snapshot has been built") {
		t.Errorf("503 body does not say what failed: %q", w.Body.String())
	}
}

// TestReloadWalksTheRotationRunbook executes docs/USAGE.md's rotation
// procedure against a live server: rotate, reload, retire, reload. Each reload
// stands in for the systemctl reload the runbook calls, and the assertions are
// what a client sees at each step.
//
// The failure this guards is deferred and arrives all at once. A reload that
// did not re-read the key would leave the served keyring carrying the outgoing
// key alone through the whole window, so every client that re-fetched during it
// would install old-only — and then fail apt update together at the next
// restart, when the incoming key alone starts signing.
func TestReloadWalksTheRotationRunbook(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)
	keyPath := filepath.Join(dir, aptsign.KeyFileName)

	outgoing := writeTestKey(t, keyPath)
	s, _, _ := refreshTestServer(t)

	if got := servedFingerprints(t, s); len(got) != 1 || got[0] != outgoing.Fingerprints()[0] {
		t.Fatalf("served keyring at startup = %v, want the outgoing key alone", got)
	}
	assertInReleaseVerifies(t, s, outgoing)

	// bodega apt key generate --rotate
	incoming, err := aptsign.Generate("bodega test incoming", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	outgoing.Add(incoming)
	if err := outgoing.WritePrivate(keyPath); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}

	// systemctl reload bodega
	s.reload(t.Context())

	if got := servedFingerprints(t, s); len(got) != 2 {
		t.Fatalf("served keyring after the rotate reload = %v, want both keys", got)
	}
	// Either key alone verifies, which is what carries a client that has
	// fetched only one of them.
	assertInReleaseVerifies(t, s, incoming)

	// bodega apt key retire <outgoing>, then reload again.
	if err := incoming.WritePrivate(keyPath); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	s.reload(t.Context())

	got := servedFingerprints(t, s)
	if len(got) != 1 || got[0] != incoming.Fingerprints()[0] {
		t.Fatalf("served keyring after the retire reload = %v, want the incoming key alone", got)
	}
	assertInReleaseVerifies(t, s, incoming)
}

// TestReloadKeepsSigningWhenTheKeyGoesBad covers the operator error mid-window.
// A client configured with Signed-By: has no unsigned fallback, so a reload
// that cannot read a key must leave the loaded one signing rather than take the
// whole archive unsigned on a transient fault.
func TestReloadKeepsSigningWhenTheKeyGoesBad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)
	keyPath := filepath.Join(dir, aptsign.KeyFileName)

	kr := writeTestKey(t, keyPath)
	s, _, _ := refreshTestServer(t)

	if err := os.WriteFile(keyPath, []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("corrupt key: %v", err)
	}
	s.reload(t.Context())
	if got := servedFingerprints(t, s); len(got) != 1 || got[0] != kr.Fingerprints()[0] {
		t.Fatalf("served keyring after an unreadable key = %v, want the loaded key still installed", got)
	}
	assertInReleaseVerifies(t, s, kr)

	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	s.reload(t.Context())
	if got := servedFingerprints(t, s); len(got) != 1 {
		t.Errorf("served keyring after the key was deleted = %v; going unsigned is a restart, not a reload", got)
	}
}

func writeTestKey(t *testing.T, path string) *aptsign.KeyRing {
	t.Helper()
	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := kr.WritePrivate(path); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	return kr
}

// servedFingerprints reads the keyring route rather than the Server field, so
// the assertion is what a client fetches.
func servedFingerprints(t *testing.T, s *Server) []string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleAptKeyring(w, httptest.NewRequest(http.MethodGet, "/apt/bodega-archive-keyring.gpg", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET bodega-archive-keyring.gpg = %d, want 200", w.Code)
	}
	el, err := openpgp.ReadKeyRing(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("served keyring does not parse: %v", err)
	}
	out := make([]string, 0, len(el))
	for _, e := range el {
		out = append(out, strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)))
	}
	return out
}

// assertInReleaseVerifies checks the served InRelease against one key alone,
// which is the client that holds only that half of a rotation window.
func assertInReleaseVerifies(t *testing.T, s *Server, kr *aptsign.KeyRing) {
	t.Helper()
	snap := s.aptSnap.Load()
	if snap == nil || snap.suites["noble"] == nil {
		t.Fatal("no snapshot")
	}
	signed := snap.suites["noble"].inRelease
	if len(signed) == 0 {
		t.Fatal("InRelease is empty; the suite is serving unsigned")
	}
	block, _ := clearsign.Decode(signed)
	if block == nil {
		t.Fatal("InRelease is not a clearsigned document")
	}
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	var sigs bytes.Buffer
	if _, err := sigs.ReadFrom(block.ArmoredSignature.Body); err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if _, err := openpgp.CheckDetachedSignature(el, bytes.NewReader(block.Bytes), bytes.NewReader(sigs.Bytes()), nil); err != nil {
		t.Errorf("InRelease does not verify under %s alone: %v", kr.Fingerprints()[0], err)
	}
}

// TestUnpooledEntryIsLogged covers the third silent drop. An entry that
// reaches a served suite but matches no .deb in the pool is absent from
// Packages, and absence reads on the client as "Unable to locate package",
// which is also what a typo produces. Without a log line the operator has the
// client's word for it and nothing else.
func TestUnpooledEntryIsLogged(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	var buf bytes.Buffer
	s.logger = newTestLogger(&buf, slog.LevelInfo)
	seedFallbackEntry(t, s) // no _pool_path, and no object seeded for it

	s.rebuildAptSnapshot(t.Context())

	logged := buf.String()
	if !strings.Contains(logged, "match no .deb in the pool") {
		t.Errorf("an entry that resolved to no pool object was dropped silently:\n%s", logged)
	}
	if !strings.Contains(logged, "late@2.0.0") {
		t.Errorf("the warning does not name the entry:\n%s", logged)
	}
}

// TestMutationAPIRefusesAVersionlessAptEntry is the guard at the write rather
// than at render time. A persisted version-less entry is addressable by no
// verb: remove, delete, hide and freeze all name a version, so its only exit
// is a 'bodega repair' run.
func TestMutationAPIRefusesAVersionlessAptEntry(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	body := `{"name":"blank","type":"apt","versions":[{"metadata":{"Architecture":"amd64"}}]}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/apt", strings.NewReader(body))
	r.SetPathValue("type", manifest.TypeApt)
	w := httptest.NewRecorder()

	s.handleCreateEntry(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an apt entry with no version", w.Code)
	}
	if pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, "blank"); pm != nil {
		t.Error("the refused entry was persisted anyway")
	}
}

// TestArchitectureLessEntryIsLogged covers the fourth silent drop, and the one
// no bucket named. generateAptPackages skips an entry with no Architecture
// before it looks at the pool, and auditAptEntries excluded the same entries
// from its unserved and unpooled walks — correctly for what those walks do,
// which is what left this the one case producing "Unable to locate package"
// with nothing in the log at all (#100).
func TestArchitectureLessEntryIsLogged(t *testing.T) {
	for _, tc := range []struct{ name, poolPath string }{
		{"without a pool path", ""},
		{"with a pool path", "pool/main/b/blank/blank_3.0.0_amd64.deb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := refreshTestServer(t)
			var buf bytes.Buffer
			s.logger = newTestLogger(&buf, slog.LevelInfo)
			md := map[string]string{}
			if tc.poolPath != "" {
				md["_pool_path"] = tc.poolPath
			}
			if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "blank", manifest.VersionEntry{
				Version:    "3.0.0",
				SourceName: "blank",
				Metadata:   md,
			}); err != nil {
				t.Fatalf("AddVersion: %v", err)
			}
			if err := s.store.SaveIndex(t.Context()); err != nil {
				t.Fatalf("SaveIndex: %v", err)
			}

			s.rebuildAptSnapshot(t.Context())

			logged := buf.String()
			if !strings.Contains(logged, "carry no Architecture metadata") {
				t.Errorf("an entry with no Architecture was dropped silently:\n%s", logged)
			}
			if !strings.Contains(logged, "blank@3.0.0") {
				t.Errorf("the warning does not name the entry:\n%s", logged)
			}
			// It belongs to one bucket, not two: an operator chasing a missing
			// package must not be sent to look for a .deb that is present.
			if strings.Contains(logged, "match no .deb in the pool") {
				t.Errorf("the entry was also reported as unpooled, which names the wrong fix:\n%s", logged)
			}
		})
	}
}
