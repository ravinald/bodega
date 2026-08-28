package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
}

func (c *ctxStore) List(ctx context.Context, prefix string) ([]string, error) {
	err := ctx.Err()
	c.lastListErr.Store(errBox{err})
	if c.honorCtx.Load() && err != nil {
		return nil, err
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
// seconds rather than in an hour.
func TestTickIntervalShortensWithoutASnapshot(t *testing.T) {
	s, _, _ := refreshTestServer(t)

	if got := s.aptTickInterval(); got != aptRefreshInterval {
		t.Errorf("interval with a snapshot = %v, want %v", got, aptRefreshInterval)
	}
	s.aptSnap.Store(nil)
	if got := s.aptTickInterval(); got != aptRetryInterval {
		t.Errorf("interval with no snapshot = %v, want %v", got, aptRetryInterval)
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
