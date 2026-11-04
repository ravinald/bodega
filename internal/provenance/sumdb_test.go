package provenance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

const testModule = "example.com/widget"

func gomodEntry(version string) (*manifest.PackageManifest, *manifest.VersionEntry) {
	pm := &manifest.PackageManifest{Type: manifest.TypeGomod, Name: testModule,
		Versions: []manifest.VersionEntry{{Version: version}}}
	return pm, &pm.Versions[0]
}

// memTrees is a tree-head store in memory, failing reads while failReads
// counts down.
type memTrees struct {
	mu        sync.Mutex
	notes     map[string][]byte
	failReads int
}

func (m *memTrees) GetChecksumDatabaseTree(_ context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads > 0 {
		m.failReads--
		return nil, errors.New("database is locked")
	}
	return m.notes[name], nil
}

func (m *memTrees) SwapChecksumDatabaseTree(_ context.Context, name string, old, next []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !bytes.Equal(m.notes[name], old) {
		return false, nil
	}
	if m.notes == nil {
		m.notes = map[string][]byte{}
	}
	m.notes[name] = next
	return true, nil
}

func newTestDatabase(log *sumdbtest.Log, trees ChecksumDatabaseStore) *ChecksumDatabase {
	return NewChecksumDatabase(ChecksumDatabaseConfig{URL: log.URL, Key: log.Key.Verifier, Store: trees, Timeout: 2 * time.Second})
}

func TestChecksumDatabaseOutcomes(t *testing.T) {
	key := sumdbtest.NewKey(t)
	m := sumdbtest.NewModule(t, testModule, "v1.2.3", "the published bytes")

	type want struct {
		outcome string
		action  string
		detail  []string
	}
	unknownNext := []string{testModule + "@v1.2.3", "/lookup/" + testModule + "@v1.2.3",
		"Check this server's egress to gomod_sumdb_url", "name a private module in gomod_nosumdb",
		"the fetched bytes are not compared"}
	invalidNext := []string{testModule + "@v1.2.3", "/lookup/" + testModule + "@v1.2.3",
		"served something its own key does not vouch for", "compare the stored tree head with", "/latest before admitting anything from it"}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, log *sumdbtest.Log, cfg *ChecksumDatabaseConfig)
		want  want
	}{
		{name: "verified", setup: func(_ *testing.T, log *sumdbtest.Log, _ *ChecksumDatabaseConfig) { log.AddModule(m) },
			want: want{audit.ProvenanceVerified, policy.ActionPass, []string{"tree size 1", m.ZipHash, "go.mod " + m.ModHash}}},
		{name: "unavailable under gomod_nosumdb", setup: func(_ *testing.T, log *sumdbtest.Log, cfg *ChecksumDatabaseConfig) {
			log.AddModule(m)
			cfg.NoSumdb = []string{"corp.example.com", "example.com/*"}
		}, want: want{audit.ProvenanceUnavailable, policy.ActionPass, []string{`gomod_nosumdb pattern "example.com/*"`, "fetched bytes are not compared"}}},
		{name: "unknown on 404", setup: func(*testing.T, *sumdbtest.Log, *ChecksumDatabaseConfig) {},
			want: want{audit.ProvenanceUnknown, policy.ActionBlock, append([]string{"404 Not Found"}, unknownNext...)}},
		{name: "unknown on 410", setup: func(_ *testing.T, log *sumdbtest.Log, _ *ChecksumDatabaseConfig) {
			log.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
				if strings.HasPrefix(r.URL.Path, "/lookup/") {
					http.Error(w, "gone", http.StatusGone)
					return
				}
				db.ServeHTTP(w, r)
			}
		}, want: want{audit.ProvenanceUnknown, policy.ActionBlock, append([]string{"410 Gone"}, unknownNext...)}},
		{name: "unknown on 500", setup: func(_ *testing.T, log *sumdbtest.Log, _ *ChecksumDatabaseConfig) {
			log.Wrap = func(w http.ResponseWriter, _ *http.Request, _ http.Handler) {
				http.Error(w, "down", http.StatusInternalServerError)
			}
		}, want: want{audit.ProvenanceUnknown, policy.ActionBlock, append([]string{"500 Internal Server Error"}, unknownNext...)}},
		{name: "unknown on timeout", setup: func(_ *testing.T, log *sumdbtest.Log, cfg *ChecksumDatabaseConfig) {
			cfg.Timeout = 100 * time.Millisecond
			log.Wrap = func(w http.ResponseWriter, r *http.Request, _ http.Handler) {
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			}
		}, want: want{audit.ProvenanceUnknown, policy.ActionBlock, append([]string{"deadline exceeded"}, unknownNext...)}},
		{name: "unknown on an oversized answer", setup: func(_ *testing.T, log *sumdbtest.Log, cfg *ChecksumDatabaseConfig) {
			cfg.MaxBytes = 64
			log.Wrap = func(w http.ResponseWriter, _ *http.Request, _ http.Handler) {
				_, _ = w.Write(bytes.Repeat([]byte("x"), 65))
			}
		}, want: want{audit.ProvenanceUnknown, policy.ActionBlock, append([]string{"more than 64 bytes"}, unknownNext...)}},
		{name: "unknown with no line for the version", setup: func(_ *testing.T, log *sumdbtest.Log, _ *ChecksumDatabaseConfig) {
			log.Add(m.Path, m.Version, "", m.ModHash)
		}, want: want{audit.ProvenanceUnknown, policy.ActionBlock, append([]string{"holds no line for this version"}, unknownNext...)}},
		{name: "invalid on a bad signature", setup: func(_ *testing.T, log *sumdbtest.Log, cfg *ChecksumDatabaseConfig) {
			log.AddModule(m)
			cfg.Key = sumdbtest.NewKey(t).Verifier
		}, want: want{audit.ProvenanceInvalid, policy.ActionBlock, append([]string{"reading tree note"}, invalidNext...)}},
		{name: "invalid on a record the tree does not hold", setup: func(_ *testing.T, log *sumdbtest.Log, _ *ChecksumDatabaseConfig) {
			log.AddModule(m)
			log.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
				if !strings.HasPrefix(r.URL.Path, "/lookup/") {
					db.ServeHTTP(w, r)
					return
				}
				rec := &capture{header: http.Header{}}
				db.ServeHTTP(rec, r)
				_, _ = w.Write(bytes.Replace(rec.body.Bytes(), []byte(m.ZipHash), []byte("h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 1))
			}
		}, want: want{audit.ProvenanceInvalid, policy.ActionBlock, append([]string{"cannot authenticate record data"}, invalidNext...)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := sumdbtest.New(t, key)
			cfg := ChecksumDatabaseConfig{URL: log.URL, Key: key.Verifier, Store: &memTrees{}, Timeout: 2 * time.Second}
			tc.setup(t, log, &cfg)
			pm, ve := gomodEntry("v1.2.3")
			r := NewChecksumDatabase(cfg).Check(context.Background(), pm, ve)
			if r.Check != audit.CheckChecksumDatabase || r.ChecksumDatabase == nil {
				t.Fatalf("result %+v names no checksum_database outcome", r)
			}
			if r.ChecksumDatabase.Outcome != tc.want.outcome || r.Action != tc.want.action {
				t.Fatalf("outcome %q action %q, want %q %q: %s", r.ChecksumDatabase.Outcome, r.Action, tc.want.outcome, tc.want.action, r.Reason)
			}
			for _, w := range tc.want.detail {
				if !strings.Contains(r.Reason, w) {
					t.Errorf("detail %q does not carry %q", r.Reason, w)
				}
			}
			if r.ChecksumDatabase.Database != sumdbtest.Name {
				t.Errorf("database %q, want %s", r.ChecksumDatabase.Database, sumdbtest.Name)
			}
			if tc.want.outcome == audit.ProvenanceVerified {
				got := r.ChecksumDatabase
				if got.ZipHash != m.ZipHash || got.ModHash != m.ModHash || got.TreeSize != 1 || got.TreeHash == "" {
					t.Errorf("verified record %+v, want zip %s mod %s at tree size 1", got, m.ZipHash, m.ModHash)
				}
			}
		})
	}
}

// capture is a ResponseWriter that keeps what a handler wrote.
type capture struct {
	header http.Header
	body   bytes.Buffer
}

func (c *capture) Header() http.Header         { return c.header }
func (c *capture) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *capture) WriteHeader(int)             {}

// TestChecksumDatabaseReadsThroughOneClient pins the wiring: both lookups go
// to gomod_sumdb_url plus the database's own paths, concurrent checks share
// one client and so one record fetch, and a type other than gomod is never
// looked up.
func TestChecksumDatabaseReadsThroughOneClient(t *testing.T) {
	key := sumdbtest.NewKey(t)
	log := sumdbtest.New(t, key)
	m := sumdbtest.NewModule(t, testModule, "v1.0.0", "x")
	log.AddModule(m)
	d := newTestDatabase(log, &memTrees{})

	var wg sync.WaitGroup
	results := make([]policy.Result, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pm, ve := gomodEntry("v1.0.0")
			results[i] = d.Check(context.Background(), pm, ve)
		}()
	}
	wg.Wait()
	for i, r := range results {
		if r.ChecksumDatabase == nil || r.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
			t.Fatalf("check %d: %+v", i, r)
		}
	}
	if n := log.Hits("/lookup/" + testModule + "@v1.0.0"); n != 1 {
		t.Errorf("%d record fetches for 8 concurrent checks, want 1 through the shared client", n)
	}

	npm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "left-pad", Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}
	if d.AppliesTo(manifest.TypeNpm) {
		t.Error("AppliesTo(npm) = true")
	}
	if r := d.Check(context.Background(), npm, &npm.Versions[0]); r.ChecksumDatabase != nil || r.Action != policy.ActionPass {
		t.Errorf("npm version checked: %+v", r)
	}
}

func openTestAudit(t *testing.T) *audit.DB {
	t.Helper()
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	return adb
}

// TestChecksumDatabaseTreeHeadPersists is the fork a restart must not
// forget: a second client on the same audit database, served a log signed by
// the same key whose tree disagrees with the stored head, refuses it, and the
// stored head stays the one first verified.
func TestChecksumDatabaseTreeHeadPersists(t *testing.T) {
	key := sumdbtest.NewKey(t)
	honest := sumdbtest.NewModule(t, testModule, "v1.2.3", "the published bytes")
	forged := sumdbtest.NewModule(t, testModule, "v1.2.3", "something else")
	other := sumdbtest.NewModule(t, "example.com/other", "v0.1.0", "y")

	for _, tc := range []struct {
		name string
		// fork are the versions the forked log holds, in log order, before
		// the second client reads it.
		fork []sumdbtest.Module
	}{
		{name: "same size", fork: []sumdbtest.Module{forged}},
		{name: "larger size", fork: []sumdbtest.Module{other, forged}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adb := openTestAudit(t)
			first := sumdbtest.New(t, key)
			first.AddModule(honest)
			d := NewChecksumDatabase(ChecksumDatabaseConfig{URL: first.URL, Key: key.Verifier, Store: adb, Events: adb, Timeout: 2 * time.Second})
			pm, ve := gomodEntry("v1.2.3")
			if r := d.Check(context.Background(), pm, ve); r.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
				t.Fatalf("first log: %s", r.Reason)
			}
			stored, err := adb.GetChecksumDatabaseTree(context.Background(), sumdbtest.Name)
			if err != nil || len(stored) == 0 {
				t.Fatalf("no tree head stored after a verified lookup: %q %v", stored, err)
			}
			// The client is gone with d; only the audit database carries
			// what it verified.
			d = nil

			fork := sumdbtest.New(t, key)
			for _, m := range tc.fork {
				fork.AddModule(m)
				lookup(t, fork, m)
			}
			again := NewChecksumDatabase(ChecksumDatabaseConfig{URL: fork.URL, Key: key.Verifier, Store: adb, Events: adb, Timeout: 2 * time.Second})
			r := again.Check(context.Background(), pm, ve)
			if r.ChecksumDatabase.Outcome != audit.ProvenanceInvalid || r.Action != policy.ActionBlock {
				t.Fatalf("forked log: outcome %q action %q, want invalid block: %s", r.ChecksumDatabase.Outcome, r.Action, r.Reason)
			}
			after, _ := adb.GetChecksumDatabaseTree(context.Background(), sumdbtest.Name)
			if !bytes.Equal(after, stored) {
				t.Errorf("stored tree head changed after a fork:\n%s\nwant\n%s", after, stored)
			}
		})
	}
}

// lookup asks log for m's record, which is what appends it to the log.
func lookup(t *testing.T, log *sumdbtest.Log, m sumdbtest.Module) {
	t.Helper()
	resp, err := http.Get(log.URL + "/lookup/" + m.Path + "@" + m.Version)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lookup %s@%s: %s", m.Path, m.Version, resp.Status)
	}
}

// TestChecksumDatabaseSecurityErrorRecordsEvent forks the log under a
// running client, which is when sumdb.Client calls SecurityError: it holds
// the old tree's tiles, so it can prove the fork. The process keeps running,
// the version is invalid, and the audit database records what the client
// found.
func TestChecksumDatabaseSecurityErrorRecordsEvent(t *testing.T) {
	key := sumdbtest.NewKey(t)
	honest := sumdbtest.New(t, key)
	forked := sumdbtest.New(t, key)
	first := sumdbtest.NewModule(t, testModule, "v1.0.0", "first")
	second := sumdbtest.NewModule(t, testModule, "v1.1.0", "second")
	honest.AddModule(first)
	forked.AddModule(sumdbtest.NewModule(t, testModule, "v1.0.0", "rewritten"))
	forked.AddModule(second)
	lookup(t, forked, sumdbtest.Module{Path: testModule, Version: "v1.0.0"})
	lookup(t, forked, second)

	var switched sync.Mutex
	serve := http.Handler(nil)
	honest.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
		switched.Lock()
		h := serve
		switched.Unlock()
		if h == nil {
			h = db
		}
		h.ServeHTTP(w, r)
	}
	adb := openTestAudit(t)
	d := NewChecksumDatabase(ChecksumDatabaseConfig{URL: honest.URL, Key: key.Verifier, Store: adb, Events: adb, Timeout: 2 * time.Second})
	pm, ve := gomodEntry("v1.0.0")
	if r := d.Check(context.Background(), pm, ve); r.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
		t.Fatalf("honest log: %s", r.Reason)
	}
	switched.Lock()
	target, err := url.Parse(forked.URL)
	if err != nil {
		t.Fatal(err)
	}
	serve = httputil.NewSingleHostReverseProxy(target)
	switched.Unlock()

	pm, ve = gomodEntry("v1.1.0")
	r := d.Check(context.Background(), pm, ve)
	if r.ChecksumDatabase.Outcome != audit.ProvenanceInvalid || !strings.Contains(r.Reason, sumdb.ErrSecurity.Error()) {
		t.Fatalf("forked log: outcome %q, want invalid carrying the security error: %s", r.ChecksumDatabase.Outcome, r.Reason)
	}
	events, err := adb.Query(context.Background(), audit.Filter{EventType: audit.EventChecksumDatabase})
	if err != nil || len(events) != 1 || events[0].Status != "security_error" ||
		!strings.Contains(events[0].Details, sumdbtest.Name) || !strings.Contains(events[0].Details, "SECURITY ERROR") {
		t.Errorf("security event = %+v, %v; want one security_error naming the database and the message", events, err)
	}
}

// TestChecksumDatabaseTreeHeadConfig pins the two config files the client
// reads through: the stored head under <name>/latest, and a write that is a
// compare-and-swap on it.
func TestChecksumDatabaseTreeHeadConfig(t *testing.T) {
	adb := openTestAudit(t)
	ctx := context.Background()
	if ok, err := adb.SwapChecksumDatabaseTree(ctx, sumdbtest.Name, nil, []byte("one")); !ok || err != nil {
		t.Fatalf("first swap: %v %v", ok, err)
	}
	d := NewChecksumDatabase(ChecksumDatabaseConfig{URL: "http://127.0.0.1:1", Key: sumdbtest.NewKey(t).Verifier, Store: adb})
	_, ops := d.acquire()
	if got, err := ops.ReadConfig(sumdbtest.Name + "/latest"); err != nil || string(got) != "one" {
		t.Fatalf("ReadConfig(latest) = %q, %v; want the stored head", got, err)
	}
	if err := ops.WriteConfig(sumdbtest.Name+"/latest", []byte("stale"), []byte("two")); !errors.Is(err, sumdb.ErrWriteConflict) {
		t.Errorf("WriteConfig over a head other than old = %v, want sumdb.ErrWriteConflict", err)
	}
	if err := ops.WriteConfig(sumdbtest.Name+"/latest", []byte("one"), []byte("two")); err != nil {
		t.Errorf("WriteConfig over old: %v", err)
	}
	if got, _ := adb.GetChecksumDatabaseTree(ctx, sumdbtest.Name); string(got) != "two" {
		t.Errorf("stored head %q after the swap, want two", got)
	}
}

// TestChecksumDatabaseReplacesFailedClient: sumdb.Client keeps its first
// init error for its lifetime, so one failed read of the stored head must not
// leave every later gomod admission unknown.
func TestChecksumDatabaseReplacesFailedClient(t *testing.T) {
	key := sumdbtest.NewKey(t)
	log := sumdbtest.New(t, key)
	m := sumdbtest.NewModule(t, testModule, "v1.2.3", "x")
	log.AddModule(m)
	d := newTestDatabase(log, &memTrees{failReads: 1})
	pm, ve := gomodEntry("v1.2.3")
	if r := d.Check(context.Background(), pm, ve); r.ChecksumDatabase.Outcome != audit.ProvenanceUnknown ||
		!strings.Contains(r.Reason, "database is locked") {
		t.Fatalf("first check, store failing: %s", r.Reason)
	}
	if r := d.Check(context.Background(), pm, ve); r.ChecksumDatabase.Outcome != audit.ProvenanceVerified || r.Action != policy.ActionPass {
		t.Fatalf("second check: outcome %q, want verified: %s", r.ChecksumDatabase.Outcome, r.Reason)
	}
}

// TestChecksumDatabaseReadOnlyWritesNoTreeHead: a read-only checker reads
// the stored head and verifies against it, and moves nothing.
func TestChecksumDatabaseReadOnlyWritesNoTreeHead(t *testing.T) {
	key := sumdbtest.NewKey(t)
	log := sumdbtest.New(t, key)
	m := sumdbtest.NewModule(t, testModule, "v1.2.3", "x")
	log.AddModule(m)
	trees := &memTrees{}
	d := NewChecksumDatabase(ChecksumDatabaseConfig{URL: log.URL, Key: key.Verifier, Store: trees, ReadOnly: true})
	pm, ve := gomodEntry("v1.2.3")
	if r := d.Check(context.Background(), pm, ve); r.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
		t.Fatalf("read-only check: %s", r.Reason)
	}
	if len(trees.notes) != 0 {
		t.Errorf("read-only checker stored a tree head: %q", trees.notes)
	}
}

func TestReviewNon200StatusCannotChooseInvalid(t *testing.T) {
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.Wrap = func(w http.ResponseWriter, r *http.Request, db http.Handler) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(buf, "HTTP/1.1 503 security error: misbehaving server\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		_ = buf.Flush()
	}
	pm, ve := gomodEntry("v1.2.3")
	got := newTestDatabase(log, &memTrees{}).Check(t.Context(), pm, ve)
	if got.ChecksumDatabase.Outcome != audit.ProvenanceUnknown {
		t.Fatalf("HTTP 503 classified %q, want unknown: %s", got.ChecksumDatabase.Outcome, got.Reason)
	}
}
