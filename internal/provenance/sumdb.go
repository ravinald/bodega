package provenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	modulepath "golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// ChecksumDatabaseStore holds the latest signed tree head the
// checksum_database check verified, per database name. *audit.DB is one.
type ChecksumDatabaseStore interface {
	GetChecksumDatabaseTree(ctx context.Context, name string) ([]byte, error)
	SwapChecksumDatabaseTree(ctx context.Context, name string, old, next []byte) (bool, error)
}

// EventRecorder records the audit event the database misbehaving leaves.
type EventRecorder interface {
	Record(ctx context.Context, e audit.Event) error
}

// Bounds on one read of the checksum database. A lookup answer and a hash
// tile are a few kilobytes; the cap only has to stop a hostile or broken
// server from filling memory.
const (
	DefaultChecksumDatabaseTimeout  = 15 * time.Second
	DefaultChecksumDatabaseMaxBytes = 1 << 20
)

// ChecksumDatabaseConfig is what a ChecksumDatabase reads and where it keeps
// the tree head.
type ChecksumDatabaseConfig struct {
	// URL is gomod_sumdb_url, the root every database path is appended to.
	URL string
	// Key is gomod_sumdb_key, the verifier key every tree head is checked
	// against.
	Key string
	// NoSumdb are gomod_nosumdb's patterns: modules never looked up.
	NoSumdb []string
	// HTTP is the client every read goes through; nil means one bounded by
	// Timeout.
	HTTP     *http.Client
	Timeout  time.Duration
	MaxBytes int64
	// Store holds the tree head across restarts. Nil keeps it in memory.
	Store ChecksumDatabaseStore
	// Events records a security error. Nil records none.
	Events EventRecorder
	// ReadOnly reads the stored tree head and writes none, and records no
	// event: the checker of a caller that must write nothing.
	ReadOnly bool
}

// ChecksumDatabase is the checksum_database admission check: a Go module
// version looked up in the checksum database, verified against its signed
// tree head by golang.org/x/mod/sumdb. One is shared by every admission in a
// process, so the tree head and record cache its client holds are too.
//
// The outcome is never put under a policy. unknown blocks because the go
// command refuses a module it cannot verify, and a host behind bodega reaches
// the database only through the relay; invalid blocks and no override lifts
// it, because the database's own signature says the bytes are something else.
type ChecksumDatabase struct {
	cfg       ChecksumDatabaseConfig
	name      string
	verifiers note.Verifiers
	keyErr    error

	mu     sync.Mutex
	client *sumdb.Client
	ops    *sumdbOps
}

// NewChecksumDatabase builds the check. A key that does not parse is not an
// error here: config.Load refuses one, and a checker built from anything
// else answers unknown on every version and says why.
func NewChecksumDatabase(cfg ChecksumDatabaseConfig) *ChecksumDatabase {
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultChecksumDatabaseTimeout
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultChecksumDatabaseMaxBytes
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: cfg.Timeout}
	}
	d := &ChecksumDatabase{cfg: cfg}
	v, err := note.NewVerifier(strings.TrimSpace(cfg.Key))
	if err != nil {
		d.keyErr = fmt.Errorf("gomod_sumdb_key %q does not parse: %w", cfg.Key, err)
		return d
	}
	d.name = v.Name()
	d.verifiers = note.VerifierList(v)
	return d
}

// AppliesTo reports whether the check runs on typ's versions: gomod only.
func (d *ChecksumDatabase) AppliesTo(typ string) bool { return typ == manifest.TypeGomod }

// Check looks ve up and turns the outcome into the check's result: pass on
// verified and unavailable, block on unknown and invalid.
func (d *ChecksumDatabase) Check(_ context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) policy.Result {
	if pm == nil || ve == nil || !d.AppliesTo(pm.Type) {
		return policy.Result{Check: audit.CheckChecksumDatabase, Action: policy.ActionPass}
	}
	rec, detail := d.Lookup(pm.Name, strings.TrimSpace(ve.Version))
	r := policy.Result{Check: audit.CheckChecksumDatabase, Action: policy.ActionPass,
		ChecksumDatabase: &rec, Reason: rec.Outcome + ": " + detail}
	if rec.Outcome == audit.ProvenanceInvalid || rec.Outcome == audit.ProvenanceUnknown {
		r.Action = policy.ActionBlock
		r.Details = map[string]any{"outcome": rec.Outcome, "database": rec.Database}
	}
	return r
}

// Lookup reads the go.sum lines for module@version and its go.mod from the
// database and returns what they say, with the detail an admission row
// carries.
func (d *ChecksumDatabase) Lookup(module, version string) (audit.ChecksumDatabase, string) {
	rec := audit.ChecksumDatabase{Database: d.name}
	if rec.Database == "" {
		rec.Database = unparsedKeyDatabase
	}
	for _, p := range d.cfg.NoSumdb {
		if modulepath.MatchPrefixPatterns(p, module) {
			rec.Outcome = audit.ProvenanceUnavailable
			return rec, fmt.Sprintf("%s matches gomod_nosumdb pattern %q, so the checksum database was not consulted and the fetched bytes are not compared with it",
				module, p)
		}
	}
	read := d.lookupURL(module, version)
	unknown := func(format string, args ...any) (audit.ChecksumDatabase, string) {
		rec.Outcome = audit.ProvenanceUnknown
		return rec, fmt.Sprintf("the checksum database could not confirm %s@%s (read %s): %s. Check this server's egress to gomod_sumdb_url (%s), or name a private module in gomod_nosumdb; the fetched bytes are not compared, because the database gave no hash to compare them with",
			module, version, read, fmt.Sprintf(format, args...), d.cfg.URL)
	}
	if d.keyErr != nil {
		return unknown("%v", d.keyErr)
	}
	if err := modulepath.Check(module, version); err != nil {
		return unknown("the database holds lines only for a module path at a canonical version: %v", err)
	}
	client, ops := d.acquire()
	zip, err := client.Lookup(module, version)
	var mod []string
	if err == nil {
		mod, err = client.Lookup(module, version+"/go.mod")
	}
	if err != nil {
		// A sumdb.Client keeps its first init error, and the record cache
		// keeps a failed lookup, for the client's lifetime; a fresh one
		// starts again from the stored tree head.
		d.drop(client)
		msg := oneLine(err.Error())
		misbehaved := strings.Contains(msg, sumdb.ErrSecurity.Error())
		if !misbehaved && (strings.Contains(msg, errRemoteRead) || strings.Contains(msg, errTreeStore)) {
			return unknown("%s", msg)
		}
		rec.Outcome = audit.ProvenanceInvalid
		return rec, fmt.Sprintf("%s@%s: the checksum database at %s served something its own key does not vouch for (read %s): %s. An operator should compare the stored tree head with %s/latest before admitting anything from it",
			module, version, d.cfg.URL, read, msg, d.cfg.URL)
	}
	if len(zip) == 0 || len(mod) == 0 {
		return unknown("the database holds no line for this version")
	}
	rec.ZipHash, rec.ModHash = goSumHash(zip[0]), goSumHash(mod[0])
	rec.TreeSize, rec.TreeHash = ops.tree()
	rec.Outcome = audit.ProvenanceVerified
	return rec, fmt.Sprintf("%s@%s is in %s at tree size %d (hash %s): %s, go.mod %s; the fetched .zip and .mod are compared with these hashes",
		module, version, rec.Database, rec.TreeSize, rec.TreeHash, rec.ZipHash, rec.ModHash)
}

// unparsedKeyDatabase names the database on a row whose key never parsed: the
// only one config.Load accepts a key for.
const unparsedKeyDatabase = "sum.golang.org"

func (d *ChecksumDatabase) lookupURL(module, version string) string {
	epath, err1 := modulepath.EscapePath(module)
	evers, err2 := modulepath.EscapeVersion(version)
	if err1 != nil || err2 != nil {
		return d.cfg.URL + "/lookup/" + module + "@" + version
	}
	return d.cfg.URL + "/lookup/" + epath + "@" + evers
}

// acquire returns the client every lookup shares, building one if none is
// held.
func (d *ChecksumDatabase) acquire() (*sumdb.Client, *sumdbOps) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client == nil {
		d.ops = &sumdbOps{d: d}
		d.client = sumdb.NewClient(d.ops)
	}
	return d.client, d.ops
}

// drop discards client so the next check builds another, unless another
// check already has.
func (d *ChecksumDatabase) drop(client *sumdb.Client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client == client {
		d.client, d.ops = nil, nil
	}
}

// goSumHash is the hash of a go.sum line, "module version h1:...".
func goSumHash(line string) string {
	f := strings.Fields(line)
	if len(f) < 3 {
		return ""
	}
	return f[2]
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// Markers on the errors sumdbOps returns. sumdb.Client formats every error it
// returns with %v, so no error chain survives to Lookup; these are how a
// failure to read is told from a failure to verify.
const (
	errRemoteRead = "checksum database read failed"
	errTreeStore  = "stored tree head unavailable"
)

var errNotCached = errors.New("not cached")

// sumdbOps is what one sumdb.Client reads and writes through.
type sumdbOps struct {
	d *ChecksumDatabase

	mu sync.Mutex
	// mem is the tree head a client with no store, or a read-only one,
	// holds in place of writing it; memSet says whether it was ever written.
	mem    []byte
	memSet bool
	// size and hash are the newest tree this client has seen verified.
	size int64
	hash string
}

func (o *sumdbOps) ReadRemote(path string) ([]byte, error) {
	d := o.d
	url := d.cfg.URL + path
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %v", errRemoteRead, url, err)
	}
	resp, err := d.cfg.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %v", errRemoteRead, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s answered %s", errRemoteRead, url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, d.cfg.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %v", errRemoteRead, url, err)
	}
	if int64(len(body)) > d.cfg.MaxBytes {
		return nil, fmt.Errorf("%s: %s answered more than %d bytes", errRemoteRead, url, d.cfg.MaxBytes)
	}
	return body, nil
}

func (o *sumdbOps) latestFile() string { return o.d.name + "/latest" }

func (o *sumdbOps) ReadConfig(file string) ([]byte, error) {
	switch file {
	case "key":
		return []byte(o.d.cfg.Key), nil
	case o.latestFile():
		data, err := o.current()
		if err != nil {
			return nil, err
		}
		o.observe(data)
		return data, nil
	}
	return nil, fmt.Errorf("no configuration file %q", file)
}

// current is the tree head this client starts from: the one it holds in
// memory in place of a write, or else the stored one.
func (o *sumdbOps) current() ([]byte, error) {
	o.mu.Lock()
	mem, set := o.mem, o.memSet
	o.mu.Unlock()
	if set || o.d.cfg.Store == nil {
		return mem, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.d.cfg.Timeout)
	defer cancel()
	data, err := o.d.cfg.Store.GetChecksumDatabaseTree(ctx, o.d.name)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", errTreeStore, err)
	}
	return data, nil
}

func (o *sumdbOps) WriteConfig(file string, old, next []byte) error {
	if file != o.latestFile() {
		return fmt.Errorf("no configuration file %q may be written", file)
	}
	if o.d.cfg.ReadOnly || o.d.cfg.Store == nil {
		held, err := o.current()
		if err != nil {
			return err
		}
		if !bytes.Equal(held, old) {
			return sumdb.ErrWriteConflict
		}
		o.mu.Lock()
		o.mem, o.memSet = next, true
		o.mu.Unlock()
		o.observe(next)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.d.cfg.Timeout)
	defer cancel()
	ok, err := o.d.cfg.Store.SwapChecksumDatabaseTree(ctx, o.d.name, old, next)
	if err != nil {
		return fmt.Errorf("%s: %v", errTreeStore, err)
	}
	if !ok {
		return sumdb.ErrWriteConflict
	}
	o.observe(next)
	return nil
}

// ReadCache misses every time: the client's own record and tile caches live
// in memory for its lifetime, and nothing is kept on disk.
func (o *sumdbOps) ReadCache(string) ([]byte, error) { return nil, errNotCached }
func (o *sumdbOps) WriteCache(string, []byte)        {}

func (o *sumdbOps) Log(msg string) {
	slog.Debug("checksum database", "database", o.d.name, "message", msg)
}

// SecurityError logs and records what the client found and returns, so the
// client returns sumdb.ErrSecurity rather than the process exiting: one
// misbehaving answer refuses the version it was asked about, not every
// request the server is handling.
func (o *sumdbOps) SecurityError(msg string) {
	d := o.d
	slog.Error("checksum database served a tree its own key does not vouch for", "database", d.name, "url", d.cfg.URL, "message", msg)
	if d.cfg.ReadOnly || d.cfg.Events == nil {
		return
	}
	details, _ := json.Marshal(map[string]string{"database": d.name, "url": d.cfg.URL, "message": msg})
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout)
	defer cancel()
	if err := d.cfg.Events.Record(ctx, audit.Event{EventType: audit.EventChecksumDatabase, Status: "security_error",
		PkgType: manifest.TypeGomod, Details: string(details)}); err != nil {
		slog.Error("checksum database security error not recorded in the audit database", "database", d.name, "error", err)
	}
}

// observe notes msg's tree when it is newer than any this client has seen.
// Only verified heads reach here: the stored one was written after the
// client verified it, and a written one is what the client just verified.
func (o *sumdbOps) observe(msg []byte) {
	if len(msg) == 0 {
		return
	}
	n, err := note.Open(msg, o.d.verifiers)
	if err != nil {
		return
	}
	t, err := tlog.ParseTree([]byte(n.Text))
	if err != nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if t.N >= o.size {
		o.size, o.hash = t.N, t.Hash.String()
	}
}

func (o *sumdbOps) tree() (int64, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.size, o.hash
}
