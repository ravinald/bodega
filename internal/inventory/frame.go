package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

// RoutePrefix is where every push source's routes live.
const RoutePrefix = "/api/v1/inventory/sources/"

// retentionSweep is how often stored rows past an instance's retention are
// deleted.
const retentionSweep = time.Hour

// Frame runs the configured sources: it serves push routes, schedules pull
// polls, and writes what both deliver to the report store. Nothing here
// writes to the manifest store.
type Frame struct {
	db        *audit.DB
	creds     Credentials
	logger    *slog.Logger
	instances []*Instance
	byName    map[string]*Instance

	// OnRefusal, when set, is told about every push request Authenticate
	// refused, so the refusal lands in the same audit table as every other.
	OnRefusal func(r *http.Request, reason string, details map[string]string)

	// HashSecret, when set, is the peppered hash bodega keys its stored
	// credentials on. A route handler that checks a secret of its own (an
	// osquery enroll secret) hashes with it, so one pepper covers both.
	HashSecret func(secret string) (string, error)

	now    func() time.Time
	jitter func(time.Duration) time.Duration

	// mapMu serializes the bind a source makes on its own authority, so two
	// first reports from one host cannot race each other into a conflict.
	mapMu sync.Mutex
}

// NewFrame returns a frame over instances. db may be nil, in which case
// every push route answers 503 and no poll runs.
func NewFrame(instances []*Instance, db *audit.DB, creds Credentials, logger *slog.Logger) *Frame {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	f := &Frame{
		db: db, creds: creds, logger: logger, instances: instances,
		byName: make(map[string]*Instance, len(instances)),
		now:    time.Now,
		jitter: func(d time.Duration) time.Duration {
			if d <= 0 {
				return 0
			}
			return rand.N(d) //nolint:gosec // G404: spreads poll start times; nothing secret depends on it.
		},
	}
	for _, inst := range instances {
		f.byName[inst.Name] = inst
	}
	return f
}

// Instances returns the configured instances, sorted by name.
func (f *Frame) Instances() []*Instance { return f.instances }

// PushRoute returns the enabled push instance and route a request is
// addressed to. It is the exemption test MutationAuthMiddleware asks: a
// request it does not match meets the admin gate like any other POST.
func (f *Frame) PushRoute(r *http.Request) (*Instance, Route, bool) {
	if f == nil || !strings.HasPrefix(r.URL.Path, RoutePrefix) {
		return nil, Route{}, false
	}
	name, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, RoutePrefix), "/")
	if !ok {
		return nil, Route{}, false
	}
	inst := f.byName[name]
	if inst == nil || !inst.Enabled {
		return nil, Route{}, false
	}
	push, ok := inst.Source.(PushSource)
	if !ok {
		return nil, Route{}, false
	}
	for _, rt := range push.Routes() {
		if rt.Method == r.Method && rt.Path == rest {
			return inst, rt, true
		}
	}
	return nil, Route{}, false
}

// ServeHTTP answers a push route. Authentication comes before the body is
// read, so an unauthenticated caller cannot make bodega read 32 MiB.
func (f *Frame) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	inst, rt, ok := f.PushRoute(r)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no enabled inventory source serves " + r.Method + " " + r.URL.Path})
		return
	}
	if f.db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured; inventory reports have nowhere to go"})
		return
	}
	if rt.Handler != nil {
		rt.Handler(w, r, &RouteEnv{f: f, Instance: inst, Route: rt})
		return
	}
	push := inst.Source.(PushSource)
	principal, err := push.Authenticate(r, f.creds)
	if err != nil {
		var ae *AuthError
		if !errors.As(err, &ae) {
			ae = &AuthError{Status: http.StatusUnauthorized, Reason: audit.DenialTokenInvalid, Message: err.Error()}
		}
		f.logger.Warn("inventory push refused", "instance", inst.Name, "path", r.URL.Path, "reason", ae.Reason, "error", ae.Message)
		if f.OnRefusal != nil {
			f.OnRefusal(r, ae.Reason, map[string]string{"instance": inst.Name})
		}
		writeJSON(w, ae.Status, map[string]string{"error": ae.Message})
		return
	}
	// An empty ExternalID is a source whose documents name their own hosts;
	// Ingest refuses any report that then names none.

	doc, ok := readCapped(w, r, rt.MaxBody)
	if !ok {
		return
	}
	batch, err := inst.Source.Normalize(doc, principal.ExternalID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	res, err := f.Ingest(r.Context(), inst, principal, batch)
	if err != nil {
		f.writeIngestError(w, inst, err)
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (f *Frame) writeIngestError(w http.ResponseWriter, inst *Instance, err error) {
	var bad *ContractError
	if errors.As(err, &bad) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	f.logger.Error("inventory ingest failed", "instance", inst.Name, "error", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

// readCapped reads a request body under limit, answering 413 itself for a
// larger one whether or not the request declared its length. Zero is no cap.
func readCapped(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if limit > 0 && r.ContentLength > limit {
		writeTooLarge(w, limit)
		return nil, false
	}
	body := r.Body
	if limit > 0 {
		body = http.MaxBytesReader(w, r.Body, limit)
	}
	doc, err := io.ReadAll(body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeTooLarge(w, limit)
			return nil, false
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
		return nil, false
	}
	return doc, true
}

// RouteEnv is what the frame lends a Route.Handler: the instance it serves,
// the store, and the frame's own body cap, ingest and refusal paths, so a
// source answering its own protocol still stores and audits like every other.
type RouteEnv struct {
	f        *Frame
	Instance *Instance
	Route    Route
}

// DB is the report store, which also holds whatever credentials a source
// keeps for its hosts.
func (e *RouteEnv) DB() *audit.DB { return e.f.db }

// Logger is the frame's logger.
func (e *RouteEnv) Logger() *slog.Logger { return e.f.logger }

// Now is the frame's clock.
func (e *RouteEnv) Now() time.Time { return e.f.now() }

// ReadBody reads the request body under the route's MaxBody. On false it has
// already answered the request.
func (e *RouteEnv) ReadBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	return readCapped(w, r, e.Route.MaxBody)
}

// Ingest stores a batch the way a frame-served route would.
func (e *RouteEnv) Ingest(ctx context.Context, p Principal, b Batch) (IngestResult, error) {
	return e.f.Ingest(ctx, e.Instance, p, b)
}

// WriteIngestError answers a failed Ingest: 400 for a batch the source
// should not have produced, 500 for anything else.
func (e *RouteEnv) WriteIngestError(w http.ResponseWriter, err error) {
	e.f.writeIngestError(w, e.Instance, err)
}

// Refuse records a refused request in the audit table under reason. details
// may say which check failed even where the response must not.
func (e *RouteEnv) Refuse(r *http.Request, reason string, details map[string]string) {
	if details == nil {
		details = map[string]string{}
	}
	details["instance"] = e.Instance.Name
	if e.f.OnRefusal != nil {
		e.f.OnRefusal(r, reason, details)
	}
}

// HashSecret hashes a secret the way bodega stores its tokens. It fails when
// the server holds no pepper to key the hash on.
func (e *RouteEnv) HashSecret(secret string) (string, error) {
	if e.f.HashSecret == nil {
		return "", errors.New("no pepper is loaded to verify secrets against")
	}
	return e.f.HashSecret(secret)
}

func writeTooLarge(w http.ResponseWriter, limit int64) {
	writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
		"error": fmt.Sprintf("report body exceeds this source's %d-byte cap (max_body_bytes)", limit),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// IngestResult is what a push route answers with.
type IngestResult struct {
	Instance string `json:"instance"`
	Reports  int    `json:"reports"`
	Attempts int    `json:"attempts"`
	// Unbound counts reports stored without an identity because nothing
	// maps their external id yet.
	Unbound int `json:"unbound"`
}

// ContractError is a batch a source should never have produced: evidence of
// a capability it does not declare, or a component outside the common
// model. It is the source's defect, and nothing from the batch is stored.
type ContractError struct{ msg string }

func (e *ContractError) Error() string { return e.msg }

func contractErr(format string, args ...any) error {
	return &ContractError{msg: fmt.Sprintf(format, args...)}
}

// Ingest stores one batch from inst. Identity on every row comes from the
// host mapping and nothing else: whatever a normalizer put there is
// discarded. A report from an unmapped external id is stored unbound.
func (f *Frame) Ingest(ctx context.Context, inst *Instance, p Principal, b Batch) (IngestResult, error) {
	res := IngestResult{Instance: inst.Name}
	if err := checkBatch(inst, b); err != nil {
		return res, err
	}
	if p.Identity != "" && p.ExternalID != "" {
		f.bindOnOwnAuthority(ctx, inst, p)
	}
	now := f.now().UTC()
	identities := map[string]string{}
	identityOf := func(ext string) (string, error) {
		if id, ok := identities[ext]; ok {
			return id, nil
		}
		id, err := f.db.InventoryHostIdentity(ctx, inst.Name, ext)
		if err != nil {
			return "", err
		}
		identities[ext] = id
		return id, nil
	}
	for _, r := range b.Reports {
		ext := firstNonEmpty(r.ExternalID, p.ExternalID)
		if ext == "" {
			return res, contractErr("source %s produced a report naming no host", inst.Name)
		}
		id, err := identityOf(ext)
		if err != nil {
			return res, err
		}
		row := audit.InventoryReport{
			Source: inst.Name, ExternalID: ext, Identity: id,
			ObservedAt: orNow(r.ObservedAt, now), ReceivedAt: now,
			Components: make([]audit.InventoryComponent, len(r.Components)),
		}
		for i, c := range r.Components {
			row.Components[i] = audit.InventoryComponent(c)
		}
		if _, err := f.db.AppendInventoryReport(ctx, row); err != nil {
			return res, err
		}
		res.Reports++
		if id == "" {
			res.Unbound++
		}
	}
	attempts := make([]audit.InventoryAttempt, 0, len(b.Attempts))
	for _, a := range b.Attempts {
		ext := firstNonEmpty(a.ExternalID, p.ExternalID)
		if ext == "" {
			return res, contractErr("source %s produced an attempt naming no host", inst.Name)
		}
		id, err := identityOf(ext)
		if err != nil {
			return res, err
		}
		attempts = append(attempts, audit.InventoryAttempt{
			Source: inst.Name, ExternalID: ext, Identity: id,
			ObservedAt: orNow(a.ObservedAt, now), ReceivedAt: now,
			Destination: a.Destination, Ecosystem: a.Ecosystem, Detail: a.Detail,
		})
	}
	if err := f.db.AppendInventoryAttempts(ctx, attempts); err != nil {
		return res, err
	}
	res.Attempts = len(attempts)
	return res, nil
}

// bindOnOwnAuthority writes the mapping a source vouched for. A table that
// already maps the id elsewhere wins: an operator's unbind is the only way
// to move a host, and the conflict is logged rather than resolved here.
func (f *Frame) bindOnOwnAuthority(ctx context.Context, inst *Instance, p Principal) {
	f.mapMu.Lock()
	defer f.mapMu.Unlock()
	_, err := f.db.BindInventoryHost(ctx, inst.Name, p.ExternalID, p.Identity)
	var conflict *audit.InventoryHostConflict
	switch {
	case errors.As(err, &conflict):
		f.logger.Warn("inventory source vouched for a host the mapping binds elsewhere; keeping the mapping",
			"instance", inst.Name, "external_id", p.ExternalID,
			"mapped", conflict.Existing.Identity, "vouched", p.Identity)
	case err != nil:
		f.logger.Error("inventory host mapping write failed", "instance", inst.Name, "external_id", p.ExternalID, "error", err)
	}
}

func checkBatch(inst *Instance, b Batch) error {
	if len(b.Reports) > 0 && !HasCapability(inst.Source, CapInventory) {
		return contractErr("source %s produced reports without declaring the %s capability", inst.Name, CapInventory)
	}
	if len(b.Attempts) > 0 && !HasCapability(inst.Source, CapAttempts) {
		return contractErr("source %s produced attempts without declaring the %s capability", inst.Name, CapAttempts)
	}
	for _, r := range b.Reports {
		for _, c := range r.Components {
			if c.Name == "" {
				return contractErr("source %s produced a component with no name", inst.Name)
			}
			if !ValidEcosystem(c.Ecosystem) {
				return contractErr("source %s produced component %s in unknown ecosystem %q", inst.Name, c.Name, c.Ecosystem)
			}
		}
	}
	for _, a := range b.Attempts {
		if a.Destination == "" {
			return contractErr("source %s produced an attempt with no destination", inst.Name)
		}
		if a.Ecosystem != "" && !ValidEcosystem(a.Ecosystem) {
			return contractErr("source %s produced an attempt in unknown ecosystem %q", inst.Name, a.Ecosystem)
		}
	}
	return nil
}

// Run starts every enabled pull instance's poll loop and the retention
// sweep, and returns once ctx is done and they have stopped.
func (f *Frame) Run(ctx context.Context) {
	if f == nil || f.db == nil {
		return
	}
	var wg sync.WaitGroup
	for _, inst := range f.instances {
		if !inst.Enabled || inst.Source.Mode() != ModePull {
			continue
		}
		wg.Add(1)
		go func(inst *Instance) {
			defer wg.Done()
			f.pollLoop(ctx, inst)
		}(inst)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.retentionLoop(ctx)
	}()
	wg.Wait()
}

// pollLoop polls one instance every Interval after a jittered start, so a
// restart does not send every instance to its vendor in the same second. A
// failed poll is logged and retried at the next interval, never sooner.
func (f *Frame) pollLoop(ctx context.Context, inst *Instance) {
	timer := time.NewTimer(f.jitter(inst.Interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		_ = f.PollOnce(ctx, inst)
		timer.Reset(inst.Interval)
	}
}

// PollOnce runs one poll of a pull instance, stores what it returns, and
// records the outcome for the staleness check.
func (f *Frame) PollOnce(ctx context.Context, inst *Instance) error {
	pull, ok := inst.Source.(PullSource)
	if !ok {
		return fmt.Errorf("inventory source %s does not poll", inst.Name)
	}
	err := f.poll(ctx, inst, pull)
	if err != nil {
		f.logger.Error("inventory poll failed; retrying at the next interval",
			"instance", inst.Name, "type", inst.Source.Type(), "interval", inst.Interval, "error", err)
	}
	if rerr := f.db.RecordInventoryPoll(ctx, inst.Name, f.now(), err); rerr != nil {
		f.logger.Error("could not record inventory poll", "instance", inst.Name, "error", rerr)
	}
	return err
}

func (f *Frame) poll(ctx context.Context, inst *Instance, pull PullSource) error {
	docs, err := pull.Poll(ctx)
	if err != nil {
		return err
	}
	for _, d := range docs {
		batch, err := pull.Normalize(d.Body, d.ExternalID)
		if err != nil {
			return fmt.Errorf("normalize: %w", err)
		}
		if _, err := f.Ingest(ctx, inst, Principal{ExternalID: d.ExternalID}, batch); err != nil {
			return err
		}
	}
	return nil
}

func (f *Frame) retentionLoop(ctx context.Context) {
	ticker := time.NewTicker(retentionSweep)
	defer ticker.Stop()
	for {
		f.Prune(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Prune deletes rows past each instance's retention. An instance with no
// retention keeps everything, which is the default.
func (f *Frame) Prune(ctx context.Context) {
	for _, inst := range f.instances {
		if inst.Retention <= 0 {
			continue
		}
		n, err := f.db.PruneInventory(ctx, inst.Name, f.now().Add(-inst.Retention))
		if err != nil {
			f.logger.Error("inventory retention sweep failed", "instance", inst.Name, "error", err)
			continue
		}
		if n > 0 {
			f.logger.Info("inventory retention removed rows", "instance", inst.Name, "rows", n, "retention", inst.Retention)
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orNow(t, now time.Time) time.Time {
	if t.IsZero() {
		return now
	}
	return t
}
