package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- dnf repositories under a profile --------------------------------------
//
// A host whose profile governs rpm is served a repomd.xml of its own: primary,
// filelists and other point at copies holding only the packages the profile
// admits, and every other entry (updateinfo, group, modules, the *_db
// variants) is the upstream's, unchanged. bodega signs that document as it
// signs the unfiltered one, so the client's repo_gpgcheck covers the filter.
//
// The filtered files are built once per profile and upstream metadata, stored
// under their own checksum beside the upstream's files, and reached only
// through the repomd.xml of the profile that built them: a metadata request
// from a governed host is matched against its profile's repomd.xml, never the
// upstream's, so neither the unfiltered primary nor another profile's copy is
// listed for it. The filter is a listing control; the package route's
// entitleGate is what refuses a package by name, whatever href asks for it.

// rpmFilteredTypes are the repomd.xml entries a profile rewrites: the three
// that list packages. Their *_zck variants are left as the upstream's, and a
// dnf with zchunk on, its default, reads those instead where they exist.
var rpmFilteredTypes = []string{"primary", "filelists", "other"}

// rpmProfileBuildsKept is how many builds a profile keeps per repository tree.
// Two covers a host still holding the revision before the newest, which
// rpmServedRepomds lets it do for up to rpmRolloverGrace.
const rpmProfileBuildsKept = 2

// rpmFilters reports whether p rewrites rpm metadata at all.
func rpmFilters(p *entitle.Profile) bool { return p.Governs(manifest.TypeRpm) }

// rpmViewID is the key rpmServed holds a host's repomd.xml under. A governed
// host's view is its profile's as it stands now, so a filtered document and
// the upstream's are never two revisions of one tree, and neither are two
// versions of one profile. The fingerprint is what keeps a profile edit out
// of rpmServed's rollover grace: that grace lets a key keep the revision it
// holds while the upstream moves, and applied to an edit it would keep
// serving a listing the profile no longer grants.
func rpmViewID(t rpmTree, p *entitle.Profile) string {
	if !rpmFilters(p) {
		return t.id()
	}
	return rpmProfileView(t, p) + p.Fingerprint(manifest.TypeRpm)
}

// rpmProfileView is the part of rpmViewID every version of p shares.
func rpmProfileView(t rpmTree, p *entitle.Profile) string {
	return t.id() + "\x00profile\x00" + p.Name() + "\x00"
}

// rpmFilteredFile is one filtered metadata file as its repomd.xml entry
// describes it.
type rpmFilteredFile struct {
	typ, href      string
	sum, openSum   string
	size, openSize int64
	timestamp      int64
}

// rpmProfileBuild is one profile's filtered files over one set of upstream
// files, identified by the profile's fingerprint and the upstream checksums.
type rpmProfileBuild struct {
	key, fingerprint string
	files            map[string]rpmFilteredFile
	kept             int
}

// rpmProfileBuilds holds each profile view's recent builds and the builds
// running for it. built counts the builds made, which is what a test reads to
// show a second host on a profile reused the first host's.
type rpmProfileBuilds struct {
	mu    sync.Mutex
	views map[string]*rpmProfileSlot
	built int
	// timeout bounds one build, rpmProfileBuildTimeout when zero. wait is how
	// long a request waits on a running build before answering without it,
	// rpmProfileBuildWait when zero. coldWait replaces wait, and the budget,
	// for a request no previous build can stand in for; rpmProfileColdWait
	// when zero.
	timeout, wait, coldWait time.Duration
	// running counts the build goroutines alive, so a test can let them end
	// before its store goes away.
	running sync.WaitGroup
	// ctx is the server's, which a build a profile change starts runs under.
	ctx context.Context
	// trees is every (profile, tree) a governed host asked for since the
	// server started, oldest first, at most rpmProfileTreesRemembered.
	trees []rpmRequestedTree
}

// rpmRequestedTree is one tree a host on profile asked for.
type rpmRequestedTree struct {
	profile string
	tree    rpmTree
}

// rpmProfileTreesRemembered bounds the trees a profile change rebuilds
// ahead of any request. A fleet of EL9 hosts on BaseOS, AppStream, CRB and
// EPEL across two architectures and two releases is 16 trees per profile, so
// this covers 16 such profiles; past it the tree asked for longest ago is
// forgotten, and its next request builds it.
const rpmProfileTreesRemembered = 256

var rpmProfileColdWait = func() time.Duration {
	d, _ := time.ParseDuration(config.DefaultRpmProfileColdWait)
	return d
}()

// Build causes, as a build's start and end records name them.
const (
	rpmBuildByRequest       = "request"
	rpmBuildByProfileChange = "profile change"
)

// rpmProfileBuildWait is how long a request waits on a build before it is
// answered from the previous build or with a 503. A build that small
// repositories finish inside it is answered in one request; rpmProfileBudget
// shortens it for a request that spent part of its budget elsewhere.
const rpmProfileBuildWait = 3 * time.Second

// rpmProfileBudget is how long a governed host's metadata request may wait,
// on the upstream repomd.xml's refresh, a running build and the store
// together, before bodega answers it without what it was waiting for. It sits
// a second under the 5 seconds a client is promised, and far under dnf's
// 30-second low-speed cutoff, so the answer is written inside both.
const rpmProfileBudget = 4 * time.Second

// rpmProfileFallbackReserve is the part of the budget a wait on a build
// leaves for checking that the previous build is still stored.
const rpmProfileFallbackReserve = 500 * time.Millisecond

// rpmProfileRetryAfter is the Retry-After a 503 for a running build carries.
const rpmProfileRetryAfter = "10"

var rpmProfileBuildTimeout = func() time.Duration {
	d, _ := time.ParseDuration(config.DefaultRpmProfileBuildTimeout)
	return d
}()

type rpmProfileSlot struct {
	mu      sync.Mutex
	recent  []*rpmProfileBuild
	running map[string]*rpmProfileJob
	// gen counts the builds published to recent. A request checks the store
	// with the lock released, and registers a build only while the
	// generation it checked against still stands: a build that finished in
	// between is checked first, or the same key is built twice.
	gen uint64
}

// rpmProfileJob is one build in progress. b and err are set before done is
// closed and never written after.
type rpmProfileJob struct {
	done    chan struct{}
	started time.Time
	b       *rpmProfileBuild
	err     error
}

// errRpmProfileBuilding is a request that found its view's build running past
// its wait with no previous build it could serve.
var errRpmProfileBuilding = errors.New("the profile's filtered metadata is still being built")

// errRpmProfileSlow is a request whose budget ran out on the upstream
// repomd.xml or the store before it had what it needed to answer.
var errRpmProfileSlow = errors.New("the upstream repomd.xml or the store did not answer within the request's budget")

// rpmProfileBuildError is a build that failed. The build logged it, so the
// requests waiting on it answer without logging it again.
type rpmProfileBuildError struct {
	file string
	err  error
}

func (e *rpmProfileBuildError) Error() string {
	return fmt.Sprintf("building the filtered %s: %v", e.file, e.err)
}

func (e *rpmProfileBuildError) Unwrap() error { return e.err }

type rpmBudgetKey struct{}

// rpmBudget is one governed request's time to answer. It runs rpmProfileBudget
// from start until the request meets a build no previous build can stand in
// for; from then on it runs to the cold wait's end and the fallback reserve
// after it, so the store reads that follow the build are not refused for
// having outlived the 4 seconds a warm request gets.
type rpmBudget struct {
	start time.Time
	mu    sync.Mutex
	cold  time.Time
}

func (b *rpmBudget) end() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.cold.IsZero() {
		return b.cold.Add(rpmProfileFallbackReserve)
	}
	return b.start.Add(rpmProfileBudget)
}

// goCold moves the budget to the cold wait that ends at coldEnd and returns
// that end.
func (b *rpmBudget) goCold(coldEnd time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cold.IsZero() {
		b.cold = coldEnd
	}
	return b.cold
}

// withRpmBudget starts r's budget, unless the request r was read for already
// started one.
func withRpmBudget(r *http.Request) *http.Request {
	if _, ok := r.Context().Value(rpmBudgetKey{}).(*rpmBudget); ok {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), rpmBudgetKey{}, &rpmBudget{start: time.Now()}))
}

func rpmBudgetOf(r *http.Request) *rpmBudget {
	if b, ok := r.Context().Value(rpmBudgetKey{}).(*rpmBudget); ok && b != nil {
		return b
	}
	return &rpmBudget{start: time.Now()}
}

// rpmBudgetEnd is when r's budget runs out.
func rpmBudgetEnd(r *http.Request) time.Time { return rpmBudgetOf(r).end() }

// rpmColdEnd moves r's budget to the cold wait and is when that wait ends.
func (c *rpmProfileBuilds) rpmColdEnd(r *http.Request) time.Time {
	b := rpmBudgetOf(r)
	return b.goCold(c.coldEnd(b.start))
}

// rpmBounded runs f and waits for it until end; ok is false when f had not
// returned by then. f is left to finish on its own rather than canceled,
// because a storage backend may ignore its context, so f must write nothing
// the caller reads after giving up on it.
func rpmBounded[T any](end time.Time, f func() T) (v T, ok bool) {
	ch := make(chan T, 1)
	go func() { ch <- f() }()
	timer := time.NewTimer(time.Until(end))
	defer timer.Stop()
	select {
	case v = <-ch:
		return v, true
	case <-timer.C:
		return v, false
	}
}

func (c *rpmProfileBuilds) slot(view string) *rpmProfileSlot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.views == nil {
		c.views = map[string]*rpmProfileSlot{}
	}
	sl := c.views[view]
	if sl == nil {
		sl = &rpmProfileSlot{running: map[string]*rpmProfileJob{}}
		c.views[view] = sl
	}
	return sl
}

// building reports whether a build is running for view.
func (c *rpmProfileBuilds) building(view string) bool {
	c.mu.Lock()
	sl := c.views[view]
	c.mu.Unlock()
	if sl == nil {
		return false
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return len(sl.running) > 0
}

// runningFor is how long the oldest build running for view has run, zero
// when none is.
func (c *rpmProfileBuilds) runningFor(view string) time.Duration {
	c.mu.Lock()
	sl := c.views[view]
	c.mu.Unlock()
	if sl == nil {
		return 0
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	var oldest time.Time
	for _, j := range sl.running {
		if oldest.IsZero() || j.started.Before(oldest) {
			oldest = j.started
		}
	}
	if oldest.IsZero() {
		return 0
	}
	return time.Since(oldest).Round(time.Millisecond)
}

// awaitView waits until no build runs for view or until passes.
func (c *rpmProfileBuilds) awaitView(ctx context.Context, view string, until time.Time) {
	c.mu.Lock()
	sl := c.views[view]
	c.mu.Unlock()
	if sl == nil {
		return
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	for {
		sl.mu.Lock()
		var job *rpmProfileJob
		for _, j := range sl.running {
			job = j
			break
		}
		sl.mu.Unlock()
		if job == nil {
			return
		}
		select {
		case <-job.done:
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		}
	}
}

// coldEnd is when a request whose budget started at start stops waiting on a
// build no previous build can stand in for. It counts from the budget's
// start, so the refresh of the upstream repomd.xml spends from it too and the
// whole request stays inside dnf's 30-second low-speed cutoff.
func (c *rpmProfileBuilds) coldEnd(start time.Time) time.Time {
	wait := c.coldWait
	if wait <= 0 {
		wait = rpmProfileColdWait
	}
	return start.Add(wait)
}

// remember records that a host bound to p asked for t, whether or not p
// filters rpm today: a profile that gains its first rpm rule rebuilds what its
// hosts already asked for. A host bound to no profile is not remembered.
func (c *rpmProfileBuilds) remember(p *entitle.Profile, t rpmTree) {
	if p == nil {
		return
	}
	profile := p.Name()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trees = slices.DeleteFunc(c.trees, func(rt rpmRequestedTree) bool {
		return rt.profile == profile && rt.tree.id() == t.id()
	})
	c.trees = append(c.trees, rpmRequestedTree{profile: profile, tree: t})
	if n := len(c.trees) - rpmProfileTreesRemembered; n > 0 {
		c.trees = slices.Delete(c.trees, 0, n)
	}
}

// treesFor is every tree a host on profile asked for that is still
// remembered.
func (c *rpmProfileBuilds) treesFor(profile string) []rpmTree {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []rpmTree
	for _, rt := range c.trees {
		if rt.profile == profile {
			out = append(out, rt.tree)
		}
	}
	return out
}

// setContext installs the server's context for the builds a profile change
// starts.
func (c *rpmProfileBuilds) setContext(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctx = ctx
}

func (c *rpmProfileBuilds) serverContext() context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

func (c *rpmProfileBuilds) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.built
}

// rpmProfileRepomd is the repomd.xml a host on p is served in place of doc.
// A doc naming no primary lists no package, so it is served as it came.
func (s *Server) rpmProfileRepomd(r *http.Request, t rpmTree, p *entitle.Profile, doc []byte) ([]byte, error) {
	data, err := parseRpmRepomd(doc)
	if err != nil {
		return nil, err
	}
	s.rpmProfileBuilds.remember(p, t)
	b, err := s.rpmProfileFiles(r, t, p, data)
	if err != nil || b == nil {
		return doc, err
	}
	return rpmRewriteRepomd(doc, b)
}

// rpmProfileFiles is p's build over the upstream files data names, made when
// no build for this fingerprint and these checksums is held or one of its
// files has gone from the store. It answers within r's budget: with the
// build, with the previous build when that one can stand in for it, or with
// errRpmProfileBuilding or errRpmProfileSlow.
func (s *Server) rpmProfileFiles(r *http.Request, t rpmTree, p *entitle.Profile, data []rpmRepomdData) (*rpmProfileBuild, error) {
	end := rpmBudgetEnd(r)
	entries, stamps, key := rpmProfileBuildKey(p, data)
	if _, ok := entries["primary"]; !ok {
		return nil, nil
	}
	if s.typeStore(manifest.TypeRpm) == nil {
		return nil, errors.New("no storage backend holds the rpm type, so a filtered metadata file has nowhere to live")
	}

	fingerprint := p.Fingerprint(manifest.TypeRpm)
	sl := s.rpmProfileBuilds.slot(rpmProfileView(t, p))
	var job *rpmProfileJob
	for job == nil {
		sl.mu.Lock()
		recent, gen := slices.Clone(sl.recent), sl.gen
		sl.mu.Unlock()
		for _, b := range recent {
			if b.key != key {
				continue
			}
			stored, ok := s.rpmProfileBuildStored(end, r, t, b)
			if !ok {
				return nil, errRpmProfileSlow
			}
			if stored {
				return b, nil
			}
		}
		sl.mu.Lock()
		if job = sl.running[key]; job == nil && sl.gen == gen {
			job = s.startRpmProfileBuild(context.WithoutCancel(r.Context()), r, rpmBuildByRequest, sl, t, p, key, fingerprint, entries, stamps)
		}
		sl.mu.Unlock()
	}

	// A previous build under this fingerprint lists what the profile grants
	// today over an older upstream; one under another fingerprint would list
	// what an edited profile no longer grants, so it is never served. It
	// stands in only for a document naming the same filtered types it built:
	// rpmRewriteRepomd leaves an entry the build has no file for as the
	// upstream's, which would list the unfiltered file, and cannot add one
	// the document lacks.
	stands := func(b *rpmProfileBuild) bool { return b.fingerprint == fingerprint && b.coversTypes(entries) }
	// The warm wait is for a request that has an answer if the build is late:
	// a build that stands in and whose files are all still stored. A record
	// of one whose files are gone serves nothing, so it counts as none.
	servable := func() *rpmProfileBuild {
		sl.mu.Lock()
		recent := slices.Clone(sl.recent)
		sl.mu.Unlock()
		for _, b := range recent {
			if !stands(b) {
				continue
			}
			if stored, ok := s.rpmProfileBuildStored(rpmBudgetEnd(r), r, t, b); ok && stored {
				return b
			}
		}
		return nil
	}
	var waitEnd time.Time
	if servable() != nil {
		wait := s.rpmProfileBuilds.wait
		if wait <= 0 {
			wait = rpmProfileBuildWait
		}
		waitEnd = time.Now().Add(wait)
		if last := end.Add(-rpmProfileFallbackReserve); last.Before(waitEnd) {
			waitEnd = last
		}
	} else {
		// Nothing can answer in the build's place, and dnf does not honor
		// Retry-After on repomd.xml: a 503 here fails the client's install
		// outright, so the request holds on for as long as dnf will, and
		// what it reads after the build gets the rest of that time.
		waitEnd = s.rpmProfileBuilds.rpmColdEnd(r)
	}
	timer := time.NewTimer(time.Until(waitEnd))
	defer timer.Stop()
	select {
	case <-job.done:
		return job.b, job.err
	case <-r.Context().Done():
		return nil, r.Context().Err()
	case <-timer.C:
	}
	if b := servable(); b != nil {
		return b, nil
	}
	return nil, errRpmProfileBuilding
}

// rpmProfileBuildKey is the filtered entries of data, their timestamps, and
// the key a build of them for p is held under.
func rpmProfileBuildKey(p *entitle.Profile, data []rpmRepomdData) (entries map[string]rpmRepomdData, stamps map[string]int64, key string) {
	entries = map[string]rpmRepomdData{}
	for _, d := range data {
		for _, typ := range rpmFilteredTypes {
			if d.Type == typ {
				if _, dup := entries[typ]; !dup {
					entries[typ] = d
				}
			}
		}
	}
	stamps = map[string]int64{}
	var latest int64
	for _, d := range data {
		if ts, ok := rpmTimestamp(d); ok && ts > latest {
			latest = ts
		}
	}
	key = p.Fingerprint(manifest.TypeRpm)
	for _, typ := range rpmFilteredTypes {
		if e, ok := entries[typ]; ok {
			ts, ok := rpmTimestamp(e)
			if !ok {
				ts = latest
			}
			stamps[typ] = ts
			key += "\x00" + typ + "=" + e.Checksum.Value + "@" + strconv.FormatInt(ts, 10)
		}
	}
	return entries, stamps, key
}

// prebuildRpmProfiles starts a build for every remembered tree of each
// profile set holds whose rpm fingerprint old did not, so the first host to
// ask after an edit is not the one that waits on it. old is nil before the
// bindings were first read, when nothing is remembered yet.
func (s *Server) prebuildRpmProfiles(old, set *profileSet) {
	if set == nil || old == set {
		return
	}
	was := map[string]string{}
	if old != nil {
		for _, p := range old.byIdentity {
			if p != nil {
				was[p.Name()] = p.Fingerprint(manifest.TypeRpm)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range set.byIdentity {
		if p == nil || seen[p.Name()] || !rpmFilters(p) {
			continue
		}
		seen[p.Name()] = true
		if fp, ok := was[p.Name()]; ok && fp == p.Fingerprint(manifest.TypeRpm) {
			continue
		}
		for _, t := range s.rpmProfileBuilds.treesFor(p.Name()) {
			s.rpmProfileBuilds.running.Add(1)
			go func() {
				defer s.rpmProfileBuilds.running.Done()
				s.prebuildRpmProfile(p, t)
			}()
		}
	}
}

// prebuildRpmProfile starts p's build of t over the upstream repomd.xml as
// bodega reads it now, under the server's context, unless one for the same
// key is running or held.
func (s *Server) prebuildRpmProfile(p *entitle.Profile, t rpmTree) {
	ctx := s.rpmProfileBuilds.serverContext()
	if ctx.Err() != nil || s.typeStore(manifest.TypeRpm) == nil {
		return
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/rpm/"+t.id()+"/repodata/repomd.xml", nil)
	if err != nil {
		return
	}
	doc, err := s.rpmRead(r, t, "repomd.xml", func(w http.ResponseWriter, req *http.Request) { s.handleRpmRepomd(w, req, t) })
	if err == nil {
		var data []rpmRepomdData
		if data, err = parseRpmRepomd(doc); err == nil {
			s.startRpmProfilePrebuild(ctx, r, p, t, data)
			return
		}
	}
	s.logger.Warn("could not read the upstream repomd.xml to rebuild a changed profile's filtered rpm metadata; the next request for it builds it",
		"profile", p.Name(), "repository", t.id(), "error", err)
}

func (s *Server) startRpmProfilePrebuild(ctx context.Context, r *http.Request, p *entitle.Profile, t rpmTree, data []rpmRepomdData) {
	entries, stamps, key := rpmProfileBuildKey(p, data)
	if _, ok := entries["primary"]; !ok {
		return
	}
	sl := s.rpmProfileBuilds.slot(rpmProfileView(t, p))
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.running[key] != nil || slices.ContainsFunc(sl.recent, func(b *rpmProfileBuild) bool { return b.key == key }) {
		return
	}
	s.startRpmProfileBuild(ctx, r, rpmBuildByProfileChange, sl, t, p, key, p.Fingerprint(manifest.TypeRpm), entries, stamps)
}

// coversTypes reports whether b filtered exactly the types entries names.
func (b *rpmProfileBuild) coversTypes(entries map[string]rpmRepomdData) bool {
	if len(b.files) != len(entries) {
		return false
	}
	for typ := range entries {
		if _, ok := b.files[typ]; !ok {
			return false
		}
	}
	return true
}

// startRpmProfileBuild registers the build of key in sl and starts it under
// parent, bounded by the build timeout; cause is what started it, for its
// records. The caller holds sl.mu.
//
// A build a request starts belongs to no request: dnf gives up on a
// repomd.xml after 30 seconds without a byte, and a build of BaseOS's
// filelists can take longer, so under the request's context it would be
// canceled and started over by every retry. That caller passes the request's
// context without its cancellation, which keeps its values (who asked, for
// the upstream fetch's records).
func (s *Server) startRpmProfileBuild(parent context.Context, r *http.Request, cause string, sl *rpmProfileSlot, t rpmTree, p *entitle.Profile, key, fingerprint string, entries map[string]rpmRepomdData, stamps map[string]int64) *rpmProfileJob {
	job := &rpmProfileJob{done: make(chan struct{}), started: time.Now()}
	sl.running[key] = job
	timeout := s.rpmProfileBuilds.timeout
	if timeout <= 0 {
		timeout = rpmProfileBuildTimeout
	}
	s.logger.Info("rpm profile build started", "profile", p.Name(), "repository", t.id(), "cause", cause)
	ctx := context.WithValue(parent, rpmBudgetKey{}, nil)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	owner := &rpmBuildOwner{}
	br := r.Clone(withRpmBuildOwner(ctx, owner))
	// The job is retired by this goroutine alone, once, when the work returns
	// or the deadline passes, whichever is first. A store may ignore its
	// context, so a write or cached read can outlast the deadline; the work is
	// then abandoned with its result unread, and nothing it does afterwards
	// reaches recent, running or the log.
	s.rpmProfileBuilds.running.Add(1)
	go func() {
		defer s.rpmProfileBuilds.running.Done()
		defer cancel()
		type result struct {
			b   *rpmProfileBuild
			err error
		}
		var file atomic.Value
		file.Store("primary")
		results := make(chan result, 1)
		s.rpmProfileBuilds.running.Add(1)
		go func() {
			defer s.rpmProfileBuilds.running.Done()
			b, err := s.rpmBuildProfileFiles(br, t, p, key, fingerprint, entries, stamps, &file)
			results <- result{b, err}
		}()
		var res result
		select {
		case res = <-results:
			if res.err == nil && ctx.Err() != nil {
				res = result{err: ctx.Err()}
			}
		case <-ctx.Done():
			res.err = fmt.Errorf("not finished within the build timeout of %s, so the store or upstream operation it was in is abandoned: %w", timeout, ctx.Err())
		}
		took := time.Since(job.started).Round(time.Millisecond)
		if res.err != nil {
			// The lifecycle's end record is at info like its start, so an
			// operator reading the build lines sees every build end. Its
			// error says only how the build failed: the upstream's own text,
			// with a refusal's incident, stays in the one error record.
			summary := fmt.Sprintf("building the filtered %s failed; the error record beside this one names the cause", file.Load())
			if errors.Is(res.err, context.DeadlineExceeded) {
				summary = fmt.Sprintf("building the filtered %s ran past the build timeout of %s", file.Load(), timeout)
			}
			owner.retire(func() {
				s.logger.Info("rpm profile build ended", "profile", p.Name(), "repository", t.id(), "cause", cause,
					"duration", took, "outcome", "failed", "error", summary)
				s.logger.Error("rpm metadata could not be filtered for a profile",
					"profile", p.Name(), "repository", t.id(), "cause", cause, "duration", took, "outcome", "failed",
					"file", file.Load(), "error", res.err)
			})
			res = result{err: &rpmProfileBuildError{file: file.Load().(string), err: res.err}}
		} else {
			s.rpmProfileBuilds.mu.Lock()
			s.rpmProfileBuilds.built++
			s.rpmProfileBuilds.mu.Unlock()
			owner.retire(func() {
				s.logger.Info("rpm profile build ended", "profile", p.Name(), "repository", t.id(), "cause", cause,
					"duration", took, "outcome", "stored", "primary", entries["primary"].Checksum.Value, "kept", res.b.kept)
			})
		}
		sl.mu.Lock()
		if sl.running[key] == job {
			delete(sl.running, key)
		}
		if res.err == nil {
			kept := []*rpmProfileBuild{res.b}
			for _, old := range sl.recent {
				if old.key != key && len(kept) < rpmProfileBuildsKept {
					kept = append(kept, old)
				}
			}
			sl.recent = kept
			sl.gen++
		}
		job.b, job.err = res.b, res.err
		sl.mu.Unlock()
		close(job.done)
	}()
	return job
}

// rpmBuildProfileFiles reads, filters and stores the files entries names,
// under r's context, which is the build's own: no read or write is begun past
// its deadline. file is kept naming the file being built, for the record of a
// failure, which is the caller's to write.
func (s *Server) rpmBuildProfileFiles(r *http.Request, t rpmTree, p *entitle.Profile, key, fingerprint string, entries map[string]rpmRepomdData, stamps map[string]int64, file *atomic.Value) (b *rpmProfileBuild, err error) {
	ctx := r.Context()
	defer func() {
		// A request's handler has net/http's recover behind it; this
		// goroutine has none, and a panic in a filter would stop the server.
		if v := recover(); v != nil {
			b, err = nil, fmt.Errorf("panic: %v", v)
		}
	}()
	store := s.typeStore(manifest.TypeRpm)
	read := func(e rpmRepomdData) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !rpmMetadataHrefServed(e.Location.Href) {
			return nil, fmt.Errorf("repomd.xml places %s at %q, outside repodata/, which bodega does not serve", e.Type, e.Location.Href)
		}
		// Every route the read passes through hands its failures to the sink
		// instead of logging them, so the one record of a failure is this
		// build's, with the profile and file beside the cause.
		sink := &upstreamErrSink{owner: rpmBuildOwnerFrom(ctx)}
		raw, err := s.rpmRead(r.WithContext(withUpstreamErrSink(ctx, sink)), t, e.Type, func(w http.ResponseWriter, req *http.Request) { s.serveRpmMetadataEntry(w, req, t, e) })
		cause := sink.get()
		var cut *rpmReadCut
		switch {
		case errors.As(err, &cut) && cause != nil:
			// The cut body fails the read whatever else was sunk beside it,
			// such as a failed cache write, so both are kept.
			return nil, fmt.Errorf("reading %s %s: %w", e.Type, e.Location.Href, rpmReadFailures{cause, err})
		case err != nil && cause != nil:
			return nil, fmt.Errorf("reading %s %s: %w", e.Type, e.Location.Href, cause)
		case cause != nil:
			// The read succeeded around a failure, such as a cache write the
			// proxy treats as best effort; still worth a record, and still
			// the build's to write.
			sink.owner.emit(func() {
				s.logger.Warn("an rpm metadata read for a profile's build succeeded around a failure",
					"profile", p.Name(), "repository", t.id(), "file", e.Type, "error", cause)
			})
		}
		return raw, err
	}
	primary := entries["primary"]
	raw, err := read(primary)
	if err != nil {
		return nil, err
	}
	ext := path.Ext(primary.Location.Href)
	kept, n, err := rpmAdmittedPkgids(ctx, raw, ext, p)
	if err != nil {
		return nil, fmt.Errorf("primary %s of %s: %w", primary.Location.Href, t.id(), err)
	}
	b = &rpmProfileBuild{key: key, fingerprint: fingerprint, files: map[string]rpmFilteredFile{}, kept: len(kept)}
	for _, typ := range rpmFilteredTypes {
		e, ok := entries[typ]
		if !ok {
			continue
		}
		file.Store(typ)
		if typ != "primary" {
			if raw, err = read(e); err != nil {
				return nil, err
			}
			ext = path.Ext(e.Location.Href)
		}
		body, open, err := rpmFilterPackages(ctx, raw, ext, n, kept, typ == "primary")
		if err != nil {
			return nil, fmt.Errorf("filter %s %s of %s: %w", typ, e.Location.Href, t.id(), err)
		}
		sum := rpmSHA256Hex(body)
		f := rpmFilteredFile{typ: typ, sum: sum, openSum: open.sum, size: int64(len(body)), openSize: open.size, timestamp: stamps[typ],
			href: "repodata/" + sum + "-" + typ + ".xml.gz"}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := store.Put(ctx, rpmFilteredKey(t, f), body); err != nil {
			return nil, fmt.Errorf("store the filtered %s of %s: %w", typ, t.id(), err)
		}
		b.files[typ] = f
	}
	return b, nil
}

// upstreamErrSink collects the failures one read meets, in place of the log
// records the routes it passes through would write, for a read whose owner
// logs its outcome with what the read was for. A route either hands its error
// to the sink directly (sinkUpstreamErr, which keeps the error's type) or logs
// through logFor, which turns a warning or worse into a sunk failure.
type upstreamErrSink struct {
	mu    sync.Mutex
	errs  []error
	owner *rpmBuildOwner
}

type upstreamErrSinkKey struct{}

func withUpstreamErrSink(ctx context.Context, sink *upstreamErrSink) context.Context {
	return context.WithValue(ctx, upstreamErrSinkKey{}, sink)
}

func upstreamErrSinkFrom(ctx context.Context) *upstreamErrSink {
	sink, _ := ctx.Value(upstreamErrSinkKey{}).(*upstreamErrSink)
	return sink
}

// sinkUpstreamErr hands err to ctx's sink and reports whether there was one;
// when there was not, the caller logs err itself.
func sinkUpstreamErr(ctx context.Context, err error) bool {
	sink := upstreamErrSinkFrom(ctx)
	if sink == nil {
		return false
	}
	sink.set(err)
	return true
}

func (k *upstreamErrSink) set(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.errs = append(k.errs, err)
}

// get is every failure set, in the order met, or nil when there was none.
func (k *upstreamErrSink) get() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch len(k.errs) {
	case 0:
		return nil
	case 1:
		return k.errs[0]
	}
	return rpmReadFailures(slices.Clone(k.errs))
}

// rpmReadFailures is more than one failure met by one read, such as a store
// read that failed before the upstream fetch that replaced it failed too.
type rpmReadFailures []error

func (e rpmReadFailures) Error() string {
	parts := make([]string, len(e))
	for i, err := range e {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; then ")
}

func (e rpmReadFailures) Unwrap() []error { return e }

// logFor is the logger for work done under ctx. Outside a sinked read it is
// s.logger. Inside one, a record at warning or above is a failure of the read
// and goes to the sink instead of the log, and the rest reach the log only
// while the read's owner still holds it. Every route a build-owned read can
// pass through logs through this, so that a failure has one record, the
// owner's, however deep in the proxy it happened, and none once the build
// that started the read has been retired.
func (s *Server) logFor(ctx context.Context) *slog.Logger {
	sink := upstreamErrSinkFrom(ctx)
	if sink == nil {
		return s.logger
	}
	return slog.New(&sinkHandler{next: s.logger.Handler(), sink: sink})
}

// noteFor is logFor for a warning that records a decision rather than a
// failure, such as a fill admitted with a policy warning: it reaches the log
// at its own level while the read's owner holds it, and is never sunk.
func (s *Server) noteFor(ctx context.Context) *slog.Logger {
	sink := upstreamErrSinkFrom(ctx)
	if sink == nil {
		return s.logger
	}
	return slog.New(&sinkHandler{next: s.logger.Handler(), sink: sink, notes: true})
}

// sinkHandler is logFor's and noteFor's handler inside a sinked read.
type sinkHandler struct {
	next  slog.Handler
	sink  *upstreamErrSink
	attrs []slog.Attr
	notes bool
}

func (h *sinkHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return (!h.notes && l >= slog.LevelWarn) || h.next.Enabled(ctx, l)
}

func (h *sinkHandler) Handle(ctx context.Context, rec slog.Record) error {
	if !h.notes && rec.Level >= slog.LevelWarn {
		h.sink.set(newLoggedFailure(rec, h.attrs))
		return nil
	}
	var err error
	h.sink.owner.emit(func() { err = h.next.Handle(ctx, rec) })
	return err
}

func (h *sinkHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &sinkHandler{next: h.next.WithAttrs(as), sink: h.sink, attrs: append(slices.Clone(h.attrs), as...), notes: h.notes}
}

func (h *sinkHandler) WithGroup(name string) slog.Handler {
	return &sinkHandler{next: h.next.WithGroup(name), sink: h.sink, attrs: h.attrs, notes: h.notes}
}

// loggedFailure is a record a route would have logged, carried as an error:
// its message and attributes, unwrapping to the error attribute it named.
type loggedFailure struct {
	text string
	err  error
}

func newLoggedFailure(rec slog.Record, attrs []slog.Attr) *loggedFailure {
	var b strings.Builder
	f := &loggedFailure{}
	b.WriteString(rec.Message)
	add := func(a slog.Attr) bool {
		if err, ok := a.Value.Any().(error); ok && f.err == nil {
			f.err = err
		}
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	}
	for _, a := range attrs {
		add(a)
	}
	rec.Attrs(add)
	f.text = b.String()
	return f
}

func (f *loggedFailure) Error() string { return f.text }

func (f *loggedFailure) Unwrap() error { return f.err }

// rpmBuildOwner is a build's claim on the log. The build's supervisor retires
// it once, writing the build's one outcome record as it does; anything the
// build's work would log afterwards, having outlived the deadline, is dropped.
// A nil owner holds the log forever, for a sinked read no build owns.
type rpmBuildOwner struct {
	mu      sync.Mutex
	retired bool
}

type rpmBuildOwnerKey struct{}

func withRpmBuildOwner(ctx context.Context, o *rpmBuildOwner) context.Context {
	return context.WithValue(ctx, rpmBuildOwnerKey{}, o)
}

func rpmBuildOwnerFrom(ctx context.Context) *rpmBuildOwner {
	o, _ := ctx.Value(rpmBuildOwnerKey{}).(*rpmBuildOwner)
	return o
}

// emit runs log unless o is retired. The lock is held across it, so a record
// is either written before retire's or not at all.
func (o *rpmBuildOwner) emit(log func()) {
	if o == nil {
		log()
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.retired {
		log()
	}
}

// retire writes the build's outcome with log and ends the build's claim.
func (o *rpmBuildOwner) retire(log func()) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.retired = true
	log()
}

// rpmTimestamp is the timestamp an upstream entry gives its file. A filtered
// file carries its upstream file's, never the time it was built, because the
// filtered repomd.xml has to come out byte for byte the same wherever it is
// rebuilt: a .asc request reaching a restarted process, or another instance
// on the same store, signs a reconstruction, and a build-time timestamp makes
// that signature fail against the document the client already holds. An
// entry with none takes the newest any entry gives.
func rpmTimestamp(d rpmRepomdData) (int64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(d.Timestamp), 64)
	if err != nil || f <= 0 {
		return 0, false
	}
	return int64(f), true
}

// rpmProfileBuildStored reports whether every file of b is still in the
// store; ok is false when the store had not answered by end.
func (s *Server) rpmProfileBuildStored(end time.Time, r *http.Request, t rpmTree, b *rpmProfileBuild) (stored, ok bool) {
	store := s.typeStore(manifest.TypeRpm)
	ctx := r.Context()
	return rpmBounded(end, func() bool {
		for _, f := range b.files {
			if info, err := store.Head(ctx, rpmFilteredKey(t, f)); err != nil || info == nil || !info.Exists {
				return false
			}
		}
		return true
	})
}

func rpmFilteredKey(t rpmTree, f rpmFilteredFile) string {
	return manifest.RpmMetadataKey(t.repo, t.releasever, t.basearch, f.sum, path.Base(f.href))
}

func rpmMetadataHrefServed(href string) bool {
	rest, ok := strings.CutPrefix(href, "repodata/")
	return ok && rest != "" && !strings.Contains(rest, "/")
}

func rpmSHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// handleRpmProfileMetadata serves a metadata file to a host on p, matched
// against the repomd.xml p serves it: the one it holds, or the one the
// current upstream document filters to. A filtered entry is read from the
// store under its own checksum; any other entry is the upstream's file.
func (s *Server) handleRpmProfileMetadata(w http.ResponseWriter, r *http.Request, t rpmTree, p *entitle.Profile, href string) {
	r = withRpmBudget(r)
	end := rpmBudgetEnd(r)
	type read struct {
		b   []byte
		err error
	}
	match := func(d rpmRepomdData) bool { return d.Location.Href == href }
	entry, err := s.rpmHeldEntry(r, t, match)
	if err != nil {
		var doc []byte
		got, ok := rpmBounded(end, func() read {
			d, err := s.rpmRead(r, t, "repomd.xml", func(w http.ResponseWriter, req *http.Request) { s.handleRpmRepomd(w, req, t) })
			return read{d, err}
		})
		doc, err = got.b, got.err
		if !ok {
			err = errRpmProfileSlow
		}
		if err == nil {
			doc, err = s.rpmProfileRepomd(r, t, p, doc)
		}
		if err == nil {
			entry, err = rpmEntryIn(doc, match)
		}
	}
	if err != nil {
		var failed *rpmProfileBuildError
		switch {
		case errors.Is(err, errRpmNotListed):
			http.Error(w, fmt.Sprintf("the repomd.xml profile %q is served for %s names no %s.", p.Name(), t.id(), href), http.StatusNotFound)
		case errors.Is(err, errRpmProfileBuilding), errors.Is(err, errRpmProfileSlow), errors.As(err, &failed):
			s.writeRpmProfileError(w, t, p, err)
		default:
			s.writeRpmReadError(w, r, t, "repomd.xml", err)
		}
		return
	}
	if !rpmFilteredType(entry.Type) {
		s.serveRpmMetadataEntry(w, r, t, entry)
		return
	}
	key := manifest.RpmMetadataKey(t.repo, t.releasever, t.basearch, entry.Checksum.Value, path.Base(entry.Location.Href))
	store := s.typeStore(manifest.TypeRpm)
	got, ok := rpmBounded(rpmBudgetEnd(r), func() read {
		b, err := store.Get(r.Context(), key)
		return read{b, err}
	})
	if !ok {
		s.writeRpmProfileError(w, t, p, errRpmProfileSlow)
		return
	}
	body, err := got.b, got.err
	if err != nil || len(body) == 0 {
		// A rebuild of the same upstream files writes this file back under
		// the same name, so the request waits on it as on a cold build; one
		// told the file is gone would fetch repomd.xml again and meet the
		// same build.
		view := rpmProfileView(t, p)
		if s.rpmProfileBuilds.building(view) {
			s.rpmProfileBuilds.awaitView(r.Context(), view, s.rpmProfileBuilds.rpmColdEnd(r))
			got, ok := rpmBounded(rpmBudgetEnd(r), func() read {
				b, err := store.Get(r.Context(), key)
				return read{b, err}
			})
			if !ok || got.err != nil || len(got.b) == 0 {
				s.writeRpmProfileError(w, t, p, errRpmProfileBuilding)
				return
			}
			body = got.b
		}
	}
	if len(body) == 0 {
		s.logger.Warn("a filtered rpm metadata file the profile's repomd.xml names is not in the store", "profile", p.Name(), "repository", t.id(), "key", key, "error", err)
		http.Error(w, fmt.Sprintf("bodega no longer holds the filtered %s of %s for profile %q; run `dnf makecache` to fetch a current repomd.xml, which rebuilds it.", entry.Type, t.id(), p.Name()), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeContent(&cacheDirectiveWriter{ResponseWriter: w, directive: cachePrivateImmutable}, r, "", time.Time{}, bytes.NewReader(body))
}

// writeRpmProfileError answers a request whose profile's repomd.xml could not
// be made. It never falls back to the unfiltered document, which lists what
// the profile withholds.
func (s *Server) writeRpmProfileError(w http.ResponseWriter, t rpmTree, p *entitle.Profile, err error) {
	var failed *rpmProfileBuildError
	switch {
	case errors.Is(err, errRpmProfileBuilding):
		s.logger.Warn("a governed rpm metadata request was answered 503 while the profile's filtered metadata builds",
			"profile", p.Name(), "repository", t.id(), "build_running_for", s.rpmProfileBuilds.runningFor(rpmProfileView(t, p)))
		w.Header().Set("Retry-After", rpmProfileRetryAfter)
		http.Error(w, fmt.Sprintf("bodega is still building the metadata of %s for profile %q; dnf retries, and the build continues without it.", t.id(), p.Name()), http.StatusServiceUnavailable)
		return
	case errors.Is(err, errRpmProfileSlow):
		s.logger.Warn("a governed rpm metadata request ran out of its budget waiting on the upstream repomd.xml or the store",
			"profile", p.Name(), "repository", t.id(), "budget", rpmProfileBudget)
		w.Header().Set("Retry-After", rpmProfileRetryAfter)
		http.Error(w, fmt.Sprintf("bodega could not read the metadata of %s for profile %q within %s, from the upstream or its store; dnf retries.", t.id(), p.Name(), rpmProfileBudget), http.StatusServiceUnavailable)
		return
	case errors.As(err, &failed):
	default:
		s.logger.Error("rpm repomd.xml could not be filtered for a profile", "profile", p.Name(), "repository", t.id(), "error", err)
	}
	http.Error(w, fmt.Sprintf("bodega could not filter the metadata of %s for profile %q, so it served no repomd.xml rather than the unfiltered one; the server log names the cause.", t.id(), p.Name()), http.StatusBadGateway)
}

func rpmFilteredType(typ string) bool {
	for _, t := range rpmFilteredTypes {
		if t == typ {
			return true
		}
	}
	return false
}

func rpmEntryIn(doc []byte, match func(rpmRepomdData) bool) (rpmRepomdData, error) {
	data, err := parseRpmRepomd(doc)
	if err != nil {
		return rpmRepomdData{}, err
	}
	for _, d := range data {
		if match(d) {
			return d, nil
		}
	}
	return rpmRepomdData{}, errRpmNotListed
}

// ---- rewriting repomd.xml --------------------------------------------------

// rpmRewriteRepomd replaces each <data> entry b filtered with one describing
// the filtered file, leaving every other byte of doc as the upstream wrote it.
func rpmRewriteRepomd(doc []byte, b *rpmProfileBuild) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var out bytes.Buffer
	last, depth := int64(0), 0
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("repomd.xml does not parse: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			if depth != 1 || se.Name.Local != "data" {
				depth++
				continue
			}
			if err := dec.Skip(); err != nil {
				return nil, fmt.Errorf("repomd.xml does not parse: %w", err)
			}
			f, ok := b.files[xmlAttr(se, "type")]
			if !ok {
				continue
			}
			out.Write(doc[last:start])
			out.WriteString(f.repomdData())
			last = dec.InputOffset()
		case xml.EndElement:
			depth--
		}
	}
	out.Write(doc[last:])
	return out.Bytes(), nil
}

func xmlAttr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (f rpmFilteredFile) repomdData() string {
	return fmt.Sprintf(`<data type="%s">
    <checksum type="sha256">%s</checksum>
    <open-checksum type="sha256">%s</open-checksum>
    <location href="%s"/>
    <timestamp>%d</timestamp>
    <size>%d</size>
    <open-size>%d</open-size>
  </data>`, f.typ, f.sum, f.openSum, f.href, f.timestamp, f.size, f.openSize)
}

// ---- filtering primary, filelists and other --------------------------------

// rpmAdmittedPkgids reads primary for the pkgid of every package p admits,
// by name and by the version primary gives it, and counts them. A package
// bodega would not serve at all is left out with the rest. It stops with
// ctx's error once ctx is done.
func rpmAdmittedPkgids(ctx context.Context, raw []byte, ext string, p *entitle.Profile) (map[string]bool, int, error) {
	r, closeFn, err := rpmDecompress(raw, ext)
	if err != nil {
		return nil, 0, fmt.Errorf("decompress: %w", err)
	}
	defer closeFn()
	lr := &io.LimitedReader{R: rpmCtxReader{ctx: ctx, r: r}, N: rpmMaxPrimary + 1}
	dec := xml.NewDecoder(lr)
	kept, n := map[string]bool{}, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return kept, n, nil
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, 0, cerr
			}
			if lr.N <= 0 {
				return nil, 0, fmt.Errorf("expands past %d bytes", int64(rpmMaxPrimary))
			}
			return nil, 0, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "package" {
			continue
		}
		var el rpmPrimaryElement
		if err := dec.DecodeElement(&el, &se); err != nil {
			return nil, 0, err
		}
		pkg, ok := el.servable()
		if !ok || !p.Permits(manifest.TypeRpm, pkg.name, pkg.evr()).Permitted {
			continue
		}
		kept[pkg.sum] = true
		n++
	}
}

// rpmOpen is the checksum and size of a filtered file's uncompressed content.
type rpmOpen struct {
	sum  string
	size int64
}

// rpmSetPackagesAttr sets the packages attribute of the start tag tag, the
// root element's package count in primary, filelists and other, to n, and
// leaves every other byte as written. It walks the tag attribute by
// attribute, as XML lays one out, rather than matching a pattern over it: a
// pattern either misses single quotes and spacing around "=", or also
// matches a prefixed x:packages and the same text inside another
// attribute's value. A tag with no unprefixed packages attribute comes back
// as it came.
func rpmSetPackagesAttr(tag []byte, n int) []byte {
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	nameEnd := func(c byte) bool { return space(c) || c == '=' || c == '>' || c == '/' }
	skip := func(i int) int {
		for i < len(tag) && space(tag[i]) {
			i++
		}
		return i
	}
	i := 1
	for i < len(tag) && !nameEnd(tag[i]) {
		i++
	}
	for {
		i = skip(i)
		start := i
		for i < len(tag) && !nameEnd(tag[i]) {
			i++
		}
		if i == start {
			return tag
		}
		name := string(tag[start:i])
		if i = skip(i); i >= len(tag) || tag[i] != '=' {
			return tag
		}
		if i = skip(i + 1); i >= len(tag) || (tag[i] != '"' && tag[i] != '\'') {
			return tag
		}
		end := bytes.IndexByte(tag[i+1:], tag[i])
		if end < 0 {
			return tag
		}
		end += i + 1
		if name == "packages" {
			out := append(bytes.Clone(tag[:i+1]), strconv.Itoa(n)...)
			return append(out, tag[end:]...)
		}
		i = end + 1
	}
}

// rpmFilterPackages copies one of primary, filelists or other through,
// keeping each top-level <package> whose pkgid kept holds and the whitespace
// before it, setting the root's packages attribute to n, and gzipping the
// result. Every byte it keeps is the upstream's: the decoder decides where an
// element starts and ends, and the bytes between those offsets are copied, so
// nothing the filter does not understand is lost by a re-encode.
//
// primary carries the pkgid in a child (<checksum pkgid="YES">); filelists
// and other carry it as the package's own attribute. It stops with ctx's
// error once ctx is done.
func rpmFilterPackages(ctx context.Context, raw []byte, ext string, n int, kept map[string]bool, primary bool) ([]byte, rpmOpen, error) {
	r, closeFn, err := rpmDecompress(raw, ext)
	if err != nil {
		return nil, rpmOpen{}, fmt.Errorf("decompress: %w", err)
	}
	defer closeFn()
	lr := &io.LimitedReader{R: rpmCtxReader{ctx: ctx, r: r}, N: rpmMaxPrimary + 1}
	rec := &rpmRecorder{r: bufio.NewReader(lr)}
	dec := xml.NewDecoder(rec)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	open := sha256.New()
	var openSize int64
	write := func(b []byte) {
		_, _ = zw.Write(b)
		_, _ = open.Write(b)
		openSize += int64(len(b))
	}

	var held []byte
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, rpmOpen{}, cerr
			}
			if lr.N <= 0 {
				return nil, rpmOpen{}, fmt.Errorf("expands past %d bytes", int64(rpmMaxPrimary))
			}
			return nil, rpmOpen{}, err
		}
		switch tt := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				hdr := rec.take(dec.InputOffset())
				at := bytes.LastIndexByte(hdr, '<')
				write(hdr[:at])
				write(rpmSetPackagesAttr(hdr[at:], n))
				depth++
				continue
			}
			if depth == 1 && tt.Name.Local == "package" {
				id, err := rpmPkgid(dec, tt, primary)
				if err != nil {
					return nil, rpmOpen{}, err
				}
				el := rec.take(dec.InputOffset())
				if kept[id] {
					write(held)
					write(el)
				}
				held = nil
				continue
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 1 && len(bytes.TrimSpace(tt)) == 0 {
				held = append(held[:0], rec.take(dec.InputOffset())...)
				continue
			}
		}
		write(held)
		held = nil
		write(rec.take(dec.InputOffset()))
	}
	write(held)
	write(rec.rest())
	if err := zw.Close(); err != nil {
		return nil, rpmOpen{}, err
	}
	return gz.Bytes(), rpmOpen{sum: hex.EncodeToString(open.Sum(nil)), size: openSize}, nil
}

// rpmCtxReader fails every read once ctx is done, so decompressing and
// parsing a file stops at a build's deadline rather than at the file's end.
type rpmCtxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c rpmCtxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// rpmPkgid reads the pkgid of the <package> se opens, consuming the element.
func rpmPkgid(dec *xml.Decoder, se xml.StartElement, primary bool) (string, error) {
	if !primary {
		id := xmlAttr(se, "pkgid")
		return id, dec.Skip()
	}
	var el rpmPrimaryElement
	if err := dec.DecodeElement(&el, &se); err != nil {
		return "", err
	}
	pkg, _ := el.servable()
	return pkg.sum, nil
}

// rpmRecorder keeps every byte the decoder reads until take hands it out. The
// decoder reads one byte at a time from an io.ByteReader and does no buffering
// of its own, so its InputOffset names a position in what was recorded; the
// one byte it may read ahead and push back stays recorded past that offset.
type rpmRecorder struct {
	r    io.ByteReader
	buf  []byte
	base int64
}

func (rr *rpmRecorder) ReadByte() (byte, error) {
	b, err := rr.r.ReadByte()
	if err == nil {
		rr.buf = append(rr.buf, b)
	}
	return b, err
}

func (rr *rpmRecorder) Read(p []byte) (int, error) {
	for i := range p {
		b, err := rr.ReadByte()
		if err != nil {
			return i, err
		}
		p[i] = b
	}
	return len(p), nil
}

// take returns the bytes recorded up to offset off and forgets them.
func (rr *rpmRecorder) take(off int64) []byte {
	n := off - rr.base
	out := rr.buf[:n:n]
	rr.buf = rr.buf[n:]
	rr.base = off
	return out
}

func (rr *rpmRecorder) rest() []byte {
	out := rr.buf
	rr.buf = nil
	return out
}
