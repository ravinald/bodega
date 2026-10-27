package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// A tag is the one oci request that names an image, so it is the only one
// the per-version checks judge. Every digest the image is made of (the index,
// each platform manifest, each config and layer) records that verdict under
// its resolved key, and a request by digest reads it there instead of judging
// again. The verdict belongs to the image the tag resolved to, the index and
// the platform manifest that dated it, and never to the tag's name: a tag
// moves, and the image it used to name keeps the verdict it was given.
//
// The record lives in the object store beside the tag it came from, not in
// the audit database, whose writes are best effort.

// The state of one image's verdict.
const (
	ociPending  = "pending"
	ociAdmitted = "admitted"
	ociRefused  = "refused"
	ociLapsed   = "lapsed" // a pending verdict older than ociPendingTTL
)

// ociPendingTTL bounds how long a pending verdict stands. A process that died
// during the checks leaves one behind, and once it lapses the image's members
// are refused until its tag is pulled again, which judges it afresh.
const ociPendingTTL = 5 * time.Minute

// ociMaxAdmitted bounds the admitted images one member record keeps. A base
// layer belongs to every release built on it, and one admitted image is all
// the verdict needs; refused and pending ones are never dropped, since
// forgetting one would serve what it refused.
const ociMaxAdmitted = 16

// ociMember is what a digest's resolved key holds.
type ociMember struct {
	// Tag is the tag that last resolved the digest, which a version
	// constraint judges a request by digest under.
	Tag string `json:"tag,omitempty"`
	// Dated is set on a platform manifest once its config has been read, and
	// Created is the config's created time, "" when it has none or carries
	// the Unix epoch. A manifest's config never changes, so neither does this.
	Dated   bool   `json:"dated,omitempty"`
	Created string `json:"created,omitempty"`
	// Images holds the verdict of each judged image the digest belongs to,
	// keyed by ociImageKey.
	Images map[string]ociImageVerdict `json:"images,omitempty"`
}

// ociImageVerdict is the verdict a tag request gave one image.
type ociImageVerdict struct {
	Tag   string `json:"tag"`
	State string `json:"state"`
	Check string `json:"check,omitempty"`
	At    string `json:"at"`
	// Direct is set on the index, on the platform manifest that dated the
	// image and on that manifest's blobs. The other platforms belong to the
	// image without having been dated, so a verdict that judged one of them
	// directly takes precedence for it.
	Direct bool `json:"direct,omitempty"`
	// Complete, on the index's own record, says every platform's manifest was
	// read and its blobs carry this verdict. A refused image that is not
	// complete is retried at its next tag request.
	Complete bool `json:"complete,omitempty"`
}

func ociImageKey(root, child string) string { return root + "/" + child }

// parseOCIMember reads a resolved key. F70 wrote the bare tag there, which
// reads as a member of no judged image.
func parseOCIMember(b []byte) (ociMember, error) {
	var m ociMember
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return m, nil
	}
	if b[0] != '{' {
		return ociMember{Tag: string(b)}, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return ociMember{}, fmt.Errorf("the record does not parse: %w", err)
	}
	return m, nil
}

func (s *Server) ociLoadMember(ctx context.Context, store storage.ObjectStore, t ociTarget, digest string) (ociMember, error) {
	if store == nil {
		return ociMember{}, nil
	}
	b, err := store.Get(ctx, manifest.OCIResolvedKey(t.registry, t.repo, digest))
	if err != nil {
		return ociMember{}, err
	}
	return parseOCIMember(b)
}

// ociUpdateMembers applies fn to the record of each digest in t's repository
// and writes back the ones it changed. One repository's records are written
// by one request at a time in this process; across processes the last write
// wins, and since every write adds the writer's own image and drops nobody
// else's but the oldest admitted ones, a lost write leaves the digest under
// the verdict of an image that does contain it.
func (s *Server) ociUpdateMembers(ctx context.Context, store storage.ObjectStore, t ociTarget, digests []string, fn func(digest string, m *ociMember)) error {
	if store == nil {
		return nil
	}
	unlock := s.ociMembers.lock(t.name())
	defer unlock()
	var errs []error
	for _, d := range digests {
		key := manifest.OCIResolvedKey(t.registry, t.repo, d)
		before, err := store.Get(ctx, key)
		if err != nil {
			errs = append(errs, fmt.Errorf("read the record of %s: %w", d, err))
			continue
		}
		m, err := parseOCIMember(before)
		if err != nil {
			s.logger.Warn("oci member record does not parse; rewriting it", "name", t.name(), "digest", d, "error", err)
		}
		fn(d, &m)
		after, _ := json.Marshal(m)
		if bytes.Equal(bytes.TrimSpace(before), after) {
			continue
		}
		if err := store.Put(ctx, key, after); err != nil {
			errs = append(errs, fmt.Errorf("write the record of %s: %w", d, err))
		}
	}
	return errors.Join(errs...)
}

// ociRecordResolved records tag as the one that last resolved each digest.
func (s *Server) ociRecordResolved(ctx context.Context, store storage.ObjectStore, t ociTarget, tag string, digests []string) {
	if err := s.ociUpdateMembers(ctx, store, t, digests, func(_ string, m *ociMember) { m.Tag = tag }); err != nil {
		s.logger.Warn("oci tag resolution not recorded; a later request by this digest is judged as never resolved",
			"name", t.name(), "tag", tag, "error", err)
	}
}

// ociResolvedTag is the tag bodega last resolved to digest in t's repository,
// "" when none did.
func (s *Server) ociResolvedTag(ctx context.Context, store storage.ObjectStore, t ociTarget, digest string) string {
	m, err := s.ociLoadMember(ctx, store, t, digest)
	if err != nil {
		return ""
	}
	return m.Tag
}

// ociInheritVerdicts gives the blobs of a manifest fetched by digest the
// images the manifest belongs to, so a platform nobody dated still carries
// the verdict of the image that named it.
func (s *Server) ociInheritVerdicts(ctx context.Context, store storage.ObjectStore, t ociTarget, body []byte) {
	m, err := s.ociLoadMember(ctx, store, t, t.ref)
	if err != nil || (m.Tag == "" && len(m.Images) == 0) {
		return
	}
	err = s.ociUpdateMembers(ctx, store, t, ociImageBlobs(body), func(_ string, b *ociMember) {
		if m.Tag != "" {
			b.Tag = m.Tag
		}
		for k, v := range m.Images {
			if cur, ok := b.Images[k]; ok && cur.Direct {
				v.Direct = true
			}
			v.Complete = false
			ociPutImage(b, k, v)
		}
	})
	if err != nil {
		s.logger.Warn("oci blobs not recorded under their manifest's verdict", "name", t.name(), "manifest", t.ref, "error", err)
	}
}

// ociPutImage sets one image's verdict on a record, dropping the oldest
// admitted images past ociMaxAdmitted.
func ociPutImage(m *ociMember, key string, v ociImageVerdict) {
	if m.Images == nil {
		m.Images = map[string]ociImageVerdict{}
	}
	m.Images[key] = v
	var admitted []string
	for k, e := range m.Images {
		if e.State == ociAdmitted {
			admitted = append(admitted, k)
		}
	}
	if len(admitted) <= ociMaxAdmitted {
		return
	}
	sort.Slice(admitted, func(i, j int) bool { return m.Images[admitted[i]].At > m.Images[admitted[j]].At })
	for _, k := range admitted[ociMaxAdmitted:] {
		delete(m.Images, k)
	}
}

// ociMemberVerdict is the verdict a digest takes from the images it belongs
// to: those that dated it directly when there are any, else all of them. An
// image admitted is enough, because the bytes are the same whichever image
// asks for them; otherwise a check still running, then a refusal, then a
// check that never finished.
func ociMemberVerdict(images map[string]ociImageVerdict, now time.Time) (ociImageVerdict, bool) {
	var direct, all []ociImageVerdict
	for _, v := range images {
		all = append(all, v)
		if v.Direct {
			direct = append(direct, v)
		}
	}
	set := direct
	if len(set) == 0 {
		set = all
	}
	if len(set) == 0 {
		return ociImageVerdict{}, false
	}
	rank := func(v ociImageVerdict) int {
		switch v.State {
		case ociAdmitted:
			return 0
		case ociPending:
			if at, err := time.Parse(time.RFC3339Nano, v.At); err == nil && now.Sub(at) < ociPendingTTL {
				return 1
			}
			return 3
		case ociRefused:
			return 2
		}
		return 3
	}
	best := slices.MinFunc(set, func(a, b ociImageVerdict) int { return rank(a) - rank(b) })
	if rank(best) == 3 {
		best.State = ociLapsed
	}
	return best, true
}

// ociUnsettled counts, per repository, the images being judged and the
// refused images whose platforms could not all be read. Until both are none,
// a digest no image claims may be one of theirs, so it is refused rather
// than served on the allow-list alone. It is held in memory: the window it
// covers is the length of one tag request, and a refused image left
// incomplete is read again at its next one.
type ociUnsettled struct {
	mu         sync.Mutex
	judging    map[string]map[string]int
	incomplete map[string]map[string]bool
}

func (u *ociUnsettled) begin(repo, key string) func() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.judging == nil {
		u.judging = map[string]map[string]int{}
	}
	if u.judging[repo] == nil {
		u.judging[repo] = map[string]int{}
	}
	u.judging[repo][key]++
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.judging[repo][key]--; u.judging[repo][key] <= 0 {
			delete(u.judging[repo], key)
		}
		if len(u.judging[repo]) == 0 {
			delete(u.judging, repo)
		}
	}
}

func (u *ociUnsettled) settle(repo, key string, complete bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if complete {
		delete(u.incomplete[repo], key)
		if len(u.incomplete[repo]) == 0 {
			delete(u.incomplete, repo)
		}
		return
	}
	if u.incomplete == nil {
		u.incomplete = map[string]map[string]bool{}
	}
	if u.incomplete[repo] == nil {
		u.incomplete[repo] = map[string]bool{}
	}
	u.incomplete[repo][key] = true
}

func (u *ociUnsettled) any(repo string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.judging[repo]) > 0 || len(u.incomplete[repo]) > 0
}

// ociManifestBytes is the manifest digest names, read from the store, and
// when it is not there and fetch is set, fetched, verified and stored.
// (nil, nil) is a manifest not held and not fetched.
func (s *Server) ociManifestBytes(ctx context.Context, t ociTarget, digest string, fetch bool) ([]byte, error) {
	if mstore, err := s.versionStore(ctx, manifest.TypeOCI, t.name(), digest); err == nil && mstore != nil {
		if b, err := mstore.Get(ctx, manifest.OCIManifestKey(t.registry, t.repo, digest)); err == nil && b != nil {
			return b, nil
		}
	}
	if !fetch {
		return nil, nil
	}
	ct := t
	ct.ref = digest
	b, cType, _, err := s.ociFetchManifest(ctx, ct, ct.url(ociManifests+"/"+digest))
	if err != nil {
		return nil, fmt.Errorf("fetch the manifest %s: %w", digest, err)
	}
	if got := ociDigest(b); got != digest {
		return nil, fmt.Errorf("the manifest %s hashes to %s", digest, got)
	}
	if err := s.ociStoreManifest(ctx, ct, digest, ociMediaType(cType, b), b); err != nil {
		return nil, err
	}
	return b, nil
}

// ociTagEntry is the tag as the per-version checks read it, dated by the
// platform manifest child, whose body is childBody (nil when it could not be
// read, childErr saying why): its config's created time, else when bodega
// first resolved the tag.
func (s *Server) ociTagEntry(ctx context.Context, store storage.ObjectStore, t ociTarget, doc ociTagDoc, child string, childBody []byte, childErr error) manifest.VersionEntry {
	ve := manifest.VersionEntry{Version: t.ref, Mode: manifest.ModeProxy}
	created, err := s.ociChildCreated(ctx, store, t, child, childBody, childErr)
	switch {
	case err != nil:
		s.logger.Warn("oci image not dated; the release-age check warns on this tag until it can be",
			"name", t.name(), "tag", t.ref, "manifest", child, "error", err)
		ve.Metadata = map[string]string{policy.OCIDateErrorKey: err.Error()}
	case created != "":
		ve.PublishedAt = created
		ve.Metadata = map[string]string{policy.OCIDatedByKey: policy.OCIDatedByCreated}
	case doc.FirstSeen != "":
		ve.PublishedAt = doc.FirstSeen
		ve.Metadata = map[string]string{policy.OCIDatedByKey: policy.OCIDatedByFirstSeen}
	default:
		ve.Metadata = map[string]string{policy.OCIDateErrorKey: "the image config carries no created time, and bodega has no record of when it first resolved the tag; it records one when the tag next resolves"}
	}
	return ve
}

// ociChildCreated is the created time of the platform manifest's config,
// read once per manifest and kept on its record.
func (s *Server) ociChildCreated(ctx context.Context, store storage.ObjectStore, t ociTarget, child string, body []byte, bodyErr error) (string, error) {
	if m, err := s.ociLoadMember(ctx, store, t, child); err == nil && m.Dated {
		return m.Created, nil
	}
	if bodyErr != nil {
		return "", fmt.Errorf("read the platform manifest %s to date the image: %w", child, bodyErr)
	}
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &m); err != nil || !manifest.OCIValidDigest(m.Config.Digest) {
		return "", errors.New("the image manifest names no config blob to read a created time from")
	}
	resp, err := s.ociGet(ctx, t, t.url(ociBlobs+"/"+m.Config.Digest), "")
	if err != nil {
		return "", fmt.Errorf("fetch the config blob %s: %w", m.Config.Digest, err)
	}
	defer drainClose(resp)
	cfg, err := io.ReadAll(io.LimitReader(resp.Body, ociMaxManifest+1))
	if err != nil {
		return "", fmt.Errorf("read the config blob %s: %w", m.Config.Digest, err)
	}
	if len(cfg) > ociMaxManifest {
		return "", fmt.Errorf("the config blob %s is over %d bytes", m.Config.Digest, ociMaxManifest)
	}
	if got := ociDigest(cfg); got != m.Config.Digest {
		return "", fmt.Errorf("the config blob %s hashes to %s", m.Config.Digest, got)
	}
	created := ociConfigCreated(cfg)
	if err := s.ociUpdateMembers(ctx, store, t, []string{child}, func(_ string, rec *ociMember) {
		rec.Dated, rec.Created = true, created
	}); err != nil {
		s.logger.Warn("oci image date not recorded; it is read again at the next tag request", "name", t.name(), "manifest", child, "error", err)
	}
	return created, nil
}

// ociTagPolicyGate runs the per-version checks on a tag (release age; OSV,
// which records that it cannot run; upstream provenance; name similarity;
// the integrations) and records the verdict on every digest of the image
// before the tag is answered. root is the manifest the tag resolved to.
func (s *Server) ociTagPolicyGate(w *ociResponseWriter, r *http.Request, t ociTarget, store storage.ObjectStore, doc ociTagDoc, root []byte, decision string, baseline baselineLookup, override overrideLookup) bool {
	if s.auditDB == nil {
		return true
	}
	ctx := r.Context()
	child, childBody, childErr := doc.Digest, root, error(nil)
	if c := ociPickChild(root, ociPlatformOf(r)); c != "" {
		child = c
		childBody, childErr = s.ociManifestBytes(ctx, t, c, true)
	}
	ve := s.ociTagEntry(ctx, store, t, doc, child, childBody, childErr)

	key := ociImageKey(doc.Digest, child)
	rootRec, err := s.ociLoadMember(ctx, store, t, doc.Digest)
	if err != nil {
		s.logger.Warn("oci image verdict not read; judging the image as new", "name", t.name(), "tag", t.ref, "digest", doc.Digest, "error", err)
	}
	prev, decided := rootRec.Images[key]
	decided = decided && (prev.State == ociAdmitted || prev.State == ociRefused)
	if !decided {
		defer s.ociUnsettled.begin(t.name(), key)()
		pending := ociImageVerdict{Tag: t.ref, State: ociPending, At: time.Now().UTC().Format(time.RFC3339Nano)}
		if _, err := s.ociRecordVerdict(ctx, store, t, doc.Digest, root, child, childBody, pending, false); err != nil {
			s.logger.Error("oci image verdict not recorded; refusing the tag", "name", t.name(), "tag", t.ref, "digest", doc.Digest, "error", err)
			w.writeError(http.StatusServiceUnavailable, "UNAVAILABLE",
				fmt.Sprintf("bodega could not record that it is checking tag %s of %s, so it cannot hold the image's layers to the verdict: %v. Retry; if it persists, the storage backend is refusing writes.", t.ref, t.name(), err))
			return false
		}
	}

	fill := fillAdmission{typ: manifest.TypeOCI, name: t.name(), version: t.ref}
	check, ok := s.admitFill(w, r, fill, ve, fetchCheckers(s.cfg, s.auditDB), "", decision, t.name(), baseline, override)
	v := ociImageVerdict{Tag: t.ref, State: ociAdmitted, At: time.Now().UTC().Format(time.RFC3339Nano)}
	if !ok {
		v.State, v.Check = ociRefused, check
	}
	if decided && prev.State == v.State && prev.Check == v.Check && (v.State == ociAdmitted || prev.Complete) {
		return ok
	}
	complete, err := s.ociRecordVerdict(ctx, store, t, doc.Digest, root, child, childBody, v, v.State == ociRefused)
	s.ociUnsettled.settle(t.name(), key, v.State == ociAdmitted || complete)
	if err == nil {
		return ok
	}
	s.logger.Error("oci image verdict not recorded", "name", t.name(), "tag", t.ref, "digest", doc.Digest, "verdict", v.State, "error", err)
	if ok {
		w.writeError(http.StatusServiceUnavailable, "UNAVAILABLE",
			fmt.Sprintf("bodega admitted tag %s of %s but could not record the verdict its layers are served under: %v. Retry; if it persists, the storage backend is refusing writes.", t.ref, t.name(), err))
	}
	return false
}

// ociRecordVerdict writes v for the image (root, child) on every digest of it
// bodega can name: the index, every platform manifest, the dated manifest's
// blobs, and the blobs of each other platform whose manifest is held, or with
// fetch set, fetched. complete reports that every platform was read.
func (s *Server) ociRecordVerdict(ctx context.Context, store storage.ObjectStore, t ociTarget, root string, rootBody []byte, child string, childBody []byte, v ociImageVerdict, fetch bool) (bool, error) {
	direct := map[string]bool{root: true}
	order := []string{root}
	add := func(d string, isDirect bool) {
		if _, seen := direct[d]; !seen {
			order = append(order, d)
		}
		direct[d] = direct[d] || isDirect
	}
	add(child, true)
	complete := childBody != nil
	for _, b := range ociImageBlobs(childBody) {
		add(b, true)
	}
	for _, sib := range ociIndexChildren(rootBody) {
		if sib == child {
			continue
		}
		add(sib, false)
		body, err := s.ociManifestBytes(ctx, t, sib, fetch)
		if err != nil {
			s.logger.Warn("oci platform manifest not read; its blobs do not carry the image's verdict yet", "name", t.name(), "manifest", sib, "error", err)
		}
		if body == nil {
			complete = false
			continue
		}
		for _, b := range ociImageBlobs(body) {
			add(b, false)
		}
	}
	key := ociImageKey(root, child)
	err := s.ociUpdateMembers(ctx, store, t, order, func(d string, m *ociMember) {
		m.Tag = v.Tag
		e := v
		e.Direct = direct[d]
		e.Complete = d == root && complete
		ociPutImage(m, key, e)
	})
	return complete, err
}

// ociMemberGate refuses a blob or a manifest by digest whose image a tag
// request refused, or is still judging, from the record its digest carries.
// A digest no judged image claims is left to the allow-list, hiding and
// constraints, unless an image in the repository is still being judged or
// could not be read whole, when it may be one of that image's.
func (s *Server) ociMemberGate(w *ociResponseWriter, r *http.Request, t ociTarget, store storage.ObjectStore) bool {
	if s.auditDB == nil || store == nil {
		return true
	}
	name := t.name()
	m, err := s.ociLoadMember(r.Context(), store, t, t.ref)
	if err != nil {
		s.logger.Error("oci verdict record not read; refusing", "name", name, "digest", t.ref, "error", err)
		w.writeError(http.StatusServiceUnavailable, "UNAVAILABLE",
			fmt.Sprintf("bodega could not read the verdict %s of %s is served under: %v. Retry; if it persists, the storage backend's own logs say why it refused the read.", t.ref, name, err))
		return false
	}
	v, found := ociMemberVerdict(m.Images, time.Now())
	if !found {
		if !s.ociUnsettled.any(name) {
			return true
		}
		v = ociImageVerdict{State: ociPending}
	}
	if v.State == ociAdmitted {
		return true
	}
	var f *refusal
	switch v.State {
	case ociRefused:
		f = newRefusal(admitRefusalWord(v.Check), manifest.TypeOCI, name, t.ref, http.StatusForbidden)
		at := v.At
		if parsed, err := time.Parse(time.RFC3339Nano, v.At); err == nil {
			at = parsed.UTC().Format(time.DateOnly)
		}
		f.reason = fmt.Sprintf("bodega refused tag %s of %s under its %s check on %s, and %s is part of the image that tag resolved to, so it takes the same verdict.",
			v.Tag, name, v.Check, at, t.ref)
		f.next = fmt.Sprintf("pull a tag the policy admits; `bodega audit admissions oci %s %s` shows what the check found.", name, v.Tag)
	case ociPending:
		f = newRefusal(checkPolicy, manifest.TypeOCI, name, t.ref, http.StatusForbidden)
		f.reason = fmt.Sprintf("bodega is still running its checks on the image %s belongs to in %s, and serves none of it before they answer.", t.ref, name)
		f.next = "retry once the tag's own request has answered."
		if v.Tag != "" {
			f.next = fmt.Sprintf("retry once the request for tag %s has answered.", v.Tag)
		}
	default:
		f = newRefusal(checkPolicy, manifest.TypeOCI, name, t.ref, http.StatusForbidden)
		f.reason = fmt.Sprintf("bodega began checking tag %s of %s, which %s is part of, and never recorded a verdict: the process checking it stopped.", v.Tag, name, t.ref)
		f.next = fmt.Sprintf("pull tag %s again, which checks the image afresh.", v.Tag)
	}
	s.logger.Warn("oci content refused under its image's verdict", "package", name, "tag", v.Tag, "digest", t.ref, "verdict", v.State, "check", v.Check, "incident", f.incident)
	recordDenialFor(s.auditDB, r, manifest.TypeOCI, name, t.ref, audit.DenialTagRefused, map[string]string{
		"tag": v.Tag, "verdict": v.State, "check": v.Check, "incident": f.incident, "reason": f.reason,
	})
	f.write(w, r)
	return false
}
