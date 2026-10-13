package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const (
	// RevetWebhookPath is the threat-feed webhook.
	RevetWebhookPath = "/api/v1/policy/revet"
	// RevetSignatureHeader carries "sha256=<hex HMAC-SHA256 of the body>".
	RevetSignatureHeader = "X-Bodega-Signature"
	// revetReplayWindow is how far a webhook body's timestamp may sit from
	// this server's clock in either direction.
	revetReplayWindow = 5 * time.Minute
	revetMaxBody      = 64 << 10
	revetMaxReason    = 512
)

// revetRequest is the webhook body. Timestamp is in the body rather than a
// header so the signature covers it: a timestamp the signature does not
// cover is one a replayer rewrites.
type revetRequest struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Reason    string `json:"reason"`
	Timestamp int64  `json:"timestamp"`
}

// revetState is the server's re-vet machinery: the revetter both the
// schedule and the webhook decide through, the flag that keeps two sweeps
// from overlapping, and the signatures seen inside the replay window.
type revetState struct {
	rv      *admit.Revetter
	running sync.Mutex
	seenMu  sync.Mutex
	seen    map[string]time.Time
}

// setupRevet builds the revetter, or leaves it nil with no audit store to
// write rows to, which the schedule and the webhook each report.
func (s *Server) setupRevet() {
	if s.auditDB == nil {
		return
	}
	s.revet = &revetState{seen: map[string]time.Time{}, rv: &admit.Revetter{
		Cfg: s.cfg, DB: s.auditDB, Store: s.store, Allow: s.policy,
		OnBlock: s.cfg.ResolveRevetOnBlock(),
		Write:   &s.mu,
		Saved: func(ctx context.Context, typ string) {
			_ = s.store.SaveIndex(ctx)
			s.rebuildAptIndexAfterWrite(ctx, typ)
		},
		Emitter: s.attest,
		Stores:  s.stores,
		Logger:  s.logger,
	}}
}

// revetLoop runs the scheduled sweep every revet_interval. The first sweep
// waits one interval: a restart is not a reason to re-check the catalog,
// and a fleet of servers restarted together would otherwise all hit the
// registries at once.
func (s *Server) revetLoop(ctx context.Context) {
	interval := s.cfg.ResolveRevetInterval()
	if interval == 0 {
		return
	}
	if s.revet == nil {
		s.logger.Warn("revet_interval is set and no audit store is open; the scheduled re-vet is off", "revet_interval", interval)
		return
	}
	s.logger.Info("scheduled re-vet enabled", "interval", interval,
		"pause", s.cfg.ResolveRevetPause(), "on_block", s.revet.rv.OnBlock)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			go s.revetSweep(ctx)
		}
	}
}

// revetSweep re-vets the whole catalog, one version at a time at
// revet_rate, and reports whether it ran. A tick that arrives while the
// previous sweep is still walking is skipped rather than queued: a catalog
// that takes longer than the interval to walk would otherwise grow a backlog
// of sweeps nobody can drain.
func (s *Server) revetSweep(ctx context.Context) bool {
	if !s.revet.running.TryLock() {
		s.logger.Warn("scheduled re-vet skipped: the previous sweep is still running")
		return false
	}
	defer s.revet.running.Unlock()
	start := time.Now()
	targets, err := s.revet.rv.Targets(ctx, admit.RevetFilter{})
	if err != nil {
		s.logger.Error("scheduled re-vet could not list the catalog", "error", err)
		return true
	}
	s.logger.Info("scheduled re-vet started", "versions", len(targets))
	sum := s.revet.rv.Sweep(ctx, targets, "schedule", s.cfg.ResolveRevetPause(), nil)
	s.logger.Info("scheduled re-vet finished", "walked", sum.Walked, "admitted", sum.Admitted,
		"refused", sum.Blocked, "hidden", sum.Hidden, "frozen", sum.Frozen, "errors", sum.Errors,
		"duration", time.Since(start).Round(time.Second))
	return true
}

// isRevetWebhook is the second exemption MutationAuthMiddleware asks about.
// The webhook is called by a threat feed from outside admin_permit_cidr and
// carries no bearer token; its body's HMAC is the authentication.
func (s *Server) isRevetWebhook(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == RevetWebhookPath
}

// selfAuthenticated is every route that skips the admin gate because the
// handler authenticates the caller itself.
func (s *Server) selfAuthenticated(r *http.Request) bool {
	return s.isRevetWebhook(r) || s.isInventoryPush(r)
}

// handleRevetWebhook re-vets the versions a threat feed names, immediately,
// and answers with their new decisions.
//
// Every authentication failure is the same bare 401: a missing header, a
// malformed one, a wrong signature, a stale timestamp and a replay. Saying
// which would tell a caller without the secret how close it got. The
// journal says which.
func (s *Server) handleRevetWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, revetMaxBody))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var req revetRequest
	if reason := s.revetAuthenticate(r, body, &req); reason != "" {
		s.logger.Warn("re-vet webhook refused", "reason", reason, "client_ip", ClientIP(r))
		recordDenial(s.auditDB, r, audit.DenialSignature, map[string]string{"reason": reason})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if req.Type == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and name are required"})
		return
	}
	if !manifest.IsKnownType(req.Type) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown type " + req.Type})
		return
	}
	if s.revet == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no audit store is open, so there is nowhere to record a re-vet"})
		return
	}
	reason := req.Reason
	if len(reason) > revetMaxReason {
		reason = reason[:revetMaxReason]
	}
	ctx := r.Context()
	targets, err := s.revet.rv.Targets(ctx, admit.RevetFilter{Type: req.Type, Name: req.Name, Version: req.Version})
	switch {
	case errors.Is(err, admit.ErrNoRevetTargets):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no cataloged version matches"})
		return
	case err != nil:
		s.logger.Error("re-vet webhook could not list the catalog", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	s.logger.Info("re-vet webhook accepted", "type", req.Type, "package", req.Name, "version", req.Version,
		"versions", len(targets), "reason", reason)
	details, _ := json.Marshal(map[string]any{"reason": reason, "versions": len(targets)})
	_ = s.auditDB.Record(ctx, audit.Event{EventType: audit.EventRevet, PkgType: req.Type, PkgName: req.Name,
		PkgVersion: req.Version, Actor: admit.RevetActor, Status: "requested", Details: string(details)})
	results := make([]admit.RevetOutcome, 0, len(targets))
	s.revet.rv.Sweep(ctx, targets, "webhook", 0, func(o admit.RevetOutcome) { results = append(results, o) })
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// revetAuthenticate checks the signature, then the timestamp, then the
// replay cache, and decodes the body into req. It returns "" on success and
// otherwise the reason for the journal.
func (s *Server) revetAuthenticate(r *http.Request, body []byte, req *revetRequest) string {
	secret := s.cfg.RevetWebhookSecret
	if secret == "" {
		return "revet_webhook_secret is unset"
	}
	got, ok := strings.CutPrefix(r.Header.Get(RevetSignatureHeader), "sha256=")
	if !ok {
		return "no " + RevetSignatureHeader + " header of the form sha256=<hex>"
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return "signature is not hex"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "signature does not match the body"
	}
	if err := json.Unmarshal(body, req); err != nil {
		return "signed body is not JSON: " + err.Error()
	}
	now := time.Now()
	at := time.Unix(req.Timestamp, 0)
	if req.Timestamp == 0 || now.Sub(at) > revetReplayWindow || at.Sub(now) > revetReplayWindow {
		return "timestamp is missing or outside the replay window"
	}
	if s.revet != nil && !s.revet.firstSight(hex.EncodeToString(sig), now) {
		return "body already accepted inside the replay window"
	}
	return ""
}

// firstSight records sig and reports whether it was new. An entry outlives
// the window on both sides of its timestamp, so a body cannot come back
// once its signature has been forgotten.
func (st *revetState) firstSight(sig string, now time.Time) bool {
	st.seenMu.Lock()
	defer st.seenMu.Unlock()
	for k, until := range st.seen {
		if now.After(until) {
			delete(st.seen, k)
		}
	}
	if _, dup := st.seen[sig]; dup {
		return false
	}
	st.seen[sig] = now.Add(2 * revetReplayWindow)
	return true
}
