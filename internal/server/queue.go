package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// queueRefusal records a refused client request in the review queue, whatever
// discover_mode says: discovery is what the fleet reached for, the queue is
// what it was turned away from, and an operator with discovery off still has
// to be able to admit what was refused. It writes synchronously, beside the
// denial row every refusal already writes, on a context detached from the
// request so a client that hangs up still leaves its row.
func (s *Server) queueRefusal(r *http.Request, q audit.QueueRefusal) {
	if s.auditDB == nil || q.PkgType == "" || q.PkgName == "" {
		return
	}
	q.Identity, q.ClientIP = callerName(r), ClientIP(r)
	ctx, cancel := auditContext(r)
	defer cancel()
	if err := s.auditDB.RecordRefusal(ctx, q, time.Now()); err != nil {
		s.logger.Error("audit write failed, refusal not queued", "type", q.PkgType, "package", q.PkgName,
			"version", q.PkgVersion, "check", q.Check, "error", err)
	}
}

// queueResult queues a refusal an admission result decided.
func (s *Server) queueResult(r *http.Request, typ, name, version string, res policy.Result, f *refusal) {
	s.queueRefusal(r, audit.QueueRefusal{PkgType: typ, PkgName: name, PkgVersion: version,
		Check: admit.QueueCheckFor(res), Unwaivable: admit.Unwaivable(res), Detail: f.reason, Incident: f.incident})
}

// queuePattern is the allow-list rule approving an allow-list row writes.
// For the types whose rule is a package name it is the exact name the
// allow-list refused, not the scope or org prefix discovery suggests, because
// approving one row admits what that row names and nothing beside it. For the
// host and URL-prefix types it is the suggestion: the candidate is a whole
// artifact URL, and a rule that exact admits one file.
func queuePattern(regType, upstreamURL, candidate, name string) string {
	switch regType {
	case manifest.TypeNpm, manifest.TypePypi, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeMaven:
		return candidate
	}
	u := upstreamURL
	if u == "" {
		u = candidate
	}
	host, p := splitUpstreamURL(u)
	if hint := policy.SuggestPattern(regType, host, p, name); hint != "" && host != "" {
		return hint
	}
	return candidate
}

func (s *Server) handleListQueue(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	q := r.URL.Query()
	f := audit.QueueFilter{PkgType: q.Get("type"), Check: q.Get("check"), State: q.Get("state")}
	if f.State == "" {
		f.State = audit.QueueOpen
	}
	switch {
	case f.PkgType != "" && !manifest.IsKnownType(f.PkgType):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown type " + strconv.Quote(f.PkgType)})
		return
	case f.Check != "" && !slices.Contains(admit.QueueChecks(), f.Check):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown check " + strconv.Quote(f.Check)})
		return
	case !slices.Contains([]string{audit.QueueOpen, audit.QueueApproved, audit.QueueDismissed}, f.State):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be open, approved or dismissed"})
		return
	}
	rows, err := s.auditDB.ListQueue(r.Context(), f)
	if err != nil {
		s.logger.Error("list queue failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// queueCaller is overrideCaller: approving a row can file an override
// request, and the two-person rule means nothing when the request carries no
// identity, so both queue mutations require a token bound to one.
func (s *Server) queueCaller(w http.ResponseWriter, r *http.Request) (string, int64, bool) {
	caller, ok := s.overrideCaller(w, r)
	if !ok {
		return "", 0, false
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return "", 0, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no queue row " + strconv.Quote(r.PathValue("id"))})
		return "", 0, false
	}
	return caller.Identity, id, true
}

func (s *Server) handleApproveQueue(w http.ResponseWriter, r *http.Request) {
	identity, id, ok := s.queueCaller(w, r)
	if !ok {
		return
	}
	var body admit.QueueApproval
	if !decodeQueueBody(w, r, &body) {
		return
	}
	res, err := admit.ApproveQueued(r.Context(), s.auditDB, s.cfg, id, identity, body, time.Now())
	if err != nil {
		s.writeQueueError(w, err)
		return
	}
	if res.Rule != nil && s.policy != nil {
		s.policy.Invalidate()
	}
	if res.Warning != "" {
		s.logger.Warn("queue approval", "id", id, "warning", res.Warning)
	}
	if len(res.Profiles) > 0 {
		s.refreshProfiles(r.Context())
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDismissQueue(w http.ResponseWriter, r *http.Request) {
	identity, id, ok := s.queueCaller(w, r)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeQueueBody(w, r, &body) {
		return
	}
	row, err := admit.DismissQueued(r.Context(), s.auditDB, id, identity, body.Reason, time.Now())
	if err != nil {
		s.writeQueueError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func decodeQueueBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return false
	}
	return true
}

func (s *Server) writeQueueError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, admit.ErrInvalidQueue), errors.Is(err, admit.ErrInvalidOverride):
		status = http.StatusBadRequest
	case errors.Is(err, audit.ErrQueueRowNotFound):
		status = http.StatusNotFound
	case errors.Is(err, audit.ErrQueueRowClosed), errors.Is(err, admit.ErrQueueUnwaivable):
		status = http.StatusConflict
	}
	if status == http.StatusInternalServerError {
		s.logger.Error("queue resolution failed", "error", err)
		writeJSON(w, status, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
