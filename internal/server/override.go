package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
)

// overrideCaller returns the identity the request's token is bound to,
// writing the refusal when there is none. Every override route requires one,
// in the localhost-only posture too, where the mutation gate asks for no
// token: a quorum of identities means nothing when a vote can arrive with
// nobody named on it.
//
// A CIDR binding is not accepted. It names a network, and every host on it
// would vote as one identity, or every person on one host as the same one.
func (s *Server) overrideCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	m := identityMatchOf(r)
	if m.Kind != audit.BindToken || m.Identity == "" {
		recordDenial(s.auditDB, r, audit.DenialTokenMissing, map[string]string{"route": "overrides"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "the override routes require a token bound to an identity: " +
			"bodega token generate, then bodega identity bind token <id> <identity>, and send it as Authorization: Bearer <token>"})
		return "", false
	}
	for _, t := range s.identityNow().tokens {
		if t.ID == m.Key && t.Scope == audit.ScopeInventory {
			refuseScope(w, r, s.auditDB, s.logger, t)
			return "", false
		}
	}
	return m.Identity, true
}

func (s *Server) handleListOverrides(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if _, ok := s.overrideCaller(w, r); !ok {
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	want := r.URL.Query().Get("status")
	switch want {
	case "", audit.OverrideStatusPending, audit.OverrideStatusActive, audit.OverrideStatusExpired, audit.OverrideStatusRejected:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be pending, active, expired or rejected"})
		return
	}
	list, err := admit.ListOverrides(r.Context(), s.auditDB, want, time.Now())
	if err != nil {
		s.logger.Error("list overrides failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleRequestOverride(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.overrideCaller(w, r)
	if !ok {
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req admit.OverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	o, err := admit.RequestOverride(r.Context(), s.auditDB, s.cfg, req, identity, time.Now())
	if err != nil {
		s.writeOverrideError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, o)
}

func (s *Server) handleApproveOverride(w http.ResponseWriter, r *http.Request) {
	s.voteOverride(w, r, true)
}

func (s *Server) handleRejectOverride(w http.ResponseWriter, r *http.Request) {
	s.voteOverride(w, r, false)
}

func (s *Server) voteOverride(w http.ResponseWriter, r *http.Request, approve bool) {
	identity, ok := s.overrideCaller(w, r)
	if !ok {
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		Comment string `json:"comment"`
	}
	// The body is optional: a vote with nothing to say is a bare POST.
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	o, err := admit.VoteOverride(r.Context(), s.auditDB, r.PathValue("id"), identity, approve, body.Comment, time.Now())
	if err != nil {
		s.writeOverrideError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) writeOverrideError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, admit.ErrInvalidOverride):
		status = http.StatusBadRequest
	case errors.Is(err, audit.ErrOverrideNotFound):
		status = http.StatusNotFound
	case errors.Is(err, audit.ErrSelfApproval):
		status = http.StatusForbidden
	case errors.Is(err, audit.ErrAlreadyVoted), errors.Is(err, audit.ErrOverrideClosed):
		status = http.StatusConflict
	}
	if status == http.StatusInternalServerError {
		s.logger.Error("override failed", "error", err)
		writeJSON(w, status, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
