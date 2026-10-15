package server

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/idp"
)

const (
	authPathPrefix   = "/api/v1/auth/"
	authExchangePath = authPathPrefix + "exchange"

	// exchangeMaxBody bounds the exchange request. An ID token is a few KB;
	// a megabyte would be a request that is not one.
	exchangeMaxBody = 64 << 10
)

// setupOIDC discovers every configured provider. It runs before the routes are
// registered and blocks on discovery, bounded by the client timeout, so a
// provider that answers is ready by the time the first CI job asks.
func (s *Server) setupOIDC() {
	if len(s.cfg.OIDCProviders) == 0 {
		return
	}
	s.oidc = idp.New(context.Background(), s.cfg.OIDCProviders, s.oidcClient, s.logger)
}

// isAuthExchange reports whether r is the token exchange, which skips the
// admin gate: CI runners and laptops are outside admin_permit_cidr, and the
// ID token is the credential.
func isAuthExchange(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == authExchangePath
}

// exchangeResponse is what POST /api/v1/auth/exchange answers with.
type exchangeResponse struct {
	Token     string `json:"token"`
	ID        string `json:"id"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
}

// handleAuthExchange trades a verified OIDC ID token for a bodega token
// carrying the scopes the provider's first matching rule grants, for at most
// oidc_token_ttl. The minted token records the subject and issuer, and every
// audit row its requests write names them.
//
// A refusal says why in the body, naming the issuer and any unmatched claims.
// It never echoes the token: a body that reached a CI log would otherwise
// carry a credential that may still be live.
func (s *Server) handleAuthExchange(w http.ResponseWriter, r *http.Request) {
	if s.auditDB == nil || s.pepper == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "token exchange needs the audit database and the pepper, and this server has not loaded both"})
		return
	}
	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, exchangeMaxBody)).Decode(&req); err != nil || req.IDToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `want a JSON body {"id_token": "<OIDC ID token>"}`})
		return
	}
	res, err := s.oidc.Exchange(r.Context(), strings.TrimSpace(req.IDToken))
	if err != nil {
		status, reason := http.StatusUnauthorized, err.Error()
		var ref *idp.Refusal
		if errors.As(err, &ref) {
			status = ref.Status
		}
		s.logger.Warn("token exchange refused", "reason", reason, "client_ip", ClientIP(r))
		recordDenial(s.auditDB, r, audit.DenialOIDCRefused, map[string]string{"reason": reason})
		writeJSON(w, status, map[string]string{"error": reason})
		return
	}

	token, id, err := mintToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	now := time.Now().UTC()
	expires := now.Add(s.cfg.ResolveOIDCTokenTTL())
	principal := audit.Principal{Subject: res.Subject, Issuer: res.Issuer}
	ctx := audit.WithPrincipal(r.Context(), principal)
	label := truncateField("oidc:"+res.Provider+":"+res.Subject, maxDetailField)
	scope := res.Scopes.String()
	if err := s.auditDB.InsertExchangedToken(ctx, id, label, audit.HashToken(token, s.pepper), scope, expires, principal); err != nil {
		s.logger.Error("store exchanged token failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if n, err := s.auditDB.DeleteExpiredExchangedTokens(ctx, now); err != nil {
		s.logger.Warn("could not prune expired exchanged tokens", "error", err)
	} else if n > 0 {
		s.logger.Debug("pruned expired exchanged tokens", "count", n)
	}
	details, _ := json.Marshal(map[string]any{
		"id": id, "scope": scope, "provider": res.Provider, "rule": res.Rule,
		"expires_at": expires.Format(time.RFC3339),
	})
	_ = s.auditDB.Record(ctx, audit.Event{
		EventType: audit.EventCreate,
		PkgType:   "token",
		PkgName:   label,
		ClientIP:  ClientIP(r),
		UserAgent: truncateField(r.UserAgent(), maxDetailField),
		Status:    "success",
		Details:   string(details),
	})
	s.logger.Info("token exchanged", "provider", res.Provider, "subject", res.Subject, "scope", scope, "token_id", id)
	writeJSON(w, http.StatusOK, exchangeResponse{
		Token: token, ID: id, Scopes: scope, ExpiresAt: expires.Format(time.RFC3339),
		Subject: res.Subject, Issuer: res.Issuer,
	})
}

// handleAuthProviders lists the providers `bodega login` can sign in through
// with the device flow. It is public by design: an issuer and a client_id are
// what a login prompt shows anyone who opens it.
func (s *Server) handleAuthProviders(w http.ResponseWriter, r *http.Request) {
	out := s.oidc.Providers(r.Context())
	if out == nil {
		out = []idp.ProviderInfo{}
	}
	writeJSON(w, http.StatusOK, out)
}

// mintToken returns a fresh bearer token and its id. The token is shown once;
// only its peppered hash is stored.
func mintToken() (token, id string, err error) {
	b := make([]byte, 32)
	if _, err := cryptoRand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	idBytes := make([]byte, 16)
	if _, err := cryptoRand.Read(idBytes); err != nil {
		return "", "", fmt.Errorf("generate token id: %w", err)
	}
	return "bodega_ak_" + hex.EncodeToString(b), hex.EncodeToString(idBytes), nil
}
