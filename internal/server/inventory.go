package server

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"

	// Inventory source types. One import per type is its registration.
	_ "github.com/ravinald/bodega/internal/inventory/cyclonedx"
)

// setupInventory builds the inventory frame from inventory_sources. Load has
// already validated the section; this runs it again because a Config built in
// code never passed through Load, and an error is held for Start to refuse on.
func (s *Server) setupInventory() {
	instances, err := inventory.Configure(s.cfg.InventorySources)
	if err != nil {
		s.inventoryErr = err
		return
	}
	s.inventory = inventory.NewFrame(instances, s.auditDB, inventoryCredentials{s}, s.logger)
	s.inventory.OnRefusal = func(r *http.Request, reason string, details map[string]string) {
		recordDenial(s.auditDB, r, reason, details)
	}
	for _, inst := range instances {
		s.logger.Info("inventory source configured", "instance", inst.Name,
			"type", inst.Source.Type(), "mode", inst.Source.Mode(), "enabled", inst.Enabled)
	}
}

// isInventoryPush is the exemption MutationAuthMiddleware asks about.
func (s *Server) isInventoryPush(r *http.Request) bool {
	if s.inventory == nil {
		return false
	}
	_, _, ok := s.inventory.PushRoute(r)
	return ok
}

func (s *Server) handleInventoryPush(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no inventory sources are configured"})
		return
	}
	s.inventory.ServeHTTP(w, r)
}

// inventoryCredentials checks a push request's credential against the same
// token table and pepper the mutation gate uses, and reads the token's
// identity binding from the live identity set.
type inventoryCredentials struct{ s *Server }

func (c inventoryCredentials) Token(r *http.Request) (inventory.Token, error) {
	s := c.s
	cred, _ := credentialFrom(r)
	if cred == "" {
		return inventory.Token{}, &inventory.AuthError{Status: http.StatusUnauthorized,
			Reason: audit.DenialTokenMissing, Message: "an inventory push needs a Bearer token"}
	}
	if s.auditDB == nil || s.pepper == "" {
		return inventory.Token{}, &inventory.AuthError{Status: http.StatusServiceUnavailable,
			Reason: audit.DenialNoTokens, Message: "token verification is unavailable on this server"}
	}
	hashes, err := s.auditDB.GetTokenHashes(r.Context())
	if err != nil {
		return inventory.Token{}, err
	}
	incoming := audit.HashToken(cred, s.pepper)
	for _, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(incoming), []byte(h.Hash)) != 1 {
			continue
		}
		if h.ExpiresAt != nil && h.ExpiresAt.Before(time.Now()) {
			return inventory.Token{}, &inventory.AuthError{Status: http.StatusUnauthorized,
				Reason: audit.DenialTokenExpired, Message: "token expired"}
		}
		//nolint:gosec // G118: last_used is written after the response, so it must not die with the request.
		go func(id string) { _ = s.auditDB.UpdateTokenLastUsed(context.Background(), id) }(h.ID)
		return inventory.Token{ID: h.ID, Scope: h.Scope, Identity: s.identityNow().byToken[h.ID]}, nil
	}
	return inventory.Token{}, &inventory.AuthError{Status: http.StatusUnauthorized,
		Reason: audit.DenialTokenInvalid, Message: "token not recognized"}
}
