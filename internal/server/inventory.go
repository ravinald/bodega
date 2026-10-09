package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/inventory/osquery"

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
	s.inventory.HashSecret = func(secret string) (string, error) {
		if s.pepper == "" {
			return "", errors.New("this server loaded no pepper, so it cannot check a secret minted against one")
		}
		return audit.HashToken(secret, s.pepper), nil
	}
	for _, inst := range instances {
		if src, ok := inst.Source.(*osquery.Source); ok {
			src.SetScanDirs(s.osqueryDirsForIdentity)
		}
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

// osqueryDirsForIdentity is the language trees a host scans, by the profile
// bound to its identity: what its plan's osquery section declares and what
// the config endpoint schedules, from one lookup.
func (s *Server) osqueryDirsForIdentity(identity string) config.OsqueryDirs {
	return s.cfg.OsqueryScanDirs.For(s.profileNow().profileFor(identity).Name())
}

// osqueryPlan is the plan's osquery section: one entry per enabled osquery
// instance, with the trees this host's profile declares.
func (s *Server) osqueryPlan(h *clientHost) []clientconf.OsqueryPlan {
	if s.inventory == nil {
		return nil
	}
	dirs := s.cfg.OsqueryScanDirs.For(h.profile.Name())
	var out []clientconf.OsqueryPlan
	for _, inst := range s.inventory.Instances() {
		src, ok := inst.Source.(*osquery.Source)
		if !ok || !inst.Enabled {
			continue
		}
		out = append(out, clientconf.OsqueryPlan{
			Instance:   inst.Name,
			Mode:       src.OsqueryMode(),
			Endpoint:   h.base + inventory.RoutePrefix + inst.Name,
			Interval:   int64(src.Interval() / time.Second),
			PythonDirs: osquery.CleanDirs(dirs.Python),
			NPMDirs:    osquery.CleanDirs(dirs.NPM),
		})
	}
	return out
}

// planOsquery renders the osquery flags file for the one server-mode source a
// host enrolls with. A shipper-mode source configures no osqueryd: something
// else owns that host's osquery config.
func (s *Server) planOsquery(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	skip := func(reason string) []planFile {
		return []planFile{{system: clientconf.SystemOsquery, action: planSkip, reason: reason}}
	}
	var servers []clientconf.OsqueryPlan
	var names []string
	for _, p := range s.osqueryPlan(h) {
		if p.Mode == osquery.ModeServer {
			servers = append(servers, p)
			names = append(names, p.Instance)
		}
	}
	switch {
	case len(servers) == 0:
		return skip("this server runs no osquery source in server mode, so there is nothing for osqueryd to enroll with")
	case len(servers) > 1:
		return skip(fmt.Sprintf("this server runs %d osquery sources in server mode (%s), and osqueryd takes its config from one; disable the others or configure this host by hand",
			len(servers), strings.Join(names, ", ")))
	case !strings.HasPrefix(h.base, "https://"):
		return skip(fmt.Sprintf("osqueryd speaks only https to its server, and this server is reached at %s; set public_url to the https address bodega or the proxy in front of it answers on", h.base))
	}
	for _, f := range clientconf.ForType(clientconf.SystemOsquery, clientconf.Inputs{Base: h.base, Osquery: &servers[0]}) {
		if f.Path(h.q.OS) != "" {
			return one(f)
		}
	}
	return skip("public_url " + h.base + " names no host for osqueryd's --tls_hostname")
}
