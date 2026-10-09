// Package osquery is the inventory source for hosts running osquery. One
// type serves both ways a host can reach bodega, chosen per instance by its
// mode key:
//
//   - server: bodega is the hosts' osquery server. It answers osquery's
//     remote API (enroll, config, logger), hands out the schedule, and
//     receives results over osquery's own tls logger. Nothing of bodega's
//     runs on the host.
//   - shipper: something else owns the hosts' osquery config, and the
//     results log reaches bodega as NDJSON from a shipper holding an
//     inventory-scoped token.
//
// Both modes normalize result lines with the same code, so a host reports
// the same components whichever way its results arrive.
package osquery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
)

// TypeName is the inventory_sources "type" this package registers.
const TypeName = "osquery"

// The two values of an instance's mode key.
const (
	ModeServer  = "server"
	ModeShipper = "shipper"
)

// Route paths below /api/v1/inventory/sources/{instance}/.
const (
	RouteEnroll  = "enroll"
	RouteConfig  = "config"
	RouteLog     = "log"
	RouteResults = "results"
)

// Interval bounds for the schedule's snapshot queries. A package list
// changes on the scale of hours; the floor stops a typo from having every
// host walk its package database every few seconds.
const (
	DefaultInterval = time.Hour
	MinInterval     = time.Minute
)

// DefaultMaxBodyBytes caps a log or results post. A full snapshot of a
// desktop image's packages runs to about 1 MiB of JSON; 16 MiB leaves room
// for a buffered backlog without letting one request hold an unbounded
// buffer.
const DefaultMaxBodyBytes int64 = 16 << 20

// controlBodyBytes caps enroll and config, whose bodies are a secret or a
// key and osquery's host_details. Both are read before the request is
// authenticated, so the cap is what an anonymous caller can make bodega read.
const controlBodyBytes int64 = 64 << 10

// maxHostIdentifier bounds the host_identifier kept with a node; osquery
// sends a hostname or a UUID.
const maxHostIdentifier = 255

func init() { inventory.Register(TypeName, newSource) }

// Source is one configured osquery instance.
type Source struct {
	instance string
	mode     string
	interval time.Duration
	maxBody  int64
	scanDirs func(identity string) config.OsqueryDirs
}

func newSource(instance string, s *inventory.Settings) (inventory.Source, error) {
	mode, err := s.String("mode", "")
	if err != nil {
		return nil, err
	}
	switch mode {
	case ModeServer, ModeShipper:
	case "":
		return nil, s.Errorf("mode", "required: %q (bodega is the hosts' osquery server) or %q (a shipper forwards the results log)", ModeServer, ModeShipper)
	default:
		return nil, s.Errorf("mode", "want %q or %q, got %q", ModeServer, ModeShipper, mode)
	}
	interval, err := s.Duration("interval", DefaultInterval)
	if err != nil {
		return nil, err
	}
	if interval < MinInterval {
		return nil, s.Errorf("interval", "%s is below the %s minimum", interval, MinInterval)
	}
	if interval%time.Second != 0 {
		return nil, s.Errorf("interval", "%s is not a whole number of seconds, which is the unit osquery schedules in", interval)
	}
	maxBody, err := s.Int64("max_body_bytes", DefaultMaxBodyBytes)
	if err != nil {
		return nil, err
	}
	if maxBody <= 0 {
		return nil, s.Errorf("max_body_bytes", "want a positive byte count, got %d", maxBody)
	}
	return &Source{instance: instance, mode: mode, interval: interval, maxBody: maxBody}, nil
}

func (*Source) Type() string         { return TypeName }
func (*Source) Mode() inventory.Mode { return inventory.ModePush }
func (*Source) Capabilities() []inventory.Capability {
	return []inventory.Capability{inventory.CapInventory}
}

// OsqueryMode is the instance's mode key: ModeServer or ModeShipper.
func (s *Source) OsqueryMode() string { return s.mode }

// Interval is how often the schedule's snapshot queries run.
func (s *Source) Interval() time.Duration { return s.interval }

// SetScanDirs gives the source the resolver for the language trees a host's
// plan declares. The server sets it before serving, so the schedule a host
// is handed and the plan it reads come from one function. Unset, every host
// scans no language trees.
func (s *Source) SetScanDirs(f func(identity string) config.OsqueryDirs) { s.scanDirs = f }

// RoutePaths names the routes an instance in mode registers, in the order a
// host meets them.
func RoutePaths(mode string) []string {
	if mode == ModeServer {
		return []string{RouteEnroll, RouteConfig, RouteLog}
	}
	return []string{RouteResults}
}

// Routes registers osquery's three remote API endpoints in server mode, and
// the results route alone in shipper mode. A server-mode instance accepts no
// shipped results, so a host cannot report through both doors of one
// instance under two external ids.
func (s *Source) Routes() []inventory.Route {
	if s.mode == ModeServer {
		return []inventory.Route{
			{Method: http.MethodPost, Path: RouteEnroll, MaxBody: controlBodyBytes, Handler: s.serveEnroll},
			{Method: http.MethodPost, Path: RouteConfig, MaxBody: controlBodyBytes, Handler: s.serveConfig},
			{Method: http.MethodPost, Path: RouteLog, MaxBody: s.maxBody, Handler: s.serveLog},
		}
	}
	return []inventory.Route{{Method: http.MethodPost, Path: RouteResults, MaxBody: s.maxBody}}
}

// Authenticate guards the results route: an inventory-scoped token, bound to
// an identity or not, since one shipper may forward a relay's worth of
// hosts. Each line names its own host, and only the host mapping turns that
// name into an identity, so the token vouches for no host.
//
// A full-scope token is refused: an admin credential copied onto a host to
// ship its results would be an admin credential on that host.
func (s *Source) Authenticate(r *http.Request, creds inventory.Credentials) (inventory.Principal, error) {
	tok, err := creds.Token(r)
	if err != nil {
		return inventory.Principal{}, err
	}
	if tok.Scope != audit.ScopeInventory {
		return inventory.Principal{}, &inventory.AuthError{
			Status: http.StatusForbidden, Reason: audit.DenialTokenScope,
			Message: fmt.Sprintf("token scope %q cannot post to %s; mint one with: bodega token create <label> --scope inventory", tok.Scope, r.URL.Path),
		}
	}
	return inventory.Principal{}, nil
}

// Normalize maps osquery result-log NDJSON, one event per line, to reports.
// externalID is empty on the results route, where each line's
// hostIdentifier names its host.
func (*Source) Normalize(doc []byte, externalID string) (inventory.Batch, error) {
	events, err := decodeNDJSON(doc)
	if err != nil {
		return inventory.Batch{}, err
	}
	return normalize(events, externalID)
}

// nodeInvalid is osquery's answer to a credential it should stop using: a
// node told this re-enrolls. The response is the same for every failed
// check; the server log and the denied row say which one failed.
func nodeInvalid(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]bool{"node_invalid": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// deny refuses a remote API request with node_invalid, recording the failed
// check where an operator reads it and the caller cannot.
func (s *Source) deny(w http.ResponseWriter, r *http.Request, env *inventory.RouteEnv, reason, credential, check string, extra map[string]string) {
	details := map[string]string{"credential": credential, "check": check}
	for k, v := range extra {
		details[k] = v
	}
	args := []any{"instance", s.instance, "route", env.Route.Path, "credential", credential, "check", check}
	for k, v := range extra {
		args = append(args, k, v)
	}
	env.Logger().Warn("osquery request refused", args...)
	env.Refuse(r, reason, details)
	nodeInvalid(w)
}

func (s *Source) serveEnroll(w http.ResponseWriter, r *http.Request, env *inventory.RouteEnv) {
	body, ok := env.ReadBody(w, r)
	if !ok {
		return
	}
	var req struct {
		EnrollSecret   string `json:"enroll_secret"`
		HostIdentifier string `json:"host_identifier"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.deny(w, r, env, audit.DenialTokenMissing, "enroll_secret", "malformed request", nil)
		return
	}
	host := truncate(req.HostIdentifier, maxHostIdentifier)
	if req.EnrollSecret == "" {
		s.deny(w, r, env, audit.DenialTokenMissing, "enroll_secret", "no secret presented", map[string]string{"host_identifier": host})
		return
	}
	hash, err := env.HashSecret(req.EnrollSecret)
	if err != nil {
		env.Logger().Error("osquery enroll cannot verify secrets", "instance", s.instance, "error", err)
		s.deny(w, r, env, audit.DenialNoTokens, "enroll_secret", "no pepper loaded", map[string]string{"host_identifier": host})
		return
	}
	ctx := r.Context()
	sec, err := env.DB().OsquerySecretByHash(ctx, s.instance, hash)
	if errors.Is(err, audit.ErrNoOsquerySecret) {
		s.deny(w, r, env, audit.DenialTokenInvalid, "enroll_secret", "unknown or revoked secret", map[string]string{"host_identifier": host})
		return
	}
	if err != nil {
		s.internalError(w, env, "look up enroll secret", err)
		return
	}
	if sec.Expired(env.Now()) {
		s.deny(w, r, env, audit.DenialTokenExpired, "enroll_secret", "secret expired",
			map[string]string{"host_identifier": host, "secret_id": sec.ID, "expired_at": sec.ExpiresAt.UTC().Format(time.RFC3339)})
		return
	}
	key, err := newNodeKey()
	if err != nil {
		s.internalError(w, env, "generate node_key", err)
		return
	}
	digest := KeyDigest(key)
	if err := env.DB().EnrollOsqueryNode(ctx, audit.OsqueryNode{
		Source: s.instance, KeySHA256: digest, SecretID: sec.ID, Identity: sec.Identity, HostIdentifier: host,
	}); errors.Is(err, audit.ErrNoOsquerySecret) {
		s.deny(w, r, env, audit.DenialTokenInvalid, "enroll_secret", "unknown or revoked secret", map[string]string{"host_identifier": host})
		return
	} else if err != nil {
		s.internalError(w, env, "record enrolled node", err)
		return
	}
	env.Logger().Info("osquery node enrolled", "instance", s.instance, "identity", sec.Identity,
		"secret_id", sec.ID, "host_identifier", host, "external_id", digest)
	writeJSON(w, http.StatusOK, map[string]any{"node_key": key, "node_invalid": false})
}

// node resolves a request's node_key, answering node_invalid itself when it
// names no enrolled node.
func (s *Source) node(ctx context.Context, w http.ResponseWriter, r *http.Request, env *inventory.RouteEnv, key string) (audit.OsqueryNode, bool) {
	if key == "" {
		s.deny(w, r, env, audit.DenialTokenMissing, "node_key", "no node_key presented", nil)
		return audit.OsqueryNode{}, false
	}
	n, found, err := env.DB().OsqueryNodeByKey(ctx, s.instance, KeyDigest(key))
	if err != nil {
		s.internalError(w, env, "look up node", err)
		return audit.OsqueryNode{}, false
	}
	if !found {
		s.deny(w, r, env, audit.DenialTokenInvalid, "node_key", "unknown or revoked node_key", nil)
		return audit.OsqueryNode{}, false
	}
	return n, true
}

func (s *Source) serveConfig(w http.ResponseWriter, r *http.Request, env *inventory.RouteEnv) {
	body, ok := env.ReadBody(w, r)
	if !ok {
		return
	}
	var req struct {
		NodeKey string `json:"node_key"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.deny(w, r, env, audit.DenialTokenMissing, "node_key", "malformed request", nil)
		return
	}
	n, ok := s.node(r.Context(), w, r, env, req.NodeKey)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedule": Schedule(s.dirsFor(n.Identity), s.interval)})
}

func (s *Source) dirsFor(identity string) config.OsqueryDirs {
	if s.scanDirs == nil {
		return config.OsqueryDirs{}
	}
	return s.scanDirs(identity)
}

// maxStatusLine bounds a status line as the debug log quotes it.
const maxStatusLine = 1024

func (s *Source) serveLog(w http.ResponseWriter, r *http.Request, env *inventory.RouteEnv) {
	body, ok := env.ReadBody(w, r)
	if !ok {
		return
	}
	var req struct {
		NodeKey string            `json:"node_key"`
		LogType string            `json:"log_type"`
		Data    []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.deny(w, r, env, audit.DenialTokenMissing, "node_key", "malformed request", nil)
		return
	}
	n, ok := s.node(r.Context(), w, r, env, req.NodeKey)
	if !ok {
		return
	}
	switch req.LogType {
	case "status":
		for _, line := range req.Data {
			env.Logger().Debug("osquery status", "instance", s.instance, "identity", n.Identity, "line", truncate(string(line), maxStatusLine))
		}
	case "result":
		events := make([]event, 0, len(req.Data))
		for i, raw := range req.Data {
			var ev event
			if err := json.Unmarshal(raw, &ev); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("data[%d] is not an osquery result event: %v", i, err)})
				return
			}
			events = append(events, ev)
		}
		batch, err := normalize(events, n.KeySHA256)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if len(batch.Reports) > 0 {
			if _, err := env.Ingest(r.Context(), inventory.Principal{ExternalID: n.KeySHA256}, batch); err != nil {
				env.WriteIngestError(w, err)
				return
			}
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("log_type %q is neither \"result\" nor \"status\"", req.LogType)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Source) internalError(w http.ResponseWriter, env *inventory.RouteEnv, what string, err error) {
	env.Logger().Error("osquery request failed", "instance", s.instance, "route", env.Route.Path, "step", what, "error", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

// newNodeKey returns 32 random bytes, hex encoded.
func newNodeKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// KeyDigest is a node_key's sha256, hex encoded: the external id its host's
// reports are stored under, and the only form of the key bodega keeps.
func KeyDigest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
