package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// importBodyLimit is the ceiling for a bulk push. The single-package route
// caps at 1 MiB, which a host catalog clears without trying: one Ubuntu server
// carries 635 apt packages and a container host carries several thousand
// across types. The limit is still here because an unbounded decode is an
// unbounded allocation.
const importBodyLimit = 64 << 20

// ImportOutcome is what happened to one manifest in a bulk push.
type ImportOutcome string

const (
	ImportImported      ImportOutcome = "imported"
	ImportMerged        ImportOutcome = "merged"
	ImportConflict      ImportOutcome = "conflict"
	ImportInvalid       ImportOutcome = "invalid"
	ImportPolicyBlocked ImportOutcome = "policy_blocked"
	ImportFailed        ImportOutcome = "failed"
)

// ImportResult reports one manifest's fate. A bulk push reports per package
// rather than failing whole: one already-present package in a 2000-package
// catalog must not discard the other 1999.
type ImportResult struct {
	Type     string        `json:"type"`
	Name     string        `json:"name"`
	Outcome  ImportOutcome `json:"outcome"`
	Reason   string        `json:"reason,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

// ImportResponse is the body of a bulk import.
type ImportResponse struct {
	Imported int            `json:"imported"`
	Merged   int            `json:"merged"`
	Skipped  int            `json:"skipped"`
	Results  []ImportResult `json:"results"`
}

// handleBulkImport accepts a whole host's catalog in one request.
//
// It is a separate route from POST /api/v1/packages/{type} rather than an
// array body on that one, because the two want opposite semantics: a single
// create is all-or-nothing and answers 409 on a name clash, while a bulk push
// is expected to land partially and must say which packages did.
//
// The path is literal, so Go's mux prefers it over the {type} wildcard. No
// package type is named "import", so nothing is shadowed.
func (s *Server) handleBulkImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	merge := r.URL.Query().Get("merge") == "true"

	s.mu.Lock()
	defer s.mu.Unlock()

	r.Body = http.MaxBytesReader(w, r.Body, importBodyLimit)

	// A leading '[' means one JSON array; anything else means a stream of
	// concatenated objects (NDJSON). Peeking rather than decoding the whole
	// body keeps both shapes on the same one-manifest-at-a-time path, so a
	// large catalog never lands in memory whole.
	br := bufio.NewReader(r.Body)
	lead, err := peekNonSpace(br)
	if err != nil {
		writeJSON(w, importDecodeStatus(err), map[string]string{"error": importDecodeMessage(err)})
		return
	}
	array := lead == '['
	dec := json.NewDecoder(br)
	if array {
		if _, err := dec.Token(); err != nil {
			writeJSON(w, importDecodeStatus(err), map[string]string{"error": importDecodeMessage(err)})
			return
		}
	}

	resp := ImportResponse{Results: []ImportResult{}}
	// An array ends at its closing bracket; an NDJSON stream ends at EOF,
	// which Decode reports below.
	for !array || dec.More() {
		var pm manifest.PackageManifest
		if err := dec.Decode(&pm); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			writeJSON(w, importDecodeStatus(err), map[string]string{"error": importDecodeMessage(err)})
			return
		}
		resp.record(s.importOne(ctx, &pm, merge))
	}

	if err := s.store.SaveIndex(ctx); err != nil {
		s.logger.Error("save index failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	s.rebuildAptIndexAfterImport(ctx, resp.Results)

	// 200 even when some packages were refused: a partial landing is the
	// expected shape here, and the per-package results say what happened.
	writeJSON(w, http.StatusOK, resp)
}

// importOne runs the shared admit path and writes, mirroring what
// 'bodega pkg import' does locally so the two surfaces cannot disagree.
func (s *Server) importOne(ctx context.Context, pm *manifest.PackageManifest, merge bool) ImportResult {
	out := ImportResult{Type: pm.Type, Name: pm.Name}

	if !manifest.IsKnownType(pm.Type) {
		out.Outcome, out.Reason = ImportInvalid, fmt.Sprintf("unknown type %q", pm.Type)
		return out
	}
	res := admit.Admit(ctx, s.policy, s.auditDB, s.cfg, pm, "")
	out.Warnings = res.Warnings
	switch res.Decision {
	case admit.Invalid:
		out.Outcome, out.Reason = ImportInvalid, res.Reason
		return out
	case admit.PolicyBlocked:
		out.Outcome, out.Reason = ImportPolicyBlocked, res.Reason
		return out
	}

	existing, _ := s.store.GetPackage(ctx, pm.Type, pm.Name)
	if existing != nil && !merge {
		out.Outcome, out.Reason = ImportConflict, "package already exists (retry with merge=true to add versions)"
		return out
	}

	target := pm
	outcome := ImportImported
	if existing != nil {
		mergeVersions(existing, pm)
		target = existing
		outcome = ImportMerged
	} else {
		pm.ConfigVersion = manifest.CurrentConfigVersion
	}

	if err := s.store.SavePackage(ctx, target); err != nil {
		s.logger.Error("bulk import save failed", "type", pm.Type, "name", pm.Name, "error", err)
		out.Outcome, out.Reason = ImportFailed, "save failed"
		return out
	}
	if s.auditDB != nil {
		blob, _ := json.MarshalIndent(target, "", "  ")
		_ = s.auditDB.Record(ctx, audit.Event{
			EventType: audit.EventCreate,
			PkgType:   pm.Type,
			PkgName:   pm.Name,
			Status:    "success",
			Details:   audit.FormatDiff(nil, blob),
		})
	}
	out.Outcome = outcome
	return out
}

// mergeVersions adds versions the stored package does not carry. An existing
// version is never overwritten, which is what keeps a hosted entry from being
// downgraded to proxy by a re-import of the host that first named it.
func mergeVersions(existing, incoming *manifest.PackageManifest) {
	for _, ve := range incoming.Versions {
		found := false
		for _, have := range existing.Versions {
			if have.Version == ve.Version {
				found = true
				break
			}
		}
		if !found {
			existing.Versions = append(existing.Versions, ve)
		}
	}
}

func (resp *ImportResponse) record(res ImportResult) {
	switch res.Outcome {
	case ImportImported:
		resp.Imported++
	case ImportMerged:
		resp.Merged++
	default:
		resp.Skipped++
	}
	resp.Results = append(resp.Results, res)
}

// rebuildAptIndexAfterImport regenerates the apt snapshot once, if any apt
// entry landed. Rebuilding per package would regenerate it 600 times for one
// host import.
func (s *Server) rebuildAptIndexAfterImport(ctx context.Context, results []ImportResult) {
	for _, res := range results {
		if res.Type != manifest.TypeApt {
			continue
		}
		if res.Outcome == ImportImported || res.Outcome == ImportMerged {
			s.rebuildAptIndexAfterWrite(ctx, manifest.TypeApt)
			return
		}
	}
}

func importDecodeStatus(err error) int {
	if err.Error() == "http: request body too large" {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func importDecodeMessage(err error) string {
	if err.Error() == "http: request body too large" {
		return fmt.Sprintf("request body too large (limit %d bytes); split the catalog or push it as NDJSON in batches", importBodyLimit)
	}
	return "invalid request body: expected a JSON array of package manifests, or one manifest per line"
}

// peekNonSpace returns the first byte that is not JSON whitespace, leaving it
// unread so the decoder sees the whole value.
func peekNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return 0, err
		}
		switch b[0] {
		case ' ', '\t', '\n', '\r':
			if _, err := br.ReadByte(); err != nil {
				return 0, err
			}
		default:
			return b[0], nil
		}
	}
}
