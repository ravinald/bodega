package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// OSVStore is the subset of audit.DB the OSV checker needs.
type OSVStore interface {
	GetOSVPolicy(ctx context.Context, ecosystem string) (audit.OSVPolicy, error)
}

// osvEcosystemFor maps bodega's registry types to OSV's ecosystem identifiers.
// Ecosystems without an OSV equivalent short-circuit to pass.
var osvEcosystemFor = map[string]string{
	manifest.TypeNpm:   "npm",
	manifest.TypePypi:  "PyPI",
	manifest.TypeGomod: "Go",
}

type OSVChecker struct {
	store OSVStore

	Endpoint string // defaults to https://api.osv.dev/v1/query
	HTTP     *http.Client
}

func NewOSVChecker(store OSVStore) *OSVChecker {
	return &OSVChecker{
		store:    store,
		Endpoint: "https://api.osv.dev/v1/query",
		HTTP:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *OSVChecker) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result {
	if pm == nil || ve == nil || ve.Version == "" {
		return Result{Check: "osv", Action: ActionPass}
	}
	osvEco, ok := osvEcosystemFor[pm.Type]
	if !ok {
		return Result{Check: "osv", Action: ActionPass}
	}

	policy, err := c.store.GetOSVPolicy(ctx, pm.Type)
	if errors.Is(err, audit.ErrOSVPolicyNotFound) {
		return Result{Check: "osv", Action: ActionPass}
	}
	if err != nil {
		return Result{Check: "osv", Action: ActionWarn, Reason: "load osv policy: " + err.Error()}
	}
	if policy.Action == ActionIgnore {
		return Result{Check: "osv", Action: ActionPass}
	}

	vulns, err := c.query(ctx, osvEco, pm.Name, ve.Version)
	if err != nil {
		return Result{Check: "osv", Action: ActionWarn,
			Reason: fmt.Sprintf("osv query failed for %s/%s@%s: %v", pm.Type, pm.Name, ve.Version, err)}
	}
	if len(vulns) == 0 {
		return Result{Check: "osv", Action: ActionPass}
	}

	// Stamp onto VersionEntry.Metadata so the knowledge follows the version.
	ids := vulnIDs(vulns)
	if ve.Metadata == nil {
		ve.Metadata = map[string]string{}
	}
	ve.Metadata["vetting.osv.vulns"] = strings.Join(ids, ",")

	return Result{
		Check:  "osv",
		Action: policy.Action,
		Reason: fmt.Sprintf("%s@%s has %d OSV record(s): %s",
			pm.Name, ve.Version, len(vulns), strings.Join(ids, ", ")),
		Details: map[string]any{
			"vulns": ids,
			"count": len(vulns),
		},
	}
}

type osvVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

func (c *OSVChecker) query(ctx context.Context, ecosystem, name, version string) ([]osvVuln, error) {
	body, _ := json.Marshal(map[string]any{
		"package": map[string]string{"name": name, "ecosystem": ecosystem},
		"version": version,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: HTTP %d", c.Endpoint, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse osv response: %w", err)
	}
	return out.Vulns, nil
}

func vulnIDs(vs []osvVuln) []string {
	ids := make([]string, 0, len(vs))
	for _, v := range vs {
		if v.ID != "" {
			ids = append(ids, v.ID)
		}
	}
	sort.Strings(ids)
	return ids
}
