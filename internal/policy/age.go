package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// AgeStore is the subset of audit.DB the age checker needs. Tests can supply
// an in-memory fake without pulling in the full DB.
type AgeStore interface {
	GetAgePolicy(ctx context.Context, ecosystem string) (audit.AgePolicy, error)
}

// AgeChecker rejects (or warns on) versions whose upstream publish timestamp
// is newer than the ecosystem's min-age policy. Ecosystems where an upstream
// timestamp isn't reliably retrievable (apt/binary/git/helm) short-circuit
// to pass; operators see this as a no-op there.
type AgeChecker struct {
	store AgeStore

	// Endpoints can be overridden in tests.
	NpmRegistry string
	PypiBase    string
	GoProxy     string

	// HTTP gets a conservative timeout so a slow upstream doesn't stall
	// admission.
	HTTP *http.Client
	Now  func() time.Time
}

func NewAgeChecker(store AgeStore) *AgeChecker {
	return &AgeChecker{
		store:       store,
		NpmRegistry: "https://registry.npmjs.org",
		PypiBase:    "https://pypi.org",
		GoProxy:     "https://proxy.golang.org",
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		Now:         time.Now,
	}
}

func (c *AgeChecker) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result {
	if pm == nil || ve == nil {
		return Result{Check: "age", Action: ActionPass}
	}

	policy, err := c.store.GetAgePolicy(ctx, pm.Type)
	if errors.Is(err, audit.ErrAgePolicyNotFound) {
		return Result{Check: "age", Action: ActionPass}
	}
	if err != nil {
		return Result{Check: "age", Action: ActionWarn,
			Reason: "load age policy: " + err.Error()}
	}
	if policy.Action == ActionIgnore {
		return Result{Check: "age", Action: ActionPass}
	}

	version := ve.Version
	if version == "" {
		return Result{Check: "age", Action: ActionPass,
			Reason: "no Version set; age gate is version-aware"}
	}

	publishedAt, err := c.publishedAt(ctx, pm.Type, pm.Name, version)
	if err != nil {
		// Not having an upstream timestamp shouldn't fail-closed; short-circuit
		// with a warn that shows up in the audit but doesn't block.
		return Result{Check: "age", Action: ActionWarn,
			Reason: fmt.Sprintf("upstream timestamp unavailable for %s/%s@%s: %v", pm.Type, pm.Name, version, err)}
	}

	age := c.Now().Sub(publishedAt)
	minAge := time.Duration(policy.MinAgeSeconds) * time.Second
	if age >= minAge {
		return Result{Check: "age", Action: ActionPass,
			Details: map[string]any{"published_at": publishedAt.UTC().Format(time.RFC3339), "age_seconds": int64(age.Seconds())}}
	}

	return Result{
		Check:  "age",
		Action: policy.Action,
		Reason: fmt.Sprintf("%s@%s is %s old, policy requires %s",
			pm.Name, version, shortDuration(age), shortDuration(minAge)),
		Details: map[string]any{
			"published_at":   publishedAt.UTC().Format(time.RFC3339),
			"age_seconds":    int64(age.Seconds()),
			"min_age_seconds": policy.MinAgeSeconds,
		},
	}
}

// publishedAt returns the upstream publish timestamp for a given ecosystem's
// package version. Returns an error for ecosystems without a known upstream
// timestamp endpoint.
func (c *AgeChecker) publishedAt(ctx context.Context, ecosystem, name, version string) (time.Time, error) {
	switch ecosystem {
	case manifest.TypeNpm:
		return c.npmPublishedAt(ctx, name, version)
	case manifest.TypePypi:
		return c.pypiPublishedAt(ctx, name, version)
	case manifest.TypeGomod:
		return c.gomodPublishedAt(ctx, name, version)
	}
	return time.Time{}, fmt.Errorf("ecosystem %q has no upstream timestamp source", ecosystem)
}

func (c *AgeChecker) npmPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	url := c.NpmRegistry + "/" + name
	var doc struct {
		Time map[string]string `json:"time"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	ts, ok := doc.Time[version]
	if !ok {
		return time.Time{}, fmt.Errorf("npm packument has no time entry for %s", version)
	}
	return time.Parse(time.RFC3339Nano, ts)
}

func (c *AgeChecker) pypiPublishedAt(ctx context.Context, name, version string) (time.Time, error) {
	// PyPI JSON API: /pypi/{name}/{version}/json; upload_time_iso_8601 lives
	// under urls[].upload_time_iso_8601. Use the earliest.
	url := c.PypiBase + "/pypi/" + name + "/" + version + "/json"
	var doc struct {
		URLs []struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	if len(doc.URLs) == 0 {
		return time.Time{}, fmt.Errorf("pypi response for %s@%s has no urls[]", name, version)
	}
	var earliest time.Time
	for _, u := range doc.URLs {
		if u.UploadTime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, u.UploadTime)
		if err != nil {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("pypi response for %s@%s has no parseable upload_time", name, version)
	}
	return earliest, nil
}

func (c *AgeChecker) gomodPublishedAt(ctx context.Context, module, version string) (time.Time, error) {
	url := c.GoProxy + "/" + strings.ToLower(module) + "/@v/" + version + ".info"
	var doc struct {
		Time string `json:"Time"`
	}
	if err := c.getJSON(ctx, url, &doc); err != nil {
		return time.Time{}, err
	}
	if doc.Time == "" {
		return time.Time{}, fmt.Errorf("gomod .info has no Time field for %s@%s", module, version)
	}
	return time.Parse(time.RFC3339Nano, doc.Time)
}

func (c *AgeChecker) getJSON(ctx context.Context, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

func shortDuration(d time.Duration) string {
	days := int64(d / (24 * time.Hour))
	if days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int64(d / time.Hour)
	if hours >= 1 {
		return fmt.Sprintf("%dh", hours)
	}
	return d.Round(time.Second).String()
}
