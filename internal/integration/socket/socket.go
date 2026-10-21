// Package socket is the Socket.dev integration: each version's purl is sent
// to Socket's package API, which scores the published code from static
// analysis and reports alerts with severities. It catches malicious packages
// no advisory names yet. It needs an API token, and the free tier's hourly
// call quota is what the cache and the Retry-After gate protect.
package socket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// Type is the integration type name.
const Type = "socket"

// BaseURL is Socket's API root. It is not a field, because the descriptor
// promises the purl goes to api.socket.dev and nowhere else; a test replaces
// it.
var BaseURL = "https://api.socket.dev/v0/"

// HTTPClient is what the API is called with. A test replaces it.
var HTTPClient = &http.Client{}

// Severities are Socket's alert severities, lowest first. "middle" is
// Socket's word, and the field takes the values the API returns.
var Severities = []string{"low", "middle", "high", "critical"}

// Synthetic alert types Socket returns in place of an analysis. Neither is a
// verdict on the code, so each is an error under the action rather than a
// pass or a hit.
const (
	alertNotFound    = "notFound"
	alertPendingScan = "pendingScan"
)

// defaultRetryAfter applies to a 429 that names no wait.
const defaultRetryAfter = time.Minute

// maxRetryAfter bounds the wait a 429 can impose, so a malformed header
// cannot turn every admission into an error for days.
const maxRetryAfter = time.Hour

// maxResponseBytes bounds one response. One purl's row with alerts is a few
// kilobytes.
const maxResponseBytes = 4 << 20

func init() {
	integration.Register(integration.Descriptor{
		Type:          Type,
		DisplayName:   "Socket.dev",
		VendorURL:     "https://socket.dev/",
		Cost:          integration.CostFreeTier,
		Ecosystems:    []string{manifest.TypeNpm, manifest.TypePypi, manifest.TypeGomod, manifest.TypeCargo},
		DataSent:      "The package's purl (name and version) is sent to api.socket.dev.",
		DefaultAction: policy.ActionWarn,
		Flags:         integration.FlagRisk,
		Fields: []integration.Field{
			{Key: "api_token", Label: "API token", Kind: integration.KindString, Secret: true, Required: true,
				Help: "A Socket organization API token with the packages:list scope."},
			{Key: "min_score", Label: "Minimum score", Kind: integration.KindInt, Max: 100,
				Validate: func(v any) error {
					if n, _ := v.(int64); n < 0 {
						return errors.New("want a whole number from 0 to 100")
					}
					return nil
				},
				Help: "Fail a version whose Socket overall score, from 0 to 100, is below this. Unset or 0 sets no floor."},
			{Key: "fail_alert_severity", Label: "Fail on alert severity", Kind: integration.KindEnum, Default: "critical",
				Options: Severities,
				Help:    "Fail a version carrying any alert at or above this severity: low, middle, high or critical."},
		},
		Probe: integration.Query{Ecosystem: manifest.TypeNpm, Name: "lodash", Version: "4.17.21"},
		New:   newChecker,
	})
}

type checker struct {
	inst     *integration.Instance
	minScore int64
	failAt   int
	now      func() time.Time

	mu sync.Mutex
	// retryAt is when the last 429 allows the next query. Until then every
	// lookup is an error without a request, so a rate-limited instance does
	// not spend the quota it is waiting on.
	retryAt time.Time
}

func newChecker(inst *integration.Instance) (integration.Checker, error) {
	return &checker{inst: inst, minScore: inst.Int("min_score"),
		failAt: slices.Index(Severities, inst.String("fail_alert_severity")), now: time.Now}, nil
}

// artifact is the part of one NDJSON row of /purl this type reads.
type artifact struct {
	Type    string `json:"_type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Score   *struct {
		Overall float64 `json:"overall"`
	} `json:"score"`
	Alerts []alert `json:"alerts"`
}

type alert struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

func (c *checker) Lookup(ctx context.Context, q integration.Query) (integration.Answer, error) {
	c.mu.Lock()
	retryAt := c.retryAt
	c.mu.Unlock()
	if now := c.now(); now.Before(retryAt) {
		return integration.Answer{}, fmt.Errorf("rate limited by Socket: Retry-After allows the next query at %s", retryAt.UTC().Format(time.RFC3339))
	}
	// Read on every query rather than once at build, so a rotated token
	// takes effect without a config change.
	token, _, err := c.inst.Secret("api_token")
	if err != nil {
		return integration.Answer{}, err
	}
	body, _ := json.Marshal(map[string]any{"components": []map[string]string{{"purl": q.PURL()}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL+"purl?alerts=true", bytes.NewReader(body))
	if err != nil {
		return integration.Answer{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return integration.Answer{}, fmt.Errorf("query Socket: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := retryAfter(resp.Header.Get("Retry-After"), c.now())
		c.mu.Lock()
		c.retryAt = c.now().Add(wait)
		c.mu.Unlock()
		return integration.Answer{}, fmt.Errorf("rate limited by Socket (429); next query in %s", wait)
	case resp.StatusCode != http.StatusOK:
		return integration.Answer{}, fmt.Errorf("query Socket: %s", resp.Status)
	}
	a, err := readArtifact(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return integration.Answer{}, fmt.Errorf("query Socket for %s: %w", q.PURL(), err)
	}
	return c.judge(a), nil
}

// retryAfter reads a Retry-After header in either of its forms, seconds or
// an HTTP date, bounded to [0, maxRetryAfter].
func retryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return defaultRetryAfter
	}
	var d time.Duration
	if n, err := strconv.ParseInt(h, 10, 64); err == nil {
		d = time.Duration(min(n, int64(maxRetryAfter/time.Second))) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = t.Sub(now)
	} else {
		return defaultRetryAfter
	}
	return min(max(d, 0), maxRetryAfter)
}

func readArtifact(r io.Reader) (artifact, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxResponseBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var a artifact
		if err := json.Unmarshal(line, &a); err != nil {
			return artifact{}, fmt.Errorf("want newline-delimited JSON: %w", err)
		}
		if a.Type != "" {
			continue
		}
		for _, al := range a.Alerts {
			switch al.Type {
			case alertNotFound:
				return artifact{}, errors.New("socket could not resolve the package version")
			case alertPendingScan:
				return artifact{}, errors.New("socket has not finished analyzing the package version")
			}
		}
		return a, nil
	}
	if err := sc.Err(); err != nil {
		return artifact{}, err
	}
	return artifact{}, errors.New("the response carried no package row")
}

// judge turns Socket's row into an answer. The reason names the score and
// every alert whether or not it fails, because it becomes the admission
// row's detail.
func (c *checker) judge(a artifact) integration.Answer {
	var why []string
	score := "no score"
	if a.Score != nil {
		pct := int64(math.Round(a.Score.Overall * 100))
		score = fmt.Sprintf("score %d/100", pct)
		if c.minScore > 0 && pct < c.minScore {
			why = append(why, fmt.Sprintf("score %d is below min_score %d", pct, c.minScore))
		}
	}
	alerts := make([]string, 0, len(a.Alerts))
	for _, al := range a.Alerts {
		alerts = append(alerts, al.Type+" ("+al.Severity+")")
		if sev := slices.Index(Severities, al.Severity); sev >= 0 && sev >= c.failAt {
			why = append(why, fmt.Sprintf("%s alert %s", al.Severity, al.Type))
		}
	}
	listed := "no alerts"
	if len(alerts) > 0 {
		listed = "alerts: " + strings.Join(alerts, ", ")
	}
	summary := score + "; " + listed
	if len(why) == 0 {
		return integration.Answer{Reason: summary}
	}
	return integration.Answer{Flagged: true,
		Reason: "Socket: " + strings.Join(why, ", ") + " (" + summary + ")"}
}
