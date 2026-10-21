// Package socket is the Socket.dev integration: every uncached version's purl
// in one admission is sent to Socket's package API in one request, up to 1024
// purls per request, and Socket scores the published code from static
// analysis and reports alerts with severities. It catches malicious packages
// no advisory names yet. It needs an API token. Socket charges quota units
// per request whatever it carries, and the free tier's hourly quota units are
// what the batching, the cache and the Retry-After gate protect.
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

// maxRowBytes bounds one NDJSON row. One purl's row with alerts is a few
// kilobytes.
const maxRowBytes = 4 << 20

// maxBytesPerPURL is what each purl in a request adds to the response bound,
// so a full chunk of rows with alerts is read whole while a stuck or hostile
// server still cannot stream without end.
const maxBytesPerPURL = 1 << 20

// batchLimit is the most purls one POST /v0/purl carries. Socket refuses a
// larger request with a 400: "batch size limit (default: 1024 PURLs per
// request)", https://docs.socket.dev/reference/batchpackagefetch.
const batchLimit = 1024

func init() {
	integration.Register(integration.Descriptor{
		Type:          Type,
		DisplayName:   "Socket.dev",
		VendorURL:     "https://socket.dev/",
		Cost:          integration.CostFreeTier,
		Ecosystems:    []string{manifest.TypeNpm, manifest.TypePypi, manifest.TypeGomod, manifest.TypeCargo},
		DataSent:      "The purl (name and version) of every uncached version in one admission is sent to api.socket.dev, up to 1024 per request.",
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

var _ integration.BatchChecker = (*checker)(nil)

func newChecker(inst *integration.Instance) (integration.Checker, error) {
	return &checker{inst: inst, minScore: inst.Int("min_score"),
		failAt: slices.Index(Severities, inst.String("fail_alert_severity")), now: time.Now}, nil
}

// artifact is the part of one NDJSON row of /purl this type reads.
type artifact struct {
	Type      string `json:"_type"`
	InputPURL string `json:"inputPurl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Score     *struct {
		Overall float64 `json:"overall"`
	} `json:"score"`
	Alerts []alert `json:"alerts"`
}

type alert struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

// Lookup is the one-query case of LookupBatch, for `bodega integration test`
// and every surface that admits one version.
func (c *checker) Lookup(ctx context.Context, q integration.Query) (integration.Answer, error) {
	r := c.LookupBatch(ctx, []integration.Query{q})[q.PURL()]
	return r.Answer, r.Err
}

func (c *checker) BatchLimit() int { return batchLimit }

// LookupBatch sends every query's purl in one request. A failure of the
// request itself (a 429, a 5xx, the network, a body that is not NDJSON) is
// the error for every query; a row Socket could not analyze is the error for
// its own purl.
func (c *checker) LookupBatch(ctx context.Context, qs []integration.Query) map[string]integration.BatchResult {
	out := make(map[string]integration.BatchResult, len(qs))
	fail := func(err error) map[string]integration.BatchResult {
		for _, q := range qs {
			out[q.PURL()] = integration.BatchResult{Err: err}
		}
		return out
	}
	c.mu.Lock()
	retryAt := c.retryAt
	c.mu.Unlock()
	if now := c.now(); now.Before(retryAt) {
		return fail(fmt.Errorf("rate limited by Socket: Retry-After allows the next query at %s", retryAt.UTC().Format(time.RFC3339)))
	}
	// Read on every query rather than once at build, so a rotated token
	// takes effect without a config change.
	token, _, err := c.inst.Secret("api_token")
	if err != nil {
		return fail(err)
	}
	components := make([]map[string]string, 0, len(qs))
	for _, q := range qs {
		components = append(components, map[string]string{"purl": q.PURL()})
	}
	body, _ := json.Marshal(map[string]any{"components": components})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL+"purl?alerts=true", bytes.NewReader(body))
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-ndjson")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return fail(fmt.Errorf("query Socket: %w", err))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := retryAfter(resp.Header.Get("Retry-After"), c.now())
		c.mu.Lock()
		c.retryAt = c.now().Add(wait)
		c.mu.Unlock()
		return fail(fmt.Errorf("rate limited by Socket (429); next query in %s", wait))
	case resp.StatusCode != http.StatusOK:
		return fail(fmt.Errorf("query Socket: %s", resp.Status))
	}
	limit := max(int64(maxRowBytes), int64(len(qs))*maxBytesPerPURL)
	rows, err := readRows(io.LimitReader(resp.Body, limit))
	if err != nil {
		return fail(fmt.Errorf("query Socket: %w", err))
	}
	for _, q := range qs {
		purl := q.PURL()
		r, ok := rows[purl]
		switch {
		case !ok:
			out[purl] = integration.BatchResult{Err: fmt.Errorf("query Socket for %s: the response carried no package row for it", purl)}
		case r.err != nil:
			out[purl] = integration.BatchResult{Err: fmt.Errorf("query Socket for %s: %w", purl, r.err)}
		default:
			out[purl] = integration.BatchResult{Answer: c.judge(r.artifact)}
		}
	}
	return out
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

type purlRow struct {
	artifact artifact
	err      error
}

// readRows reads the NDJSON response keyed by inputPurl, the purl as sent.
// Socket documents neither row order nor a usable batchIndex, so the key is
// the only way to tell which row answers which query.
func readRows(r io.Reader) (map[string]purlRow, error) {
	rows := map[string]purlRow{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxRowBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var a artifact
		if err := json.Unmarshal(line, &a); err != nil {
			return nil, fmt.Errorf("want newline-delimited JSON: %w", err)
		}
		if a.Type != "" {
			continue
		}
		if _, dup := rows[a.InputPURL]; dup {
			continue
		}
		rows[a.InputPURL] = purlRow{artifact: a, err: unanalyzed(a)}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// unanalyzed is why a row carries no verdict on the code, or nil when it
// does.
func unanalyzed(a artifact) error {
	for _, al := range a.Alerts {
		switch al.Type {
		case alertNotFound:
			return errors.New("socket could not resolve the package version")
		case alertPendingScan:
			return errors.New("socket has not finished analyzing the package version")
		}
	}
	return nil
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
