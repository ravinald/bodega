package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/logging"
)

// The one moment a token can be read is the response to its own creation, so
// handleCreateToken puts the plaintext in the body. At log_level 4 the trace
// body capture wrote that into the journal, and the tokens carry no scope, so
// a journal the journal group can read was a write credential. F11 closed the
// header channel; this is the sibling one function above it.
func TestTraceBodyCaptureRedactsTheIssuedToken(t *testing.T) {
	const token = "bodega_ak_22e74efc83a51511d1c51f615e6c32fe4daaeaf54d34701107ad82f4a5ac7824" //nolint:gosec // G101: the value under test is that this never reaches the log
	const id = "7e308f80d89a57c81cefc5e18160731e"

	var buf bytes.Buffer
	logger := newTestLogger(&buf, logging.LevelTrace)

	// The body handleCreateToken writes (internal/server/server.go).
	issue := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"token": token,
			"id":    id,
			"label": "trace-probe",
		})
	})

	handler := RequestLogger(logger)(issue)
	req := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"label":"trace-probe"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), token) {
		t.Fatal("the handler no longer returns the token; this test is asserting the wrong body")
	}

	log := buf.String()
	if strings.Contains(log, token) {
		t.Errorf("plaintext token written to the log:\n%s", log)
	}
	if !strings.Contains(log, "resp_body") {
		t.Errorf("response body withheld entirely; redaction should keep the rest of it:\n%s", log)
	}
	for _, keep := range []string{id, "trace-probe"} {
		if !strings.Contains(log, keep) {
			t.Errorf("redaction dropped %q, which is not a credential:\n%s", keep, log)
		}
	}
	if !strings.Contains(log, "[redacted]") {
		t.Errorf("token value replaced with nothing rather than a marker:\n%s", log)
	}
}

// A truncated or malformed JSON body is scrubbed against the same key set
// rather than withheld. maxBodyCapture truncates at 64KB, and a handler can
// answer with a JSON content type over something that is not JSON; both are
// what trace level exists to show, so the body survives and the credential
// does not.
func TestTraceBodyCaptureScrubsUnparsableJSON(t *testing.T) {
	const token = "bodega_ak_deadbeef" //nolint:gosec // G101: a fixture, not a credential

	var buf bytes.Buffer
	logger := newTestLogger(&buf, logging.LevelTrace)

	truncated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"abc","token":"` + token))
	})

	handler := RequestLogger(logger)(truncated)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/tokens", nil))

	log := buf.String()
	if strings.Contains(log, token) {
		t.Errorf("truncated JSON body logged verbatim, carrying the credential:\n%s", log)
	}
	if !strings.Contains(log, "resp_body") {
		t.Errorf("body withheld; a malformed body is what trace level is for:\n%s", log)
	}
	if !strings.Contains(log, "abc") {
		t.Errorf("scrub dropped a non-credential field:\n%s", log)
	}
}

// The scrub runs on the raw bytes, so it is asserted directly on the shapes a
// truncated capture produces.
func TestRedactBodyScrubsWithoutAParse(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"cut mid-value", `{"token":"bodega_ak_secretvalue`},
		{"cut at the closing quote", `{"token":"bodega_ak_secretvalue"`},
		{"trailing garbage", `{"token":"bodega_ak_secretvalue"} <<<`},
		{"uppercase key", `{"Token":"bodega_ak_secretvalue"`},
		{"escaped quote in value", `{"secret":"bodega_ak_\"secretvalue"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactBody("application/json", []byte(tc.in))
			if strings.Contains(got, "secretvalue") {
				t.Errorf("credential survived the scrub: %s", got)
			}
			if !strings.Contains(got, redactedValue) {
				t.Errorf("value dropped rather than marked: %s", got)
			}
		})
	}
}

// A credential nested under a wrapper is the same credential.
func TestRedactBodyWalksNestedDocuments(t *testing.T) {
	in := []byte(`{"data":{"items":[{"name":"a","secret":"s3cr3t"}],"Token":"tok"},"ok":true}`)
	got := redactBody("application/json", in)
	for _, leaked := range []string{"s3cr3t", "tok"} {
		if strings.Contains(got, leaked) {
			t.Errorf("leaked %q: %s", leaked, got)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("redacted body is not valid JSON: %v (%s)", err, got)
	}
	if !strings.Contains(got, `"name":"a"`) {
		t.Errorf("redaction dropped a non-credential field: %s", got)
	}
}

// Non-JSON bodies pass through, which is what they did before redaction
// existed: there is no key to match on and withholding every text body would
// make trace level useless.
func TestRedactBodyPassesNonJSONThrough(t *testing.T) {
	if got := redactBody("text/plain", []byte("plain text body")); got != "plain text body" {
		t.Errorf("redactBody(text/plain) = %q", got)
	}
}
