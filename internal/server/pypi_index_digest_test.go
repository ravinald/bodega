package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

const (
	digestDist     = "sixdigest"
	digestWheel    = "sixdigest-1.0.0-py3-none-any.whl"
	digestWheelRel = "/files/12/34/" + digestWheel
)

// digestIndexServer is a proxy for one wheel whose simple index lists it with
// the given fragment ("" for none).
func digestIndexServer(t *testing.T, fragment string) (*Server, *recordingUpstream, *syncBuffer) {
	t.Helper()
	s := proxyingServer(t)
	var buf syncBuffer
	s.logger = slog.New(slog.NewTextHandler(&buf, nil))
	up := newRecordingUpstream(t)
	href := up.ts.URL + digestWheelRel
	if fragment != "" {
		href += "#" + fragment
	}
	up.route("/simple/"+digestDist+"/", fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s">%s</a></body></html>`, href, digestWheel))
	up.route(digestWheelRel, wheelBytes)
	s.cfg.PypiUpstream = up.ts.URL
	addVersion(t, s, manifest.TypePypi, digestDist, manifest.VersionEntry{
		Version: "1.0.0", URL: up.ts.URL, Mode: manifest.ModeProxy,
	})
	return s, up, &buf
}

func wheelSHA256() string {
	sum := sha256.Sum256([]byte(wheelBytes))
	return hex.EncodeToString(sum[:])
}

func digestWheelCached(t *testing.T, s *Server) bool {
	t.Helper()
	st, err := s.typeStore(manifest.TypePypi).Head(t.Context(), "pypi/wheels/"+digestWheel)
	if err != nil {
		t.Fatalf("head the cached wheel: %v", err)
	}
	return st != nil && st.Exists
}

// B190: bytes the index's own #sha256= does not vouch for are refused before
// they are pinned, cached or served, and the next request goes upstream again.
func TestPypiWheelDifferingFromIndexDigestIsRefusedAndNotCached(t *testing.T) {
	listed := strings.Repeat("ab", 32)
	s, up, logs := digestIndexServer(t, "sha256="+listed)

	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+digestWheel)
	if status != http.StatusBadGateway {
		t.Fatalf("GET a wheel whose bytes differ from the index digest = %d, want 502 (body %q)", status, body)
	}
	for _, want := range []string{digestWheel, listed, wheelSHA256(), up.ts.URL + "/simple/" + digestDist + "/", "report it to the upstream", "nothing was cached"} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal body names no %q:\n%s", want, body)
		}
	}
	if digestWheelCached(t, s) {
		t.Error("the refused wheel was written to the cache")
	}
	if s.auditDB != nil {
		if pinned, err := s.auditDB.GetChecksum(t.Context(), "pypi/wheels/"+digestWheel); err != nil || (pinned != nil && pinned.Value != "") {
			t.Errorf("checksum of record after a refusal = %+v (err %v), want none pinned", pinned, err)
		}
	}
	log := logs.String()
	if !strings.Contains(log, listed) || !strings.Contains(log, wheelSHA256()) {
		t.Errorf("operator log does not carry both digests:\n%s", log)
	}

	if status, _ := getStatusAndBody(t, s, "/pypi/wheels/"+digestWheel); status != http.StatusBadGateway {
		t.Errorf("second GET = %d, want 502 again", status)
	}
	if n := up.hits(digestWheelRel); n != 2 {
		t.Errorf("upstream served the wheel %d time(s), want 2: a refusal must leave nothing for the second request to hit", n)
	}
}

func TestPypiWheelMatchingIndexDigestIsServedAndCached(t *testing.T) {
	s, _, _ := digestIndexServer(t, "sha256="+strings.ToUpper(wheelSHA256()))

	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+digestWheel)
	if status != http.StatusOK || body != wheelBytes {
		t.Fatalf("GET a wheel matching the index digest = %d %q, want 200 and the wheel", status, body)
	}
	if !digestWheelCached(t, s) {
		t.Error("the verified wheel was not cached")
	}
}

func TestPypiWheelWithNoIndexSHA256FillsAndSaysSo(t *testing.T) {
	for _, fragment := range []string{"", "md5=0123456789abcdef0123456789abcdef"} {
		t.Run("fragment="+fragment, func(t *testing.T) {
			s, _, logs := digestIndexServer(t, fragment)

			status, body := getStatusAndBody(t, s, "/pypi/wheels/"+digestWheel)
			if status != http.StatusOK || body != wheelBytes {
				t.Fatalf("GET a wheel the index lists with no sha256 = %d %q, want 200 and the wheel", status, body)
			}
			if !strings.Contains(logs.String(), "the pypi index named no sha256 for this file") {
				t.Errorf("log does not say the index named no sha256:\n%s", logs.String())
			}
		})
	}
}
