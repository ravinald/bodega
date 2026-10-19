package server

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
)

func TestFaviconMatchesAsset(t *testing.T) {
	want, err := os.ReadFile("../../assets/favicon.ico")
	if err != nil {
		t.Fatalf("read the asset the embedded copy must equal: %v", err)
	}
	s := newDenialServer(t, []string{"127.0.0.1/32"}, nil)

	rec := doRequest(s, "GET", "/favicon.ico", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("Content-Type = %q, want image/x-icon", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=") || strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want a cacheable response", cc)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Errorf("served favicon (%d bytes) differs from assets/favicon.ico (%d bytes); copy the asset into internal/server/web",
			rec.Body.Len(), len(want))
	}
}

// The favicon must answer exactly as the page does under each auth setup, so
// it opens no path the page does not. Comparing the two responses rather than
// hard-coding codes keeps the test true when the read posture changes.
func TestFaviconAnswersAsRootDoes(t *testing.T) {
	cases := []struct {
		name     string
		admin    []string
		deny     []string
		withTok  bool
		clientIP string
	}{
		{"loopback-only, no token", []string{"127.0.0.1/32"}, nil, false, "127.0.0.1"},
		{"widened with tokens, no token sent", []string{"10.0.0.0/8"}, nil, true, "10.0.0.5"},
		{"client on the deny list", []string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}, true, "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newDenialServer(t, tc.admin, tc.deny)
			if tc.withTok {
				insertToken(t, s, "tok-present", "secret-token", nil)
			}
			hdr := map[string]string{"X-Real-IP": tc.clientIP}

			before := allEvents(t, s)
			root := doRequest(s, "GET", "/", hdr)
			afterRoot := allEvents(t, s)
			fav := doRequest(s, "GET", "/favicon.ico", hdr)
			afterFav := allEvents(t, s)

			if fav.Code != root.Code {
				t.Errorf("GET /favicon.ico = %d, GET / = %d; the favicon must answer as the page does", fav.Code, root.Code)
			}
			byRoot := afterRoot[:len(afterRoot)-len(before)]
			byFav := afterFav[:len(afterFav)-len(afterRoot)]
			if len(byFav) != len(byRoot) {
				t.Fatalf("GET / wrote %d audit rows, GET /favicon.ico wrote %d", len(byRoot), len(byFav))
			}
			for i := range byFav {
				if byFav[i].EventType != byRoot[i].EventType || byFav[i].Status != byRoot[i].Status {
					t.Errorf("row %d: favicon wrote %s/%s, page wrote %s/%s", i,
						byFav[i].EventType, byFav[i].Status, byRoot[i].EventType, byRoot[i].Status)
				}
			}
		})
	}
}

func TestIndexDeclaresFavicon(t *testing.T) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	head, _, ok := strings.Cut(string(data), "</head>")
	if !ok {
		t.Fatal("index.html has no </head>")
	}
	const link = `<link rel="icon" href="/favicon.ico" sizes="16x16 32x32">`
	if !strings.Contains(head, link) {
		t.Errorf("index.html <head> lacks %s", link)
	}
}

// allEvents returns every audit row, newest first.
func allEvents(t *testing.T, s *Server) []audit.StoredEvent {
	t.Helper()
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("query audit db: %v", err)
	}
	return rows
}
