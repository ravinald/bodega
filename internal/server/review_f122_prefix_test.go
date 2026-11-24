package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

func TestReviewF122FailedBareSuiteDoesNotCarryQualifiedSuite(t *testing.T) {
	for _, tc := range []struct {
		name, archive string
		legacy        bool
	}{
		{"qualified-vendor", "vendor", false},
		{"legacy-stable", "stable", true},
		{"qualified-stable", "stable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := tc.archive
			const old = "vendor previous build"
			const fresh = "vendor current build"
			bare := indexedArchive(t, "stable", map[string]string{fixtureDeb: "bare build"}, map[string]string{fixtureDeb: "bare build"})
			vendor := indexedArchive(t, "noble", map[string]string{fixtureDeb: old}, map[string]string{fixtureDeb: old})
			s := mirrorServer(t)
			suite := archive + "/noble"
			if tc.legacy {
				suite = "noble"
				s.cfg.AptArchives = map[string][]string{archive: {"noble"}}
			}
			s.cfg.AptUpstreams = map[string][]config.AptUpstream{
				"stable": {{URL: bare.URL()}},
				suite:    {{URL: vendor.URL()}},
			}
			first := s.aptPoolIndexNow(t.Context())
			if len(first.failed) != 0 {
				t.Fatalf("initial index: %v", first.failed)
			}
			bare.removeObject("dists/stable/Release")
			updated := indexedArchive(t, "noble", map[string]string{fixtureDeb: fresh}, map[string]string{fixtureDeb: fresh})
			for rel, body := range updated.objects {
				vendor.setObject(rel, body)
			}
			s.aptUpstreamIdx.Clear()
			s.aptPoolIdx.mu.Lock()
			s.aptPoolIdx.idx.at = time.Time{}
			s.aptPoolIdx.mu.Unlock()
			key := manifest.AptArchiveKey(archive, fixtureDeb)
			stanza, conflict := s.aptPoolParagraph(t.Context(), key)
			if conflict != nil || stanza == nil || stanza.sha256 != sha256Of(fresh) {
				t.Errorf("refreshed %s paragraph = %+v conflict=%+v; want current SHA256 %s", suite, stanza, conflict, sha256Of(fresh))
			}
			code, body := mirrorGet(t, s, "/apt/"+archive+"/"+fixtureDeb)
			if code != http.StatusOK || string(body) != fresh {
				t.Errorf("GET refreshed %s pool = %d %q; want 200 %q", suite, code, body, fresh)
			}
		})
	}
}
