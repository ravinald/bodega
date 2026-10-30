package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// A Gradle plugin marker publishes a .pom and no .jar, and Gradle asks for
// both: the .jar is the path every outage case below requests.
const (
	markerDir = "/maven2/io/spring/dependency-management/io.spring.dependency-management.gradle.plugin/1.1.7/"
	markerPom = "io/spring/dependency-management/io.spring.dependency-management.gradle.plugin/1.1.7/io.spring.dependency-management.gradle.plugin-1.1.7.pom"
	markerJar = "io/spring/dependency-management/io.spring.dependency-management.gradle.plugin/1.1.7/io.spring.dependency-management.gradle.plugin-1.1.7.jar"
)

// outageUpstream is a Maven repository publishing the marker's .pom whose
// failure mode a test chooses: answering, answering 500 to everything, or
// gone, with its listener closed.
type outageUpstream struct {
	ts      *httptest.Server
	failing atomic.Bool
	jar     atomic.Pointer[string]
}

func newOutageUpstream(t *testing.T) *outageUpstream {
	t.Helper()
	u := &outageUpstream{}
	u.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case u.failing.Load():
			http.Error(w, "upstream down", http.StatusInternalServerError)
		case r.URL.Path == markerDir+filepath.Base(markerPom):
			_, _ = w.Write([]byte("<project>marker</project>"))
		case r.URL.Path == markerDir+filepath.Base(markerJar) && u.jar.Load() != nil:
			_, _ = w.Write([]byte(*u.jar.Load()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(u.ts.Close)
	return u
}

// notFoundServer is a proxying server over store, so two of them built over
// one store are the same bodega before and after a restart.
func notFoundServer(t *testing.T, store storage.ObjectStore, upstream string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		LogDir:         dir,
		AuditDB:        filepath.Join(dir, "audit.db"),
		StoragePath:    dir,
		DiscoverMode:   "observe",
		AllowPlaintext: true,
		MavenUpstreams: []string{upstream + "/maven2"},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(store),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.discovery != nil {
		ctx, cancel := context.WithCancel(context.Background())
		go s.discovery.Start(ctx)
		t.Cleanup(cancel)
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Hour}
	allowLoopbackUpstreams(t)
	return s
}

func wantMaven(t *testing.T, s *Server, p string, want int) {
	t.Helper()
	if code, body, _ := getMaven(t, s, p); code != want {
		t.Fatalf("GET /maven/%s = %d, want %d (body %q)", p, code, want, body)
	}
}

func notFoundRecords(t *testing.T, s *Server) []string {
	t.Helper()
	keys, err := s.typeStore(manifest.TypeMaven).List(t.Context(), notFoundPrefix)
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	return keys
}

// TestOutageAnswersARecorded404 is B185: online, the marker's .jar is a 404
// and the .pom is cached; cut off, the .pom is served from the cache and the
// .jar has to stay a 404, or Gradle reads the repository as broken.
func TestOutageAnswersARecorded404(t *testing.T) {
	for _, outage := range []struct {
		name string
		cut  func(*outageUpstream)
	}{
		{"connection refused", func(u *outageUpstream) { u.ts.Close() }},
		{"5xx", func(u *outageUpstream) { u.failing.Store(true) }},
	} {
		t.Run(outage.name, func(t *testing.T) {
			up := newOutageUpstream(t)
			s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
			wantMaven(t, s, markerPom, http.StatusOK)
			wantMaven(t, s, markerJar, http.StatusNotFound)
			if got := notFoundRecords(t, s); len(got) != 1 {
				t.Fatalf("records after the upstream's 404 = %v, want one", got)
			}

			outage.cut(up)
			wantMaven(t, s, markerPom, http.StatusOK)
			wantMaven(t, s, markerJar, http.StatusNotFound)

			// Past the window the record no longer speaks for the upstream.
			s.cache.NotFoundTTL = map[string]time.Duration{manifest.TypeMaven: time.Nanosecond}
			wantMaven(t, s, markerJar, http.StatusBadGateway)
		})
	}
}

func TestOutageNeverInventsA404(t *testing.T) {
	up := newOutageUpstream(t)
	s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
	up.ts.Close()
	wantMaven(t, s, markerJar, http.StatusBadGateway)
}

// A 403 is the upstream answering, so it is reported as before even with a
// record standing.
func TestRecordAnswersOnlyAnUnreachableUpstream(t *testing.T) {
	if upstreamUnreachable(&upstreamStatusError{url: "u", status: http.StatusForbidden}) {
		t.Fatal("a 403 counted as an unreachable upstream")
	}
	if !upstreamUnreachable(&upstreamStatusError{url: "u", status: http.StatusBadGateway}) {
		t.Fatal("a 502 did not count as an unreachable upstream")
	}
}

func TestPublishedAfterA404LeavesNoRecord(t *testing.T) {
	up := newOutageUpstream(t)
	s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
	wantMaven(t, s, markerJar, http.StatusNotFound)
	if got := notFoundRecords(t, s); len(got) != 1 {
		t.Fatalf("records after the upstream's 404 = %v, want one", got)
	}

	body := "now published"
	up.jar.Store(&body)
	wantMaven(t, s, markerJar, http.StatusOK)
	if got := notFoundRecords(t, s); len(got) != 0 {
		t.Fatalf("records after the upstream's 200 = %v, want none", got)
	}
}

func TestNotFoundRecordSurvivesARestart(t *testing.T) {
	root := t.TempDir()
	up := newOutageUpstream(t)
	before := notFoundServer(t, storage.NewLocal(root), up.ts.URL)
	wantMaven(t, before, markerJar, http.StatusNotFound)

	up.ts.Close()
	after := notFoundServer(t, storage.NewLocal(root), up.ts.URL)
	wantMaven(t, after, markerJar, http.StatusNotFound)
}
