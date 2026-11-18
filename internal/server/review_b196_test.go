package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

type reviewB196DeleteFailure struct {
	storage.ObjectStore
	key string
}

func (s reviewB196DeleteFailure) Delete(ctx context.Context, key string) error {
	if key == s.key {
		return errors.New("object store delete unavailable")
	}
	return s.ObjectStore.Delete(ctx, key)
}

func TestReviewB196DeleteFailureNeverServesRejectedCache(t *testing.T) {
	const stale = "wrong distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	key := manifest.AptKey(fixtureDeb)
	store := s.typeStore(manifest.TypeApt)
	if err := store.Put(t.Context(), key, []byte(stale)); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.StoreChecksum(t.Context(), key, manifest.TypeApt, "nginx", "1.24.0-2ubuntu7.1", "sha256", sha256Of(stale), "computed"); err != nil {
		t.Fatal(err)
	}
	broken := reviewB196DeleteFailure{ObjectStore: store, key: key}
	for range 2 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil)
		s.handleAptMirrorPool(w, r, "", fixtureDeb, broken)
		if w.Code == http.StatusOK && w.Body.String() != fixtureDebBody {
			t.Errorf("GET = %d %q; must never serve the rejected cached build after Delete fails", w.Code, w.Body.String())
		}
	}
}

func TestReviewB196ClearedPinStillChecksCachedBuild(t *testing.T) {
	const stale = "wrong distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	key := manifest.AptKey(fixtureDeb)
	if err := s.typeStore(manifest.TypeApt).Put(t.Context(), key, []byte(stale)); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.StoreChecksum(t.Context(), key, manifest.TypeApt, "nginx", "1.24.0-2ubuntu7.1", "sha256", sha256Of(stale), "computed"); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.ClearChecksum(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusOK || string(body) != fixtureDebBody {
		t.Fatalf("GET = %d %q, want 200 and the paragraph's build after clearing the old pin", code, body)
	}
}

func TestReviewB196FailedRefreshKeepsKnownDigest(t *testing.T) {
	const wrong = "wrong distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: wrong})
	s := mirrorServer(t, archive)
	if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusBadGateway {
		t.Fatalf("initial mismatch = %d %q, want 502", code, body)
	}
	archive.removeObject("dists/" + mirroredCodename + "/Release")
	s.cache.MetadataTTL = time.Nanosecond
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx.at = time.Time{}
	s.aptPoolIdx.mu.Unlock()
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway {
		t.Errorf("after a failed index refresh GET = %d %q, want 502 for the same known mismatch", code, body)
	}
	key := manifest.AptKey(fixtureDeb)
	if info, err := s.typeStore(manifest.TypeApt).Head(t.Context(), key); err != nil || (info != nil && info.Exists) {
		t.Errorf("known mismatching bytes reached storage: %+v %v", info, err)
	}
	if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || (pin != nil && pin.Value != "") {
		t.Errorf("known mismatching bytes were pinned: %+v %v", pin, err)
	}
}

func TestReviewB196WaitingFillChecksItsParagraph(t *testing.T) {
	const old = "previous build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: old}, map[string]string{fixtureDeb: old})
	entered, resume := make(chan struct{}), make(chan struct{})
	var gets atomic.Int64
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/ubuntu/"+fixtureDeb && gets.Add(1) == 1 {
			close(entered)
			<-resume
			_, _ = w.Write([]byte(old))
			return
		}
		archive.ts.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(release)
	s := mirrorServer(t, archive)
	s.cfg.AptUpstreams[mirroredCodename][0].URL = upstream.URL + "/ubuntu"
	handler := s.Handler()
	first, second := httptest.NewRecorder(), httptest.NewRecorder()
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(firstDone)
		handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil))
	}()
	t.Cleanup(func() { release(); <-firstDone })
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first fill never reached upstream")
	}

	fresh := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
	for rel, body := range fresh.objects {
		archive.setObject(rel, body)
	}
	s.aptUpstreamIdx.Clear()
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx.at = time.Time{}
	s.aptPoolIdx.mu.Unlock()
	go func() {
		defer close(secondDone)
		handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil))
	}()
	t.Cleanup(func() { release(); <-secondDone })
	key := manifest.AptKey(fixtureDeb)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.aptMirror.mu.Lock()
		lock := s.aptMirror.m[key]
		waiting := lock != nil && lock.refs == 2
		s.aptMirror.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second request did not wait for the old fill")
		}
		time.Sleep(time.Millisecond)
	}
	want, conflict := s.aptPoolParagraph(t.Context(), key)
	if conflict != nil || want == nil || want.sha256 != sha256Of(fixtureDebBody) {
		t.Fatal("the waiting request did not read the updated paragraph")
	}
	release()
	<-firstDone
	<-secondDone
	if second.Code != http.StatusOK || second.Body.String() != fixtureDebBody {
		t.Fatalf("waiting request = %d %q, want 200 and the updated paragraph's build", second.Code, second.Body.String())
	}
}
