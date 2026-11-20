package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

type reviewB196OpenPause struct {
	storage.ObjectStore
	key    string
	opened chan struct{}
	resume chan struct{}
	opens  atomic.Int64
}

func (s *reviewB196OpenPause) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	res, err := s.ObjectStore.GetStream(ctx, key)
	if key == s.key && err == nil && res != nil && s.opens.Add(1) == 1 {
		close(s.opened)
		<-s.resume
	}
	return res, err
}

func TestReviewB196OpenedCopyCannotBorrowReplacementPin(t *testing.T) {
	const stale = "wrong distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	key := manifest.AptKey(fixtureDeb)
	store := &reviewB196OpenPause{ObjectStore: storage.NewLocal(t.TempDir()), key: key, opened: make(chan struct{}), resume: make(chan struct{})}
	if err := store.Put(t.Context(), key, []byte(stale)); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.StoreChecksum(t.Context(), key, manifest.TypeApt, "nginx", "1.24.0-2ubuntu7.1", "sha256", sha256Of(stale), "computed"); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { close(store.resume) }) }
	first, second := httptest.NewRecorder(), httptest.NewRecorder()
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(firstDone)
		s.handleAptMirrorPool(first, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil), "", fixtureDeb, store)
	}()
	t.Cleanup(func() { release(); <-firstDone })
	select {
	case <-store.opened:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never opened the cached object")
	}
	go func() {
		defer close(secondDone)
		s.handleAptMirrorPool(second, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil), "", fixtureDeb, store)
	}()
	t.Cleanup(func() { release(); <-secondDone })
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
wait:
	for {
		select {
		case <-secondDone:
			break wait
		case <-tick.C:
			s.aptMirror.mu.Lock()
			lock := s.aptMirror.m[key]
			serialized := lock != nil && lock.refs == 2
			s.aptMirror.mu.Unlock()
			if serialized {
				break wait
			}
		case <-deadline.C:
			t.Fatal("second request neither repaired the cache nor waited on its fill lock")
		}
	}
	release()
	<-firstDone
	<-secondDone
	if second.Code != http.StatusOK || second.Body.String() != fixtureDebBody {
		t.Fatalf("repair request = %d %q, want 200 and the listed build", second.Code, second.Body.String())
	}
	if first.Code != http.StatusOK || first.Body.String() != fixtureDebBody {
		t.Fatalf("request holding the old open handle = %d %q, want 200 and the listed build", first.Code, first.Body.String())
	}
}

func TestReviewB196MissingPackagesKeepsKnownDigest(t *testing.T) {
	const wrong = "wrong distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: wrong})
	s := mirrorServer(t, archive)
	if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusBadGateway {
		t.Fatalf("initial mismatch = %d %q, want 502", code, body)
	}
	archive.removeObject("dists/" + mirroredCodename + "/" + packagesPath + ".gz")
	s.aptUpstreamIdx.Clear()
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx.at = time.Time{}
	s.aptPoolIdx.mu.Unlock()
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway {
		t.Errorf("after Packages 404 GET = %d %q, want 502 for the known mismatch", code, body)
	}
	key := manifest.AptKey(fixtureDeb)
	if info, err := s.typeStore(manifest.TypeApt).Head(t.Context(), key); err != nil || (info != nil && info.Exists) {
		t.Errorf("known mismatching bytes reached storage: %+v %v", info, err)
	}
	if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || (pin != nil && pin.Value != "") {
		t.Errorf("known mismatching bytes were pinned: %+v %v", pin, err)
	}
}
