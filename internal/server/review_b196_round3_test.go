package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

type reviewB196RequestTag struct{}

type reviewB196FallbackRaceStore struct {
	storage.ObjectStore
	key           string
	fallbackHeads atomic.Int64
	hit           chan struct{}
	resumeHit     chan struct{}
	deleted       chan struct{}
	resumeDelete  chan struct{}
	deleteOnce    sync.Once
}

func (s *reviewB196FallbackRaceStore) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	info, err := s.ObjectStore.Head(ctx, key)
	if key == s.key && ctx.Value(reviewB196RequestTag{}) == "fallback" && s.fallbackHeads.Add(1) == 2 {
		close(s.hit)
		<-s.resumeHit
	}
	return info, err
}

func (s *reviewB196FallbackRaceStore) Delete(ctx context.Context, key string) error {
	err := s.ObjectStore.Delete(ctx, key)
	if key == s.key && err == nil {
		s.deleteOnce.Do(func() { close(s.deleted); <-s.resumeDelete })
	}
	return err
}

func TestReviewB196FallbackFillCannotBypassListedAdmission(t *testing.T) {
	const old = "previous distribution build"
	archive := indexedArchive(t, mirroredCodename, nil, map[string]string{fixtureDeb: old})
	probe, resumeProbe := make(chan struct{}), make(chan struct{})
	var probes atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/ubuntu/"+fixtureDeb && probes.Add(1) == 1 {
			close(probe)
			<-resumeProbe
		}
		archive.ts.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	s := mirrorServer(t, archive)
	s.cfg.AptUpstreams[mirroredCodename][0].URL = upstream.URL + "/ubuntu"
	key := manifest.AptKey(fixtureDeb)
	store := &reviewB196FallbackRaceStore{ObjectStore: storage.NewLocal(t.TempDir()), key: key,
		hit: make(chan struct{}), resumeHit: make(chan struct{}), deleted: make(chan struct{}), resumeDelete: make(chan struct{})}
	var probeOnce, hitOnce, deleteOnce sync.Once
	releaseProbe := func() { probeOnce.Do(func() { close(resumeProbe) }) }
	releaseHit := func() { hitOnce.Do(func() { close(store.resumeHit) }) }
	releaseDelete := func() { deleteOnce.Do(func() { close(store.resumeDelete) }) }
	releaseAll := func() { releaseProbe(); releaseHit(); releaseDelete() }
	t.Cleanup(releaseAll)
	wait := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	publish := func(body string) {
		t.Helper()
		fresh := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: body}, nil)
		for rel, data := range fresh.objects {
			archive.setObject(rel, data)
		}
		s.aptUpstreamIdx.Clear()
		s.aptPoolIdx.mu.Lock()
		s.aptPoolIdx.idx.at = time.Time{}
		s.aptPoolIdx.mu.Unlock()
	}
	get := func(w *httptest.ResponseRecorder, tag string) {
		r := httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil)
		r = r.WithContext(context.WithValue(r.Context(), reviewB196RequestTag{}, tag))
		s.handleAptMirrorPool(w, r, "", fixtureDeb, store)
	}
	fallback := httptest.NewRecorder()
	fallbackDone := make(chan struct{})
	go func() { defer close(fallbackDone); get(fallback, "fallback") }()
	t.Cleanup(func() { releaseAll(); <-fallbackDone })
	wait(probe, "the unnamed request's upstream probe")

	held := func() bool {
		s.aptMirror.mu.Lock()
		defer s.aptMirror.mu.Unlock()
		return s.aptMirror.m[key] != nil
	}
	serialized := held()
	if serialized {
		releaseHit()
		releaseProbe()
		wait(fallbackDone, "the serialized fallback")
	} else {
		publish(old)
		seed := httptest.NewRecorder()
		get(seed, "seed")
		if seed.Code != http.StatusOK || seed.Body.String() != old {
			t.Fatalf("seed = %d %q", seed.Code, seed.Body.String())
		}
		releaseProbe()
		wait(store.hit, "the fallback's cache hit before its lock decision")
		serialized = held()
		if serialized {
			releaseHit()
			wait(fallbackDone, "the fallback holding the fill lock")
		}
	}

	publish(fixtureDebBody)
	listed := httptest.NewRecorder()
	listedDone := make(chan struct{})
	go func() { defer close(listedDone); get(listed, "listed") }()
	t.Cleanup(func() { releaseAll(); <-listedDone })
	wait(store.deleted, "the listed request's removal of the old build")
	releaseHit()
	if !serialized {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
	waitFill:
		for {
			select {
			case <-fallbackDone:
				break waitFill
			case <-tick.C:
				s.aptMirror.mu.Lock()
				lock := s.aptMirror.m[key]
				waiting := lock != nil && lock.refs == 2
				s.aptMirror.mu.Unlock()
				if waiting {
					break waitFill
				}
			case <-deadline.C:
				t.Fatal("fallback neither filled nor waited on the repair lock")
			}
		}
	}
	releaseDelete()
	wait(listedDone, "the listed request")
	wait(fallbackDone, "the fallback request")
	if fallback.Code != http.StatusOK || fallback.Body.String() != old {
		t.Fatalf("fallback = %d %q", fallback.Code, fallback.Body.String())
	}
	if listed.Code != http.StatusBadGateway {
		t.Fatalf("listed request = %d %q, want 502: upstream still serves the build its paragraph rejects", listed.Code, listed.Body.String())
	}
}

func TestReviewB196PinnedHitStillChecksParagraphSize(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%v", cached), func(t *testing.T) {
			archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
			s := mirrorServer(t, archive)
			if cached {
				if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK || string(body) != fixtureDebBody {
					t.Fatalf("initial fill = %d %q", code, body)
				}
			}
			kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
			if err != nil {
				t.Fatal(err)
			}
			packages := strings.Replace(fixturePackages(fixtureDeb, fixtureDebBody),
				fmt.Sprintf("Size: %d", len(fixtureDebBody)), fmt.Sprintf("Size: %d", len(fixtureDebBody)+1), 1)
			for rel, data := range fixtureDistsFor(t, kr, mirroredCodename, packages, "amd64") {
				archive.setObject(rel, data)
			}
			s.aptUpstreamIdx.Clear()
			s.aptPoolIdx.mu.Lock()
			if s.aptPoolIdx.idx != nil {
				s.aptPoolIdx.idx.at = time.Time{}
			}
			s.aptPoolIdx.mu.Unlock()
			if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusBadGateway {
				t.Fatalf("GET = %d %q, want 502 for %d bytes against the paragraph's Size %d", code, body, len(fixtureDebBody), len(fixtureDebBody)+1)
			}
		})
	}
}

func TestReviewB196CachedHitDoesNotWaitForFillDelivery(t *testing.T) {
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	first := &reviewF112WaitingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), resume: make(chan struct{})}
	firstDone := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(first.resume) }) }
	go func() {
		defer close(firstDone)
		s.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil))
	}()
	t.Cleanup(func() { release(); <-firstDone })
	select {
	case <-first.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the fill never reached response delivery")
	}
	key := manifest.AptKey(fixtureDeb)
	if body, err := s.typeStore(manifest.TypeApt).Get(t.Context(), key); err != nil || string(body) != fixtureDebBody {
		t.Fatalf("the fill has not cached the complete build: %q %v", body, err)
	}
	if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || pin == nil || pin.Value != sha256Of(fixtureDebBody) {
		t.Fatalf("the fill has not pinned the complete build: %+v %v", pin, err)
	}
	second := httptest.NewRecorder()
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		s.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil))
	}()
	t.Cleanup(func() { release(); <-secondDone })
	select {
	case <-secondDone:
		if second.Code != http.StatusOK || second.Body.String() != fixtureDebBody {
			t.Fatalf("cached request = %d %q", second.Code, second.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cached request waited for the first client's delivery after the complete object and pin were stored")
	}
}

func TestReviewB196SharedStoreReplacementCannotBorrowPin(t *testing.T) {
	const old = "distribution build one"
	const newer = "distribution build two"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: old}, map[string]string{fixtureDeb: old})
	first, second := mirrorServer(t, archive), mirrorServer(t, archive)
	store := storage.NewLocal(t.TempDir())
	first.stores = storage.NewSingle(store)
	second.stores = storage.NewSingle(store)
	key := manifest.AptKey(fixtureDeb)

	if code, body := mirrorGet(t, first, "/apt/"+fixtureDeb); code != http.StatusOK || string(body) != old {
		t.Fatalf("first instance's fill = %d %q", code, body)
	}
	fresh := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: newer}, map[string]string{fixtureDeb: newer})
	for rel, data := range fresh.objects {
		archive.setObject(rel, data)
	}
	if code, body := mirrorGet(t, second, "/apt/"+fixtureDeb); code != http.StatusOK || string(body) != newer {
		t.Fatalf("second instance's repair = %d %q", code, body)
	}
	want, conflict := first.aptPoolParagraph(t.Context(), key)
	if want == nil || conflict != nil || want.sha256 != sha256Of(old) {
		t.Fatal("first instance lost the paragraph its request must enforce")
	}
	if pin, err := first.auditDB.GetChecksum(t.Context(), key); err != nil || pin == nil || pin.Value != sha256Of(old) {
		t.Fatalf("first instance's pin = %+v %v", pin, err)
	}
	if code, body := mirrorGet(t, first, "/apt/"+fixtureDeb); code != http.StatusBadGateway {
		t.Fatalf("first instance after shared-store replacement = %d %q, want 502: its paragraph names %q and upstream only serves %q", code, body, old, newer)
	}
}

func TestReviewB196ServedPackagesRetainAuthorityBeforeFirstPoolRequest(t *testing.T) {
	const wrong = "wrong distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: wrong})
	s := mirrorServer(t, archive)
	for _, rel := range []string{"Release", packagesPath + ".gz"} {
		if code, _ := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+rel); code != http.StatusOK {
			t.Fatalf("client's index read %s = %d", rel, code)
		}
	}
	archive.removeObject("dists/" + mirroredCodename + "/Release")
	s.cache.MetadataTTL = time.Nanosecond
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway {
		t.Errorf("after serving Packages then losing Release, first pool request = %d %q, want 502 for bytes the served paragraph rejects", code, body)
	}
	key := manifest.AptKey(fixtureDeb)
	if info, err := s.typeStore(manifest.TypeApt).Head(t.Context(), key); err != nil || (info != nil && info.Exists) {
		t.Errorf("known mismatching bytes reached storage: %+v %v", info, err)
	}
	if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || (pin != nil && pin.Value != "") {
		t.Errorf("known mismatching bytes were pinned: %+v %v", pin, err)
	}
}

func TestReviewB196ScopedBaseRepairsWrongVendorCache(t *testing.T) {
	s, _, scoped, _, vendor := scopedVendorArchives(t)
	const stale = "nginx from the wrong distribution"
	key := manifest.AptKey(profileNginxDeb)
	store := s.typeStore(manifest.TypeApt)
	if err := store.Put(t.Context(), key, []byte(stale)); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.StoreChecksum(t.Context(), key, manifest.TypeApt, "nginx", profileNginxVersion, "sha256", sha256Of(stale), "computed"); err != nil {
		t.Fatal(err)
	}
	s.recordCacheOrigin(t.Context(), store, key, vendor.URL()+"/"+profileNginxDeb, sha256Of(stale))
	code, body := clientGet(t, s, scoped.token, "/apt/"+profileNginxDeb)
	if code != http.StatusOK || body != aptProfilePool()[profileNginxDeb] {
		t.Fatalf("scoped host's permitted base package = %d %q, want 200 and its base's listed build after repairing the wrong vendor copy", code, body)
	}
}

func TestReviewB196CachedMetadataReplayCannotReplaceBuiltAuthority(t *testing.T) {
	const old = "previous distribution build"
	archive := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: old}, map[string]string{fixtureDeb: old})
	s := mirrorServer(t, archive)
	readMetadata := func() {
		t.Helper()
		for _, rel := range []string{"Release", packagesPath + ".gz"} {
			if code, _ := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+rel); code != http.StatusOK {
				t.Fatalf("client metadata read %s = %d", rel, code)
			}
		}
	}
	readMetadata()
	fresh := indexedArchive(t, mirroredCodename, map[string]string{fixtureDeb: fixtureDebBody}, map[string]string{fixtureDeb: fixtureDebBody})
	for rel, data := range fresh.objects {
		archive.setObject(rel, data)
	}
	s.aptUpstreamIdx.Clear()
	if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK || string(body) != fixtureDebBody {
		t.Fatalf("pool build from the newer archive = %d %q", code, body)
	}
	key := manifest.AptKey(fixtureDeb)
	want, conflict := s.aptPoolParagraph(t.Context(), key)
	if want == nil || conflict != nil || want.sha256 != sha256Of(fixtureDebBody) {
		t.Fatal("pool index did not establish the new paragraph")
	}
	reads := archive.count("dists/" + mirroredCodename + "/" + packagesPath + ".gz")
	readMetadata()
	if got := archive.count("dists/" + mirroredCodename + "/" + packagesPath + ".gz"); got != reads {
		t.Fatal("metadata replay must use the older cached document, not a new upstream read")
	}
	archive.setObject(fixtureDeb, old)
	archive.removeObject("dists/" + mirroredCodename + "/Release")
	s.aptUpstreamIdx.Clear()
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx.at = s.aptPoolIdx.idx.at.Add(-2 * s.aptPoolIdx.idx.ttl)
	s.aptPoolIdx.mu.Unlock()
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway && (code != http.StatusOK || string(body) != fixtureDebBody) {
		t.Errorf("failed refresh after old metadata replay = %d %q, want the cached build %q from the last successful pool-index read or a 502 refusal", code, body, fixtureDebBody)
	}
	if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || (pin != nil && pin.Value != "" && pin.Value != sha256Of(fixtureDebBody)) {
		t.Errorf("last successful pool-index digest was replaced: %+v %v", pin, err)
	}
	if stored, err := s.typeStore(manifest.TypeApt).Get(t.Context(), key); err != nil || (len(stored) > 0 && string(stored) != fixtureDebBody) {
		t.Errorf("last successful pool-index build was replaced: %q %v", stored, err)
	}
}

func TestReviewB196FreshOtherArchitectureCannotPromoteCachedReplay(t *testing.T) {
	const old = "previous distribution build"
	const armPath = "main/binary-arm64/Packages"
	const armDeb = "pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_arm64.deb"
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	objects := func(amd string) map[string]string {
		t.Helper()
		main := fixtureDistsFor(t, kr, mirroredCodename, fixturePackages(fixtureDeb, amd), "amd64")
		arm := fixtureDistsFor(t, kr, mirroredCodename,
			strings.ReplaceAll(fixturePackages(armDeb, "arm64 package"), "Architecture: amd64", "Architecture: arm64"), "arm64")
		base := "dists/" + mirroredCodename + "/"
		_, hashes, ok := strings.Cut(arm[base+"Release"], "\nSHA256:\n")
		if !ok {
			t.Fatal("arm fixture has no hashes")
		}
		release := strings.Replace(main[base+"Release"], "Architectures: amd64", "Architectures: amd64 arm64", 1) + hashes
		for k, v := range arm {
			main[k] = v
		}
		main[base+"Release"] = release
		signed, err := kr.ClearSign([]byte(release))
		if err != nil {
			t.Fatal(err)
		}
		main[base+"InRelease"] = string(signed)
		detached, err := kr.DetachSign([]byte(release))
		if err != nil {
			t.Fatal(err)
		}
		main[base+"Release.gpg"] = string(detached)
		main[fixtureDeb] = amd
		return main
	}
	archive := newFixtureArchive(t, objects(old))
	s := mirrorServer(t, archive)
	read := func(rel string) {
		t.Helper()
		if code, body := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+rel); code != http.StatusOK {
			t.Fatalf("metadata %s = %d %q", rel, code, body)
		}
	}
	read("Release")
	read(packagesPath + ".gz")
	for rel, data := range objects(fixtureDebBody) {
		archive.setObject(rel, data)
	}
	s.aptUpstreamIdx.Clear()
	if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK || string(body) != fixtureDebBody {
		t.Fatalf("new pool-index build = %d %q", code, body)
	}
	key := manifest.AptKey(fixtureDeb)
	want, conflict := s.aptPoolParagraph(t.Context(), key)
	if want == nil || conflict != nil || want.sha256 != sha256Of(fixtureDebBody) {
		t.Fatal("pool did not establish the new paragraph")
	}
	reads := archive.count("dists/" + mirroredCodename + "/" + packagesPath + ".gz")
	read("Release")
	read(packagesPath + ".gz")
	if archive.count("dists/"+mirroredCodename+"/"+packagesPath+".gz") != reads {
		t.Fatal("amd64 replay fetched upstream")
	}
	armReads := archive.count("dists/" + mirroredCodename + "/" + armPath + ".gz")
	read(armPath + ".gz")
	if archive.count("dists/"+mirroredCodename+"/"+armPath+".gz") != armReads+1 {
		t.Fatal("arm64 read did not fetch upstream")
	}
	archive.setObject(fixtureDeb, old)
	archive.removeObject("dists/" + mirroredCodename + "/Release")
	s.aptUpstreamIdx.Clear()
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx.at = time.Time{}
	s.aptPoolIdx.mu.Unlock()
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway && (code != http.StatusOK || string(body) != fixtureDebBody) {
		t.Errorf("fresh arm64 read promoted old amd64 replay: got %d %q, want %q or 502", code, body, fixtureDebBody)
	}
	if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || (pin != nil && pin.Value != "" && pin.Value != sha256Of(fixtureDebBody)) {
		t.Errorf("last pool-read pin replaced: %+v %v", pin, err)
	}
	if stored, err := s.typeStore(manifest.TypeApt).Get(t.Context(), key); err != nil || (len(stored) > 0 && string(stored) != fixtureDebBody) {
		t.Errorf("last pool-read bytes replaced: %q %v", stored, err)
	}
}

func TestReviewB196PoolCacheReplayCannotUndoRetainedAuthority(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%v", partial), func(t *testing.T) {
			const old = "previous distribution build"
			const armDeb = "pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_arm64.deb"
			const armPath = "main/binary-arm64/Packages.gz"
			const otherPath = "main/binary-s390x/Packages.gz"
			base := "dists/" + mirroredCodename + "/"
			kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
			if err != nil {
				t.Fatal(err)
			}
			objects := func(armBody string) map[string]string {
				t.Helper()
				all := map[string]string{}
				var release string
				for _, arch := range []string{"amd64", "arm64", "s390x"} {
					deb, body := fixtureDeb, fixtureDebBody
					if arch == "arm64" {
						deb, body = armDeb, armBody
					}
					if arch == "s390x" {
						deb, body = strings.Replace(fixtureDeb, "amd64", "s390x", 1), "s390x package"
					}
					docs := fixtureDistsFor(t, kr, mirroredCodename,
						strings.ReplaceAll(fixturePackages(deb, body), "Architecture: amd64", "Architecture: "+arch), arch)
					_, hashes, ok := strings.Cut(docs[base+"Release"], "\nSHA256:\n")
					if !ok {
						t.Fatal("missing hashes")
					}
					if release == "" {
						release = strings.Replace(docs[base+"Release"], "Architectures: amd64", "Architectures: amd64 arm64 s390x", 1)
					} else {
						release += hashes
					}
					for k, v := range docs {
						all[k] = v
					}
					all[deb] = body
				}
				all[base+"Release"] = release
				signed, err := kr.ClearSign([]byte(release))
				if err != nil {
					t.Fatal(err)
				}
				all[base+"InRelease"] = string(signed)
				return all
			}
			archive := newFixtureArchive(t, objects(old))
			var failAMD, failOther atomic.Bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rel := strings.TrimPrefix(r.URL.Path, "/ubuntu/")
				if (rel == base+packagesPath+".gz" && failAMD.Load()) || (rel == base+otherPath && failOther.Load()) {
					http.Error(w, "temporary index outage", http.StatusBadGateway)
					return
				}
				archive.ts.Config.Handler.ServeHTTP(w, r)
			}))
			t.Cleanup(upstream.Close)
			s := mirrorServer(t, archive)
			s.cfg.AptUpstreams[mirroredCodename][0].URL = upstream.URL + "/ubuntu"
			expirePool := func() {
				s.aptPoolIdx.mu.Lock()
				s.aptPoolIdx.idx.at = time.Time{}
				s.aptPoolIdx.mu.Unlock()
			}
			if code, body := mirrorGet(t, s, "/apt/"+armDeb); code != http.StatusOK || string(body) != old {
				t.Fatalf("initial pool build = %d %q", code, body)
			}
			key := manifest.AptKey(armDeb)
			for rel, data := range objects(fixtureDebBody) {
				archive.setObject(rel, data)
			}
			for _, rel := range []string{"Release", armPath} {
				if code, body := mirrorGet(t, s, "/apt/"+base+rel); code != http.StatusOK {
					t.Fatalf("fresh metadata %s = %d %q", rel, code, body)
				}
			}
			// Expire just one document, as independently acquired metadata entries do.
			s.aptUpstreamIdx.Delete(mirroredCodename + "/" + packagesPath + ".gz")
			failAMD.Store(true)
			expirePool()
			if code, body := mirrorGet(t, s, "/apt/"+armDeb); code != http.StatusOK || string(body) != fixtureDebBody {
				t.Fatalf("retained newer paragraph was not established = %d %q", code, body)
			}
			want, conflict := s.aptPoolParagraph(t.Context(), key)
			if want == nil || conflict != nil || want.sha256 != sha256Of(fixtureDebBody) {
				t.Fatal("pool index did not establish newer retained authority")
			}
			reads := archive.count(base + armPath)
			failAMD.Store(false)
			if partial {
				s.aptUpstreamIdx.Delete(mirroredCodename + "/" + otherPath)
				failOther.Store(true)
			}
			archive.setObject(armDeb, old)
			expirePool()
			code, body := mirrorGet(t, s, "/apt/"+armDeb)
			if archive.count(base+armPath) != reads {
				t.Fatal("arm64 replay fetched upstream")
			}
			if code != http.StatusBadGateway && (code != http.StatusOK || string(body) != fixtureDebBody) {
				t.Errorf("cached pool-reader document undid newer retained authority: got %d %q, want %q or 502", code, body, fixtureDebBody)
			}
			if pin, err := s.auditDB.GetChecksum(t.Context(), key); err != nil || (pin != nil && pin.Value != "" && pin.Value != sha256Of(fixtureDebBody)) {
				t.Errorf("newer pool pin replaced: %+v %v", pin, err)
			}
			if stored, err := s.typeStore(manifest.TypeApt).Get(t.Context(), key); err != nil || (len(stored) > 0 && string(stored) != fixtureDebBody) {
				t.Errorf("newer cached bytes replaced: %q %v", stored, err)
			}
		})
	}
}
