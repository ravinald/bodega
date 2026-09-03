package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// rssTypes is one representative artifact fetch per manifest type, with the
// key each type's handler composes and the size the measurement moves through
// it. apt carries the body over the old 256 MB buffer ceiling.
var rssTypes = []struct {
	regType string
	key     string
	size    int64
}{
	{manifest.TypeApt, manifest.AptKey("pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb"), 300 << 20},
	{manifest.TypeBinary, manifest.BinaryPrefix + "hashicorp/terraform/1.7.5/terraform.zip", 1 << 20},
	{manifest.TypeGomod, "gomod/github.com/aws/aws-sdk-go-v2/@v/v1.30.0.zip", 1 << 20},
	{manifest.TypeNpm, "npm/lodash/-/lodash-4.17.21.tgz", 1 << 20},
	{manifest.TypeHelm, "charts/nginx-15.1.0.tgz", 1 << 20},
	{manifest.TypePypi, "pypi/wheels/requests-2.32.3-py3-none-any.whl", 1 << 20},
	{manifest.TypeCargo, "cargo/crates/serde/1.0.210/download", 1 << 20},
	{manifest.TypeGit, "repos/netbox-community--netbox/netbox-v4.5.5.bundle", 1 << 20},
}

// TestProxyPeakRSS drives one artifact fetch per type through proxyOrResolve
// and leaves the peak resident set for the caller to read off the process.
//
// Gated on BODEGA_PROXY_RSS because it moves a third of a gigabyte, and run
// under a tool that reports the process peak — the number this exists to
// produce is not one the test can print for itself:
//
//	go test -c -o /tmp/server.test ./internal/server
//	BODEGA_PROXY_RSS=1 /usr/bin/time -l /tmp/server.test -test.run TestProxyPeakRSS
//
// Against the buffered path the apt row is refused at the 256 MB ceiling, so
// the comparable "before" number comes from lowering that row's size to just
// under it.
func TestProxyPeakRSS(t *testing.T) {
	if os.Getenv("BODEGA_PROXY_RSS") == "" {
		t.Skip("set BODEGA_PROXY_RSS=1 to run the memory measurement")
	}
	allowLoopbackUpstream(t)

	// Bodies are generated, never held: a fixture that built a 300 MB string
	// would be measuring the fixture.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var size int64
		if _, err := fmt.Sscanf(r.URL.Path, "/%d", &size); err != nil {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64<<10)
		for sent := int64(0); sent < size; {
			n := int64(len(chunk))
			if rem := size - sent; rem < n {
				n = rem
			}
			written, err := w.Write(chunk[:n])
			if err != nil {
				return
			}
			sent += int64(written)
		}
	}))
	defer upstream.Close()

	// A filesystem store, not the in-memory one: caching 300 MB into a map
	// would put the artifact back in the heap the streaming path took it out
	// of, and the measurement would report the fixture's choice.
	dir := t.TempDir()
	cfg := &config.Config{StoragePath: dir, AllowPlaintext: true}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()),
		storage.NewSingle(storage.NewLocal(dir)),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.cache = CacheConfig{Enabled: true}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := 0
		if _, err := fmt.Sscanf(r.URL.Query().Get("i"), "%d", &i); err != nil {
			http.Error(w, "bad index", http.StatusBadRequest)
			return
		}
		tc := rssTypes[i]
		url := fmt.Sprintf("%s/%d", upstream.URL, tc.size)
		s.proxyOrCache(w, r, s.typeStore(tc.regType), tc.key, url, tc.regType, url, "rss", true, true)
	}))
	defer ts.Close()

	var total int64
	for i, tc := range rssTypes {
		resp, err := http.Get(fmt.Sprintf("%s/?i=%d", ts.URL, i)) //nolint:gosec,noctx // test-owned loopback URL
		if err != nil {
			t.Fatalf("%s: %v", tc.regType, err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("%s: read body: %v", tc.regType, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tc.regType, resp.StatusCode)
		}
		if n != tc.size {
			t.Errorf("%s: served %d bytes, want %d", tc.regType, n, tc.size)
		}
		total += n
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("moved %d bytes across %d types; go heap peak (TotalAlloc %d, HeapSys %d)",
		total, len(rssTypes), ms.TotalAlloc, ms.HeapSys)
}
