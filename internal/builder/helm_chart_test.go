package builder

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// chartTGZ packs one <chart>/Chart.yaml with the body given, which is the only
// member FetchHelm reads.
func chartTGZ(t *testing.T, chart, chartYAML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte(chartYAML)
	if err := tw.WriteHeader(&tar.Header{
		Name: chart + "/Chart.yaml", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fetchPinnedChart runs a helm fetch of an entry pinning pin against a server
// returning tgz, and reports the summary plus the path the chart would land on.
func fetchPinnedChart(t *testing.T, pin string, tgz []byte) (*Summary, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tgz)
	}))
	t.Cleanup(srv.Close)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeHelm,
		Name:     "podinfo",
		Versions: []manifest.VersionEntry{{Version: pin, URL: srv.URL + "/podinfo-" + pin + ".tgz"}},
	}
	cfg, store, _ := pinEnv(t, pm)
	s := FetchHelm(cfg, store, "podinfo")
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	return s, helmLocalPath(d, "podinfo", pm.Versions[0])
}

// R4: the filename, the index entry and the object key are all rendered from
// ve.Version, so a url naming another release publishes a chart body nobody
// downstream can tell apart from the pinned one.
func TestFetchHelmRefusesAChartYAMLThatDisagreesWithThePin(t *testing.T) {
	tgz := chartTGZ(t, "podinfo", "apiVersion: v2\nname: podinfo\nversion: 6.7.1\nappVersion: 6.7.1\n")
	s, dest := fetchPinnedChart(t, "6.7.0", tgz)

	if s.Failures == 0 {
		t.Fatal("a chart declaring 6.7.1 was stored under an entry pinning 6.7.0")
	}
	err := s.Results[0].Err.Error()
	for _, want := range []string{"helm/podinfo", "6.7.0", "6.7.1", "podinfo-6.7.0.tgz"} {
		if !strings.Contains(err, want) {
			t.Errorf("the refusal does not name %q: %s", want, err)
		}
	}
	if _, statErr := os.Stat(dest); statErr == nil {
		t.Errorf("the refused fetch left %s on disk", filepath.Base(dest))
	}
}

func TestFetchHelmAcceptsAChartYAMLThatAgrees(t *testing.T) {
	tgz := chartTGZ(t, "podinfo", "apiVersion: v2\nname: podinfo\nversion: 6.7.0\n")
	s, dest := fetchPinnedChart(t, "6.7.0", tgz)

	if s.Failures != 0 {
		t.Fatalf("a chart declaring the pinned version was refused: %+v", s.Results)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("the accepted fetch stored nothing at %s: %v", dest, err)
	}
}

// Missing, unparseable and mismatched are three different things an operator
// does three different things about, so they do not collapse into one error.
func TestReadChartMetadataDistinguishesItsFailures(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, err := readChartMetadata(write("notgz.tgz", []byte("plain bytes"))); err == nil {
		t.Error("a non-gzip file read as a chart")
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "podinfo/values.yaml", Mode: 0o644, Size: 0, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	if _, err := readChartMetadata(write("nochart.tgz", buf.Bytes())); !errors.Is(err, errChartYAMLMissing) {
		t.Errorf("an archive with no Chart.yaml = %v, want errChartYAMLMissing", err)
	}

	bad := write("bad.tgz", chartTGZ(t, "podinfo", "version: [unclosed\n"))
	if _, err := readChartMetadata(bad); !errors.Is(err, errChartYAMLUnparseable) {
		t.Errorf("unparseable Chart.yaml = %v, want errChartYAMLUnparseable", err)
	}

	noVer := write("nover.tgz", chartTGZ(t, "podinfo", "apiVersion: v2\nname: podinfo\n"))
	if _, err := readChartMetadata(noVer); !errors.Is(err, errChartYAMLUnparseable) {
		t.Errorf("Chart.yaml with no version = %v, want errChartYAMLUnparseable", err)
	}

	big := write("big.tgz", chartTGZ(t, "podinfo", "version: 6.7.0\n# "+strings.Repeat("x", chartYAMLMaxBytes)+"\n"))
	if _, err := readChartMetadata(big); !errors.Is(err, errChartYAMLUnparseable) {
		t.Errorf("an oversized Chart.yaml = %v, want the read bounded and refused", err)
	}

	// A subchart's Chart.yaml is not the archive's.
	var sub bytes.Buffer
	sgz := gzip.NewWriter(&sub)
	stw := tar.NewWriter(sgz)
	body := []byte("apiVersion: v2\nname: dep\nversion: 1.2.3\n")
	if err := stw.WriteHeader(&tar.Header{Name: "podinfo/charts/dep/Chart.yaml", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := stw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = stw.Close()
	_ = sgz.Close()
	if _, err := readChartMetadata(write("subonly.tgz", sub.Bytes())); !errors.Is(err, errChartYAMLMissing) {
		t.Errorf("a subchart Chart.yaml was read as the archive's: %v", err)
	}
}

// The admission digests the chart in a request of its own, so a server that
// answers the fetch's request with other bytes must not get them stored under
// a verified signature.
func TestFetchHelmRefusesBytesTheProvDidNotSign(t *testing.T) {
	key, err := openpgp.NewEntity("Chart Publisher", "", "charts@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	signed := chartTGZ(t, "podinfo", "apiVersion: v2\nname: podinfo\nversion: 6.7.0\n")
	swapped := chartTGZ(t, "podinfo", "apiVersion: v2\nname: podinfo\nversion: 6.7.0\ndescription: swapped\n")
	sum := sha256.Sum256(signed)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var prov bytes.Buffer
	w, err := clearsign.Encode(&prov, key.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("apiVersion: v2\nname: podinfo\nversion: 6.7.0\n\n...\nfiles:\n  podinfo-6.7.0.tgz: " + digest + "\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var chartGets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/podinfo-6.7.0.tgz":
			if chartGets.Add(1) == 1 {
				_, _ = rw.Write(signed)
				return
			}
			_, _ = rw.Write(swapped)
		case "/podinfo-6.7.0.tgz.prov":
			_, _ = rw.Write(prov.Bytes())
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(srv.Close)
	var pub bytes.Buffer
	if err := key.Serialize(&pub); err != nil {
		t.Fatal(err)
	}
	keyring := filepath.Join(t.TempDir(), "charts.gpg")
	if err := os.WriteFile(keyring, pub.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	chartURL := srv.URL + "/podinfo-6.7.0.tgz"
	pm := &manifest.PackageManifest{Type: manifest.TypeHelm, Name: "podinfo",
		Versions: []manifest.VersionEntry{{Version: "6.7.0", URL: chartURL}}}
	cfg, store, _ := pinEnv(t, pm)
	cfg.app = &config.Config{HelmKeyrings: map[string]string{srv.URL + "/": keyring}}
	s := FetchHelm(cfg, store, "podinfo")

	if s.Failures != 1 || chartGets.Load() != 2 {
		t.Fatalf("failures = %d after %d chart requests: %+v", s.Failures, chartGets.Load(), s.Results)
	}
	msg := s.Results[0].Err.Error()
	for _, want := range []string{digest, "sha256:" + hex.EncodeToString(func() []byte { h := sha256.Sum256(swapped); return h[:] }()), chartURL} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	if _, err := os.Stat(helmLocalPath(d, "podinfo", pm.Versions[0])); err == nil {
		t.Error("the refused chart was left at its local path")
	}
}
