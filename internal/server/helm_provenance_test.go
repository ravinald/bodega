package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// signedChartUpstream is a classic chart repository publishing one chart and
// a .prov signing the bytes in signed. The first chart GET answers signed;
// every later one answers later, which is the upstream that swaps the bytes
// between the admission's read and the proxy's fetch.
type signedChartUpstream struct {
	ts            *httptest.Server
	keyring       string
	signed, later []byte
	digest        string
	chartGets     atomic.Int32
}

func newSignedChartUpstream(t *testing.T, signed, later []byte) *signedChartUpstream {
	t.Helper()
	key, err := openpgp.NewEntity("Chart Publisher", "", "charts@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	u := &signedChartUpstream{signed: signed, later: later, digest: "sha256:" + hex.EncodeToString(sum[:])}
	var prov bytes.Buffer
	w, err := clearsign.Encode(&prov, key.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("apiVersion: v2\nname: podinfo\nversion: 6.7.0\n\n...\nfiles:\n  podinfo-6.7.0.tgz: " + u.digest + "\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	u.ts = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/charts/podinfo-6.7.0.tgz":
			if u.chartGets.Add(1) == 1 {
				_, _ = rw.Write(u.signed)
				return
			}
			_, _ = rw.Write(u.later)
		case "/charts/podinfo-6.7.0.tgz.prov":
			_, _ = rw.Write(prov.Bytes())
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(u.ts.Close)
	var pub bytes.Buffer
	if err := key.Serialize(&pub); err != nil {
		t.Fatal(err)
	}
	u.keyring = filepath.Join(t.TempDir(), "charts.gpg")
	if err := os.WriteFile(u.keyring, pub.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return u
}

func helmProvenanceServer(t *testing.T, up *signedChartUpstream) *Server {
	t.Helper()
	s := proxyingServer(t)
	s.cfg.HelmKeyrings = map[string]string{up.ts.URL + "/": up.keyring}
	seedProxyHelm(t, s, "podinfo", "6.7.0", up.ts.URL+"/charts")
	return s
}

func helmProvenanceRow(t *testing.T, s *Server) audit.AdmissionCheck {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeHelm, PkgName: "podinfo"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("admissions: %d rows, %v", len(rows), err)
	}
	for _, c := range rows[0].Checks {
		if c.Check == audit.CheckUpstreamProvenance {
			return c
		}
	}
	t.Fatalf("the admission row has no upstream_provenance check: %+v", rows[0].Checks)
	return audit.AdmissionCheck{}
}

// A classic chart fetched through the proxy is admitted on its .prov, and the
// row names who signed it and what.
func TestHelmProxyFillVerifiesProv(t *testing.T) {
	chart := []byte("signed chart bytes")
	up := newSignedChartUpstream(t, chart, chart)
	s := helmProvenanceServer(t, up)

	status, body := getStatusAndBody(t, s, "/helm/charts/podinfo-6.7.0.tgz")
	if status != http.StatusOK || body != string(chart) {
		t.Fatalf("GET = %d %q, want 200 with the signed chart", status, body)
	}
	c := helmProvenanceRow(t, s)
	if c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceVerified ||
		c.Provenance.SubjectDigest != up.digest || len(c.Provenance.SignerFingerprint) != 40 {
		t.Fatalf("provenance = %+v (%s), want verified over %s with a signer fingerprint", c.Provenance, c.Detail, up.digest)
	}
	for _, other := range []string{audit.CheckAge, audit.CheckOSV} {
		rows, _ := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeHelm, PkgName: "podinfo"})
		for _, rc := range rows[0].Checks {
			if rc.Check == other && (rc.Status != audit.CheckNotEvaluated || !strings.Contains(rc.Detail, "provenance check only")) {
				t.Errorf("%s = %s %q, want not_evaluated naming why", other, rc.Status, rc.Detail)
			}
		}
	}
}

// An upstream that serves the proxy other bytes than the ones the admission
// read and the .prov signed is refused, and nothing is cached.
func TestHelmProxyFillRefusesBytesTheProvDidNotSign(t *testing.T) {
	up := newSignedChartUpstream(t, []byte("signed chart bytes"), []byte("swapped chart bytes"))
	s := helmProvenanceServer(t, up)

	status, body := getStatusAndBody(t, s, "/helm/charts/podinfo-6.7.0.tgz")
	if status != http.StatusBadGateway || strings.Contains(body, "swapped") {
		t.Fatalf("GET = %d %q, want 502 without the swapped bytes", status, body)
	}
	if !strings.Contains(body, ".prov signed") {
		t.Errorf("the refusal does not say the bytes miss the signed digest: %q", body)
	}
	if up.chartGets.Load() != 2 {
		t.Errorf("chart GETs = %d, want 2: one by the admission, one by the fill", up.chartGets.Load())
	}
	if c := helmProvenanceRow(t, s); c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceVerified {
		t.Fatalf("provenance = %+v, want the admission verified before the fetch", c.Provenance)
	}
	info, err := s.typeStore(manifest.TypeHelm).Head(t.Context(), manifest.HelmChartKey("podinfo", "6.7.0"))
	if err == nil && info != nil && info.Exists {
		t.Error("the swapped chart was cached")
	}
}

func TestReviewHelmRefusedProxyBytesDoNotPoisonChecksum(t *testing.T) {
	signed := []byte("signed chart bytes")
	up := newSignedChartUpstream(t, signed, []byte("swapped chart bytes"))
	s := helmProvenanceServer(t, up)
	status, _ := getStatusAndBody(t, s, "/helm/charts/podinfo-6.7.0.tgz")
	if status != http.StatusBadGateway {
		t.Fatalf("first GET = %d, want 502", status)
	}
	pin, err := s.auditDB.GetChecksum(t.Context(), manifest.HelmChartKey("podinfo", "6.7.0"))
	if err != nil {
		t.Fatal(err)
	}
	if pin != nil && pin.Value != "" {
		t.Errorf("refused bytes left checksum pin sha256:%s; publisher signed %s", pin.Value, up.digest)
	}
	up.later = signed
	status, body := getStatusAndBody(t, s, "/helm/charts/podinfo-6.7.0.tgz")
	if status != http.StatusOK || body != string(signed) {
		t.Fatalf("retry with publisher's bytes = %d %q; want 200 and signed chart, without operator clearing a poisoned checksum", status, body)
	}
}
