package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// ociPolicyServer is ociServer with the real per-version checks, counting
// each time a request builds them, and the age floor at a week, blocking.
func ociPolicyServer(t *testing.T, f *ociFixture) (*Server, *atomic.Int32) {
	t.Helper()
	var built atomic.Int32
	prev := fetchCheckers
	fetchCheckers = func(cfg *config.Config, adb *audit.DB) []policy.VersionChecker {
		built.Add(1)
		return admit.VersionCheckers(cfg, adb)
	}
	t.Cleanup(func() { fetchCheckers = prev })
	s := ociServer(t, f)
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeOCI,
		MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	return s, &built
}

func ociCreatedAgo(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

// ociTagRow is the newest admission row for a tag.
func ociTagRow(t *testing.T, s *Server, name, tag string) audit.Admission {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeOCI, PkgName: name, PkgVersion: tag, Limit: 1})
	if err != nil || len(rows) != 1 {
		t.Fatalf("admissions for %s:%s = %d rows, %v; want 1", name, tag, len(rows), err)
	}
	return rows[0]
}

func ociRowCheck(t *testing.T, row audit.Admission, check string) audit.AdmissionCheck {
	t.Helper()
	for _, c := range row.Checks {
		if c.Check == check {
			return c
		}
	}
	t.Fatalf("row carries no %s check: %+v", check, row.Checks)
	return audit.AdmissionCheck{}
}

// An image younger than the age floor is refused at its tag, an older one is
// served, and the verdict says it was dated by the config's created time.
func TestOCIReleaseAge(t *testing.T) {
	f := newOCIFixture(t)
	young, old := newOCIImageCreated(ociCreatedAgo(24*time.Hour)), newOCIImageCreated(ociCreatedAgo(30*24*time.Hour))
	f.hub.publish("library/nginx", "young", young)
	f.hub.publish("library/nginx", "old", old)
	s, _ := ociPolicyServer(t, f)

	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/young", nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "holds new versions back for 7d")
	refusalIncident(t, rec.Header(), checkAge)
	row := ociTagRow(t, s, "docker.io/library/nginx", "young")
	if row.Decision != audit.AdmissionPolicyBlocked {
		t.Errorf("young tag decision %q", row.Decision)
	}
	if c := ociRowCheck(t, row, audit.CheckAge); c.Status != audit.CheckBlock || !strings.Contains(c.Detail, "created time") {
		t.Errorf("age check %+v, want a block naming the created time", c)
	}

	rec = doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/old", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(old.index) {
		t.Fatalf("old tag: %d %s", rec.Code, rec.Body.String())
	}
	if c := ociRowCheck(t, ociTagRow(t, s, "docker.io/library/nginx", "old"), audit.CheckAge); c.Status != audit.CheckPass {
		t.Errorf("old tag age check %+v, want a pass", c)
	}
}

// A config at the Unix epoch is judged by when bodega first resolved the tag,
// which the tag's record keeps across a refresh, and the refusal says so.
func TestOCIReleaseAgeEpochUsesFirstSeen(t *testing.T) {
	f := newOCIFixture(t)
	f.hub.publish("library/nginx", "repro", newOCIImageCreated("1970-01-01T00:00:00Z"))
	s, _ := ociPolicyServer(t, f)
	path := "/v2/library/nginx/manifests/repro"

	rec := doRequest(s, http.MethodGet, path, nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "no build time", "first resolved the tag")
	if c := ociRowCheck(t, ociTagRow(t, s, "docker.io/library/nginx", "repro"), audit.CheckAge); c.Status != audit.CheckBlock || !strings.Contains(c.Detail, "first resolved") {
		t.Errorf("age check %+v, want a block naming first-seen", c)
	}
	key := manifest.OCITagKey("docker.io", "library/nginx", "repro")
	first := ociStoredTagDoc(t, s, key)
	if first.Created != "" || first.FirstSeen == "" {
		t.Fatalf("tag record %+v, want first-seen and no created", first)
	}

	s.cache.MetadataTTL = time.Nanosecond
	time.Sleep(1100 * time.Millisecond)
	doRequest(s, http.MethodGet, path, nil)
	if n := f.hub.hitsFor("/v2/library/nginx/manifests/repro"); n != 2 {
		t.Fatalf("tag resolved %d times, want 2", n)
	}
	if again := ociStoredTagDoc(t, s, key); again.FirstSeen != first.FirstSeen {
		t.Errorf("first-seen moved on refresh: %s, then %s", first.FirstSeen, again.FirstSeen)
	}
}

func ociStoredTagDoc(t *testing.T, s *Server, key string) ociTagDoc {
	t.Helper()
	b, err := s.typeStore(manifest.TypeOCI).Get(t.Context(), key)
	if err != nil {
		t.Fatalf("tag record %s: %v", key, err)
	}
	var doc ociTagDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("tag record %s: %v", key, err)
	}
	return doc
}

// OSV records that it did not run on an image, rather than a pass.
func TestOCIOSVNotRunRow(t *testing.T) {
	f := newOCIFixture(t)
	s, _ := ociPolicyServer(t, f)
	f.hub.publish("library/nginx", "old", newOCIImageCreated(ociCreatedAgo(30*24*time.Hour)))
	if rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/old", nil); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	c := ociRowCheck(t, ociTagRow(t, s, "docker.io/library/nginx", "old"), audit.CheckOSV)
	if c.Status != audit.CheckNotEvaluated || c.Detail != policy.OSVNotRunOCI {
		t.Errorf("osv check %+v, want not_evaluated with %q", c, policy.OSVNotRunOCI)
	}
}

func TestOCISimilarity(t *testing.T) {
	f := newOCIFixture(t)
	old := newOCIImageCreated(ociCreatedAgo(30 * 24 * time.Hour))
	f.hub.publish("library/ngnix", "1.27", old)
	f.hub.publish("library/nginx", "old", old)
	s, _ := ociPolicyServer(t, f)
	if err := s.auditDB.SetSimilarityPolicy(t.Context(), audit.SimilarityPolicy{Ecosystem: manifest.TypeOCI, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(s, http.MethodGet, "/v2/library/ngnix/manifests/1.27", nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "docker.io/library/ngnix")
	refusalIncident(t, rec.Header(), checkSimilarity)
	if c := ociRowCheck(t, ociTagRow(t, s, "docker.io/library/ngnix", "1.27"), audit.CheckNameSimilarity); c.Status != audit.CheckBlock || !strings.Contains(c.Detail, "library/nginx") {
		t.Errorf("similarity check %+v, want a block naming library/nginx", c)
	}

	if rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/old", nil); rec.Code != http.StatusOK {
		t.Fatalf("docker.io/library/nginx: %d %s", rec.Code, rec.Body.String())
	}
}

// A blob and a platform manifest under a refused tag take its verdict: they
// are refused without the checks being built again, and nothing is fetched.
func TestOCIBlobUnderARefusedTag(t *testing.T) {
	f := newOCIFixture(t)
	young := newOCIImageCreated(ociCreatedAgo(time.Hour))
	f.hub.publish("library/nginx", "young", young)
	s, built := ociPolicyServer(t, f)

	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/young", nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED")
	if n := built.Load(); n != 1 {
		t.Fatalf("checks built %d times for one tag, want 1", n)
	}
	for _, p := range []string{
		"/v2/library/nginx/blobs/" + young.amd64LayerD,
		"/v2/library/nginx/manifests/" + young.amd64Digest,
	} {
		before := f.hub.total()
		rec := doRequest(s, http.MethodGet, p, nil)
		msg := assertOCIError(t, rec, http.StatusForbidden, "DENIED", "tag young", "age check")
		refusalIncident(t, rec.Header(), checkAge)
		if !strings.Contains(msg, "same verdict") {
			t.Errorf("%s: message %q does not say it took the tag's verdict", p, msg)
		}
		if n := f.hub.total() - before; n != 0 {
			t.Errorf("%s: registry contacted %d times", p, n)
		}
	}
	if n := built.Load(); n != 1 {
		t.Errorf("checks built %d times in all, want 1: a blob is not judged a second time", n)
	}
	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatal(err)
	}
	denied := 0
	for _, r := range rows {
		if r.Status == audit.DenialTagRefused {
			denied++
		}
	}
	if denied != 2 {
		t.Errorf("%d tag_refused denial rows, want 2", denied)
	}
}

// The tag's platform is the one Docker names in its User-Agent, and
// linux/amd64 otherwise.
func TestOCIPickChild(t *testing.T) {
	im := newOCIImage()
	for _, tc := range []struct {
		ua   string
		want string
	}{
		{"docker/27.3.1 go/go1.22.7 git-commit/41ca978 kernel/6.8.0 os/linux arch/arm64 UpstreamClient(Docker-Client/27.3.1)", im.arm64Digest},
		{"containerd/1.7.22", im.amd64Digest},
		{"docker/27.3.1 os/windows arch/amd64", im.amd64Digest},
	} {
		r, _ := http.NewRequest(http.MethodGet, "/v2/", nil)
		r.Header.Set("User-Agent", tc.ua)
		if got := ociPickChild(im.index, ociPlatformOf(r)); got != tc.want {
			t.Errorf("%q picked %s, want %s", tc.ua, got, tc.want)
		}
	}
	if got := ociPickChild(im.amd64, ociPlatform{"linux", "amd64"}); got != "" {
		t.Errorf("an image manifest picked child %q", got)
	}
	for in, want := range map[string]string{
		`{"created":"2026-10-01T12:00:00.123Z"}`: "2026-10-01T12:00:00Z",
		`{"created":"1970-01-01T00:00:00Z"}`:     "",
		`{"created":"0001-01-01T00:00:00Z"}`:     "",
		`{}`:                                     "",
		`{"created":"yesterday"}`:                "",
	} {
		if got := ociConfigCreated([]byte(in)); got != want {
			t.Errorf("ociConfigCreated(%s) = %q, want %q", in, got, want)
		}
	}
}
