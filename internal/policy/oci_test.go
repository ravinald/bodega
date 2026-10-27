package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func ociAgeChecker(minAge time.Duration) *AgeChecker {
	return NewAgeChecker(&fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeOCI: {Ecosystem: manifest.TypeOCI, MinAgeSeconds: int64(minAge.Seconds()), Action: ActionBlock},
	}})
}

func ociTagEntry(at time.Time, datedBy string) *manifest.VersionEntry {
	return &manifest.VersionEntry{Version: "1.27", PublishedAt: at.UTC().Format(time.RFC3339),
		Metadata: map[string]string{OCIDatedByKey: datedBy}}
}

var ociNginx = &manifest.PackageManifest{Type: manifest.TypeOCI, Name: "docker.io/library/nginx"}

// An image is judged by the time its tag's record carries, and the verdict
// names which time that was.
func TestOCIAgeJudgesTheRecordedTime(t *testing.T) {
	ck := ociAgeChecker(7 * 24 * time.Hour)

	young := ck.Check(t.Context(), ociNginx, ociTagEntry(time.Now().Add(-2*24*time.Hour), OCIDatedByCreated))
	if young.Action != ActionBlock {
		t.Fatalf("a 2d-old image under a 7d floor = %+v, want a block", young)
	}
	if young.Details["dated_by"] != OCIDatedByCreated || !strings.Contains(young.Reason, "created time") {
		t.Errorf("young verdict does not say it used created: %+v", young)
	}

	old := ck.Check(t.Context(), ociNginx, ociTagEntry(time.Now().Add(-30*24*time.Hour), OCIDatedByCreated))
	if old.Action != ActionPass || old.Details["dated_by"] != OCIDatedByCreated {
		t.Errorf("a 30d-old image = %+v, want a pass dated by created", old)
	}

	firstSeen := ck.Check(t.Context(), ociNginx, ociTagEntry(time.Now().Add(-time.Hour), OCIDatedByFirstSeen))
	if firstSeen.Action != ActionBlock || firstSeen.Details["dated_by"] != OCIDatedByFirstSeen ||
		!strings.Contains(firstSeen.Reason, "first resolved") {
		t.Errorf("first-seen verdict = %+v, want a block saying it used first-seen", firstSeen)
	}
}

// A tag the registry could not date warns, as an unreachable upstream does
// for every other type, and names why.
func TestOCIAgeUndatedWarns(t *testing.T) {
	ck := ociAgeChecker(time.Hour)
	for _, ve := range []*manifest.VersionEntry{
		{Version: "1.27"},
		{Version: "1.27", Metadata: map[string]string{OCIDateErrorKey: "config blob fetch failed"}},
	} {
		r := ck.Check(t.Context(), ociNginx, ve)
		if r.Action != ActionWarn {
			t.Errorf("%+v: %+v, want a warn", ve.Metadata, r)
		}
	}
	if r := ck.Check(t.Context(), ociNginx, &manifest.VersionEntry{Version: "1.27",
		Metadata: map[string]string{OCIDateErrorKey: "config blob fetch failed"}}); !strings.Contains(r.Reason, "config blob fetch failed") {
		t.Errorf("reason %q does not carry the registry's error", r.Reason)
	}
	if !UndatableVersion(manifest.TypeOCI, "1.27") {
		t.Error("an oci tag is datable by lookup; import would try one")
	}
}

func TestOCIOSVNotRun(t *testing.T) {
	ck := NewOSVChecker(&fakeOSVStore{})
	r := ck.Check(t.Context(), ociNginx, &manifest.VersionEntry{Version: "1.27"})
	if r.Action != ActionNotEvaluated || r.Reason != OSVNotRunOCI {
		t.Fatalf("oci = %+v, want not_evaluated with the no-ecosystem reason", r)
	}
	if !strings.Contains(r.Reason, "no container image ecosystem") {
		t.Errorf("reason %q", r.Reason)
	}
	if r := ck.CheckMalware(t.Context(), ociNginx, &manifest.VersionEntry{Version: "1.27"}); r.Action != ActionNotEvaluated {
		t.Errorf("malware-only = %+v, want not_evaluated", r)
	}
}

func TestOCISimilarity(t *testing.T) {
	p, ok := EmbeddedPopularNames(manifest.TypeOCI)
	if !ok || !p.Contains("library/nginx") || !strings.HasPrefix(p.Source, "https://hub.docker.com/") {
		t.Fatalf("embedded oci list: ok=%v source %q", ok, p.Source)
	}

	r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeOCI, "docker.io/library/ngnix")
	if r.Action != ActionBlock || r.Details["nearest"] != "library/nginx" {
		t.Fatalf("docker.io/library/ngnix = %+v, want a block near library/nginx", r)
	}
	if d, _ := r.Details["distance"].(int); d < 1 || d > MaxSimilarityDistance {
		t.Errorf("distance %v, want within %d", r.Details["distance"], MaxSimilarityDistance)
	}
	if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeOCI, "docker.io/library/nginx"); r.Action != ActionPass {
		t.Errorf("docker.io/library/nginx = %+v, want a pass", r)
	}
	// Only the last two segments are compared: the same squat at another
	// registry, or deeper in a group, is caught too.
	for _, name := range []string{"ghcr.io/library/ngnix", "ghcr.io/acme/mirror/library/ngnix"} {
		if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeOCI, name); r.Action != ActionBlock {
			t.Errorf("%s = %+v, want a block", name, r)
		}
	}
	exact := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeOCI, Pattern: "docker.io/library/ngnix"}}}
	if r := checkName(t, exact, manifest.TypeOCI, "docker.io/library/ngnix"); r.Action != ActionPass {
		t.Errorf("exact rule = %+v, want an exempt pass", r)
	}
	if ExactRule(manifest.TypeOCI, "docker.io/library/*") {
		t.Error("a prefix rule counts as exact and would exempt every repository under it")
	}
}

func TestSimilarityName(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io/library/nginx":         "library/nginx",
		"ghcr.io/a/b/c":                   "b/c",
		"quay.io/solo":                    "solo",
		"docker.io/example-corp/web":      "example-corp/web",
		"registry.example.com/team/x/y/z": "y/z",
	} {
		if got := SimilarityName(manifest.TypeOCI, in); got != want {
			t.Errorf("SimilarityName(oci, %q) = %q, want %q", in, got, want)
		}
	}
	if got := SimilarityName(manifest.TypeNpm, "@a/b"); got != "@a/b" {
		t.Errorf("npm name changed: %q", got)
	}
}
