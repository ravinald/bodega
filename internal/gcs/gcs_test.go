package gcs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	gstorage "cloud.google.com/go/storage"

	"github.com/ravinald/bodega/internal/gcs/gcstest"
	"github.com/ravinald/bodega/internal/manifest"
)

func project(id string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return id, nil }
}

func noProject(context.Context) (string, error) {
	return "", errors.New("the test asked for no project")
}

// controls reads back the four settings InitBucket is responsible for, from
// the bucket as the API reports it.
func controls(t *testing.T, client *gstorage.Client, bucket string) (ubla, pap, versioning bool, rules []gstorage.LifecycleRule) {
	t.Helper()
	attrs, err := client.Bucket(bucket).Attrs(t.Context())
	if err != nil {
		t.Fatalf("read back gs://%s: %v", bucket, err)
	}
	return attrs.UniformBucketLevelAccess.Enabled, attrs.PublicAccessPrevention == gstorage.PublicAccessPreventionEnforced,
		attrs.VersioningEnabled, attrs.Lifecycle.Rules
}

func changed(out string) bool {
	return strings.Contains(out, "CREATED") || strings.Contains(out, "CONFIGURED") || strings.Contains(out, "ENABLED")
}

// TestInitBucketCreatesAndIsIdempotent: a missing bucket is created with all
// four controls in the named project and location, and a second run reports
// every line as already correct and writes nothing.
func TestInitBucketCreatesAndIsIdempotent(t *testing.T) {
	srv := gcstest.New(t)
	client := srv.Client(t)
	var out bytes.Buffer
	if err := InitBucket(t.Context(), client, &out, "example-bodega-artifacts", "us-central1", project("example-project")); err != nil {
		t.Fatalf("first init: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "CREATED gs://example-bodega-artifacts in project example-project, US-CENTRAL1") {
		t.Errorf("first run did not report the create:\n%s", out.String())
	}
	ubla, pap, versioning, rules := controls(t, client, "example-bodega-artifacts")
	if !ubla || !pap || !versioning {
		t.Errorf("created bucket: uniform access %v, public access prevention %v, versioning %v; want all three", ubla, pap, versioning)
	}
	if len(rules) != 1 {
		t.Fatalf("created bucket holds %d lifecycle rules, want 1", len(rules))
	}
	if got := srv.Bucket("example-bodega-artifacts")["location"]; got != "US-CENTRAL1" {
		t.Errorf("bucket location = %v, want US-CENTRAL1", got)
	}

	before := len(srv.Requests())
	out.Reset()
	if err := InitBucket(t.Context(), client, &out, "example-bodega-artifacts", "", noProject); err != nil {
		t.Fatalf("second init: %v\n%s", err, out.String())
	}
	if changed(out.String()) {
		t.Errorf("second run reported a change:\n%s", out.String())
	}
	for _, r := range srv.Requests()[before:] {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("second run wrote to a bucket that was already correct: %s", r)
		}
	}
}

// TestInitBucketConfiguresAnExistingBucket: a bucket made elsewhere with none
// of the controls gets all four in one patch conditional on the
// metageneration read, and an operator's own lifecycle rule survives it.
func TestInitBucketConfiguresAnExistingBucket(t *testing.T) {
	srv := gcstest.New(t)
	client := srv.Client(t)
	srv.AddBucket("existing")
	theirs := gstorage.LifecycleRule{
		Action:    gstorage.LifecycleAction{Type: gstorage.SetStorageClassAction, StorageClass: "NEARLINE"},
		Condition: gstorage.LifecycleCondition{AgeInDays: 90},
	}
	// Drift: a rule in bodega's form that ages out manifests/.
	drift := LifecycleRule()
	drift.Condition.MatchesPrefix = []string{manifest.ManifestsPrefix}
	if _, err := client.Bucket("existing").Update(t.Context(), gstorage.BucketAttrsToUpdate{
		Lifecycle: &gstorage.Lifecycle{Rules: []gstorage.LifecycleRule{theirs, drift}},
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := InitBucket(t.Context(), client, &out, "existing", "", noProject); err != nil {
		t.Fatalf("init: %v\n%s", err, out.String())
	}
	for _, want := range []string{"bucket:     exists in US", "access:     CONFIGURED", "public:     CONFIGURED", "versioning: ENABLED", "lifecycle:  CONFIGURED"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	ubla, pap, versioning, rules := controls(t, client, "existing")
	if !ubla || !pap || !versioning {
		t.Errorf("uniform access %v, public access prevention %v, versioning %v; want all three", ubla, pap, versioning)
	}
	if len(rules) != 2 || rules[0].Action.Type != gstorage.SetStorageClassAction || rules[0].Condition.AgeInDays != 90 {
		t.Fatalf("rules after init = %+v, want the operator's rule kept first and one bodega rule", rules)
	}
	var patches []string
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "PATCH ") {
			patches = append(patches, r)
		}
	}
	if last := patches[len(patches)-1]; len(patches) != 2 || !strings.Contains(last, "ifMetagenerationMatch=") {
		t.Errorf("init patched %d times (after the test's own one), want once and conditional: %v", len(patches)-1, patches)
	}

	out.Reset()
	if err := InitBucket(t.Context(), client, &out, "existing", "", noProject); err != nil || changed(out.String()) {
		t.Errorf("second run: err %v, output reports a change:\n%s", err, out.String())
	}
}

// TestLifecycleRuleNeverNamesHistory is the rule itself: noncurrent
// generations only, after NoncurrentVersionDays, under every storage prefix
// except the two whose history is the point.
func TestLifecycleRuleNeverNamesHistory(t *testing.T) {
	r := LifecycleRule()
	if r.Action.Type != gstorage.DeleteAction || r.Condition.Liveness != gstorage.Archived ||
		r.Condition.DaysSinceNoncurrentTime != 30 || NoncurrentVersionDays != 30 {
		t.Errorf("rule = %+v, want a delete of noncurrent generations after 30 days", r)
	}
	if r.Condition.AgeInDays != 0 || r.Condition.AllObjects || r.Condition.NumNewerVersions != 0 {
		t.Errorf("rule carries a condition that reaches live objects: %+v", r.Condition)
	}
	for _, p := range r.Condition.MatchesPrefix {
		// A prefix match is by string, so "manifests/" is also named by any
		// prefix of it.
		for _, kept := range []string{manifest.ManifestsPrefix, manifest.AttestationPrefix} {
			if strings.HasPrefix(kept, p) {
				t.Errorf("rule prefix %q reaches %s, whose noncurrent generations are kept", p, kept)
			}
		}
	}
	for _, p := range manifest.StoragePrefixes() {
		kept := p == manifest.ManifestsPrefix || p == manifest.AttestationPrefix
		if slices.Contains(r.Condition.MatchesPrefix, p) == kept {
			t.Errorf("storage prefix %q: named by the rule = %v, want %v", p, !kept, !kept)
		}
	}
	if len(r.Condition.MatchesPrefix) == 0 {
		t.Error("rule names no prefix, which Cloud Storage reads as the whole bucket")
	}
}

func TestInitBucketRefusals(t *testing.T) {
	srv := gcstest.New(t)
	client := srv.Client(t)
	srv.AddBucket("elsewhere")

	err := InitBucket(t.Context(), client, nil, "elsewhere", "europe-west1", noProject)
	if err == nil || !strings.Contains(err.Error(), "location cannot change") {
		t.Errorf("location mismatch: err = %v, want a refusal", err)
	}
	if got := srv.Bucket("elsewhere"); got["versioning"] != nil {
		t.Errorf("a refused run changed the bucket: %v", got)
	}

	err = InitBucket(t.Context(), client, nil, "missing-bucket", "", noProject)
	if err == nil || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "no project") {
		t.Errorf("missing bucket, no project: err = %v, want both named", err)
	}
	if srv.Bucket("missing-bucket") != nil {
		t.Error("a bucket was created with no project resolved")
	}

	for _, bad := range []string{"", "ab", "Upper-Case", "has space", "star*", "-leading"} {
		if err := InitBucket(t.Context(), client, nil, bad, "", project("p")); err == nil || !strings.Contains(err.Error(), "not a valid") {
			t.Errorf("bucket %q: err = %v, want the name refused", bad, err)
		}
	}

	srv.FailNext("GET /storage/v1/b/elsewhere", 1)
	err = InitBucket(t.Context(), client, nil, "elsewhere", "", noProject)
	if err == nil || !strings.Contains(err.Error(), "storage.buckets.get") {
		t.Errorf("403 on the read: err = %v, want the permission and the global-name cause named", err)
	}
}

// TestCheckAccess: every runtime permission is asked about in one read-only
// call and reported by name, a missing bucket and a dead network are errors
// rather than missing permissions, and nothing is written.
func TestCheckAccess(t *testing.T) {
	srv := gcstest.New(t)
	client := srv.Client(t)
	srv.AddBucket("b")

	var out bytes.Buffer
	r, err := CheckAccess(t.Context(), client, &out, "b")
	if err != nil || len(r.Missing) != 0 || !slices.Equal(r.Allowed, RuntimeRole().Permissions) {
		t.Fatalf("all held: report %+v, err %v\n%s", r, err, out.String())
	}

	srv.Deny("storage.objects.delete")
	out.Reset()
	r, err = CheckAccess(t.Context(), client, &out, "b")
	if err != nil || !slices.Equal(r.Missing, []string{"storage.objects.delete"}) || len(r.Allowed) != 3 {
		t.Fatalf("delete denied: report %+v, err %v", r, err)
	}
	if !strings.Contains(out.String(), "storage.objects.delete   missing; grant it on gs://b") {
		t.Errorf("output does not name the missing permission and where to grant it:\n%s", out.String())
	}

	out.Reset()
	r, err = CheckAccess(t.Context(), client, &out, "no-such-bucket")
	if err == nil || len(r.Missing) != 0 || !strings.Contains(out.String(), "does not exist") {
		t.Errorf("missing bucket: report %+v, err %v, output %q; want an error and no missing permission", r, err, out.String())
	}

	for _, req := range srv.Requests() {
		if !strings.HasPrefix(req, "GET ") {
			t.Errorf("check wrote to the bucket: %s", req)
		}
	}

	srv.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r, err = CheckAccess(ctx, client, nil, "b")
	if err == nil || len(r.Missing) != 0 || !strings.Contains(err.Error(), "says nothing about the role") {
		t.Errorf("no answer from the API: report %+v, err %v; want an error drawing no conclusion", r, err)
	}
}

// TestRolesGrantWhatTheCallsNeedAndNoMore pins the two permission sets. The
// setup role deletes nothing and the runtime role holds no bucket permission;
// either changing is a decision, and this is where it gets noticed.
func TestRolesGrantWhatTheCallsNeedAndNoMore(t *testing.T) {
	setup, runtime := SetupRole(), RuntimeRole()
	if want := []string{"storage.buckets.create", "storage.buckets.get", "storage.buckets.setIamPolicy", "storage.buckets.update"}; !slices.Equal(setup.Permissions, want) {
		t.Errorf("setup permissions = %v, want %v", setup.Permissions, want)
	}
	if want := []string{"storage.objects.create", "storage.objects.delete", "storage.objects.get", "storage.objects.list"}; !slices.Equal(runtime.Permissions, want) {
		t.Errorf("runtime permissions = %v, want %v", runtime.Permissions, want)
	}
	for _, p := range setup.Permissions {
		if strings.Contains(p, "delete") {
			t.Errorf("setup role holds %s; init never deletes", p)
		}
	}
	for _, p := range runtime.Permissions {
		if strings.HasPrefix(p, "storage.buckets.") {
			t.Errorf("runtime role holds %s; the service must not be able to change the bucket", p)
		}
	}
	if setup.Predefined != "roles/storage.admin" || runtime.Predefined != "roles/storage.objectUser" {
		t.Errorf("predefined roles = %s, %s", setup.Predefined, runtime.Predefined)
	}
	yaml := runtime.YAML()
	for _, p := range runtime.Permissions {
		if !strings.Contains(yaml, "- "+p+"\n") {
			t.Errorf("role definition lacks %s:\n%s", p, yaml)
		}
	}
	if !strings.HasPrefix(yaml, "title: bodega runtime\n") || !strings.Contains(yaml, "includedPermissions:\n") {
		t.Errorf("role definition is not the file gcloud iam roles create reads:\n%s", yaml)
	}
}

func TestProjectPrefersTheEnvironment(t *testing.T) {
	t.Setenv(ProjectEnv, "example-project")
	if p, err := Project(t.Context()); err != nil || p != "example-project" {
		t.Errorf("Project() = %q, %v", p, err)
	}
	t.Setenv(ProjectEnv, "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/adc.json")
	if _, err := Project(t.Context()); err == nil || !strings.Contains(err.Error(), ProjectEnv) {
		t.Errorf("no project anywhere: err = %v, want the variable named as the fix", err)
	}
}

// TestUsageDocCoversGCS holds docs/usage.md to what an operator standing up a
// gcs backend has to find under Storage backends: the config, both ways
// credentials resolve, the roles with their generated permissions, init with
// its controls, the check, and the conformance suite.
func TestUsageDocCoversGCS(t *testing.T) {
	raw, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	backends := strings.Index(doc, "\n### Storage backends\n")
	start := strings.Index(doc, "\n#### GCS setup\n")
	if backends < 0 || start < backends {
		t.Fatalf("no GCS setup section under Storage backends (backends at %d, section at %d)", backends, start)
	}
	if next := strings.Index(doc[backends+1:start], "\n### "); next >= 0 {
		t.Fatal("the GCS setup section sits under a heading other than Storage backends")
	}
	section := doc[start+1:]
	if end := strings.Index(section, "\n### "); end >= 0 {
		section = section[:end]
	}
	if end := strings.Index(section, "\n#### "); end >= 0 {
		section = section[:end]
	}
	for _, want := range []string{
		`"storage_backend": "gcs"`, "`bucket`", "`prefix`",
		"Application Default Credentials", "GOOGLE_APPLICATION_CREDENTIALS", "gcloud auth application-default login", "service account", ProjectEnv,
		SetupRole().Predefined, RuntimeRole().Predefined, "--print-policy",
		"bodega init", "--location", "uniform bucket-level access", "public access prevention", "versioning", "`manifests/`", "`attestations/`",
		"bodega init check", "testIamPermissions",
		"BODEGA_GCS_CONFORMANCE", "TestObjectStoreConformance/gcs", "soft delete",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("GCS setup section does not mention %s", want)
		}
	}
	for _, role := range []Role{SetupRole(), RuntimeRole()} {
		if !strings.Contains(section, "```yaml\n"+role.YAML()+"```") {
			t.Errorf("the section's %s role definition is not the one --print-policy prints:\n%s", role.Title, role.YAML())
		}
	}
	if !strings.Contains(section, "30 days") {
		t.Error("the section does not state the noncurrent-version retention")
	}
}
