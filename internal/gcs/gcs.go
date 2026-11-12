// Package gcs prepares and checks the Cloud Storage bucket behind a gcs
// storage backend: the client every caller dials, what `bodega init` sets on
// the bucket, and the IAM permissions the setup and runtime identities need.
// The ObjectStore over a bucket is storage.GCS.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"cloud.google.com/go/auth/credentials"
	gstorage "cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"

	"github.com/ravinald/bodega/internal/manifest"
)

// Dial builds the client for every gcs backend from Application Default
// Credentials and nothing else. It takes no key file on purpose: a path in
// bodega's config would be a second place a long-lived credential lives, and
// ADC already reads one from GOOGLE_APPLICATION_CREDENTIALS for a host that
// has to use it.
func Dial(ctx context.Context) (*gstorage.Client, error) {
	client, err := gstorage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create the Cloud Storage client from Application Default Credentials: %w "+
			"(on GCE attach a service account to the instance; elsewhere set GOOGLE_APPLICATION_CREDENTIALS "+
			"or run `gcloud auth application-default login`)", err)
	}
	return client, nil
}

// ProjectEnv names the project a new bucket is created in, ahead of the one
// the credentials carry. User credentials from gcloud carry none.
const ProjectEnv = "GOOGLE_CLOUD_PROJECT"

// Project resolves the project a bucket is created in: ProjectEnv, then the
// one Application Default Credentials name (a service account key's own, or
// the instance's on GCE).
func Project(ctx context.Context) (string, error) {
	if p := os.Getenv(ProjectEnv); p != "" {
		return p, nil
	}
	const hint = "set " + ProjectEnv + " to the project the bucket belongs in, or create the bucket there yourself and re-run"
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{Scopes: []string{gstorage.ScopeFullControl}})
	if err != nil {
		return "", fmt.Errorf("no project to create the bucket in: %w; %s", err, hint)
	}
	p, err := creds.ProjectID(ctx)
	if err != nil {
		return "", fmt.Errorf("no project to create the bucket in: %w; %s", err, hint)
	}
	if p == "" {
		return "", fmt.Errorf("no project to create the bucket in: Application Default Credentials name none; %s", hint)
	}
	return p, nil
}

// bucketName is the Cloud Storage naming rule for a name without dots, plus
// the dotted form. It is enforced before a name reaches a printed gcloud
// command or a create call, so what an operator pastes is one argument.
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)

// ValidateBucket refuses a name Cloud Storage would.
func ValidateBucket(bucket string) error {
	if !bucketName.MatchString(bucket) {
		return fmt.Errorf("bucket %q is not a valid Cloud Storage bucket name (3-63 characters, or up to 222 with dots: lowercase letters, digits, '-', '_' and '.')", bucket)
	}
	return nil
}

// Role is the set of IAM permissions one identity needs, with the nearest
// predefined role for an operator who would rather not define a custom one.
type Role struct {
	// ID is a custom role id: letters, digits, underscores and periods.
	ID          string
	Title       string
	Description string
	// Permissions are exactly what bodega's calls need, sorted.
	Permissions []string
	// Predefined is the narrowest predefined role holding all of Permissions,
	// and Excess is what it grants beyond them that matters.
	Predefined string
	Excess     string
	// GrantOn is the resource the role is bound on.
	GrantOn string
}

// SetupRole is for whoever runs `bodega init`. Creating a bucket is a project
// permission, so the role is bound on the project. It holds no delete of any
// kind: init never removes a bucket or an object.
//
// storage.buckets.setIamPolicy is there because Cloud Storage requires it to
// change public access prevention, in addition to storage.buckets.update.
func SetupRole() Role {
	return Role{
		ID:          "bodegaSetup",
		Title:       "bodega setup",
		Description: "Creates and configures the bucket behind a bodega gcs storage backend. Cannot delete a bucket or an object.",
		Permissions: []string{"storage.buckets.create", "storage.buckets.get", "storage.buckets.setIamPolicy", "storage.buckets.update"},
		Predefined:  "roles/storage.admin",
		Excess:      "it can also delete buckets and read, write and delete every object",
		GrantOn:     "the project",
	}
}

// RuntimeRole is for the service. It holds no bucket permission, so a
// compromised service cannot switch off public access prevention, uniform
// access or versioning.
//
// storage.objects.delete is required to replace an object as well as to
// remove one, and Cloud Storage has no narrower permission for a noncurrent
// version: the identity that can overwrite a manifest can also delete the
// generations versioning kept. What stands behind those is the bucket's soft
// delete window, not this role.
func RuntimeRole() Role {
	return Role{
		ID:          "bodegaRuntime",
		Title:       "bodega runtime",
		Description: "Reads, lists, writes and deletes objects for a bodega gcs storage backend. Cannot change the bucket.",
		Permissions: []string{"storage.objects.create", "storage.objects.delete", "storage.objects.get", "storage.objects.list"},
		Predefined:  "roles/storage.objectUser",
		Excess:      "it also grants object metadata updates, restore, move, folders and multipart uploads",
		GrantOn:     "the bucket",
	}
}

// YAML renders the role as the definition `gcloud iam roles create --file`
// reads.
func (r Role) YAML() string {
	var b strings.Builder
	fmt.Fprintf(&b, "title: %s\ndescription: %s\nstage: GA\nincludedPermissions:\n", r.Title, r.Description)
	for _, p := range r.Permissions {
		fmt.Fprintf(&b, "  - %s\n", p)
	}
	return b.String()
}

// NoncurrentVersionDays is how long a replaced or deleted artifact's previous
// generation is kept. It is stated in `bodega init --help` and docs/usage.md.
const NoncurrentVersionDays = 30

// historyPrefixes keep every noncurrent generation. Under manifests/ that
// generation is what a manifest has against whoever can already write it, and
// under attestations/ it is the signed record of what was admitted; a rule
// that aged either out would finish a compromised service's deletion for it.
var historyPrefixes = []string{manifest.ManifestsPrefix, manifest.AttestationPrefix}

// Namespaces are the key prefixes bodega's backends hold in one bucket. Each
// is "" for the bucket root or ends in "/", as the driver roots keys.
type Namespaces struct {
	// Target is the backend InitBucket prepares the bucket for.
	Target string
	// Others are the other backends configured on the same bucket. Their
	// rules are left alone and their history is kept out of every rule.
	Others []string
}

func (n Namespaces) all() []string {
	all := append([]string{n.Target}, n.Others...)
	slices.Sort(all)
	return slices.Compact(all)
}

func describe(namespace string) string {
	if namespace == "" {
		return "the bucket root"
	}
	return namespace
}

func historyUnder(namespace string) []string {
	out := make([]string, len(historyPrefixes))
	for i, p := range historyPrefixes {
		out[i] = namespace + p
	}
	return out
}

// selects reports whether a rule matching one of prefixes reaches an object
// under one of kept. Cloud Storage matches the start of the whole object
// name, so two prefixes share objects exactly when one starts the other.
func selects(prefixes, kept []string) bool {
	for _, p := range prefixes {
		for _, k := range kept {
			if strings.HasPrefix(p, k) || strings.HasPrefix(k, p) {
				return true
			}
		}
	}
	return false
}

// check refuses a set of namespaces no rules can serve: one backend's
// artifact prefix that holds another's history. A lifecycle condition cannot
// exclude a prefix, so the rule that expires the first would expire the
// second, and dropping either half silently is worse than saying so.
func (n Namespaces) check(bucket string) error {
	all := n.all()
	for _, a := range all {
		for _, b := range all {
			if a != b && selects(LifecycleRule(a).Condition.MatchesPrefix, historyUnder(b)) {
				return fmt.Errorf("gs://%s holds a backend at %s and one at %s, and the rule that expires the first one's artifacts "+
					"would also match the second one's manifests/ or attestations/, which keep every generation. "+
					"A Cloud Storage lifecycle rule cannot exclude a prefix, so nothing was written: "+
					"give one of the two a prefix outside the other's artifact prefixes, or its own bucket",
					bucket, describe(a), describe(b))
			}
		}
	}
	return nil
}

// LifecycleRule is the rule InitBucket keeps on the bucket for the backend
// rooted at namespace: noncurrent generations under each of its artifact
// prefixes are deleted after NoncurrentVersionDays, and nothing under its
// historyPrefixes is named.
//
// Cloud Storage needs no second rule for abandoned uploads. A resumable
// session that never finishes is not an object, appears in no listing and
// expires on its own after a week.
func LifecycleRule(namespace string) gstorage.LifecycleRule {
	var prefixes []string
	for _, p := range manifest.StoragePrefixes() {
		if !slices.Contains(historyPrefixes, p) {
			prefixes = append(prefixes, namespace+p)
		}
	}
	slices.Sort(prefixes)
	return gstorage.LifecycleRule{
		Action: gstorage.LifecycleAction{Type: gstorage.DeleteAction},
		Condition: gstorage.LifecycleCondition{
			DaysSinceNoncurrentTime: NoncurrentVersionDays,
			Liveness:                gstorage.Archived,
			MatchesPrefix:           prefixes,
		},
	}
}

// ruleNamespaces returns the namespaces a rule on the bucket could have been
// written for by InitBucket, and nil for a rule in any other form. A Cloud
// Storage rule has no id to mark it with, so ownership is by form: a delete
// of noncurrent generations scoped to nothing but bodega's own prefixes under
// one namespace. That includes one naming manifests/, which is drift. A
// prefix can end in more than one storage prefix ("x/oci/manifests/" is
// manifests/ under "x/oci/" and oci/manifests/ under "x/"), so the answer is
// every namespace all of the rule's prefixes agree on.
func ruleNamespaces(r gstorage.LifecycleRule) []string {
	if r.Action.Type != gstorage.DeleteAction || r.Condition.Liveness != gstorage.Archived {
		return nil
	}
	var agreed []string
	for i, p := range r.Condition.MatchesPrefix {
		var candidates []string
		for _, sp := range manifest.StoragePrefixes() {
			ns, ok := strings.CutSuffix(p, sp)
			if ok && (ns == "" || strings.HasSuffix(ns, "/")) {
				candidates = append(candidates, ns)
			}
		}
		if i > 0 {
			candidates = slices.DeleteFunc(candidates, func(ns string) bool { return !slices.Contains(agreed, ns) })
		}
		if agreed = candidates; len(agreed) == 0 {
			return nil
		}
	}
	return agreed
}

// reconcileLifecycle returns the rules the bucket should hold, whether
// current already holds them, and the rules it removed besides the target's
// own. Rules in no bodega form are the operator's and come first, unchanged.
// A bodega-form rule is kept when it is for another namespace, configured
// here or not (a second install may share the bucket), with one exception: a
// rule that reaches the history of a namespace configured here is removed,
// because keeping it deletes what init exists to keep and removing it only
// costs storage until its owner runs init again.
func reconcileLifecycle(current []gstorage.LifecycleRule, n Namespaces) (rules []gstorage.LifecycleRule, satisfied bool, removed []gstorage.LifecycleRule) {
	want := LifecycleRule(n.Target)
	var kept []string
	for _, ns := range n.all() {
		kept = append(kept, historyUnder(ns)...)
	}
	changed := false
	for _, r := range current {
		namespaces := ruleNamespaces(r)
		sorted := r
		sorted.Condition.MatchesPrefix = slices.Sorted(slices.Values(r.Condition.MatchesPrefix))
		switch {
		case namespaces == nil:
			rules = append(rules, r)
		case !satisfied && reflect.DeepEqual(sorted, want):
			satisfied = true
		case slices.Contains(namespaces, n.Target):
			changed = true
		case selects(r.Condition.MatchesPrefix, kept):
			changed = true
			removed = append(removed, r)
		default:
			rules = append(rules, r)
		}
	}
	return append(rules, want), satisfied && !changed, removed
}

// lifecycleNote says what the target's rule does, in the words init prints.
func lifecycleNote(namespace string) string {
	under := ""
	if namespace != "" {
		under = " under " + namespace
	}
	return fmt.Sprintf("noncurrent versions%s after %dd, %s kept", under, NoncurrentVersionDays, strings.Join(historyUnder(namespace), " and "))
}

// InitBucket creates the bucket if it is missing and holds it to four
// controls: uniform bucket-level access, public access prevention enforced,
// object versioning, and LifecycleRule for namespaces.Target. It is
// idempotent, and writes one line per control to out: lowercase when the
// bucket was already correct, UPPERCASE when this call changed it.
//
// location is used only when the bucket is created, and empty leaves the
// choice to Cloud Storage. project is asked only then too, so preparing a
// bucket that exists needs no project.
//
// An existing bucket is changed in one conditional patch, held to the
// metageneration this call read. The patch replaces the whole lifecycle
// configuration, so a rule someone added between the read and the write would
// otherwise be deleted by it.
func InitBucket(ctx context.Context, client *gstorage.Client, out io.Writer, bucket, location string, project func(context.Context) (string, error), namespaces Namespaces) error {
	if out == nil {
		out = io.Discard
	}
	if err := ValidateBucket(bucket); err != nil {
		return err
	}
	if err := namespaces.check(bucket); err != nil {
		return err
	}
	b := client.Bucket(bucket)
	attrs, err := b.Attrs(ctx)
	if errors.Is(err, gstorage.ErrBucketNotExist) {
		return createBucket(ctx, b, out, bucket, location, project, namespaces.Target)
	}
	if err != nil {
		if statusOf(err) == http.StatusForbidden {
			return fmt.Errorf("read bucket gs://%s: %w. Bucket names are global: either these credentials lack storage.buckets.get on it "+
				"(`bodega init --print-policy=setup` prints the role), or the name belongs to someone else's project", bucket, err)
		}
		return fmt.Errorf("read bucket gs://%s: %w", bucket, err)
	}
	if location != "" && !strings.EqualFold(location, attrs.Location) {
		return fmt.Errorf("bucket gs://%s exists in %s, and --location asked for %s: a bucket's location cannot change. "+
			"Drop --location to prepare it where it is, or name a new bucket", bucket, attrs.Location, strings.ToUpper(location))
	}
	fmt.Fprintf(out, "  bucket:     exists in %s\n", attrs.Location)

	var (
		update  gstorage.BucketAttrsToUpdate
		changed bool
	)
	access := "  access:     uniform bucket-level\n"
	public := "  public:     prevented\n"
	// The two share one field of the bucket resource, so a patch of either
	// states both rather than trusting the encoding to leave the other alone.
	if !attrs.UniformBucketLevelAccess.Enabled || attrs.PublicAccessPrevention != gstorage.PublicAccessPreventionEnforced {
		if !attrs.UniformBucketLevelAccess.Enabled {
			access = "  access:     CONFIGURED (uniform bucket-level; object ACLs no longer apply)\n"
		}
		if attrs.PublicAccessPrevention != gstorage.PublicAccessPreventionEnforced {
			public = "  public:     CONFIGURED (public access prevention enforced)\n"
		}
		update.UniformBucketLevelAccess = &gstorage.UniformBucketLevelAccess{Enabled: true}
		update.PublicAccessPrevention = gstorage.PublicAccessPreventionEnforced
		changed = true
	}
	versioning := "  versioning: enabled\n"
	if !attrs.VersioningEnabled {
		versioning = "  versioning: ENABLED\n"
		update.VersioningEnabled = true
		changed = true
	}
	lifecycle := "  lifecycle:  configured\n"
	if rules, ok, removed := reconcileLifecycle(attrs.Lifecycle.Rules, namespaces); !ok {
		lifecycle = fmt.Sprintf("  lifecycle:  CONFIGURED (%s)\n", lifecycleNote(namespaces.Target))
		for _, r := range removed {
			lifecycle += fmt.Sprintf("  lifecycle:  REMOVED the rule matching %s: it reaches manifests/ or attestations/ of a backend configured here\n",
				strings.Join(r.Condition.MatchesPrefix, ", "))
		}
		update.Lifecycle = &gstorage.Lifecycle{Rules: rules}
		changed = true
	}
	if changed {
		_, err := b.If(gstorage.BucketConditions{MetagenerationMatch: attrs.MetaGeneration}).Update(ctx, update)
		if statusOf(err) == http.StatusPreconditionFailed {
			return fmt.Errorf("configure bucket gs://%s: someone changed it while this run was reading it, so nothing was written; re-run: %w", bucket, err)
		}
		if err != nil {
			return fmt.Errorf("configure bucket gs://%s: %w", bucket, err)
		}
	}
	_, err = io.WriteString(out, access+public+versioning+lifecycle)
	return err
}

func createBucket(ctx context.Context, b *gstorage.BucketHandle, out io.Writer, bucket, location string, project func(context.Context) (string, error), namespace string) error {
	p, err := project(ctx)
	if err != nil {
		return fmt.Errorf("bucket gs://%s does not exist: %w", bucket, err)
	}
	err = b.Create(ctx, p, &gstorage.BucketAttrs{
		Location:                 location,
		UniformBucketLevelAccess: gstorage.UniformBucketLevelAccess{Enabled: true},
		PublicAccessPrevention:   gstorage.PublicAccessPreventionEnforced,
		VersioningEnabled:        true,
		Lifecycle:                gstorage.Lifecycle{Rules: []gstorage.LifecycleRule{LifecycleRule(namespace)}},
	})
	if err != nil {
		return fmt.Errorf("create bucket gs://%s in project %s: %w", bucket, p, err)
	}
	where := "the default location"
	if location != "" {
		where = strings.ToUpper(location)
	}
	fmt.Fprintf(out, "  bucket:     CREATED gs://%s in project %s, %s\n", bucket, p, where)
	fmt.Fprintf(out, "  access:     CONFIGURED (uniform bucket-level)\n")
	fmt.Fprintf(out, "  public:     CONFIGURED (public access prevention enforced)\n")
	fmt.Fprintf(out, "  versioning: ENABLED\n")
	fmt.Fprintf(out, "  lifecycle:  CONFIGURED (%s)\n", lifecycleNote(namespace))
	return nil
}

// AccessReport is what CheckAccess proved, per IAM permission of RuntimeRole.
type AccessReport struct {
	Allowed []string
	Missing []string
}

// CheckAccess asks the bucket which of RuntimeRole's permissions the current
// credentials hold, writing one line per permission to out. It changes
// nothing: testIamPermissions is the service's own answer to the question, so
// unlike the S3 check there is no probe to design and no permission left
// unproven.
//
// Only an answer from the API counts. An error raised before a request was
// sent, or one the network returned, says nothing about the role, and
// CheckAccess returns it as an error instead of a missing permission.
func CheckAccess(ctx context.Context, client *gstorage.Client, out io.Writer, bucket string) (AccessReport, error) {
	if out == nil {
		out = io.Discard
	}
	var r AccessReport
	want := RuntimeRole().Permissions
	held, err := client.Bucket(bucket).IAM().TestPermissions(ctx, want)
	switch status := statusOf(err); {
	case err == nil:
	case status == http.StatusNotFound:
		fmt.Fprintf(out, "  bucket:     does not exist; run `bodega init` with the setup role first\n")
		return r, fmt.Errorf("bucket gs://%s does not exist", bucket)
	case status != 0:
		return r, fmt.Errorf("the Cloud Storage API refused to say which permissions these credentials hold on gs://%s: %w", bucket, err)
	default:
		return r, fmt.Errorf("no answer from the Cloud Storage API, so this says nothing about the role "+
			"(check what Application Default Credentials resolve, GOOGLE_APPLICATION_CREDENTIALS, and the network): %w", err)
	}
	for _, p := range want {
		if slices.Contains(held, p) {
			r.Allowed = append(r.Allowed, p)
			fmt.Fprintf(out, "  %-24s allowed\n", p)
			continue
		}
		r.Missing = append(r.Missing, p)
		fmt.Fprintf(out, "  %-24s missing; grant it on gs://%s\n", p, bucket)
	}
	return r, nil
}

// statusOf is the HTTP status the API answered with, or 0 when err is not an
// answer from the API.
func statusOf(err error) int {
	var ge *googleapi.Error
	if errors.As(err, &ge) {
		return ge.Code
	}
	return 0
}
