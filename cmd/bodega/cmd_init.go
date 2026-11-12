package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/config"
	bogcs "github.com/ravinald/bodega/internal/gcs"
	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/storage"
)

// s3Target is storage.S3Target under the names this package's verbs and
// tests use.
type s3Target struct {
	name   string
	bucket string
	region string
	prefix string
	opts   bos3.Options
}

// resolveS3Target resolves the backend named by args, or the default, through
// storage.ResolveS3Target, the same resolution the TUI's init action uses.
func resolveS3Target(cfg *config.Config, args []string) (s3Target, error) {
	name := config.DefaultStorageName
	if len(args) > 0 {
		name = args[0]
	}
	t, err := storage.ResolveS3Target(cfg, name)
	return s3Target{name: t.Name, bucket: t.Bucket, region: t.Region, prefix: t.Prefix, opts: t.Options}, err
}

func dialS3Target(ctx context.Context, t s3Target) (*bos3.Client, error) {
	return storage.DialS3Target(ctx, storage.S3Target{Name: t.name, Bucket: t.bucket, Region: t.region, Prefix: t.prefix, Options: t.opts})
}

// initBackend names the backend an init verb acts on and the driver it uses.
// The argument is a backend name, or a driver name standing for the one
// backend on that driver: config.Load refuses a backend named like a driver,
// so the two never collide, and `bodega init gcs` reads as what it does. The
// returned args are the argument that names the backend, empty for the
// default, which is the form every message that quotes a command back uses.
//
// A name nothing configures comes back with an empty driver, for the s3
// path's resolver to refuse with the list of what is configured.
func initBackend(cfg *config.Config, args []string) (name, driver string, rest []string, err error) {
	name = config.DefaultStorageName
	if len(args) > 0 {
		name = args[0]
	}
	if slices.Contains(storage.Drivers(), name) {
		var on []string
		if storageBackendName(cfg) == name {
			on = append(on, config.DefaultStorageName)
		}
		var named []string
		for n, b := range cfg.StorageBackends {
			if b.Driver == name {
				named = append(named, n)
			}
		}
		slices.Sort(named)
		switch on = append(on, named...); len(on) {
		case 0:
			return "", "", nil, fmt.Errorf("no storage backend uses the %s driver: set storage_backend to %q, or add a storage_backends entry on it", name, name)
		case 1:
			name = on[0]
		default:
			return "", "", nil, fmt.Errorf("%d storage backends use the %s driver (%s): name the one to act on", len(on), name, strings.Join(on, ", "))
		}
	}
	if name != config.DefaultStorageName {
		rest = []string{name}
	}
	spec, _ := storage.SpecFor(cfg, name)
	driver = spec.Driver
	if driver == "" && name == config.DefaultStorageName {
		driver = "local"
	}
	return name, driver, rest, nil
}

// gcsBucket is the bucket a gcs backend names, refused when it names none or
// one Cloud Storage would refuse.
func gcsBucket(cfg *config.Config, name string) (storage.Spec, error) {
	spec, _ := storage.SpecFor(cfg, name)
	if spec.Bucket == "" {
		if name == config.DefaultStorageName {
			return spec, fmt.Errorf("a bucket is required: set --bucket, the REPO_BUCKET env var, or add \"bucket\" to config.json")
		}
		return spec, fmt.Errorf("storage_backends[%q] uses the gcs driver and names no bucket; add \"bucket\" to that entry", name)
	}
	return spec, bogcs.ValidateBucket(spec.Bucket)
}

// gcsNamespaces is where the backend called name keeps its keys in its
// bucket, and where every other gcs backend of this config on the same bucket
// keeps its own.
func gcsNamespaces(cfg *config.Config, name string, spec storage.Spec) bogcs.Namespaces {
	ns := bogcs.Namespaces{Target: spec.KeyPrefix()}
	for _, other := range append([]string{config.DefaultStorageName}, slices.Sorted(maps.Keys(cfg.StorageBackends))...) {
		if other == name {
			continue
		}
		o, ok := storage.SpecFor(cfg, other)
		if ok && o.Driver == "gcs" && o.Bucket == spec.Bucket {
			ns.Others = append(ns.Others, o.KeyPrefix())
		}
	}
	return ns
}

// runInitGCS is `bodega init` for a backend on the gcs driver.
func runInitGCS(ctx context.Context, out io.Writer, cfg *config.Config, name, printPolicy, location string) error {
	spec, err := gcsBucket(cfg, name)
	if err != nil {
		return err
	}
	if printPolicy != "" {
		return printGCSRoles(out, spec.Bucket, printPolicy)
	}
	client, err := bogcs.Dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	fmt.Fprintf(out, "Initializing bucket gs://%s (backend %q)...\n", spec.Bucket, name)
	namespaces := gcsNamespaces(cfg, name, spec)
	if namespaces.Target != "" {
		fmt.Fprintf(out, "  prefix:     %s (the lifecycle rule is scoped under it)\n", namespaces.Target)
	}
	if err := bogcs.InitBucket(ctx, client, out, spec.Bucket, location, bogcs.Project, namespaces); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nBucket gs://%s is ready.\n", spec.Bucket)
	return nil
}

// printGCSRoles writes the requested roles. One role prints as the bare
// definition `gcloud iam roles create --file` reads, so it can be redirected
// into a file; both print with who each is for, where it is bound, and the
// predefined role that covers it for an operator who wants no custom one.
func printGCSRoles(w io.Writer, bucket, which string) error {
	setup, runtime := bogcs.SetupRole(), bogcs.RuntimeRole()
	switch which {
	case "setup":
		_, err := io.WriteString(w, setup.YAML())
		return err
	case "runtime":
		_, err := io.WriteString(w, runtime.YAML())
		return err
	case "all":
		for i, r := range []struct {
			role bogcs.Role
			who  string
		}{
			{setup, "for whoever runs `bodega init`; creates and configures gs://" + bucket + " and cannot delete it"},
			{runtime, "for the service; reads, writes and deletes objects, cannot change the bucket"},
		} {
			if i > 0 {
				fmt.Fprintln(w)
			}
			key := strings.TrimPrefix(r.role.Title, "bodega ")
			fmt.Fprintf(w, "  %s: %s\n", key, r.who)
			fmt.Fprintf(w, "    bind on:    %s\n", r.role.GrantOn)
			fmt.Fprintf(w, "    predefined: %s (%s)\n", r.role.Predefined, r.role.Excess)
			fmt.Fprintf(w, "    custom:     gcloud iam roles create %s --project=PROJECT --file=%s.yaml, with this file:\n", r.role.ID, key)
			if _, err := io.WriteString(w, r.role.YAML()); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("--print-policy=%q: want setup, runtime, or no value for both", which)
}

// runInitCheckGCS is `bodega init check` for a backend on the gcs driver.
func runInitCheckGCS(ctx context.Context, out io.Writer, cfg *config.Config, name string, args []string) error {
	spec, err := gcsBucket(cfg, name)
	if err != nil {
		return err
	}
	client, err := bogcs.Dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	fmt.Fprintf(out, "Checking gs://%s (backend %q) with Application Default Credentials...\n", spec.Bucket, name)
	report, err := bogcs.CheckAccess(ctx, client, out, spec.Bucket)
	if err != nil {
		return err
	}
	if len(report.Missing) > 0 {
		return fmt.Errorf("these credentials lack %s; `bodega init %s--print-policy=runtime` prints the role that grants them. "+
			"If it was granted in the last minute, re-run this check once before changing it",
			strings.Join(report.Missing, ", "), argPrefix(args))
	}
	fmt.Fprintf(out, "\nOn gs://%s these credentials hold everything the runtime role grants: %s.\n", spec.Bucket, strings.Join(report.Allowed, ", "))
	return nil
}

func newInitCmd(gf *globalFlags) *cobra.Command {
	var (
		printPolicy      string
		allowUnsupported bool
		location         string
	)
	cmd := &cobra.Command{
		Use:   "init [backend]",
		Short: "Create and configure the bucket an s3 or gcs storage backend needs",
		Long: fmt.Sprintf(`init is for s3 and gcs storage backends. It acts on the default backend, or on
the storage_backends entry named as its argument, and refuses a backend whose
driver is "local": that stores artifacts in a directory and needs nothing here.
A driver name stands for the one backend on that driver, so "bodega init gcs"
prepares the gcs backend of an install that has one.

For a gcs backend it creates the bucket, in the project GOOGLE_CLOUD_PROJECT
or Application Default Credentials name and the location --location gives,
and holds it to:
  - Uniform bucket-level access, so no object carries an ACL
  - Public access prevention, enforced
  - Object versioning, so a rewritten manifest keeps its previous generation
  - Lifecycle: noncurrent generations are deleted after %d days under every
    artifact prefix, and never under manifests/ or attestations/. A backend
    with a prefix gets its rule under that prefix, beside the rules of other
    backends on the bucket
Lifecycle rules in any other form are yours and are kept. --print-policy
prints the IAM roles instead, as custom role definitions with the predefined
role that covers each, and "init check" asks the bucket through
testIamPermissions which runtime permissions the credentials hold.
Credentials are Application Default Credentials; bodega reads no key file.

For an s3 backend it creates the bucket and configures it with:
  - Server-side encryption (AES-256 / SSE-S3; no KMS option)
  - Versioning, so a rewritten manifest keeps its previous version
  - All public access blocked
  - Lifecycle: incomplete multipart uploads abort after %d days, bucket-wide;
    noncurrent versions expire after %d days under every artifact prefix,
    and never under manifests/
  - A zero-byte marker under each storage prefix

Lifecycle rules whose ID does not start with "bodega-" are yours and are kept.
A bodega- rule edited on the bucket is drift, and the next init rewrites it:
the periods are AbortIncompleteMultipartDays and NoncurrentVersionDays in
internal/s3/init.go.

The command is idempotent. Each line reads lowercase when the bucket was
already correct and UPPERCASE when this run changed it.

An S3-compatible store may not implement the public access block, default
encryption, versioning or lifecycle rules. init tries all four, prints
NOT APPLIED beside each one the store answers as not implemented, and exits
non-zero naming them. --allow-unsupported finishes the run without them; set
the store's own equivalent first where it has one. Any other failure of a
control stops the run with or without the flag.

--print-policy prints the IAM policies instead, and changes nothing: "setup"
for whoever runs init, "runtime" for the service. Both are derived from the
calls bodega makes. "init check" asks the bucket whether the current
credentials hold the runtime one.

Credentials come from the AWS default chain: environment variables,
AWS_PROFILE and the shared config, SSO, or an instance role.`, bogcs.NoncurrentVersionDays, bos3.AbortIncompleteMultipartDays, bos3.NoncurrentVersionDays),
		Example: `  bodega init
  bodega init archive
  bodega init gcs --location us-central1
  bodega init --allow-unsupported
  bodega init --print-policy
  bodega init archive --print-policy=runtime
  bodega init check`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			name, driver, args, err := initBackend(cfg, args)
			if err != nil {
				return err
			}
			ctx := backgroundCtx()
			if driver == "gcs" {
				if allowUnsupported {
					return fmt.Errorf("--allow-unsupported is for an S3-compatible store; storage backend %q is on the gcs driver, which has every control init sets", name)
				}
				return runInitGCS(ctx, cmd.OutOrStdout(), cfg, name, printPolicy, location)
			}
			if location != "" {
				return fmt.Errorf("--location places a new gcs bucket; storage backend %q is not on the gcs driver (an s3 bucket is created in its region)", name)
			}
			target, err := resolveS3Target(cfg, args)
			if err != nil {
				return err
			}
			client, err := dialS3Target(ctx, target)
			if err != nil {
				return err
			}
			if printPolicy != "" {
				return printPolicies(cmd.OutOrStdout(), target, client.Region(), printPolicy)
			}

			fmt.Printf("Initializing bucket s3://%s in %s (backend %q)...\n", target.bucket, client.Region(), target.name)
			if target.prefix != "" {
				fmt.Printf("  prefix:     %s is not applied; markers and lifecycle rules sit at the bucket root\n", target.prefix)
			}
			if err := bos3.InitBucket(ctx, client.S3Client(), os.Stdout, target.bucket, client.Region(), allowUnsupported); err != nil {
				return err
			}
			fmt.Printf("\nBucket s3://%s is ready.\n", target.bucket)
			return nil
		},
	}
	cmd.Flags().StringVar(&printPolicy, "print-policy", "",
		`print IAM policies and change nothing: "setup", "runtime", or both when given no value`)
	cmd.Flags().Lookup("print-policy").NoOptDefVal = "all"
	cmd.Flags().BoolVar(&allowUnsupported, "allow-unsupported", false,
		"finish without the bucket controls the store reports as not implemented, naming each one")
	cmd.Flags().StringVar(&location, "location", "",
		"gcs: the location a bucket is created in (us-central1, EU, ...); unset leaves it to Cloud Storage")
	cmd.AddCommand(noReloadSignal(newInitCheckCmd(gf)))
	return cmd
}

// printPolicies writes the requested policy documents. One policy prints as
// bare JSON so it can be redirected into a file an IAM tool reads; both print
// with a line naming who each is for.
func printPolicies(w io.Writer, t s3Target, region, which string) error {
	setup, err := bos3.SetupPolicy(t.bucket, region)
	if err != nil {
		return err
	}
	runtime, err := bos3.RuntimePolicy(t.bucket, region)
	if err != nil {
		return err
	}
	switch which {
	case "setup":
		return writePolicy(w, setup)
	case "runtime":
		return writePolicy(w, runtime)
	case "all":
		fmt.Fprintf(w, "  setup: for whoever runs `bodega init`; creates and configures s3://%s and cannot delete it\n", t.bucket)
		if err := writePolicy(w, setup); err != nil {
			return err
		}
		fmt.Fprintf(w, "\n  runtime: for the service; reads and writes objects, cannot change the bucket or remove earlier versions\n")
		return writePolicy(w, runtime)
	}
	return fmt.Errorf("--print-policy=%q: want setup, runtime, or no value for both", which)
}

func writePolicy(w io.Writer, p bos3.Policy) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

func newInitCheckCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "check [backend]",
		Short: "Check which runtime permissions the current credentials hold on an s3 or gcs backend",
		Long: `check asks the bucket whether the credentials the AWS default chain resolves
hold what the runtime policy grants, and names each action the API refused.
It changes nothing, so it runs under credentials that cannot write.

On a gcs backend it asks Cloud Storage's testIamPermissions about each
permission of the runtime role under Application Default Credentials, so
every one is answered, delete included, and nothing below applies.

Listing and reading are probed directly. Writing is probed with a conditional
PUT against the empty manifests/ marker, which S3 authorizes and then refuses
without storing anything. Deleting cannot be proven without deleting, so it is
reported as not checked. With nothing refused, the last line names what was
allowed and what was not checked; without the manifests/ marker, writing is
among the not checked.

Only a refusal the API returned counts. A policy attached in the last few
seconds may not have propagated yet: re-run once before changing it.`,
		Example: `  bodega init check
  bodega init check archive`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			name, driver, args, err := initBackend(cfg, args)
			if err != nil {
				return err
			}
			ctx := backgroundCtx()
			if driver == "gcs" {
				return runInitCheckGCS(ctx, cmd.OutOrStdout(), cfg, name, args)
			}
			target, err := resolveS3Target(cfg, args)
			if err != nil {
				return err
			}
			client, err := dialS3Target(ctx, target)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Checking s3://%s in %s (backend %q) with the current AWS credentials...\n", target.bucket, client.Region(), target.name)
			report, err := bos3.CheckAccess(ctx, client.S3Client(), out, target.bucket, client.Region())
			if err != nil {
				return err
			}
			if len(report.Missing) > 0 {
				return fmt.Errorf("these credentials lack %s; `bodega init %s--print-policy=runtime` prints the policy that grants them. "+
					"If it was attached in the last minute, re-run this check once before changing it",
					strings.Join(report.Missing, ", "), argPrefix(args))
			}
			writeCheckVerdict(out, target, args, report)
			return nil
		},
	}
}

// writeCheckVerdict closes a check that found nothing refused. It names what
// was proven and what was not, because "nothing refused" is not "can run
// bodega" while delete, and sometimes write, went unprobed.
func writeCheckVerdict(w io.Writer, t s3Target, args []string, r bos3.AccessReport) {
	fmt.Fprintf(w, "\nOn s3://%s these credentials were allowed %s; not checked: %s.\n",
		t.bucket, strings.Join(r.Allowed, ", "), strings.Join(r.Unchecked, ", "))
	if slices.Contains(r.Unchecked, "s3:PutObject") {
		fmt.Fprintf(w, "Writing was not proven: the probe needs the empty %s marker; run `%s`, then check again.\n",
			manifest.ManifestsPrefix, strings.TrimSpace("bodega init "+argPrefix(args)))
	}
}

func argPrefix(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0] + " "
}
