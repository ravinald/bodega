package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/storage"
)

// s3Target is the one s3 backend an init verb acts on. region is as
// configured and may be empty; dialS3Target reports the one the SDK resolves.
type s3Target struct {
	name   string
	bucket string
	region string
	prefix string
}

// resolveS3Target names the backend an init verb reaches: the default one, or
// a storage_backends entry, read through the same storage.SpecFor the
// service's resolver builds its stores from. It refuses a backend whose driver
// is not s3 rather than falling back to the bucket key, which an install on
// the local driver may still carry, so init never dials AWS for a backend that
// stores nothing there.
func resolveS3Target(cfg *config.Config, args []string) (s3Target, error) {
	name := config.DefaultStorageName
	if len(args) > 0 {
		name = args[0]
	}
	spec, ok := storage.SpecFor(cfg, name)
	if !ok {
		names := []string{config.DefaultStorageName}
		for n := range cfg.StorageBackends {
			names = append(names, n)
		}
		sort.Strings(names[1:])
		return s3Target{}, fmt.Errorf("unknown storage backend %q (configured: %s)", name, strings.Join(names, ", "))
	}
	t := s3Target{name: name, bucket: spec.Bucket, region: spec.Region, prefix: spec.Prefix}
	driver := spec.Driver
	if driver == "" {
		driver = "local"
	}
	if driver != "s3" {
		return t, fmt.Errorf("storage backend %q uses the %s driver, which keeps artifacts in a directory and needs no init; "+
			"init prepares s3 backends only (set storage_backend to \"s3\", or name an s3 entry from storage_backends)", name, driver)
	}
	if t.bucket == "" {
		if name == config.DefaultStorageName {
			return t, requireBucket(cfg)
		}
		return t, fmt.Errorf("storage_backends[%q] uses the s3 driver and names no bucket; add \"bucket\" to that entry", name)
	}
	return t, nil
}

// dialS3Target builds the client the service would build for t, through the
// same bos3.NewClient call, so an entry with no region resolves through the
// SDK's chain here exactly as it does there. It refuses when that chain names
// no region, because every call would fail, in the service as well.
func dialS3Target(ctx context.Context, t s3Target) (*bos3.Client, error) {
	client, err := bos3.NewClient(ctx, t.bucket, t.region)
	if err != nil {
		return nil, fmt.Errorf("storage backend %q: %w", t.name, err)
	}
	if client.Region() == "" {
		return nil, fmt.Errorf("storage backend %q has no AWS region: storage_backends[%q] sets no \"region\", and neither AWS_REGION, "+
			"AWS_DEFAULT_REGION nor the AWS profile names one, so the service could not reach s3://%s either; add \"region\" to that entry",
			t.name, t.name, t.bucket)
	}
	return client, nil
}

func newInitCmd(gf *globalFlags) *cobra.Command {
	var printPolicy string
	cmd := &cobra.Command{
		Use:   "init [backend]",
		Short: "Create and configure the bucket an s3 storage backend needs",
		Long: fmt.Sprintf(`init is for s3 storage backends only. It acts on the default backend, or on
the storage_backends entry named as its argument, and refuses a backend whose
driver is "local": that stores artifacts in a directory and needs nothing here.

It creates the bucket and configures it with:
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

--print-policy prints the IAM policies instead, and changes nothing: "setup"
for whoever runs init, "runtime" for the service. Both are derived from the
calls bodega makes. "init check" asks the bucket whether the current
credentials hold the runtime one.

Credentials come from the AWS default chain: environment variables,
AWS_PROFILE and the shared config, SSO, or an instance role.`, bos3.AbortIncompleteMultipartDays, bos3.NoncurrentVersionDays),
		Example: `  bodega init
  bodega init archive
  bodega init --print-policy
  bodega init archive --print-policy=runtime
  bodega init check`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			target, err := resolveS3Target(cfg, args)
			if err != nil {
				return err
			}
			ctx := backgroundCtx()
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
			if err := bos3.InitBucket(ctx, client.S3Client(), os.Stdout, target.bucket, client.Region()); err != nil {
				return err
			}
			fmt.Printf("\nBucket s3://%s is ready.\n", target.bucket)
			return nil
		},
	}
	cmd.Flags().StringVar(&printPolicy, "print-policy", "",
		`print IAM policies and change nothing: "setup", "runtime", or both when given no value`)
	cmd.Flags().Lookup("print-policy").NoOptDefVal = "all"
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
		Short: "Check which runtime-policy actions the current AWS credentials hold on an s3 backend",
		Long: `check asks the bucket whether the credentials the AWS default chain resolves
hold what the runtime policy grants, and names each action the API refused.
It changes nothing, so it runs under credentials that cannot write.

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
			target, err := resolveS3Target(cfg, args)
			if err != nil {
				return err
			}
			ctx := backgroundCtx()
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
