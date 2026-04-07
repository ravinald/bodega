package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
	bos3 "github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/s3"
)

func newDeleteCmd(gf *globalFlags) *cobra.Command {
	var removeFromS3 bool

	cmd := &cobra.Command{
		Use:   "delete <type> <name>",
		Short: "Remove an entry from the manifest",
		Long: `delete removes the named entry from a manifest and writes the updated file.

Use --remove-from-s3 to also delete the corresponding artifact from S3.
Frozen entries cannot be deleted; unfreeze them first with 'reman freeze'.`,
		Example: `  reman delete git netbox
  reman delete binary awscli-v2 --remove-from-s3`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, name := args[0], args[1]
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q", t)
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			// Check frozen status before deletion.
			if frozen, err := isFrozen(store, t, name); err != nil {
				return err
			} else if frozen {
				return fmt.Errorf("entry %s/%s is frozen — unfreeze it first with 'reman freeze %s %s'", t, name, t, name)
			}

			// Remove from S3 first if requested.
			if removeFromS3 {
				if err := requireBucket(cfg); err != nil {
					return err
				}
				ctx := backgroundCtx()
				client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
				if err != nil {
					return fmt.Errorf("connect to AWS: %w", err)
				}
				key := s3KeyFor(store, t, name)
				if key != "" {
					fmt.Printf("Deleting s3://%s/%s ...\n", cfg.Bucket, key)
					if err := client.DeleteObject(ctx, key); err != nil {
						return err
					}
					fmt.Println("  Deleted from S3.")
				}
			}

			// Remove from manifest.
			switch t {
			case manifest.TypeApt:
				if err := store.RemoveApt(name); err != nil {
					return err
				}
			case manifest.TypeGit:
				if err := store.RemoveGit(name); err != nil {
					return err
				}
			case manifest.TypeBinary:
				if err := store.RemoveBinary(name); err != nil {
					return err
				}
			case manifest.TypeGomod:
				if err := store.RemoveGomod(name); err != nil {
					return err
				}
			case manifest.TypeHelm:
				if err := store.RemoveHelm(name); err != nil {
					return err
				}
			case manifest.TypeNpm:
				if err := store.RemoveNpm(name); err != nil {
					return err
				}
			case manifest.TypePypi:
				return fmt.Errorf("pypi uses a single manifest — edit manifests/pypi.json directly")
			}

			fmt.Printf("Removed %s/%s from manifest.\n", t, name)
			return nil
		},
	}

	cmd.Flags().BoolVar(&removeFromS3, "remove-from-s3", false, "Also delete the artifact from S3")
	return cmd
}

// s3KeyFor returns the primary S3 key for a named entry.
func s3KeyFor(store *manifest.Store, t, name string) string {
	switch t {
	case manifest.TypeBinary:
		e := store.FindBinary(name)
		if e == nil {
			return ""
		}
		filename := e.Filename
		if filename == "" {
			filename = lastS3Segment(e.URL)
		}
		return "binaries/" + filename
	case manifest.TypeGit:
		e := store.FindGit(name)
		if e == nil {
			return ""
		}
		return fmt.Sprintf("repos/%s/%s-%s.bundle", e.Name, e.Name, e.Ref)
	}
	return ""
}

// lastS3Segment returns the basename portion of a URL path.
func lastS3Segment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

// isFrozen returns whether the named entry is frozen, or an error if not found.
func isFrozen(store *manifest.Store, t, name string) (bool, error) {
	switch t {
	case manifest.TypeApt:
		e := store.FindApt(name)
		if e == nil {
			return false, fmt.Errorf("apt entry %q not found", name)
		}
		return e.Frozen, nil
	case manifest.TypeGit:
		e := store.FindGit(name)
		if e == nil {
			return false, fmt.Errorf("git entry %q not found", name)
		}
		return e.Frozen, nil
	case manifest.TypeBinary:
		e := store.FindBinary(name)
		if e == nil {
			return false, fmt.Errorf("binary entry %q not found", name)
		}
		return e.Frozen, nil
	case manifest.TypeGomod:
		e := store.FindGomod(name)
		if e == nil {
			return false, fmt.Errorf("gomod entry %q not found", name)
		}
		return e.Frozen, nil
	case manifest.TypeHelm:
		e := store.FindHelm(name)
		if e == nil {
			return false, fmt.Errorf("helm entry %q not found", name)
		}
		return e.Frozen, nil
	case manifest.TypeNpm:
		e := store.FindNpm(name)
		if e == nil {
			return false, fmt.Errorf("npm entry %q not found", name)
		}
		return e.Frozen, nil
	case manifest.TypePypi:
		return store.Pypi.Frozen, nil
	}
	return false, fmt.Errorf("unknown type %q", t)
}
