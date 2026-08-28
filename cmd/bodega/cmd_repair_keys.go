package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

func newRepairKeysCmd(gf *globalFlags) *cobra.Command {
	var deleteSource bool
	var dryRun bool
	var typeFilter string

	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Move artifacts sitting at a superseded object key to the canonical one",
		Long: `keys finds artifacts written under an object key no current code path reads,
copies them to the key the uploader and the server now agree on, verifies the
copy at its destination, and only then considers the source.

One superseded layout exists today. Go modules were uploaded under the
filesystem-safe name ("gomod/github.com--aws--aws-sdk-go-v2/@v/...") while the
Go client asks for the module path with its slashes intact, so no module bodega
ever uploaded could be served. Any install that uploaded a gomod artifact has
data at the old key.

Source and destination are the same backend, so this is not a 'pkg move' and
nothing in the manifest changes: the key is derived, never recorded. The source
copy is left in place unless --delete-source says otherwise, and re-running
after an interruption is safe.`,
		Example: `  bodega repair keys --dry-run
  bodega repair keys
  bodega repair keys --type gomod --delete-source`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if !dryRun {
				if err := ensureMutable(cfg); err != nil {
					return err
				}
			}
			if typeFilter != "" && !isValidType(typeFilter) {
				return fmt.Errorf("unknown type %q — must be one of: %s", typeFilter, strings.Join(manifest.AllTypes, ", "))
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			ctx := backgroundCtx()

			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}

			r := &keyRepairer{
				stores: stores,
				store:  store,
				spool:  filepath.Join(cfg.BuildRoot, "tmp"),
				out:    cmd.OutOrStdout(),
				del:    deleteSource,
				dry:    dryRun,
			}
			types := manifest.AllTypes
			if typeFilter != "" {
				types = []string{typeFilter}
			}
			if err := r.run(ctx, types); err != nil {
				return err
			}
			if !dryRun && r.copied > 0 {
				notifyServer(gf)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&deleteSource, "delete-source", false,
		"Delete the superseded object after the canonical copy is verified (default: leave it)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report what would be copied without writing anything")
	cmd.Flags().StringVar(&typeFilter, "type", "", "Limit the walk to one package type")
	return cmd
}

// supersededKeys returns the keys a previous release of bodega wrote for this
// version alongside the canonical key each one should now hold.
//
// Only gomod has a superseded layout: builder derived its keys from
// Store.ListPackages, which returns filesystem-safe names, so a module path's
// slashes were collapsed to "--" on the way to the backend while handleGomod
// rebuilt the path form from the wire. Everything else already agreed.
//
// A module whose path has no slash encodes to itself and yields nothing to
// repair, which is what keeps a re-run cheap.
func supersededKeys(pm *manifest.PackageManifest, ve manifest.VersionEntry) map[string]string {
	if pm.Type != manifest.TypeGomod {
		return nil
	}
	safe := manifest.SafeName(pm.Name)
	if safe == pm.Name {
		return nil
	}
	out := make(map[string]string, 4)
	for _, ext := range []string{".zip", ".info", ".mod"} {
		out[manifest.GomodKey(safe, ve.Version, ext)] = manifest.GomodKey(pm.Name, ve.Version, ext)
	}
	out[manifest.GomodListKey(safe)] = manifest.GomodListKey(pm.Name)
	return out
}

// keyRepairer walks the manifests and repairs one superseded key at a time.
type keyRepairer struct {
	stores  storage.Resolver
	store   *manifest.Store
	spool   string
	out     io.Writer
	del     bool
	dry     bool
	copied  int
	present int // already at the canonical key, from an earlier run
}

func (r *keyRepairer) run(ctx context.Context, types []string) error {
	for _, typ := range types {
		for _, name := range r.store.ListPackages(typ) {
			pm, err := r.store.GetPackage(ctx, typ, name)
			if err != nil {
				return fmt.Errorf("get %s/%s: %w", typ, name, err)
			}
			if pm == nil {
				continue
			}
			for _, ve := range pm.Versions {
				if err := r.repairVersion(ctx, pm, ve); err != nil {
					return err
				}
			}
		}
	}
	switch {
	case r.copied == 0 && r.present == 0:
		fmt.Fprintln(r.out, "No artifacts found at a superseded key.")
		return nil
	case r.copied == 0:
		fmt.Fprintf(r.out, "%d object(s) already at the canonical key; nothing to copy.\n", r.present)
	case r.dry:
		fmt.Fprintf(r.out, "%d object(s) would be copied. Re-run without --dry-run.\n", r.copied)
		return nil
	default:
		fmt.Fprintf(r.out, "%d object(s) copied to their canonical key.\n", r.copied)
	}
	if !r.del && !r.dry {
		fmt.Fprintln(r.out, "The superseded copies are still there; --delete-source removes them.")
	}
	return nil
}

// repairVersion copies each of one version's superseded objects to its
// canonical key, verifies it there, and only then considers the source.
//
// The ordering is the same one 'pkg move' establishes and for the same reason:
// both backends answer a missing object with "not found" rather than an error,
// so an artifact lost between a delete and its replacement would look exactly
// like one that was never uploaded.
func (r *keyRepairer) repairVersion(ctx context.Context, pm *manifest.PackageManifest, ve manifest.VersionEntry) error {
	pairs := supersededKeys(pm, ve)
	if len(pairs) == 0 {
		return nil
	}
	label := pm.Name + "@" + versionLabel(ve)
	backend := effectiveStorage(ve.Storage)
	store, err := r.stores.ByName(ve.Storage)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	// The canonical order the artifact keys are derived in, so the .zip is
	// verified against the manifest digest and its siblings are not.
	canonical, err := inventory.ArtifactKeys(ctx, store, pm, ve)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	primary := ""
	if len(canonical) > 0 {
		primary = canonical[0]
	}

	for _, oldKey := range sortedKeys(pairs) {
		newKey := pairs[oldKey]
		src, err := store.Head(ctx, oldKey)
		if err != nil {
			return fmt.Errorf("%s: head %s on %q: %w", label, oldKey, backend, err)
		}
		if !src.Exists {
			continue
		}
		dst, err := store.Head(ctx, newKey)
		if err != nil {
			return fmt.Errorf("%s: head %s on %q: %w", label, newKey, backend, err)
		}
		if dst.Exists && dst.Size == src.Size {
			fmt.Fprintf(r.out, "  %s: %s already holds the same %d bytes\n", label, newKey, dst.Size)
			r.present++
		} else {
			if r.dry {
				fmt.Fprintf(r.out, "  %s: would copy %s -> %s on %q (%d bytes)\n", label, oldKey, newKey, backend, src.Size)
				r.copied++
				continue
			}
			fmt.Fprintf(r.out, "  %s: %s -> %s on %q\n", label, oldKey, newKey, backend)
			size, err := copyObject(ctx, store, store, oldKey, newKey, r.spool)
			if err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
			if err := verifyCopy(ctx, store, backend, newKey, size, ve, newKey == primary); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
			r.copied++
		}

		// Nothing below runs until the copy above is verified at its
		// destination.
		if !r.del || r.dry {
			continue
		}
		if err := store.Delete(ctx, oldKey); err != nil {
			fmt.Fprintf(r.out, "  %s: warning: could not delete %s from %q: %v\n", label, oldKey, backend, err)
			continue
		}
		fmt.Fprintf(r.out, "  %s: deleted %s from %q\n", label, oldKey, backend)
	}
	return nil
}

// sortedKeys orders a repair map so a run reports the same sequence twice.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
