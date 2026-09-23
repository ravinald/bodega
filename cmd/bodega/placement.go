package main

// placement.go binds the command layer to internal/placement.
//
// The placer moved out of this package when the TUI needed it: two copies of
// "which backend does this write go to" is one copy that stops matching the
// other, which is how the TUI came to upload every type to the default bucket
// while the CLI honored storage_by_type. These names stay lowercase and local
// so the command files read the same as they did before the move.

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/placement"
	"github.com/ravinald/bodega/internal/storage"
)

type placer = placement.Placer

func newPlacer(ctx context.Context, cfg *config.Config, store *manifest.Store, out io.Writer, replace bool) (*placer, error) {
	return placement.New(ctx, cfg, store, out, replace)
}

func directoryPlaced(typ string) bool { return placement.DirectoryPlaced(typ) }

func writePlacement(stores storage.Resolver, typ, policy string, groups []string) storage.Decision {
	return placement.WritePlacement(stores, typ, policy, groups)
}

func storagePolicyWarning(typ, policy string) string {
	return placement.StoragePolicyWarning(typ, policy)
}

func storageGroupWarning(typ, group string) string {
	return placement.StorageGroupWarning(typ, group)
}

func noPerPackagePlacement(typ string) string { return placement.NoPerPackagePlacement(typ) }

func effectiveStorage(recorded string) string { return placement.EffectiveStorage(recorded) }

func versionIndex(pm *manifest.PackageManifest, v string) int { return placement.VersionIndex(pm, v) }

func versionLabel(ve manifest.VersionEntry) string { return placement.VersionLabel(ve) }

// parseUploadArgs separates type arguments from the one package selector.
//
// It lives here rather than in either command file because 'build upload' and
// 'build sync' are the same push behind two cascade policies, and a selector
// that meant one thing under one of them is the split internal/placement
// exists to prevent.
//
// A non-type argument is checked against the catalog rather than assumed to be
// a package name: 'bodega build upload gitt' used to fail on the unknown type
// and would otherwise start filtering for a package nothing is named, upload
// nothing, and exit 0.
func parseUploadArgs(args []string, store *manifest.Store) ([]string, string, error) {
	var typeArgs []string
	var selector string
	for _, a := range args {
		switch {
		case isTypeArg(a):
			typeArgs = append(typeArgs, a)
		case selector != "":
			return nil, "", fmt.Errorf("only one package may be named; got %q and %q", selector, a)
		default:
			selector = a
		}
	}
	types, err := resolveTypes(typeArgs)
	if err != nil {
		return nil, "", err
	}
	if selector == "" {
		return types, "", nil
	}
	name, _ := splitVersionArg(selector)
	for _, t := range types {
		if slices.Contains(store.ListPackages(t), name) {
			return types, selector, nil
		}
	}
	if len(typeArgs) > 0 {
		return nil, "", fmt.Errorf("no package %q in %s", name, strings.Join(types, ", "))
	}
	return nil, "", fmt.Errorf("%q is neither a package in the catalog nor one of the types: %s",
		name, strings.Join(manifest.AllTypes, ", "))
}

// applyUploadScope binds a parsed selector to the placer and reports what was
// selected, or an error naming why this selection cannot be honored.
//
// --storage demands one type and one version because it names a backend for
// one artifact. Without the version it would be a package-level placement,
// which is storage_policy and already exists; without the single type it would
// place whatever package of that name each type happens to hold.
func applyUploadScope(cfg *config.Config, pl *placer, types []string, selector, backend string) error {
	name, version := splitVersionArg(selector)
	if name != "" {
		pl.Only(name)
	}
	if backend == "" {
		return nil
	}
	if err := checkBackendName(cfg, backend); err != nil {
		return fmt.Errorf("--storage: %w", err)
	}
	if len(types) != 1 {
		return fmt.Errorf("--storage places one artifact, so it needs one type: name it before %s, as in 'binary %s --storage %s'",
			cmp.Or(selector, "NAME@VERSION"), cmp.Or(selector, "NAME@VERSION"), backend)
	}
	if directoryPlaced(types[0]) {
		return fmt.Errorf("--storage cannot place a %s version: %s; set storage_by_type.%s and re-upload with --replace-placement instead",
			types[0], noPerPackagePlacement(types[0]), types[0])
	}
	if version == "" {
		return fmt.Errorf("--storage places one version: name it as NAME@VERSION, as in '%s@<version>'. "+
			"To place every future version of a package, use 'bodega pkg create %s %s --storage %s'",
			cmp.Or(name, "NAME"), types[0], cmp.Or(name, "NAME"), backend)
	}
	pl.PlaceVersion(name, version, backend)
	return nil
}

// confirmPlaced fails a run whose --storage named a version the upload never
// reached. Reporting success there would leave the operator believing an
// artifact is on a backend nothing ever wrote to.
func confirmPlaced(pl *placer, typ, selector, backend string) error {
	if pl.PlacedVersion() {
		return nil
	}
	name, version := splitVersionArg(selector)
	return fmt.Errorf("--storage %s named %s@%s, which this run never uploaded: nothing was written to %q. "+
		"Check the version against 'bodega show pkg %s %s'; a frozen version is skipped by every upload, and so is one whose artifact is not on disk",
		backend, name, version, backend, typ, name)
}
