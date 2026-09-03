package main

// placement.go binds the command layer to internal/placement.
//
// The placer moved out of this package when the TUI needed it: two copies of
// "which backend does this write go to" is one copy that stops matching the
// other, which is how the TUI came to upload every type to the default bucket
// while the CLI honored storage_by_type. These names stay lowercase and local
// so the command files read the same as they did before the move.

import (
	"context"
	"io"

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

func writePlacement(stores storage.Resolver, typ, policy string) storage.Decision {
	return placement.WritePlacement(stores, typ, policy)
}

func storagePolicyWarning(typ, policy string) string {
	return placement.StoragePolicyWarning(typ, policy)
}

func noPerPackagePlacement(typ string) string { return placement.NoPerPackagePlacement(typ) }

func effectiveStorage(recorded string) string { return placement.EffectiveStorage(recorded) }

func versionIndex(pm *manifest.PackageManifest, v string) int { return placement.VersionIndex(pm, v) }

func versionLabel(ve manifest.VersionEntry) string { return placement.VersionLabel(ve) }
