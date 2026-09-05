package main

import (
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
)

// TestStringFlagsDoNotShadowConfig covers the class rather than the cell that
// broke. Every string global flag is the head of a firstNonEmpty chain in
// config.Load, so a non-empty default wins outright and the env var and config
// key beneath it become unreachable. That is what made manifest_dir in
// config.json dead: --manifest-dir was registered with an absolute path nobody
// typed, so the file value could never be read and manifests landed relative
// to $PWD — under a unit with no WorkingDirectory=, at /manifests.
//
// The built-in default belongs at the tail of the chain in config.Load, never
// at the flag.
func TestStringFlagsDoNotShadowConfig(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"bucket", "region", "build-root", "manifest-dir"} {
		f := root.PersistentFlags().Lookup(name)
		if f == nil {
			t.Errorf("--%s is not registered as a persistent flag", name)
			continue
		}
		if f.DefValue != "" {
			t.Errorf("--%s is registered with default %q: it shadows its env var and config key, which no invocation can then reach", name, f.DefValue)
		}
	}
}

// TestBuildVersionReachesTheBuilder pins main's init, which is the whole wire.
// -ldflags can only stamp package main and internal/builder cannot import it,
// so a Config built anywhere else stamps builder's own default. The defaults
// differ on purpose: delete the init and this reads "unknown" against main's
// "dev", where two matching defaults would have let the assignment go missing
// with every test still green.
func TestBuildVersionReachesTheBuilder(t *testing.T) {
	if builder.Version != version {
		t.Errorf("builder.Version = %q, want main.version %q", builder.Version, version)
	}
	if builder.NewConfig(&config.Config{}).BodegaVersion != version {
		t.Errorf("NewConfig stamps %q, want %q",
			builder.NewConfig(&config.Config{}).BodegaVersion, version)
	}
}
