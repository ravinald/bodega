package main

import "testing"

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
