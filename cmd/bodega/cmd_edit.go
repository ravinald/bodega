package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newEditCmd(gf *globalFlags) *cobra.Command {
	var editorFlag string

	cmd := &cobra.Command{
		Use:   "edit <type> <name> [version]",
		Short: "Edit a manifest entry in $EDITOR",
		Long: `edit loads the JSON for a package (or a single version when VERSION is given)
into a temp file, opens it in $EDITOR, and re-imports it on save.

Without VERSION, the entire PackageManifest is edited — every version, plus
top-level fields like Description and DepPolicy.

With VERSION, only the matching VersionEntry is edited (matches either
Version or Ref). This is the recommended form for targeted changes.

Editor resolution: --editor flag → $VISUAL → $EDITOR → "vi".

A no-op save (no bytes changed) exits cleanly without touching storage.
Validation or policy failures leave the edited temp file on disk so you can
re-run with --editor cat to inspect, or copy and retry.`,
		Example: `  bodega pkg edit npm @bitwarden/cli
  bodega pkg edit npm @bitwarden/cli 2026.4.0
  bodega pkg edit --editor=nvim git netbox`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			name := args[1]
			versionArg := ""
			if len(args) == 3 {
				versionArg = args[2]
			}
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			ctx := context.Background()

			pm, err := store.GetPackage(ctx, t, name)
			if err != nil {
				return fmt.Errorf("get %s/%s: %w", t, name, err)
			}
			if pm == nil {
				return fmt.Errorf("%s entry %q not found", t, name)
			}

			// Capture the authoritative before-state for the audit diff. This is
			// always the full PackageManifest, even when scope is a single version,
			// so the diff reflects the complete change as applied to storage.
			beforeJSON, _ := json.MarshalIndent(pm, "", "  ")

			// Resolve what we're handing to the editor.
			var editTarget any
			var targetIdx int // set when versionArg != ""
			if versionArg == "" {
				editTarget = pm
			} else {
				idx := findVersion(pm, versionArg)
				if idx < 0 {
					return fmt.Errorf("version %q not found in %s/%s; known: %s",
						versionArg, t, name, knownVersions(pm))
				}
				editTarget = pm.Versions[idx]
				targetIdx = idx
			}

			payload, err := json.MarshalIndent(editTarget, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal edit target: %w", err)
			}

			tmpPath, err := writeEditBuffer(t, name, versionArg, payload)
			if err != nil {
				return err
			}

			// Hash the file as it lands on disk — writeEditBuffer may add a
			// trailing newline, and we need to compare like-for-like with what
			// the editor hands back.
			preBytes, err := os.ReadFile(tmpPath) //nolint:gosec // path produced above
			if err != nil {
				return fmt.Errorf("read seeded buffer: %w (path: %s)", err, tmpPath)
			}
			preHash := sha256.Sum256(preBytes)

			editor := resolveEditor(editorFlag)
			if err := runEditor(editor, tmpPath); err != nil {
				return fmt.Errorf("editor exited with error: %w (buffer kept: %s)", err, tmpPath)
			}

			edited, err := os.ReadFile(tmpPath) //nolint:gosec // path produced above
			if err != nil {
				return fmt.Errorf("read edited buffer: %w (path: %s)", err, tmpPath)
			}
			postHash := sha256.Sum256(edited)
			if preHash == postHash {
				_ = os.Remove(tmpPath)
				fmt.Printf("%s/%s: no changes\n", t, name)
				return nil
			}

			// Apply the edit. Either mode preserves the package identity (Name,
			// Type) — renames go through create/delete, not edit.
			if versionArg == "" {
				var edited2 manifest.PackageManifest
				if err := json.Unmarshal(edited, &edited2); err != nil {
					return fmt.Errorf("parse edited JSON: %w (buffer kept: %s)", err, tmpPath)
				}
				if edited2.Name != pm.Name || edited2.Type != pm.Type {
					return fmt.Errorf("edit cannot change Name or Type (was %s/%s, got %s/%s); buffer kept: %s",
						pm.Type, pm.Name, edited2.Type, edited2.Name, tmpPath)
				}
				edited2.ConfigVersion = manifest.CurrentConfigVersion
				*pm = edited2
			} else {
				var ve manifest.VersionEntry
				if err := json.Unmarshal(edited, &ve); err != nil {
					return fmt.Errorf("parse edited JSON: %w (buffer kept: %s)", err, tmpPath)
				}
				pm.Versions[targetIdx] = ve
			}

			if err := validateManifest(pm); err != nil {
				return fmt.Errorf("validation failed: %w (buffer kept: %s)", err, tmpPath)
			}

			// Policy enforcement mirrors cmd_import's hard-reject behavior —
			// there is no override path on edit.
			adb := openAuditDB(gf)
			if adb != nil {
				defer adb.Close()
			}
			var checker *policy.Checker
			if adb != nil {
				checker = policy.NewChecker(adb)
			}
			if err := enforceImportPolicy(ctx, checker, adb, pm); err != nil {
				return fmt.Errorf("policy rejected edit: %w (buffer kept: %s)", err, tmpPath)
			}

			if err := store.SavePackage(ctx, pm); err != nil {
				return fmt.Errorf("save %s/%s: %w (buffer kept: %s)", t, name, err, tmpPath)
			}
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save index: %w (buffer kept: %s)", err, tmpPath)
			}

			afterJSON, _ := json.MarshalIndent(pm, "", "  ")
			if adb != nil {
				pkgVersion := versionArg
				_ = adb.Record(ctx, audit.Event{
					EventType:  audit.EventEdit,
					PkgType:    t,
					PkgName:    name,
					PkgVersion: pkgVersion,
					Actor:      audit.CurrentActor(),
					Status:     "success",
					Details:    audit.FormatDiff(beforeJSON, afterJSON),
				})
			}

			_ = os.Remove(tmpPath)
			if versionArg != "" {
				fmt.Printf("Updated %s/%s@%s\n", t, name, versionArg)
			} else {
				fmt.Printf("Updated %s/%s (%d version(s))\n", t, name, len(pm.Versions))
			}
			notifyServer(gf)
			return nil
		},
	}

	cmd.Flags().StringVar(&editorFlag, "editor", "",
		`Editor to invoke (overrides $VISUAL and $EDITOR); defaults to "vi"`)
	return cmd
}

// findVersion returns the index in pm.Versions whose Version or Ref matches v,
// or -1 if none. An empty v never matches — callers want a real identifier.
func findVersion(pm *manifest.PackageManifest, v string) int {
	if v == "" {
		return -1
	}
	for i, ve := range pm.Versions {
		if ve.Version == v || ve.Ref == v {
			return i
		}
	}
	return -1
}

func knownVersions(pm *manifest.PackageManifest) string {
	var out []string
	for _, ve := range pm.Versions {
		v := ve.Version
		if v == "" {
			v = ve.Ref
		}
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return "(none)"
	}
	return strings.Join(out, ", ")
}

// writeEditBuffer writes payload to a temp file named after the package for
// easier recovery if the edit fails.
func writeEditBuffer(t, name, version string, payload []byte) (string, error) {
	safeName := strings.NewReplacer("/", "_", "@", "", ":", "_").Replace(name)
	prefix := fmt.Sprintf("bodega-edit-%s-%s-", t, safeName)
	if version != "" {
		prefix += strings.ReplaceAll(version, "/", "_") + "-"
	}
	f, err := os.CreateTemp("", prefix+"*.json")
	if err != nil {
		return "", fmt.Errorf("create temp buffer: %w", err)
	}
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write temp buffer: %w", err)
	}
	// Trailing newline so editors don't flag the file as missing EOL.
	if !bytes.HasSuffix(payload, []byte("\n")) {
		_, _ = f.Write([]byte("\n"))
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close temp buffer: %w", err)
	}
	return f.Name(), nil
}

// resolveEditor picks the editor to invoke, honoring the documented
// precedence: flag → $VISUAL → $EDITOR → "vi".
func resolveEditor(flag string) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv("VISUAL"); v != "" {
		return v
	}
	if v := os.Getenv("EDITOR"); v != "" {
		return v
	}
	return "vi"
}

// runEditor splits the editor spec into argv (so "code --wait" works) and
// attaches stdio to the terminal.
func runEditor(editor, path string) error {
	parts := strings.Fields(editor)
	if len(parts) == 0 {
		return errors.New("empty editor")
	}
	args := append(parts[1:], path)
	cmd := exec.Command(parts[0], args...) //nolint:gosec // user-chosen editor
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
