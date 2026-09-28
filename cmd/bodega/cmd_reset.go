package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/syslog"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/storage"
)

func newResetCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear all manifests and local artifacts, keeping app config",
		Long: `reset removes all manifest files and local build artifacts, giving you a
clean slate. The config file is preserved, and reset names it before asking for
confirmation.

This is a destructive operation. You will be asked to type a randomly
generated confirmation word before anything is deleted.

What gets deleted:
  - All manifest JSON files (apt.json, git.json, pypi.json, etc.)
  - Every build directory each package type writes, under build_root or
    under that type's *_root override. Each one is named before the
    confirmation, and one outside build_root is marked as such.
  - The audit database

What is preserved:
  - Application config (bucket, region, TLS, deny list, etc.)
  - S3 bucket contents (use 'bodega remove' for individual S3 cleanup)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			reader := bufio.NewReader(os.Stdin)

			auditPath := cfg.AuditDB
			if auditPath == "" {
				auditPath = filepath.Join(cfg.LogDir, "audit.db")
			}

			// Gather decisions before the destructive confirmation.
			fmt.Println("WARNING: This will delete all manifests and local build artifacts.")
			fmt.Println()
			fmt.Println("The following will be cleared:")
			fmt.Printf("  Manifests:  %s\n", cfg.ManifestDir)
			if cfg.Bucket != "" {
				fmt.Printf("  S3 bucket:  s3://%s/manifests/\n", cfg.Bucket)
			}
			targets := resetTargets(cfg)
			printResetTargets(os.Stdout, cfg.BuildRoot, targets)
			fmt.Println()
			fmt.Println("The following is preserved:")
			fmt.Printf("  Config:     %s\n", config.ConfigPath())
			fmt.Println()

			fmt.Printf("  Also reset the audit database (%s)? [y/N]: ", auditPath)
			auditInput, _ := reader.ReadString('\n')
			resetAudit := strings.TrimSpace(strings.ToLower(auditInput)) == "y" ||
				strings.TrimSpace(strings.ToLower(auditInput)) == "yes"
			fmt.Println()

			// Generate a random confirmation word.
			word, err := randomWord()
			if err != nil {
				return fmt.Errorf("generate confirmation word: %w", err)
			}
			fmt.Printf("Type %q to confirm: ", word)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			if input != word {
				return fmt.Errorf("confirmation failed: expected %q, got %q", word, input)
			}

			fmt.Println()

			// Delete local manifest directory.
			if err := os.RemoveAll(cfg.ManifestDir); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not remove %s: %v\n", cfg.ManifestDir, err)
			}
			fmt.Println("  Local manifests cleared.")

			// Clear remote manifests -- delete everything under manifests/ prefix.
			if cfg.Bucket != "" {
				ctx := context.Background()
				objStore, err := storage.New(ctx, cfg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  warning: could not connect to storage: %v\n", err)
				} else {
					keys, err := objStore.List(ctx, "manifests/")
					if err != nil {
						fmt.Fprintf(os.Stderr, "  warning: could not list remote manifests: %v\n", err)
					} else {
						deleted := 0
						for _, key := range keys {
							if err := objStore.Delete(ctx, key); err != nil {
								fmt.Fprintf(os.Stderr, "  warning: could not delete s3://%s/%s: %v\n", cfg.Bucket, key, err)
							} else {
								deleted++
							}
						}
						fmt.Printf("  S3 manifests cleared: %d objects deleted from s3://%s/manifests/\n", deleted, cfg.Bucket)
					}
				}
			}

			failed := clearResetTargets(os.Stdout, os.Stderr, targets)

			// Remove audit database if user opted in.
			if resetAudit {
				// Fail-safe: write to syslog before wiping the audit trail.
				auditFailsafe("audit database reset", auditPath)

				for _, ext := range []string{"", "-shm", "-wal"} {
					_ = os.Remove(auditPath + ext)
				}
				fmt.Println("  Audit database cleared.")
			} else {
				fmt.Println("  Audit database preserved.")
			}

			fmt.Println()
			if failed > 0 {
				// The manifests are already gone, and an error return skips the
				// root's post-run reload.
				signalReloadNow(cmd, gf)
				return fmt.Errorf("reset incomplete: %d of %d build paths could not be removed (named above); fix the cause and run 'bodega reset' again", failed, len(targets))
			}
			fmt.Println("Reset complete. Config preserved. Run 'bodega init' to re-initialize.")
			return nil
		},
	}
	return cmd
}

// randomWord generates a short random string for confirmation prompts.
func randomWord() (string, error) {
	words := []string{
		"confirm", "proceed", "delete", "reset", "purge",
		"clear", "wipe", "erase", "remove", "destroy",
	}
	// Pick a random word and append a random 3-digit number.
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
	if err != nil {
		return "", err
	}
	num, err := rand.Int(rand.Reader, big.NewInt(900))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%d", words[idx.Int64()], num.Int64()+100), nil
}

// auditFailsafe writes a record to syslog (or a fallback file) before the
// audit database is wiped. This creates an immutable record outside the DB
// that the audit trail was intentionally cleared.
func auditFailsafe(action, dbPath string) {
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	msg := fmt.Sprintf("bodega: %s by %s at %s (db: %s)",
		action, username, time.Now().UTC().Format(time.RFC3339), dbPath)

	// Try syslog first.
	if w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_AUTH, "bodega"); err == nil {
		_ = w.Warning(msg)
		_ = w.Close()
		return
	}

	// Fallback: append to a file next to the audit DB.
	fallbackPath := filepath.Join(filepath.Dir(dbPath), "audit-failsafe.log")
	f, err := os.OpenFile(fallbackPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write audit failsafe: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintln(f, msg)
}

// resetTarget is a build path reset removes. Outside marks one a *_root
// override put beyond build_root: that path was chosen by hand and may share a
// parent with something else, so the prompt names it on its own line.
type resetTarget struct {
	builder.ResetPath
	Outside bool
}

func resetTargets(cfg *config.Config) []resetTarget {
	buildRoot, _ := filepath.Abs(cfg.BuildRoot)
	var out []resetTarget
	for _, rp := range builder.ResetPaths(builder.NewConfig(cfg, nil)) {
		abs, _ := filepath.Abs(rp.Path)
		rel, err := filepath.Rel(buildRoot, abs)
		out = append(out, resetTarget{ResetPath: rp, Outside: err != nil || !filepath.IsLocal(rel)})
	}
	return out
}

func printResetTargets(w io.Writer, buildRoot string, targets []resetTarget) {
	_, _ = fmt.Fprintf(w, "  Build root: %s\n", buildRoot)
	var outside []resetTarget
	for _, t := range targets {
		if t.Outside {
			outside = append(outside, t)
			continue
		}
		_, _ = fmt.Fprintf(w, "    %s\n", t.Path)
	}
	if len(outside) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "  Outside build_root, set by a *_root override:")
	for _, t := range outside {
		keys := make([]string, len(t.Types))
		for i, typ := range t.Types {
			keys[i] = typ + "_root"
		}
		_, _ = fmt.Fprintf(w, "    %s  (%s)\n", t.Path, strings.Join(keys, ", "))
	}
}

// clearResetTargets removes every target, naming each one removed and each one
// it could not remove, and returns how many it could not.
func clearResetTargets(stdout, stderr io.Writer, targets []resetTarget) int {
	failed := 0
	for _, t := range targets {
		if _, err := os.Lstat(t.Path); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.RemoveAll(t.Path); err != nil {
			_, _ = fmt.Fprintf(stderr, "  could not remove %s: %v\n", t.Path, err)
			failed++
			continue
		}
		_, _ = fmt.Fprintf(stdout, "  Removed %s\n", t.Path)
	}
	if failed > 0 {
		_, _ = fmt.Fprintf(stderr, "  Build artifacts NOT cleared: %d of %d paths remain.\n", failed, len(targets))
		return failed
	}
	_, _ = fmt.Fprintln(stdout, "  Build artifacts cleared.")
	return 0
}
