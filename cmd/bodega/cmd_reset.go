package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"log/syslog"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/storage"
)

func newResetCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear all manifests and local artifacts, keeping app config",
		Long: `reset removes all manifest files and local build artifacts, giving you a
clean slate. The application config (/etc/bodega/config.json or
~/.config/bodega/config.json) is preserved.

This is a destructive operation. You will be asked to type a randomly
generated confirmation word before anything is deleted.

What gets deleted:
  - All manifest JSON files (apt.json, git.json, pypi.json, etc.)
  - All local build artifacts (sources, repos, bundles, wheels, etc.)
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
			fmt.Printf("  Build root: %s\n", cfg.BuildRoot)
			if cfg.Bucket != "" {
				fmt.Printf("  S3 bucket:  s3://%s/manifests/\n", cfg.Bucket)
			}
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

			// Clear build artifacts.
			artifactDirs := []string{
				"sources", "repos", "bundles", "wheels", "binaries",
				"apt-repo", "gomod", "charts", "npm",
			}
			for _, dir := range artifactDirs {
				path := filepath.Join(cfg.BuildRoot, dir)
				if err := os.RemoveAll(path); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: could not remove %s: %v\n", path, err)
				}
			}
			fmt.Println("  Build artifacts cleared.")

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
