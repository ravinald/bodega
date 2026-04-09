package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	bos3 "github.com/scaleapi/bodega/internal/s3"
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

			// Delete manifest files.
			manifests := []string{"apt.json", "git.json", "pypi.json", "binary.json",
				"gomod.json", "helm.json", "npm.json"}
			for _, name := range manifests {
				for _, ext := range []string{"", ".md5"} {
					path := filepath.Join(cfg.ManifestDir, name+ext)
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						fmt.Fprintf(os.Stderr, "  warning: could not remove %s: %v\n", path, err)
					}
				}
			}
			fmt.Println("  Local manifests cleared.")

			// Clear S3 manifests if bucket is configured.
			if cfg.Bucket != "" {
				ctx := context.Background()
				s3client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  warning: could not connect to S3: %v\n", err)
				} else {
					for _, name := range manifests {
						for _, ext := range []string{"", ".md5"} {
							key := "manifests/" + name + ext
							if err := s3client.DeleteObject(ctx, key); err != nil {
								fmt.Fprintf(os.Stderr, "  warning: could not delete s3://%s/%s: %v\n", cfg.Bucket, key, err)
							}
						}
					}
					fmt.Printf("  S3 manifests cleared (s3://%s/manifests/).\n", cfg.Bucket)
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
