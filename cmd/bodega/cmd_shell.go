package main

import (
	"fmt"

	"github.com/spf13/cobra"

	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/storage"
	"github.com/ravinald/bodega/internal/tui"
)

// newShellCmd constructs the "shell" sub-command which launches the TUI.
func newShellCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "shell",
		Short: "Launch the interactive TUI",
		Long: `shell opens the three-pane interactive terminal UI.

  Top-left:  Sources tree (manifest entries grouped by type)
  Top-right: Details for the selected entry
  Bottom:    Command shell with scrolling output

Tab switches focus between the Sources tree and the command shell.
Press ? for keybinding help, q to quit.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			// Load manifests from S3 by default, or local with --local-config.
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			auditDB := openAuditDB(gf)
			if auditDB != nil {
				defer auditDB.Close()
			}

			// The status pane resolves each entry to the backend its manifest
			// records, so it works on a local-only install.
			stores, err := storage.NewResolver(backgroundCtx(), cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}

			// The client is for reloading manifests kept in S3 and nothing
			// else: a bucket key left on a local-driver install dials nothing,
			// and the I action dials the backend it resolves.
			var s3client *bos3.Client
			if !cfg.UsesLocalManifests() {
				if s3client, err = newS3Client(cfg); err != nil {
					return fmt.Errorf("connect to AWS: %w", err)
				}
			}
			return tui.Run(cfg, store, s3client, stores, auditDB)
		},
	}
}
