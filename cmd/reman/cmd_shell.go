package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/tui"
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

			// The S3 client is optional. When no bucket is configured all local
			// commands (build, fetch, package, verify, freeze, delete) still work;
			// only S3-touching commands (status, upload, sync, remove, init) will
			// report an error when executed from the shell pane.
			if cfg.Bucket == "" {
				return tui.Run(cfg, store, nil)
			}

			s3client, err := newS3Client(cfg)
			if err != nil {
				return fmt.Errorf("connect to AWS: %w", err)
			}
			return tui.Run(cfg, store, s3client)
		},
	}
}
