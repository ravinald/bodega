package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/manifest"
)

func newVerifyCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify all .md5 files match their manifest files",
		Long: `verify reads each manifest file and checks that its companion .md5 file
contains the correct MD5 digest.

A missing .md5 file is reported as a warning, not an error — it means the
manifest has never been written by this tool.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			failures := 0
			for _, t := range manifest.AllTypes {
				path := filepath.Join(cfg.ManifestDir, t+".json")
				data, readErr := os.ReadFile(path)
				if os.IsNotExist(readErr) {
					fmt.Printf("  %-8s MISSING (no manifest file)\n", t)
					continue
				}
				if readErr != nil {
					fmt.Printf("  %-8s ERROR reading file: %v\n", t, readErr)
					failures++
					continue
				}

				stored, err := manifest.ReadMD5File(path)
				if err != nil {
					fmt.Printf("  %-8s ERROR reading .md5: %v\n", t, err)
					failures++
					continue
				}

				if stored == "" {
					fmt.Printf("  %-8s WARNING: no .md5 companion file\n", t)
					continue
				}

				ok, err := manifest.VerifyMD5(path, data)
				if err != nil {
					fmt.Printf("  %-8s ERROR: %v\n", t, err)
					failures++
					continue
				}
				if !ok {
					fmt.Printf("  %-8s FAIL (MD5 mismatch — run: bootstrap --break-glass-update-md5 %s)\n", t, t)
					failures++
				} else {
					fmt.Printf("  %-8s OK  (%s)\n", t, stored)
				}
			}

			if failures > 0 {
				return fmt.Errorf("%d manifest(s) failed integrity check", failures)
			}
			fmt.Println("\nAll manifests passed integrity check.")
			return nil
		},
	}
}
