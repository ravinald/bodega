package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
)

const tokenPrefix = "bodega_ak_"

func newTokenCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "token",
		Short: "Manage API tokens for the mutation API",
	}
	parent.AddCommand(
		newTokenGenerateCmd(gf),
		newTokenListCmd(gf),
		newTokenRevokeCmd(gf),
	)
	return parent
}

// bodega token generate <label> [expiry <days|date|never>] [comment]
func newTokenGenerateCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "generate <label> [expiry <duration|date|never>] [comment]",
		Short: "Generate a new API token",
		Long: `Generate a cryptographically random API token. The raw token is displayed
once and cannot be retrieved later. A SHA-256 hash (with pepper) is stored.

Examples:
  bodega token generate ci-pipeline
  bodega token generate ci-pipeline expiry 90d
  bodega token generate ci-pipeline expiry 2027-06-01
  bodega token generate ci-pipeline expiry never
  bodega token generate ci-pipeline expiry 90d "Jenkins deploy key"
  bodega token generate ci-pipeline "Jenkins deploy key"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			label := args[0]
			expiry, comment := parseExpiryAndComment(args[1:])

			// Open audit DB.
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			// Load or create pepper.
			pepper, err := audit.LoadOrCreatePepper(audit.DefaultPepperPaths)
			if err != nil {
				return fmt.Errorf("pepper: %w", err)
			}

			// Generate random token.
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return fmt.Errorf("generate random bytes: %w", err)
			}
			token := tokenPrefix + hex.EncodeToString(b)

			// Hash with pepper using HMAC-SHA256.
			hash := audit.HashToken(token, pepper)

			// Generate short ID.
			idBytes := make([]byte, 16)
			if _, err := rand.Read(idBytes); err != nil {
				return fmt.Errorf("generate token ID: %w", err)
			}
			id := hex.EncodeToString(idBytes)

			// Compute expiry time.
			var expiresAt *time.Time
			if expiry != "never" && expiry != "" {
				t, err := parseExpiryValue(expiry)
				if err != nil {
					return fmt.Errorf("invalid expiry %q: %w", expiry, err)
				}
				expiresAt = &t
			}

			// Store in DB.
			ctx := context.Background()
			if err := adb.InsertToken(ctx, id, label, hash, comment, expiresAt); err != nil {
				return fmt.Errorf("store token: %w", err)
			}

			// Record audit event.
			_ = adb.Record(ctx, audit.Event{
				EventType: audit.EventCreate,
				PkgType:   "token",
				PkgName:   label,
				Status:    "success",
				Details:   fmt.Sprintf("id=%s", id),
			})

			// Display.
			fmt.Println("Token generated. Save this now — it cannot be retrieved later.")
			fmt.Println()
			fmt.Printf("  Token:   %s\n", token)
			fmt.Printf("  ID:      %s\n", id)
			fmt.Printf("  Label:   %s\n", label)
			if expiresAt != nil {
				fmt.Printf("  Expires: %s\n", expiresAt.Format("2006-01-02"))
			} else {
				fmt.Printf("  Expires: never\n")
			}
			if comment != "" {
				fmt.Printf("  Comment: %s\n", comment)
			}

			return nil
		},
	}
}

func newTokenListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all API tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			tokens, err := adb.ListTokens(context.Background())
			if err != nil {
				return fmt.Errorf("list tokens: %w", err)
			}

			if len(tokens) == 0 {
				fmt.Println("No tokens configured.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tLABEL\tCREATED\tEXPIRES\tLAST USED\tCOMMENT")
			for _, t := range tokens {
				created := t.CreatedAt.Format("2006-01-02")
				expires := "never"
				if t.ExpiresAt != nil {
					if t.ExpiresAt.Before(time.Now()) {
						expires = t.ExpiresAt.Format("2006-01-02") + " EXPIRED"
					} else {
						expires = t.ExpiresAt.Format("2006-01-02")
					}
				}
				lastUsed := "-"
				if t.LastUsed != nil {
					lastUsed = t.LastUsed.Format("2006-01-02 15:04")
				}
				comment := t.Comment
				if len(comment) > 40 {
					comment = comment[:37] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					t.ID, t.Label, created, expires, lastUsed, comment)
			}
			return w.Flush()
		},
	}
}

func newTokenRevokeCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id|label>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()

			// Try by ID first, then by label.
			found, err := adb.DeleteToken(ctx, target)
			if err != nil {
				return fmt.Errorf("revoke token: %w", err)
			}
			if !found {
				// ID didn't match — try by label.
				if err := adb.DeleteTokenByLabel(ctx, target); err != nil {
					return fmt.Errorf("revoke token: %w", err)
				}
			}

			_ = adb.Record(ctx, audit.Event{
				EventType: audit.EventDelete,
				PkgType:   "token",
				PkgName:   target,
				Status:    "success",
			})

			fmt.Printf("Token %q revoked.\n", target)
			return nil
		},
	}
}

// parseExpiryAndComment parses the remaining args after the label.
// Pattern: [expiry <value>] [comment words...]
func parseExpiryAndComment(args []string) (expiry, comment string) {
	if len(args) == 0 {
		return "365d", ""
	}

	if args[0] == "expiry" {
		if len(args) < 2 {
			return "365d", ""
		}
		expiry = args[1]
		if len(args) > 2 {
			comment = strings.Join(args[2:], " ")
		}
		return expiry, comment
	}

	// No expiry keyword — everything is the comment.
	return "365d", strings.Join(args, " ")
}

// parseExpiryValue converts an expiry string to a time.Time.
// Accepts: "30d", "90d", "365d", "1y", "2027-01-01"
func parseExpiryValue(s string) (time.Time, error) {
	now := time.Now().UTC()

	// Try duration with 'd' suffix.
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err == nil && days > 0 {
			return now.AddDate(0, 0, days), nil
		}
	}

	// Try duration with 'y' suffix.
	if strings.HasSuffix(s, "y") {
		years, err := strconv.Atoi(strings.TrimSuffix(s, "y"))
		if err == nil && years > 0 {
			return now.AddDate(years, 0, 0), nil
		}
	}

	// Try date format.
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}

	// Try RFC3339.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("expected duration (30d, 1y), date (2027-01-01), or 'never'")
}
