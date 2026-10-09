package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/inventory/osquery"
)

const enrollSecretPrefix = "bodega_es_"

// newOsqueryCmd manages what an osquery inventory source in server mode
// needs beyond its config: the enroll secrets hosts present to get a
// node_key.
func newOsqueryCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "osquery <secret>",
		Short: "Manage osquery enroll secrets for an osquery inventory source",
	}
	secret := &cobra.Command{
		Use:   "secret <create|list|revoke>",
		Short: "Create, list and revoke osquery enroll secrets",
		Long: `An osquery inventory source in server mode answers osquery's enroll
endpoint. A host presents an enroll secret and gets back a node_key, and the
secret's identity becomes the identity every report under that key carries.
Mint one secret per host, or per group of hosts that should share an identity.

Examples:
  bodega osquery secret create osq web-01 --expires 30d
  bodega osquery secret list
  bodega osquery secret revoke 3f9a01c2d4e5b6a7`,
	}
	secret.AddCommand(newOsquerySecretCreateCmd(gf), newOsquerySecretListCmd(gf), newOsquerySecretRevokeCmd(gf))
	parent.AddCommand(secret)
	return parent
}

// osqueryServerInstance refuses an instance that is not an osquery source in
// server mode, since nothing else reads an enroll secret.
func osqueryServerInstance(cfg *config.Config, name string) error {
	if err := inventoryInstance(cfg, name); err != nil {
		return err
	}
	insts, err := inventory.Configure(cfg.InventorySources)
	if err != nil {
		return err
	}
	for _, inst := range insts {
		if inst.Name != name {
			continue
		}
		src, ok := inst.Source.(*osquery.Source)
		if !ok {
			return fmt.Errorf("inventory source %q is type %q, and only an osquery source reads enroll secrets", name, inst.Source.Type())
		}
		if src.OsqueryMode() != osquery.ModeServer {
			return fmt.Errorf("inventory source %q runs in %s mode, where hosts post results with a token and never enroll; enroll secrets are for mode %q", name, src.OsqueryMode(), osquery.ModeServer)
		}
	}
	return nil
}

// parseSecretExpiry takes a Go duration ("12h") or anything token expiry
// takes ("30d", "1y", a date).
func parseSecretExpiry(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, errors.New("want a positive duration")
		}
		return time.Now().UTC().Add(d), nil
	}
	return parseExpiryValue(s)
}

func newOsquerySecretCreateCmd(gf *globalFlags) *cobra.Command {
	var expires, label string
	c := &cobra.Command{
		Use:   "create <instance> <identity> [--expires <duration>]",
		Short: "Mint an enroll secret and print it once",
		Long: `create mints a random enroll secret for an osquery source in server mode
and prints it once. Only its peppered hash is stored, so it cannot be shown
again: put it in the file osqueryd's --enroll_secret_path names.

A host enrolling with it becomes <identity>. --expires stops new enrollments
after that time; node keys already handed out keep working until the secret
is revoked.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, identity := args[0], strings.TrimSpace(args[1])
			if identity == "" {
				return errors.New("identity is empty")
			}
			if label == "" {
				label = identity
			}
			var expiresAt *time.Time
			if expires != "" && expires != "never" {
				t, err := parseSecretExpiry(expires)
				if err != nil {
					return fmt.Errorf("invalid --expires %q: %w", expires, err)
				}
				expiresAt = &t
			}
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			if err := osqueryServerInstance(cfg, instance); err != nil {
				return err
			}
			pepper, err := mintPepper("enroll secret")
			if err != nil {
				return err
			}
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return fmt.Errorf("generate random bytes: %w", err)
			}
			secret := enrollSecretPrefix + hex.EncodeToString(raw)
			idBytes := make([]byte, 8)
			if _, err := rand.Read(idBytes); err != nil {
				return fmt.Errorf("generate secret id: %w", err)
			}
			rec := audit.OsquerySecret{
				ID: hex.EncodeToString(idBytes), Source: instance, Label: label,
				Identity: identity, ExpiresAt: expiresAt,
			}
			ctx := backgroundCtx()
			if err := adb.InsertOsquerySecret(ctx, rec, audit.HashToken(secret, pepper)); err != nil {
				return fmt.Errorf("store enroll secret: %w", err)
			}
			_ = adb.Record(ctx, audit.Event{
				EventType: audit.EventCreate, PkgType: "osquery-secret", PkgName: label,
				Actor: audit.CurrentActor(), Status: "success",
				Details: fmt.Sprintf("id=%s source=%s identity=%s", rec.ID, instance, identity),
			})
			fmt.Println("Enroll secret created. Save it now; it cannot be shown again.")
			fmt.Println()
			fmt.Printf("  Secret:   %s\n", secret)
			fmt.Printf("  ID:       %s\n", rec.ID)
			fmt.Printf("  Source:   %s\n", instance)
			fmt.Printf("  Identity: %s\n", identity)
			fmt.Printf("  Label:    %s\n", label)
			fmt.Printf("  Expires:  %s\n", fmtSecretExpiry(expiresAt))
			fmt.Println("\nOn the host, write it to the file --enroll_secret_path names, mode 0600.")
			return nil
		},
	}
	c.Flags().StringVar(&expires, "expires", "", "Stop enrollments after this: a duration (12h, 30d, 1y), a date, or never (the default)")
	c.Flags().StringVar(&label, "label", "", "A name for the secret in list output (default: the identity)")
	return c
}

func fmtSecretExpiry(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func newOsquerySecretListCmd(gf *globalFlags) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "list",
		Short: "List enroll secrets, never the secrets themselves",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			adb, err := openInventoryDB(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			rows, err := adb.ListOsquerySecrets(backgroundCtx())
			if err != nil {
				return err
			}
			if asJSON {
				if rows == nil {
					rows = []audit.OsquerySecret{}
				}
				return printJSON(rows)
			}
			if len(rows) == 0 {
				fmt.Println("No enroll secrets.")
				return nil
			}
			now := time.Now()
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSOURCE\tLABEL\tIDENTITY\tCREATED\tEXPIRES\tNODES")
			for _, s := range rows {
				exp := fmtSecretExpiry(s.ExpiresAt)
				if s.Expired(now) {
					exp += " EXPIRED"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n", s.ID, s.Source, s.Label, s.Identity,
					s.CreatedAt.UTC().Format(time.RFC3339), exp, s.Nodes)
			}
			return w.Flush()
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return c
}

func newOsquerySecretRevokeCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Delete an enroll secret and revoke every node_key enrolled with it",
		Long: `revoke deletes the secret, so no host can enroll with it again, and every
node_key handed out under it, so each of those hosts gets node_invalid on its
next config or log request. Reports already stored keep their identity.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			ctx := backgroundCtx()
			sec, nodes, err := adb.RevokeOsquerySecret(ctx, args[0])
			if errors.Is(err, audit.ErrNoOsquerySecret) {
				return fmt.Errorf("no enroll secret has id %q; bodega osquery secret list shows them", args[0])
			}
			if err != nil {
				return err
			}
			_ = adb.Record(ctx, audit.Event{
				EventType: audit.EventDelete, PkgType: "osquery-secret", PkgName: sec.Label,
				Actor: audit.CurrentActor(), Status: "success",
				Details: fmt.Sprintf("id=%s source=%s identity=%s nodes=%d", sec.ID, sec.Source, sec.Identity, nodes),
			})
			fmt.Printf("Revoked enroll secret %s (%s) and %d node key(s) enrolled with it.\n", sec.ID, sec.Label, nodes)
			return nil
		},
	}
}
