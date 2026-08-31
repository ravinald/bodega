package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/server"
)

// aclList describes one of the three CIDR lists for the command tree and for
// the error text, which has to name both the CLI word and the config key an
// operator may still have in their file.
type aclList struct {
	name      string // admin | deny | proxies
	configKey string // admin_permit_cidr | deny_list | trusted_proxies
	short     string
}

var aclLists = []aclList{
	{audit.ACLAdmin, "admin_permit_cidr", "CIDRs allowed to reach the mutation API"},
	{audit.ACLDeny, "deny_list", "CIDRs refused on every route"},
	{audit.ACLProxies, "trusted_proxies", "peers whose forwarded headers are believed"},
}

func newACLCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "acl <admin|deny|proxies> <add|remove|list> [cidr]",
		Short: "Manage the CIDR access lists in the audit database",
		Long: `Manage the three CIDR access lists. They live in the audit database, not in
config.json: a change lands on a running server within 30 seconds, or at once
on ` + "`systemctl reload bodega`" + `, with no restart.

Lists, named for the config.json keys they replace:

  admin     admin_permit_cidr  CIDRs allowed to reach the mutation API
  deny      deny_list          CIDRs refused on every route
  proxies   trusted_proxies    peers whose forwarded headers are believed

The config file's values are copied into the database the first time bodega
sees a database without them. After that the database is the only source and
the file's entries are inert.

Examples:
  bodega acl admin add 10.0.0.0/8
  bodega acl admin add 10.0.0.0/8 --comment "ops jump host"
  bodega acl deny add 203.0.113.0/24
  bodega acl proxies list
  bodega acl admin remove 10.0.0.0/8`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return fmt.Errorf(
				"no list named %q: bodega acl manages three lists and the caller has to name one.\n"+
					"  admin    (admin_permit_cidr)  CIDRs allowed to reach the mutation API\n"+
					"  deny     (deny_list)          CIDRs refused on every route\n"+
					"  proxies  (trusted_proxies)    peers whose forwarded headers are believed\n"+
					"Try: bodega acl admin %s",
				args[0], strings.Join(args, " "))
		},
	}
	for _, l := range aclLists {
		parent.AddCommand(newACLListCmd(gf, l))
	}
	return parent
}

func newACLListCmd(gf *globalFlags, list aclList) *cobra.Command {
	c := &cobra.Command{
		Use:   list.name + " <add|remove|list> [cidr]",
		Short: fmt.Sprintf("Manage %s: %s", list.configKey, list.short),
	}
	c.AddCommand(newACLAddCmd(gf, list), newACLRemoveCmd(gf, list), newACLShowCmd(gf, list))
	return c
}

func newACLAddCmd(gf *globalFlags, list aclList) *cobra.Command {
	var force bool
	var comment string
	c := &cobra.Command{
		Use:   "add <cidr>",
		Short: "Add a CIDR to " + list.configKey,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cidr, err := normalizeCIDR(args[0])
			if err != nil {
				return err
			}
			ctx := context.Background()
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			// Read the list as the server reads it today, and clear the
			// guards, before claiming it for the database. A command that
			// refuses should leave no write behind it.
			current, err := effectiveACL(ctx, adb, cfg, list.name)
			if err != nil {
				return err
			}
			if containsCIDR(current, cidr) {
				fmt.Printf("%s is already in the %s list.\n", cidr, list.name)
				return nil
			}
			if list.name == audit.ACLAdmin && !force {
				if err := checkAdminWidening(ctx, adb, current, cidr); err != nil {
					return err
				}
			}
			if err := ensureACLSeeded(ctx, adb, cfg, list.name); err != nil {
				return err
			}
			added, err := adb.AddACL(ctx, audit.ACLEntry{
				List: list.name, CIDR: cidr, Comment: comment, Actor: audit.CurrentActor(),
			})
			if err != nil {
				return fmt.Errorf("add %s to the %s list: %w", cidr, list.name, err)
			}
			if !added {
				fmt.Printf("%s is already in the %s list.\n", cidr, list.name)
				return nil
			}
			recordACLChange(ctx, adb, audit.EventCreate, list.name, cidr, "add", force)
			fmt.Printf("Added %s to the %s list (%s).\n", cidr, list.name, list.configKey)
			fmt.Println(aclEffectNote)
			return nil
		},
	}
	c.Flags().StringVar(&comment, "comment", "", "note stored beside the entry")
	if list.name == audit.ACLAdmin {
		c.Flags().BoolVar(&force, "force", false,
			"add anyway when the result would turn on the Bearer token requirement with no tokens issued")
	}
	return c
}

func newACLRemoveCmd(gf *globalFlags, list aclList) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "remove <cidr>",
		Short: "Remove a CIDR from " + list.configKey,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cidr, err := normalizeCIDR(args[0])
			if err != nil {
				return err
			}
			ctx := context.Background()
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			// Confirm membership before claiming the list. Seeding first would
			// let a typo'd `acl proxies remove` move trusted_proxies from the
			// built-in default to an explicit empty list (trusting no header
			// from anyone) as a side effect of a command that then failed.
			current, err := effectiveACL(ctx, adb, cfg, list.name)
			if err != nil {
				return err
			}
			if !containsCIDR(current, cidr) {
				return fmt.Errorf("%s is not in the %s list.\n  See what is: bodega acl %s list",
					cidr, list.name, list.name)
			}
			if list.name == audit.ACLAdmin && !force {
				if err := checkAdminLockout(current, cidr); err != nil {
					return err
				}
			}
			if err := ensureACLSeeded(ctx, adb, cfg, list.name); err != nil {
				return err
			}
			if _, err := adb.RemoveACL(ctx, list.name, cidr); err != nil {
				return fmt.Errorf("remove %s from the %s list: %w", cidr, list.name, err)
			}
			recordACLChange(ctx, adb, audit.EventDelete, list.name, cidr, "remove", force)
			fmt.Printf("Removed %s from the %s list (%s).\n", cidr, list.name, list.configKey)
			fmt.Println(aclEffectNote)
			return nil
		},
	}
	if list.name == audit.ACLAdmin {
		c.Flags().BoolVar(&force, "force", false,
			"remove anyway when the result would be an empty admin list, locking out every mutation")
	}
	return c
}

func newACLShowCmd(gf *globalFlags, list aclList) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show " + list.configKey,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			adb := openAuditDB(gf)
			if adb == nil {
				fmt.Printf("%s (%s)  source: config file, no audit database\n", list.name, list.configKey)
				printCIDRs(aclConfigValue(cfg, list.name))
				return nil
			}
			defer adb.Close()

			owned, err := adb.ACLSeeded(ctx, list.name)
			if err != nil {
				return fmt.Errorf("read %s list: %w", list.name, err)
			}
			if !owned {
				fmt.Printf("%s (%s)  source: config file, not yet copied into the database\n",
					list.name, list.configKey)
				printCIDRs(aclConfigValue(cfg, list.name))
				return nil
			}
			entries, err := adb.ListACL(ctx, list.name)
			if err != nil {
				return fmt.Errorf("read %s list: %w", list.name, err)
			}
			fmt.Printf("%s (%s)  source: database\n", list.name, list.configKey)
			if len(entries) == 0 {
				if list.name == audit.ACLProxies {
					fmt.Println("(empty: no peer's forwarded headers are believed)")
				} else {
					fmt.Println("(empty)")
				}
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CIDR\tADDED\tACTOR\tCOMMENT")
			for _, e := range entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					e.CIDR, e.CreatedAt.Format("2006-01-02"), e.Actor, e.Comment)
			}
			return w.Flush()
		},
	}
}

const aclEffectNote = "A running server picks this up within 30s, or at once on `systemctl reload bodega`."

// openACLStore loads the config, refuses a read-only install, and opens the
// audit database. Every write path needs all three.
func openACLStore(gf *globalFlags) (*config.Config, *audit.DB, error) {
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	if err := ensureMutable(cfg); err != nil {
		return nil, nil, err
	}
	adb := openAuditDB(gf)
	if adb == nil {
		return nil, nil, fmt.Errorf(
			"could not open the audit database, which is where the access lists live.\n" +
				"  Check audit_db (or log_dir) in config.json, then: bodega status")
	}
	if adb.ReadOnly() {
		_ = adb.Close()
		return nil, nil, fmt.Errorf(
			"the audit database is read-only, so the access lists cannot be changed.\n" +
				"  Run as the user that owns it, or with sudo")
	}
	return cfg, adb, nil
}

// normalizeCIDR validates one entry and returns it in the canonical form the
// server parses it into, so "10.0.0.1/8" added is "10.0.0.0/8" removed.
func normalizeCIDR(in string) (string, error) {
	nets, err := server.ParseDenyList([]string{in})
	if err != nil {
		return "", fmt.Errorf("%q is not a CIDR or an address: %w.\n"+
			"  Write a network (10.0.0.0/8) or a bare address, which is taken as /32 or /128", in, err)
	}
	if len(nets) != 1 {
		return "", fmt.Errorf("%q is empty; give one CIDR or address", in)
	}
	return nets[0].String(), nil
}

// ensureACLSeeded copies the config file's value for one list into the
// database before a write touches it. Without this, the first `bodega acl
// admin add` on an install whose lists still live in config.json would produce
// a one-entry admin list and drop the loopback default with it.
func ensureACLSeeded(ctx context.Context, adb *audit.DB, cfg *config.Config, list string) error {
	owned, err := adb.ACLSeeded(ctx, list)
	if err != nil {
		return fmt.Errorf("read %s list: %w", list, err)
	}
	if owned {
		return nil
	}
	raw := aclConfigValue(cfg, list)
	entries := normalizeCIDRs(raw)
	if _, err := adb.SeedACL(ctx, list, entries, ""); err != nil {
		return fmt.Errorf("copy %s from config into the audit database: %w", list, err)
	}
	switch {
	case len(entries) > 0:
		fmt.Printf("Copied %s from config.json into the audit database (%d entries); the file's value is now inert.\n",
			audit.ACLConfigKey(list), len(entries))
	case list == audit.ACLProxies && raw == nil:
		// The tri-state: unset in the file means the built-in default was in
		// force, and claiming the list ends that. Say so, because the operator
		// typed one CIDR and is getting a narrower answer than they had.
		fmt.Println("trusted_proxies was unset, so the built-in default applied (loopback + RFC 1918).")
		fmt.Println("The database owns it from here: only the entries listed by `bodega acl proxies list` are trusted.")
	default:
		fmt.Printf("Claimed %s for the audit database; the config file's value is now inert.\n",
			audit.ACLConfigKey(list))
	}
	return nil
}

// effectiveACL returns the list as the server reads it today: from the
// database where it owns the list, from the config file where it does not.
func effectiveACL(ctx context.Context, adb *audit.DB, cfg *config.Config, list string) ([]string, error) {
	owned, err := adb.ACLSeeded(ctx, list)
	if err != nil {
		return nil, fmt.Errorf("read %s list: %w", list, err)
	}
	if owned {
		cidrs, err := adb.ACLCIDRs(ctx, list)
		if err != nil {
			return nil, fmt.Errorf("read %s list: %w", list, err)
		}
		return cidrs, nil
	}
	return normalizeCIDRs(aclConfigValue(cfg, list)), nil
}

// normalizeCIDRs best-effort canonicalizes config file entries so they compare
// against stored ones. An entry the parser rejects is passed through: the
// server logs it and ignores it, and dropping it here would quietly change
// what an operator sees.
func normalizeCIDRs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		if n, err := normalizeCIDR(e); err == nil {
			out = append(out, n)
		} else {
			out = append(out, e)
		}
	}
	return out
}

func containsCIDR(list []string, cidr string) bool {
	for _, e := range list {
		if e == cidr {
			return true
		}
	}
	return false
}

func aclConfigValue(cfg *config.Config, list string) []string {
	switch list {
	case audit.ACLAdmin:
		return cfg.AdminPermitCIDR
	case audit.ACLDeny:
		return cfg.DenyList
	case audit.ACLProxies:
		return cfg.TrustedProxies
	}
	return nil
}

// checkAdminWidening refuses an add that would take admin_permit_cidr past
// localhost while no token exists to satisfy the Bearer requirement the
// widening turns on. That combination answers every mutation with a 401 and
// names nothing that points at the cause.
func checkAdminWidening(ctx context.Context, adb *audit.DB, current []string, adding string) error {
	after, err := server.ParseDenyList(append(append([]string{}, current...), adding))
	if err != nil {
		return fmt.Errorf("parse the resulting admin list: %w", err)
	}
	if server.LocalhostOnly(after) {
		return nil
	}
	n, err := adb.TokenCount(ctx)
	if err != nil {
		return fmt.Errorf("count api tokens: %w", err)
	}
	if n > 0 {
		return nil
	}
	return fmt.Errorf(
		"refusing to add %s to the admin list: it takes admin_permit_cidr past localhost, which\n"+
			"turns on the Bearer token requirement, and no API tokens exist. Every mutation would\n"+
			"answer 401, including the ones from localhost that work today.\n"+
			"  Issue a token first:  bodega token generate <label>\n"+
			"  Or add it anyway:     bodega acl admin add %s --force",
		adding, adding)
}

// checkAdminLockout refuses a removal that would empty the admin list. An empty
// admin_permit_cidr permits nobody on either half of the admin surface: the
// mutation verbs and the four admin reads. The command that would put an entry
// back is the one the removal just disabled over HTTP.
func checkAdminLockout(current []string, removing string) error {
	remaining := 0
	for _, e := range current {
		if e != removing {
			remaining++
		}
	}
	if remaining > 0 {
		return nil
	}
	return fmt.Errorf(
		"refusing to remove %s from the admin list: it is the last entry, and an empty\n"+
			"admin_permit_cidr permits nobody. Every mutation is refused, from localhost\n"+
			"included, and so are the four admin reads: /api/v1/audit, /api/v1/tokens,\n"+
			"/api/v1/policies and /api/v1/config. Nothing could put an entry back over HTTP.\n"+
			"  Add the replacement first:  bodega acl admin add <cidr>\n"+
			"  Or accept the lockout:      bodega acl admin remove %s --force",
		removing, removing)
}

// recordACLChange writes the audit row for one list change. Who changed the
// rule belongs in the same queryable place as who the rule turned away.
func recordACLChange(ctx context.Context, adb *audit.DB, ev audit.EventType, list, cidr, direction string, forced bool) {
	details := "direction=" + direction
	if forced {
		details += " force=true"
	}
	_ = adb.Record(ctx, audit.Event{
		EventType:  ev,
		PkgType:    "acl",
		PkgName:    list,
		PkgVersion: cidr,
		Actor:      audit.CurrentActor(),
		Status:     "success",
		Details:    details,
	})
}

func printCIDRs(entries []string) {
	if entries == nil {
		fmt.Println("(unset: the built-in default applies)")
		return
	}
	if len(entries) == 0 {
		fmt.Println("(empty)")
		return
	}
	for _, e := range entries {
		fmt.Printf("  %s\n", e)
	}
}
