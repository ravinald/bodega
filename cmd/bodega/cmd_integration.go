package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
)

func newIntegrationCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integration",
		Short: "External admission checks: list, configure and test them",
		Long: `An integration is an external risk check that runs on every version
admitted, beside the age, OSV, provenance and name-similarity checks. Each
configured instance has a name, a type and that type's settings, and lives
under "integrations" in the config file. These commands edit that key and
nothing else in the file; the TUI's Integrations view (G) and a hand edit
reach the same validator.

A new instance is added disabled. Read what it sends off the host, then
enable it. Its action per ecosystem is set with 'bodega policy integration'.
A running 'bodega serve' reads integrations when it starts.

  bodega integration types
  bodega integration add aikido malware-list
  bodega integration enable aikido
  bodega integration test aikido
  bodega policy integration set aikido npm block`,
	}
	cmd.AddCommand(newIntegrationTypesCmd(), newIntegrationListCmd(gf), newIntegrationShowCmd(),
		newIntegrationAddCmd(), newIntegrationSetCmd(), newIntegrationEnableCmd(true), newIntegrationEnableCmd(false),
		newIntegrationRemoveCmd(), newIntegrationSecretCmd(), newIntegrationTestCmd(gf))
	return cmd
}

func newIntegrationTypesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "types",
		Short: "List the integration types this binary can run",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			for i, d := range integration.Types() {
				if i > 0 {
					fmt.Fprintln(out)
				}
				fmt.Fprintf(out, "%s  %s (%s)\n", d.Type, d.DisplayName, d.VendorURL)
				fmt.Fprintf(out, "  cost:           %s\n", d.Cost)
				fmt.Fprintf(out, "  ecosystems:     %s\n", strings.Join(d.Ecosystems, ", "))
				fmt.Fprintf(out, "  default action: %s\n", d.DefaultAction)
				fmt.Fprintf(out, "  sends:          %s\n", d.DataSent)
			}
			return nil
		},
	}
}

// integrationRow is one instance as `list --json` prints it.
type integrationRow struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	Valid       bool   `json:"valid"`
	Problem     string `json:"problem,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt string `json:"last_error_at,omitempty"`
}

func newIntegrationListCmd(gf *globalFlags) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured instances, enabled state and last error",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := integration.FileEntries()
			if err != nil {
				return err
			}
			var lastErrors map[string]audit.IntegrationError
			if adb := openIntegrationAuditDB(gf); adb != nil {
				defer adb.Close()
				lastErrors, _ = adb.IntegrationErrors(cmd.Context())
			}
			rows := []integrationRow{}
			for _, n := range integration.SortedNames(entries) {
				e := entries[n]
				r := integrationRow{Name: n, Valid: true}
				r.Type, _ = e["type"].(string)
				r.Enabled, _ = e["enabled"].(bool)
				if _, err := integration.ValidateInstance(n, e); err != nil {
					r.Valid, r.Problem = false, err.Error()
				}
				if le, ok := lastErrors[n]; ok {
					r.LastError, r.LastErrorAt = le.Message, le.At.UTC().Format(time.RFC3339)
				}
				rows = append(rows, r)
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No integrations configured in %s. 'bodega integration types' lists what can be added.\n", config.ConfigPath())
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tENABLED\tLAST ERROR")
			for _, r := range rows {
				last := "-"
				if r.LastError != "" {
					last = r.LastErrorAt + " " + r.LastError
				}
				if !r.Valid {
					last = "INVALID: " + r.Problem
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.Type, yesNo(r.Enabled), last)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// openIntegrationAuditDB opens the audit store for a read that can do
// without it, quietly: `list` still answers from the config file when the
// store is missing or the config does not load.
func openIntegrationAuditDB(gf *globalFlags) *audit.DB {
	db, err := openAuditDBErr(gf)
	if err != nil {
		return nil
	}
	return db
}

// integrationLogDir is the log_dir an instance keeps its state under, or ""
// when the config does not load, which `test` must survive because it is how
// an operator checks an entry they are repairing.
func integrationLogDir(gf *globalFlags) string {
	cfg, err := loadConfig(gf)
	if err != nil {
		return ""
	}
	return cfg.LogDir
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func newIntegrationShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show <instance>",
		Short: "Print an instance's settings, secrets redacted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			entry, err := fileEntry(name)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(integration.Redact(entry))
			}
			out := cmd.OutOrStdout()
			inst, verr := integration.ValidateInstance(name, entry)
			typ, _ := entry["type"].(string)
			enabled, _ := entry["enabled"].(bool)
			fmt.Fprintf(out, "instance: %s\ntype:     %s\nenabled:  %s\n", name, typ, yesNo(enabled))
			if verr != nil {
				fmt.Fprintf(out, "INVALID:  %v\n", verr)
			}
			d, ok := integration.Lookup(typ)
			if !ok {
				red := integration.Redact(entry)
				keys := make([]string, 0, len(red))
				for k := range red {
					if k != "type" && k != "enabled" {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(out, "%s: %s\n", k, integration.FormatValue(red[k]))
				}
				return nil
			}
			fmt.Fprintf(out, "sends:    %s\n\n", d.DataSent)
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tVALUE\tSOURCE")
			for _, f := range d.Fields {
				if f.Secret {
					src := "not set"
					if inst != nil {
						if _, s, err := inst.Secret(f.Key); err == nil {
							src = s
						}
					}
					fmt.Fprintf(w, "%s\t%s\t%s\n", f.Key, integration.Redacted, src)
					continue
				}
				v, set := entry[f.Key]
				src := "config file"
				if !set {
					v, src = f.Default, "default"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", f.Key, integration.FormatValue(v), src)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the entry as the config file holds it, secrets redacted")
	return cmd
}

func fileEntry(name string) (config.Integration, error) {
	entries, err := integration.FileEntries()
	if err != nil {
		return nil, err
	}
	e, ok := entries[name]
	if !ok {
		return nil, fmt.Errorf("no integration instance %q in %s ('bodega integration list' shows those that exist)", name, config.ConfigPath())
	}
	return e, nil
}

// applyAssignments sets each key=value on entry through the descriptor.
func applyAssignments(entry config.Integration, assignments []string) error {
	typ, _ := entry["type"].(string)
	d, ok := integration.Lookup(typ)
	if !ok {
		return fmt.Errorf("unknown integration type %q", typ)
	}
	for _, a := range assignments {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return fmt.Errorf("%q: want key=value", a)
		}
		if err := integration.SetText(entry, d, k, v); err != nil {
			return err
		}
	}
	return nil
}

func newIntegrationAddCmd() *cobra.Command {
	var sets []string
	cmd := &cobra.Command{
		Use:   "add <instance> <type>",
		Short: "Add a disabled instance of a type",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, typ := args[0], args[1]
			entries, err := integration.FileEntries()
			if err != nil {
				return err
			}
			if _, exists := entries[name]; exists {
				return fmt.Errorf("integration instance %q already exists; change it with 'bodega integration set %s key=value'", name, name)
			}
			d, ok := integration.Lookup(typ)
			if !ok {
				return fmt.Errorf("unknown integration type %q ('bodega integration types' lists them)", typ)
			}
			entry := config.Integration{"type": typ, "enabled": false}
			if err := applyAssignments(entry, sets); err != nil {
				return fmt.Errorf("integrations.%s.%w", name, err)
			}
			path, err := integration.SaveEntry(name, entry)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Added %s (%s), disabled, to %s.\n", name, d.DisplayName, path)
			fmt.Fprintf(out, "What it sends off this host: %s\n", d.DataSent)
			for _, f := range d.Fields {
				if f.Secret {
					fmt.Fprintf(out, "Store its %s with: bodega integration secret %s %s\n", f.Key, name, f.Key)
				}
			}
			fmt.Fprintf(out, "Turn it on with: bodega integration enable %s\n", name)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&sets, "set", nil, "key=value, repeatable")
	return cmd
}

func newIntegrationSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <instance> key=value...",
		Short: "Change an instance's settings; an empty value restores the default",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			entry, err := fileEntry(name)
			if err != nil {
				return err
			}
			before := integration.Redact(entry)
			if err := applyAssignments(entry, args[1:]); err != nil {
				return fmt.Errorf("integrations.%s.%w", name, err)
			}
			path, err := integration.SaveEntry(name, entry)
			if err != nil {
				return err
			}
			after := integration.Redact(entry)
			for _, a := range args[1:] {
				k, _, _ := strings.Cut(a, "=")
				fmt.Fprintf(cmd.OutOrStdout(), "%s.%s: %s -> %s\n", name, k, showValue(before, k), showValue(after, k))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Saved to %s.\n", path)
			return nil
		},
	}
}

func showValue(e config.Integration, k string) string {
	v, ok := e[k]
	if !ok {
		return "(default)"
	}
	return integration.FormatValue(v)
}

func newIntegrationEnableCmd(enable bool) *cobra.Command {
	use, short := "enable", "Turn an instance on"
	if !enable {
		use, short = "disable", "Turn an instance off, keeping its settings"
	}
	return &cobra.Command{
		Use:   use + " <instance>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			entry, err := fileEntry(name)
			if err != nil {
				return err
			}
			entry["enabled"] = enable
			path, err := integration.SaveEntry(name, entry)
			if err != nil {
				return err
			}
			if enable {
				if d, ok := integration.Lookup(fmt.Sprint(entry["type"])); ok {
					fmt.Fprintf(cmd.OutOrStdout(), "What it sends off this host: %s\n", d.DataSent)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%sd %s in %s. A running 'bodega serve' picks this up when it restarts.\n",
				strings.ToUpper(use[:1])+use[1:], name, path)
			return nil
		},
	}
}

func newIntegrationRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <instance>",
		Short: "Remove an instance from the config file",
		Long: `Remove an instance from the config file. Its integration_policy rows and
any credential file stay where they are, so adding it back under the same
name restores its actions.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := integration.RemoveEntry(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s from %s.\n", args[0], path)
			return nil
		},
	}
}

func newIntegrationSecretCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "secret <instance> <key>",
		Short: "Store a secret read from standard input, never echoed",
		Long: `Read a secret from standard input and write it, mode 0600, to the file
the instance's <key>_file names, or to credentials/<instance>.<key> beside the
config file, recording that path as <key>_file. The secret is never written to
the config file and never printed.

At run time a secret is read from $CREDENTIALS_DIRECTORY/<instance>.<key>
first, then BODEGA_<INSTANCE>_<KEY>, then <key>_file.

  bodega integration secret socket api_token
  printf %s "$TOKEN" | bodega integration secret socket api_token`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, key := args[0], args[1]
			entry, err := fileEntry(name)
			if err != nil {
				return err
			}
			// Validated as disabled, so a required secret that does not
			// exist yet is not what stops the command that stores it.
			probe := config.Integration{}
			for k, v := range entry {
				probe[k] = v
			}
			probe["enabled"] = false
			inst, err := integration.ValidateInstance(name, probe)
			if err != nil {
				return err
			}
			in := cmd.InOrStdin()
			if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s for %s (input hidden): ", key, name)
				b, err := term.ReadPassword(int(f.Fd()))
				fmt.Fprintln(cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				in = bytes.NewReader(b)
			}
			path, err := integration.WriteSecret(inst, key, in)
			if err != nil {
				return err
			}
			if entry[key+"_file"] != path {
				entry[key+"_file"] = path
				if _, err := integration.SaveEntry(name, entry); err != nil {
					return fmt.Errorf("secret written to %s, but %s_file was not recorded: %w", path, key, err)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored %s.%s in %s (mode 0600).\n", name, key, path)
			return nil
		},
	}
}

func newIntegrationTestCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "test <instance>",
		Short: "Make one real query for a well-known package and print the answer",
		Long: `Ask the instance about its type's well-known package, bypassing the
cache, and print the answer, the latency and any quota the vendor reported.
It runs whether or not the instance is enabled, and it is the one command
here that reaches the network.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			entry, err := fileEntry(name)
			if err != nil {
				return err
			}
			var store integration.Store
			if adb := openIntegrationAuditDB(gf); adb != nil {
				defer adb.Close()
				store = adb
			}
			return integration.RunTest(cmd.Context(), cmd.OutOrStdout(), name, entry, integrationLogDir(gf), store)
		},
	}
}
