package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// newIdentityCmd manages the binding table the serve path attributes requests
// through. It lives beside `bodega acl` rather than under it: an ACL entry
// decides admission, a binding decides attribution, and the two answer to
// different reviews.
func newIdentityCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "identity <bind|unbind|list>",
		Short: "Bind tokens and networks to the host names the audit trail records",
		Long: `identity maps something the serve path can observe about a request — the
token it presented, or the network its address falls in — to a name.

Two kinds, because they answer different questions:

  token <id> <name>    precise; needs the credential on the host first
  cidr  <cidr> <name>  no bootstrap problem; right for "this subnet is devboxes"

Resolution order on a request is token, then longest-prefix CIDR, then
unidentified. A request carrying no credential is served exactly as it was
before any binding existed: this table decides what the audit row says, never
what may be fetched.

One token or one CIDR resolves to at most one name. A second binding that
would make the answer ambiguous is refused here, at write time, naming the
one already in the table.

A CIDR binding needs trusted_proxies answered. On the built-in default any
RFC 1918 peer can send X-Real-IP and be believed, which makes a CIDR binding
assertable by whoever asks; bodega serve refuses to start in that state. Name
the proxy with ` + "`bodega acl proxies add`" + `, or write "trusted_proxies": []
in the config file to trust no forwarded header at all.

Examples:
  bodega identity bind cidr 10.20.0.0/16 devbox
  bodega identity bind token 4f3c... build-07 --comment "CI runner"
  bodega identity list
  bodega identity unbind cidr 10.20.0.0/16`,
	}
	parent.AddCommand(newIdentityBindCmd(gf), newIdentityUnbindCmd(gf), newIdentityListCmd(gf))
	return parent
}

func newIdentityBindCmd(gf *globalFlags) *cobra.Command {
	var comment string
	c := &cobra.Command{
		Use:   "bind <token|cidr> <key> <identity>",
		Short: "Bind a token id or a CIDR to an identity",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, key, name := args[0], args[1], args[2]
			if !audit.ValidBindKind(kind) {
				return fmt.Errorf("no binding kind named %q: bodega binds a token id or a CIDR.\n"+
					"  token <id> <identity>    the credential a host presents\n"+
					"  cidr  <cidr> <identity>  the network a host's address falls in", kind)
			}
			ctx := backgroundCtx()
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()

			if kind == audit.BindToken {
				if err := requireToken(ctx, adb, key); err != nil {
					return err
				}
			}
			added, err := adb.AddIdentityBinding(ctx, audit.IdentityBinding{
				Kind: kind, Key: key, Identity: name,
				Comment: comment, Actor: audit.CurrentActor(),
			})
			if err != nil {
				return err
			}
			if !added {
				fmt.Printf("%s %s is already bound to %s.\n", kind, key, name)
				return nil
			}
			fmt.Printf("Bound %s %s to %s.\n", kind, key, name)
			if kind == audit.BindCIDR {
				if warn := proxyTrustWarning(ctx, adb, cfg); warn != "" {
					fmt.Fprint(cmd.ErrOrStderr(), warn)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&comment, "comment", "", "Note stored with the binding")
	return c
}

// requireToken refuses a binding to a token id no token has. A binding to a
// mistyped id is inert and looks identical to one that works: every request
// from that host resolves through the CIDR fallback, or to nothing, and the
// audit rows read as a host that never authenticated.
func requireToken(ctx context.Context, adb *audit.DB, id string) error {
	tokens, err := adb.ListTokens(ctx)
	if err != nil {
		return fmt.Errorf("read tokens: %w", err)
	}
	for _, t := range tokens {
		if t.ID == id {
			return nil
		}
	}
	return fmt.Errorf("no token has id %q, so the binding would resolve for nobody.\n"+
		"  The ids:  bodega token list\n"+
		"  A new one:  bodega token generate <label>", id)
}

// proxyTrustWarning repeats, at bind time, the refusal `bodega serve` will
// produce on its next start. Discovering an interlock from a server that will
// not come back up is worse than discovering it from the command that armed it.
func proxyTrustWarning(ctx context.Context, adb *audit.DB, cfg *config.Config) string {
	owned, err := adb.ACLSeeded(ctx, audit.ACLProxies)
	if err != nil || owned || cfg.TrustedProxies != nil {
		return ""
	}
	return "\nWarning: trusted_proxies is still the built-in default (loopback + RFC 1918), and every\n" +
		"peer in that range has its X-Real-IP believed verbatim, so any of them can claim an\n" +
		"address inside a bound network and collect that identity. bodega serve refuses to start\n" +
		"in this state. Answer it either way:\n" +
		"  bodega acl proxies add <proxy-cidr>   name the proxy that terminates for clients\n" +
		"  \"trusted_proxies\": [] in " + config.ConfigPath() + "\n" +
		"                                        trust no forwarded header from anyone\n"
}

func newIdentityUnbindCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "unbind <token|cidr> <key>",
		Short: "Remove a binding",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, key := args[0], args[1]
			_, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			removed, err := adb.RemoveIdentityBinding(backgroundCtx(), kind, key)
			if err != nil {
				return err
			}
			if !removed {
				fmt.Printf("No %s binding for %s.\n", kind, key)
				return nil
			}
			fmt.Printf("Removed the %s binding for %s.\n", kind, key)
			return nil
		},
	}
}

func newIdentityListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show every identity binding",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open the audit database, which is where the bindings live.\n" +
					"  Check audit_db (or log_dir) in config.json, then: bodega status")
			}
			defer adb.Close()
			bindings, err := adb.ListIdentityBindings(backgroundCtx())
			if err != nil {
				return fmt.Errorf("read identity bindings: %w", err)
			}
			if len(bindings) == 0 {
				fmt.Println("No identity bindings. Every request is recorded by address alone.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "KIND\tKEY\tIDENTITY\tACTOR\tCREATED\tCOMMENT")
			for _, b := range bindings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					b.Kind, b.Key, b.Identity, b.Actor,
					b.CreatedAt.Format("2006-01-02 15:04"), b.Comment)
			}
			return w.Flush()
		},
	}
}
