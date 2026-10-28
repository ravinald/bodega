package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
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
		Use:   "osquery <secret|extension>",
		Short: "Manage osquery enroll secrets, and run bodega's osquery extension",
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
	parent.AddCommand(secret, newOsqueryExtensionCmd())
	return parent
}

func newOsqueryExtensionCmd() *cobra.Command {
	var (
		socket            string
		timeout, interval int
		verbose           bool
	)
	c := &cobra.Command{
		Use:   "extension --socket <path>",
		Short: "Serve the package origin tables to osqueryd as an extension",
		Long: `Registers two tables with the osqueryd listening on --socket and serves
them until osqueryd exits:

  bodega_npm_origins  directory, name, version, path, resolved
                      from <directory>/node_modules/.package-lock.json
  bodega_pip_origins  directory, name, version, path, url
                      from <directory>/*.dist-info/direct_url.json (PEP 610)

Both need directory in the WHERE clause and return no rows without it. A
file that does not parse is skipped and named on stderr.

osqueryd starts it with --socket, --timeout and --interval when the bodega
binary is listed in its extensions_autoload file under a name ending in .ext,
which ` + "`bodega doctor --configure osquery --apply`" + ` sets up. A binary invoked
under such a name runs this command directly.

Examples:
  osqueryi --extension /usr/local/lib/bodega/bodega.ext
  bodega osquery extension --socket /var/osquery/osquery.em`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if timeout <= 0 || interval <= 0 {
				return fmt.Errorf("--timeout and --interval take a positive number of seconds, got %d and %d", timeout, interval)
			}
			return osquery.RunExtension(osquery.ExtensionOptions{
				Socket:   socket,
				Timeout:  time.Duration(timeout) * time.Second,
				Interval: time.Duration(interval) * time.Second,
				Log:      cmd.ErrOrStderr(),
			})
		},
	}
	c.Flags().StringVar(&socket, "socket", "", "Path to osqueryd's extensions socket")
	c.Flags().IntVar(&timeout, "timeout", 3, "Seconds to wait for osqueryd to answer")
	c.Flags().IntVar(&interval, "interval", 3, "Seconds between checks that osqueryd is still there")
	c.Flags().BoolVar(&verbose, "verbose", false, "Accepted because osqueryd passes it; the extension logs only skipped files")
	return c
}

// osqueryExtensionArgs turns the command line osqueryd starts an autoloaded
// extension with into bodega's own. osqueryd runs the .ext path itself with
// its flags and no subcommand, so a binary invoked under that name is the
// extension.
func osqueryExtensionArgs(args []string) ([]string, bool) {
	if len(args) == 0 || !strings.HasSuffix(args[0], ".ext") {
		return args, false
	}
	return append([]string{args[0], "osquery", "extension"}, args[1:]...), true
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

// osqueryExtension is what --configure osquery installs for a host whose
// server-mode instance sets origins: the bodega binary linked under a .ext
// name, and that name listed in osqueryd's autoload file. root prefixes both
// paths, "" on a real host.
type osqueryExtension struct {
	binary string
	// name is the link's path as osqueryd reads it, without root.
	name         string
	link         string
	autoload     string
	linkCurrent  bool
	listed       bool
	autoloadBody []byte
}

// planOsqueryExtension decides the extension install from the plan. It
// refuses a host whose server-mode instance does not set origins, with the
// refusal --configure osquery has always given: the flags, the enroll secret
// and the restart are setup.sh's, and without origins there is nothing else.
func planOsqueryExtension(plan clientconf.Plan, goos, binary, root string) (*osqueryExtension, error) {
	var servers []clientconf.OsqueryPlan
	for _, p := range plan.Osquery {
		if p.Mode == osquery.ModeServer {
			servers = append(servers, p)
		}
	}
	setupHint := "  Run the served setup script for the flags, the enroll secret and the restart: BODEGA_OSQUERY_SECRET=<secret> sh setup.sh --url <base> --systems osquery --apply"
	switch {
	case len(servers) != 1:
		return nil, fmt.Errorf("--configure osquery installs bodega's osquery extension for the one server-mode osquery source a host enrolls with, and this server runs %d.\n%s", len(servers), setupHint)
	case !servers[0].Origins:
		return nil, fmt.Errorf("osquery source %q does not set origins, so its schedule reads no extension and --configure osquery has nothing to install.\n%s", servers[0].Instance, setupHint)
	}
	link, autoload := clientconf.OsqueryExtensionPaths[goos], clientconf.OsqueryAutoloadPaths[goos]
	if link == "" || autoload == "" {
		return nil, fmt.Errorf("bodega knows where osqueryd autoloads extensions on linux and freebsd, not on %s", goos)
	}
	ext := &osqueryExtension{binary: binary, name: link, link: filepath.Join(root, link), autoload: filepath.Join(root, autoload)}
	if dest, err := os.Readlink(ext.link); err == nil && dest == binary {
		ext.linkCurrent = true
	}
	body, err := os.ReadFile(ext.autoload)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read osqueryd's autoload file %s: %w", ext.autoload, err)
	}
	ext.autoloadBody = body
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == link {
			ext.listed = true
		}
	}
	return ext, nil
}

// checkExtensionBinary refuses a binary osqueryd's autoloader would refuse:
// one not owned by root, or writable by its group or anyone. osqueryd says
// so only in its own log, and the host would report nothing at all, since
// its schedule names the extension's tables.
func checkExtensionBinary(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat the bodega binary %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s on this platform", path)
	}
	if st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("osqueryd autoloads only an extension owned by root and writable by no one else, and %s is owned by uid %d with mode %s.\n"+
			"  Install bodega where root owns it (install -o root -m 0755 bodega /usr/local/bin/bodega), then re-run from there", path, st.Uid, fi.Mode().Perm())
	}
	return nil
}

func (e *osqueryExtension) unchanged() bool { return e.linkCurrent && e.listed }

func (e *osqueryExtension) printPlan(w io.Writer) {
	if e.linkCurrent {
		fmt.Fprintf(w, "unchanged  %-10s %s -> %s\n", clientconf.SystemOsquery, e.link, e.binary)
	} else {
		fmt.Fprintf(w, "link       %-10s %s -> %s (osquery extension)\n", clientconf.SystemOsquery, e.link, e.binary)
	}
	if e.listed {
		fmt.Fprintf(w, "unchanged  %-10s %s lists the extension\n", clientconf.SystemOsquery, e.autoload)
	} else {
		fmt.Fprintf(w, "autoload   %-10s %s gains the line %s\n", clientconf.SystemOsquery, e.autoload, e.name)
	}
}

// apply writes the link and the autoload line. The link is replaced through
// a rename so osqueryd never reads a half-made one, and the autoload file
// keeps every line it held.
func (e *osqueryExtension) apply() error {
	if !e.linkCurrent {
		if err := os.MkdirAll(filepath.Dir(e.link), 0o755); err != nil {
			return fmt.Errorf("create %s for the osquery extension: %w", filepath.Dir(e.link), err)
		}
		tmp := e.link + ".bodega-tmp"
		_ = os.Remove(tmp)
		if err := os.Symlink(e.binary, tmp); err != nil {
			return fmt.Errorf("link the osquery extension: %w", err)
		}
		if err := os.Rename(tmp, e.link); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("link the osquery extension at %s: %w", e.link, err)
		}
	}
	if !e.listed {
		body := e.autoloadBody
		if len(body) > 0 && body[len(body)-1] != '\n' {
			body = append(body, '\n')
		}
		body = append(body, e.name+"\n"...)
		if err := os.MkdirAll(filepath.Dir(e.autoload), 0o755); err != nil {
			return fmt.Errorf("create %s for osqueryd's autoload file: %w", filepath.Dir(e.autoload), err)
		}
		if err := os.WriteFile(e.autoload, body, 0o644); err != nil {
			return fmt.Errorf("write osqueryd's autoload file %s: %w", e.autoload, err)
		}
	}
	return nil
}

// configureOsqueryExtension is --configure osquery: the extension half of
// the osquery system, which only this binary can do because the extension
// is this binary.
func configureOsqueryExtension(w io.Writer, plan clientconf.Plan, apply bool) error {
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find the bodega binary to link as the osquery extension: %w", err)
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		return fmt.Errorf("resolve the bodega binary: %w", err)
	}
	ext, err := planOsqueryExtension(plan, runtime.GOOS, binary, "")
	if err != nil {
		return err
	}
	if err := checkExtensionBinary(binary); err != nil {
		return err
	}
	ext.printPlan(w)
	restart := "osqueryd loads it at its next start: the setup script sets extensions_autoload and restarts osqueryd (--systems osquery --apply)"
	switch {
	case ext.unchanged():
		fmt.Fprintf(w, "\nNothing to change: the extension is linked and listed. %s.\n", restart)
		return nil
	case !apply:
		fmt.Fprintln(w, "\nDry run: nothing was written. Re-run with --apply, as root, to link and list the extension.")
		return nil
	case os.Geteuid() != 0:
		return fmt.Errorf("osqueryd autoloads only a root-owned extension from a root-owned directory, so --configure osquery --apply needs root. Re-run with sudo. Nothing was written")
	}
	if err := ext.apply(); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote      %s\nwrote      %s\n\n%s.\n", ext.link, ext.autoload, restart)
	return nil
}
