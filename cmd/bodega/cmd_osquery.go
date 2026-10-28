package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
// name, that name listed in the autoload file osqueryd reads, and, when the
// flags file names none, the extensions_autoload flag naming the default
// one. root prefixes every path, "" on a real host.
type osqueryExtension struct {
	goos   string
	binary string
	// name is the link's path as osqueryd reads it, without root.
	name     string
	link     string
	autoload string
	// autoloadName is the autoload file as the flag names it, without root.
	autoloadName string
	flagfile     string
	linkCurrent  bool
	listed       bool
	flagSet      bool
	autoloadBody []byte
	flagBody     []byte
	flagMode     os.FileMode
}

// planOsqueryExtension decides the extension install from the plan. It
// refuses a host whose server-mode instance does not set origins, with the
// refusal --configure osquery has always given: the flags, the enroll secret
// and the restart are setup.sh's, and without origins there is nothing else.
//
// The autoload file is the one osqueryd will read: the flagfile is found
// where setup.sh finds it, and an extensions_autoload line already in it is
// kept and followed. Pointing the flag at bodega's default instead would
// drop every extension the operator's file lists at the next restart.
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
	flagfile, err := osqueryFlagfile(goos, root)
	if err != nil {
		return nil, err
	}
	ext := &osqueryExtension{goos: goos, binary: binary, name: link, link: filepath.Join(root, link), flagfile: filepath.Join(root, flagfile), flagMode: 0o644}
	if dest, err := os.Readlink(ext.link); err == nil && dest == binary {
		ext.linkCurrent = true
	}
	if fi, err := os.Stat(ext.flagfile); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("osqueryd's flagfile %s is not a regular file; move it aside, then re-run. Nothing was written", ext.flagfile)
		}
		ext.flagMode = fi.Mode().Perm()
	}
	if ext.flagBody, err = os.ReadFile(ext.flagfile); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read osqueryd's flagfile %s: %w", ext.flagfile, err)
	}
	ext.autoloadName = autoload
	if v, set := clientconf.OsqueryFlagValue(ext.flagBody, "extensions_autoload"); set {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return nil, fmt.Errorf("%s sets --extensions_autoload=%q, which is not a clean absolute path bodega can add its extension to. Name the file osqueryd should read, or remove the line for %s, then re-run. Nothing was written", ext.flagfile, v, autoload)
		}
		ext.autoloadName, ext.flagSet = v, true
	}
	ext.autoload = filepath.Join(root, ext.autoloadName)
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

// osqueryFlagfile is the flagfile osqueryd reads, found as setup.sh's
// osq_flagfile finds it: the variable the OS package sets it in, else the
// package default. Two implementations disagreeing would put the flag in a
// file one of them never opens.
func osqueryFlagfile(goos, root string) (string, error) {
	variable, source := clientconf.OsqueryFlagSources[goos][0], clientconf.OsqueryFlagSources[goos][1]
	found := ""
	switch source {
	case "sysrc":
		args := []string{"-n", variable}
		if root != "" {
			args = append([]string{"-R", root}, args...)
		}
		if out, err := exec.Command("sysrc", args...).Output(); err == nil {
			found = strings.TrimSpace(string(out))
		}
	default:
		body, err := os.ReadFile(filepath.Join(root, source))
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("read %s for where osqueryd's flagfile is: %w", filepath.Join(root, source), err)
		}
		found = shellAssignment(body, variable)
	}
	if found == "" {
		return clientconf.OsqueryFlagsPaths[goos], nil
	}
	if !filepath.IsAbs(found) || strings.IndexFunc(found, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-", r))
	}) >= 0 {
		return "", fmt.Errorf("%s in %s names %s as osqueryd's flagfile, which is not an absolute path bodega will write. Nothing was written", variable, source, found)
	}
	return found, nil
}

// shellAssignment is the last value a shell-syntax file such as
// /etc/default/osqueryd assigns name, quoted or bare, as setup.sh reads it.
func shellAssignment(body []byte, name string) string {
	v := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimLeft(line, " \t")
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && strings.ContainsAny(rest[:1], " \t") {
			line = strings.TrimLeft(rest, " \t")
		}
		val, ok := strings.CutPrefix(line, name+"=")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(val, `"`):
			val, _, _ = strings.Cut(val[1:], `"`)
		case strings.HasPrefix(val, "'"):
			val, _, _ = strings.Cut(val[1:], "'")
		default:
			if i := strings.IndexAny(val, " \t#"); i >= 0 {
				val = val[:i]
			}
		}
		v = val
	}
	return v
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

func (e *osqueryExtension) unchanged() bool { return e.linkCurrent && e.listed && e.flagSet }

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
	if e.flagSet {
		fmt.Fprintf(w, "unchanged  %-10s %s names %s as the autoload file\n", clientconf.SystemOsquery, e.flagfile, e.autoloadName)
	} else {
		fmt.Fprintf(w, "flag       %-10s %s gains --extensions_autoload=%s\n", clientconf.SystemOsquery, e.flagfile, e.autoloadName)
	}
}

// apply writes the link, the autoload line and the flag, each only when
// missing, in that order so a flag never names a file before bodega's line
// is in it. Every file is replaced through a rename, so osqueryd never reads
// a half-written one, and keeps every line it held.
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
		mode := os.FileMode(0o644)
		if fi, err := os.Stat(e.autoload); err == nil {
			mode = fi.Mode().Perm()
		}
		if err := replaceFile(e.autoload, appendLine(e.autoloadBody, e.name), mode); err != nil {
			return fmt.Errorf("write osqueryd's autoload file %s: %w", e.autoload, err)
		}
	}
	if !e.flagSet {
		if err := replaceFile(e.flagfile, appendLine(e.flagBody, "--extensions_autoload="+e.autoloadName), e.flagMode); err != nil {
			return fmt.Errorf("write osqueryd's flagfile %s: %w. The extension is linked and listed; re-run to set the flag", e.flagfile, err)
		}
	}
	return nil
}

func appendLine(body []byte, line string) []byte {
	out := append([]byte(nil), body...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, line+"\n"...)
}

// replaceFile writes body to path through a temporary file beside it and a
// rename. A symlinked path is written through to its target, so the link an
// operator made still names the file osqueryd reads.
func replaceFile(path string, body []byte, mode os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".bodega-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// osqueryRestart is the command that makes osqueryd read what apply wrote.
func osqueryRestart(goos string) string {
	if goos == clientconf.OSFreeBSD {
		return "service osqueryd restart"
	}
	return "systemctl restart osqueryd"
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
	switch {
	case ext.unchanged():
		fmt.Fprintf(w, "\nNothing to change: the extension is linked, listed in %s, and the flags name that file. osqueryd loads it at its next start (%s).\n", ext.autoloadName, osqueryRestart(ext.goos))
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
	for _, f := range []struct {
		done bool
		path string
	}{{ext.linkCurrent, ext.link}, {ext.listed, ext.autoload}, {ext.flagSet, ext.flagfile}} {
		if !f.done {
			fmt.Fprintf(w, "wrote      %s\n", f.path)
		}
	}
	fmt.Fprintf(w, "\nosqueryd loads the extension at its next start: %s\n", osqueryRestart(ext.goos))
	return nil
}
