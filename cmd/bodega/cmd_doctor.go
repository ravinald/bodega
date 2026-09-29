package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// newDoctorCmd reports host-level configuration that would silently bypass
// bodega's supply-chain controls, and the server's own policy posture where
// this machine holds an install. The checks are read-only: doctor changes
// nothing it inspects and never creates the audit database it reports on.
// What a doctor run can leave behind is not a check's doing — main() writes a
// default config file, and the log directory it names, before any command runs.
// Exit code is 0 when all checks are clean (OK or N/A), 2 when at least one
// check produced a finding (WARN or FAIL), and 3 when at least one check could
// not run (SKIPPED), whether or not it also found something. 3 outranks 2
// because the two answer different questions: 2 is a measured host with gaps,
// and 3 is a host doctor did not finish measuring.
//
// The threat model and rationale for each check is documented in
// docs/threat-model.md.
func newDoctorCmd(gf *globalFlags) *cobra.Command {
	var writeCreds, writeAptSources, writePkgRepo, apply, allowPlaintext bool
	var token, baseURL, pkgABI, aptSuite string
	var configure []string
	var pkgRelease int
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect the local host and this install's policy posture for gaps in bodega's controls",
		Long: `doctor scans the machine running this command for distribution channels
and package-manager configurations that would silently fetch software from
outside bodega's allow-list. Common findings:

  - snapd or flatpak installed (opaque, auto-refreshing bundles)
  - Homebrew with auto-update enabled
  - pip / cargo / npm / apt configured to talk to public registries directly
  - GOPROXY unset or falling through to proxy.golang.org
  - on FreeBSD, a pkg repository still enabled at pkg.FreeBSD.org, or a
    make.conf that does not send distfiles through bodega

Where this machine holds a bodega install, doctor also reports the server's
own posture: an install with no allow-list rule and no publish-age or OSV
gate admits every upstream fetch, and one whose gates are all set to ignore
is configured but enforcing nothing. Those checks read the audit database
and report N/A on a client host that has none, and SKIPPED where this account
cannot read the config or the store: an unprivileged run against the root-owned
paths the service unit prescribes measures no posture at all, and says so.

Reports only: the posture checks open the audit database read-only, so a
doctor run neither creates one nor migrates the one it finds. One caveat for
a CI runner. Every bodega command bootstraps a config file on first run,
doctor included, so a host with neither /etc/bodega/config.json nor
~/.config/bodega/config.json gains the second one (the first, as root), and
the log directory that config names, before the checks execute.

Exit code is 0 when clean, 2 when one or more findings are present, and 3
when one or more checks could not run, so this command can gate CI pipelines
for build hosts that are supposed to route everything through bodega. A gate
written as "non-zero fails" needs no change; one that reads 2 specifically
now separates a host with gaps from a report with holes in it.

--write-credentials is the one thing doctor does that is not a report. It
takes a token and writes it into the file each of the eight clients reads
its credential from, so a host can be attributed on the read path without
eight hand edits. Five files serve the eight: pip, go, git and curl/wget all
read ~/.netrc. A second run rewrites bodega's own entry rather than stacking
another beside it, and nothing else in those files is touched. ~/.netrc gets
no marker comment: Python's netrc module refuses a comment that follows a
blank line, and refuses the whole file for it, so a marker there would cost
pip every credential in the file. The machine <host> stanza is the anchor.

  bodega doctor --write-credentials --token bodega_ak_... --url https://bodega.internal

The token names the host through bodega identity bind token <id> <name>. The
write changes what an audit row says, never what the host may fetch.

--configure is the other write. It applies the plan GET /client/plan returns
for this host, the same plan the served setup script applies: which files
each named system installs, where, and their SHA-256. Every file is fetched
and checked against that digest before anything is compared, and a mismatch
stops the run with nothing written. Without --apply it prints a unified diff
per file and writes nothing; with --apply it backs up each file it replaces
beside the original, suffixed .bodega-<UTC timestamp>, then writes.

  bodega doctor --configure apt,pypi --url https://bodega.internal
  bodega doctor --configure apt,pypi --url https://bodega.internal --apply

A system the plan does not list is an error naming the ones it does, and so
is a named system the plan refuses or skips, with the server's reason.

--write-apt-sources and --write-pkg-repo are --configure apt --apply and
--configure freebsd --apply. They combine with each other and with
--configure.

--token is optional: a host bound with "bodega identity bind cidr" is
identified by its address and needs none. A host bodega cannot identify is
refused with the command that would admit it.

--suite names the apt codename this host reads. An instance that mirrors
serves a codename per upstream beside the one it generates, and with no
profile to choose between them the server names none: which one a host reads
is the operator's decision. A host whose profile scopes apt is refused a
codename other than the profile's.

  bodega doctor --write-apt-sources --suite noble --url https://bodega.internal

--abi is the pkg ABI the freebsd system is configured for, "pkg config abi"
on a FreeBSD host by default. The tags the pkg override disables follow the
major release the ABI carries; --release says otherwise for a host whose
release is not the one the repository is named for.

See docs/threat-model.md for the rationale behind each check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			systems := slices.Clone(configure)
			if writeAptSources && !slices.Contains(systems, manifest.TypeApt) {
				systems = append(systems, manifest.TypeApt)
			}
			if writePkgRepo && !slices.Contains(systems, manifest.TypeFreeBSD) {
				systems = append(systems, manifest.TypeFreeBSD)
			}
			configuring := len(systems) > 0 || cmd.Flags().Changed("configure")
			if writeCreds && configuring {
				return fmt.Errorf("run one write at a time: --write-credentials places the token every client reads, " +
					"--configure (and --write-apt-sources, --write-pkg-repo) applies the plan this server holds for the host")
			}
			if writeCreds {
				return writeClientCredentials(gf, token, baseURL)
			}
			if !configuring {
				for _, f := range []string{"apply", "suite", "abi", "release"} {
					if cmd.Flags().Changed(f) {
						return fmt.Errorf("--%s applies to --configure, and that flag is not set.\n"+
							"  Add it:  bodega doctor --configure <system,...> --%s", f, f)
					}
				}
			}
			if configuring {
				return configureFromPlan(gf, planRequest{
					token: token, baseURL: baseURL, systems: systems,
					suite: aptSuite, abi: pkgABI, release: pkgRelease,
					apply: apply || writeAptSources || writePkgRepo, allowPlaintext: allowPlaintext,
				})
			}
			findings := make([]host.Finding, 0, len(host.AllChecks())+len(postureChecks))
			for _, fn := range host.AllChecks() {
				findings = append(findings, fn())
			}
			findings = append(findings, serverPostureFindings(backgroundCtx(), gf)...)
			findings = append(findings, retiredConfigKeys(gf), pepperPosture())

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CHECK\tSTATUS\tDETAIL")
			actionable, skipped := 0, 0
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\n", f.Check, f.Status, f.Detail)
				switch {
				case f.IsFinding():
					actionable++
				case f.IsSkipped():
					skipped++
				}
			}
			_ = w.Flush()

			if actionable > 0 {
				printRemediation("Remediation:", findings, host.Finding.IsFinding)
			}
			if skipped > 0 {
				printRemediation("Could not run:", findings, host.Finding.IsSkipped)
			}
			if code := doctorSummary(os.Stdout, actionable, skipped); code != 0 {
				os.Exit(code) //nolint:revive // CI-gating exit codes distinct from cobra's 1
			}
			return nil
		},
	}
	c.Flags().BoolVar(&writeCreds, "write-credentials", false,
		"Write a read-path credential into each client's own configuration file")
	c.Flags().StringSliceVar(&configure, "configure", nil,
		"Apply this server's plan for the named systems (comma-separated); prints a diff and writes nothing without --apply")
	c.Flags().BoolVar(&apply, "apply", false,
		"With --configure: back up each file that differs, then write it")
	c.Flags().BoolVar(&writeAptSources, "write-apt-sources", false,
		"Alias for --configure apt --apply")
	c.Flags().BoolVar(&writePkgRepo, "write-pkg-repo", false,
		"Alias for --configure freebsd --apply")
	c.Flags().StringVar(&aptSuite, "suite", "",
		"The apt codename to configure, for an instance serving several and no profile to choose between them")
	c.Flags().StringVar(&pkgABI, "abi", "",
		"The pkg ABI to configure for; defaults to what `pkg config abi` reports on this host")
	c.Flags().IntVar(&pkgRelease, "release", 0,
		"FreeBSD major release whose repository tags the override disables; defaults to the one the ABI names")
	c.Flags().StringVar(&token, "token", "",
		"The token to write (bodega token generate <label>)")
	c.Flags().StringVar(&baseURL, "url", "",
		"Base URL clients reach this bodega at; defaults to public_url from the config file")
	c.Flags().BoolVar(&allowPlaintext, "allow-plaintext", false,
		"Permit --url over http; refused by default because a bearer token would travel in the clear")
	return c
}

// printRemediation prints one block of next steps, one line per row the
// predicate keeps. Findings and skipped checks get separate blocks because
// they ask for different things: a finding is a host to change, a skipped
// check is a run to repeat with what it needed.
func printRemediation(heading string, findings []host.Finding, keep func(host.Finding) bool) {
	// Grouped by the step rather than by the check: the posture rows share one
	// reason and one remedy, so a line each would repeat "re-run as root" four
	// times and bury the row that is genuinely its own.
	var order []string
	checks := map[string][]string{}
	for _, f := range findings {
		if !keep(f) || f.Remediation == "" {
			continue
		}
		if _, seen := checks[f.Remediation]; !seen {
			order = append(order, f.Remediation)
		}
		checks[f.Remediation] = append(checks[f.Remediation], f.Check)
	}
	if len(order) == 0 {
		return
	}
	fmt.Println()
	fmt.Println(heading)
	for _, remedy := range order {
		fmt.Printf("  [%s] %s\n", strings.Join(checks[remedy], ", "), remedy)
	}
}

// doctorSummary writes the closing lines and returns the exit code.
//
// A skipped check outranks a finding, and gets a code of its own. Exit 2 is
// what a CI gate reads as "doctor measured this host and it has gaps", and a
// run that could not read the config measured nothing: answering with 2 would
// make "fix these three and we are clean" a false statement, because the
// checks that never ran can hold any number of gaps. 3 is additive for a gate
// written as "non-zero fails", and separable for one that distinguishes.
func doctorSummary(w io.Writer, actionable, skipped int) int {
	fmt.Fprintln(w)
	switch {
	case skipped > 0 && actionable > 0:
		fmt.Fprintf(w, "%d finding(s) on what was measured, and %d check(s) that could not run and measured nothing.\n", actionable, skipped)
	case skipped > 0:
		fmt.Fprintf(w, "No finding on what was measured, and %d check(s) that could not run and measured nothing.\n", skipped)
	case actionable > 0:
		fmt.Fprintf(w, "%d finding(s) — host is not fully aligned with bodega's threat model.\n", actionable)
	default:
		fmt.Fprintln(w, "OK: host configuration aligns with bodega's threat model.")
		return 0
	}
	if skipped > 0 {
		fmt.Fprintln(w, "The host cannot be called aligned with bodega's threat model on a partial read.")
	}
	fmt.Fprintln(w, "See docs/threat-model.md for context.")
	if skipped > 0 {
		return 3
	}
	return 2
}

// writeClientCredentials lands one token in every file the eight clients read
// their credential from, and prints what it did per client.
//
// It reports rather than aborting on the first failure: /etc/apt/auth.conf.d
// needs root and the other seven do not, so a run as a normal user should
// configure seven clients and name the one it could not.
func writeClientCredentials(gf *globalFlags, token, baseURL string) error {
	if token == "" {
		return fmt.Errorf("--write-credentials needs a --token to write.\n" +
			"  Mint one:  bodega token generate <label>\n" +
			"  Name the host it belongs to:  bodega identity bind token <id> <name>")
	}
	if baseURL == "" {
		cfg, err := loadConfig(gf)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		baseURL = cfg.PublicURL
	}
	if baseURL == "" {
		return fmt.Errorf("--write-credentials needs the base URL clients reach this bodega at.\n" +
			"  Pass --url https://bodega.internal, or set public_url in the config file")
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" {
		return fmt.Errorf("%q is not a URL with a host: pass --url https://bodega.internal", baseURL)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}

	printCredentialPrecondition()

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CLIENT\tSTATUS\tFILE\tNOTE")
	failed := 0
	for _, t := range host.CredentialTargets(home) {
		status, note := "written", t.Note
		changed, err := host.WriteCredential(t, base, token)
		switch {
		case err != nil:
			status, note = "FAILED", err.Error()
			failed++
		case !changed:
			// Four clients share ~/.netrc, so three of them find the entry
			// the first already wrote. Unchanged is the answer, not a failure.
			status = "current"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Client, status, t.Path, note)
	}
	_ = w.Flush()

	if failed > 0 {
		fmt.Printf("\n%d of %d clients could not be written. /etc/apt/auth.conf.d needs root; the rest do not.\n",
			failed, len(host.CredentialTargets(home)))
		os.Exit(2) //nolint:revive // same CI-gating exit code the checks use
	}
	fmt.Println()
	fmt.Println("Credential written. bodega attributes a request carrying it to whatever")
	fmt.Println("bodega identity bind token <id> <name> named, and serves it either way.")
	return nil
}

// printCredentialPrecondition states what the token being written can do
// beyond the read path, before the write rather than after it.
//
// api_tokens rows carry no scope, so the mutation gate accepts any unexpired
// one of them as its credential half. Read-path attribution is the reason this
// command exists, but the token it distributes is the same credential, and a
// client host inside admin_permit_cidr gains write access the moment it holds
// one. Nothing in the read path grants that; the absence of scopes does.
func printCredentialPrecondition() {
	fmt.Println("Before writing: bodega tokens carry no scope, so this same token is the")
	fmt.Println("credential half of the mutation gate. A host that holds it and whose address")
	fmt.Println("is inside admin_permit_cidr can POST and DELETE against this bodega.")
	fmt.Println("  Keep admin_permit_cidr at loopback (bodega acl admin list), or treat every")
	fmt.Println("  host you write a credential to as admin-capable.")
	fmt.Println()
}

// planRequest is what `doctor --configure` asks the server for.
type planRequest struct {
	token, baseURL string
	systems        []string
	suite, abi     string
	release        int
	apply          bool
	allowPlaintext bool
}

// configureFromPlan applies the plan GET /client/plan returns for this host,
// through internal/clientconf, the same way the served setup script does:
// every file fetched and checked against the plan's digest first, then a
// diff per file, then under apply a backup and a write.
//
// The codename goes to the server only when --suite names one. The script
// states VERSION_CODENAME because it has nothing else to go on; this command
// has always let the server choose when it could, and a host on an instance
// that generates one suite under its own name would lose that choice.
func configureFromPlan(gf *globalFlags, req planRequest) error {
	if req.baseURL == "" {
		cfg, err := loadConfig(gf)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		req.baseURL = cfg.PublicURL
	}
	if req.baseURL == "" {
		return fmt.Errorf("--configure needs the base URL clients reach this bodega at.\n" +
			"  Pass --url https://bodega.internal, or set public_url in the config file")
	}
	client, err := NewClient(req.baseURL, req.token, req.allowPlaintext)
	if err != nil {
		return err
	}
	q := url.Values{"os": {runtime.GOOS}}
	if req.abi == "" && runtime.GOOS == clientconf.OSFreeBSD {
		abi, err := localPkgABI()
		if err != nil && slices.Contains(req.systems, manifest.TypeFreeBSD) {
			return err
		}
		req.abi = abi
	}
	if req.abi != "" {
		q.Set("abi", req.abi)
	}
	if req.suite != "" {
		q.Set("codename", req.suite)
	}
	if req.release > 0 {
		q.Set("release", strconv.Itoa(req.release))
	}
	var plan clientconf.Plan
	if err := getJSON(client, "/client/plan?"+q.Encode(), &plan); err != nil {
		return err
	}
	records, err := plan.Select(req.systems)
	if err != nil {
		return err
	}
	if len(plan.Records) > 0 {
		r := plan.Records[0]
		fmt.Printf("Plan for %s (profile %s, matched by %s) from %s\n\n", r.Identity, r.Profile, r.Match, client.BaseURL)
	}
	home, _ := os.UserHomeDir()
	var changes []clientconf.Change
	for _, rec := range records {
		body, err := getPlanFile(client, rec.URL, req.allowPlaintext)
		if err != nil {
			return fmt.Errorf("%s: %w", rec.System, err)
		}
		c, err := clientconf.NewChange(rec, body, home)
		if err != nil {
			return err
		}
		changes = append(changes, c)
	}
	changed := 0
	for _, c := range changes {
		if c.Unchanged() {
			fmt.Printf("unchanged  %-10s %s\n", c.Record.System, c.Target)
			continue
		}
		d, err := c.Diff()
		if err != nil {
			return err
		}
		fmt.Printf("\n%s", d)
		changed++
	}
	switch {
	case changed == 0:
		fmt.Println("\nNothing to change: every file already matches the plan.")
		return nil
	case !req.apply:
		fmt.Printf("\nDry run: nothing was written. Re-run with --apply to back up and write the %d file(s) above.\n", changed)
		return nil
	}
	applied, err := clientconf.Apply(changes, clientconf.BackupSuffix(time.Now()))
	for _, a := range applied {
		if a.Backup != "" {
			fmt.Printf("backed up  %s -> %s\n", a.Target, a.Backup)
		}
		fmt.Printf("wrote      %s\n", a.Target)
	}
	if err != nil {
		return err
	}
	for _, c := range changes {
		switch {
		case c.Unchanged():
		case c.Record.System == manifest.TypeApt && c.Target == clientconf.AptSourcesPath:
			fmt.Println("\nApply it:  apt-get update")
		case c.Record.System == manifest.TypeFreeBSD:
			fmt.Println("\nApply it:  pkg update")
			fmt.Println("Confirm the upstream repository is off:  pkg -vv | grep -A2 -E '^  (FreeBSD|bodega)'")
		}
	}
	return nil
}

// getPlanFile fetches one URL a plan names. The URL carries the server's
// public_url, which need not be the --url this command was given, so the
// plain-http rule is applied to it again rather than inherited.
func getPlanFile(c *Client, raw string, allowPlaintext bool) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("the plan names %q, which is not a URL with a host; refusing to fetch it", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowPlaintext:
	case u.Scheme == "http":
		return nil, fmt.Errorf("the plan names %s, which is plain http, and --allow-plaintext is not set.\n"+
			"  Set public_url on the server to https, or pass --allow-plaintext on a link you trust", raw)
	default:
		return nil, fmt.Errorf("the plan names %s, which is not an http or https URL; refusing to fetch it", raw)
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", raw, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", raw, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s\n%s", raw, resp.Status, serverError(body))
	}
	return body, nil
}

// localPkgABI asks pkg what ABI this host is, which is the only authority on
// it: the ABI string carries the release and the architecture as pkg spells
// them, and a value composed from runtime.GOARCH is wrong on every host where
// those two spellings differ.
func localPkgABI() (string, error) {
	out, err := exec.Command("pkg", "config", "abi").Output()
	if err != nil {
		return "", fmt.Errorf("--configure freebsd needs the ABI to configure for, and `pkg config abi` did not answer on this host (%v).\n"+
			"  Pass it:  --abi FreeBSD:14:amd64", err)
	}
	abi := strings.TrimSpace(string(out))
	if abi == "" {
		return "", fmt.Errorf("`pkg config abi` returned nothing on this host.\n" +
			"  Pass it:  --abi FreeBSD:14:amd64")
	}
	return abi, nil
}

// getJSON reads one JSON document off the read API, treating any non-200 as
// the failure it is: a caller here is asking a question with one right answer.
func getJSON(c *Client, path string, out any) error {
	body, err := getBody(c, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func getBody(c *Client, path string) ([]byte, error) {
	resp, err := c.Get(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s\n%s", path, resp.Status, serverError(body))
	}
	return body, nil
}

// retiredKeyReaders names the config keys nothing reads any more, and what to
// do about each. Save preserves a key it did not parse, so a retired key
// survives every write and goes on looking like a setting in force — which is
// B11's reason for reporting tls_autocert at the server, and the same reason
// this row exists for an operator who never starts one.
var retiredKeyReaders = []struct {
	key    string
	reason string
}{
	{"tls_autocert", "bodega has no ACME client; set tls_cert and tls_key, or terminate TLS in front and set allow_plaintext"},
	{"tls_domain", "bodega has no ACME client; set tls_cert and tls_key, or terminate TLS in front and set allow_plaintext"},
	{"custom_paths", "the per-type roots are always honored, so this gated nothing; delete the key and keep or clear the roots themselves"},
}

// retiredConfigKeys reports keys the file still carries that nothing reads. A
// key held at its zero value says nothing was asked for and is not reported:
// "custom_paths": false and an absent custom_paths describe the same install.
func retiredConfigKeys(gf *globalFlags) host.Finding {
	f := host.Finding{Check: "retired-config-keys", Status: host.StatusOK}

	cfg, err := loadConfig(gf)
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = "could not read the config file: " + err.Error()
		f.Remediation = skipRemedy(config.ConfigPath(), err)
		return f
	}

	var found []string
	for _, k := range retiredKeyReaders {
		raw, ok := cfg.RawFileValue(k.key)
		if !ok || isZeroJSON(raw) {
			continue
		}
		found = append(found, k.key+" ("+k.reason+")")
	}
	if len(found) == 0 {
		f.Detail = "the config file carries no key that nothing reads"
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = "retired keys still in " + config.ConfigPath() + ": " + strings.Join(found, "; ")
	f.Remediation = "delete them; they are preserved on every save and read by nothing"
	return f
}

// pepperPosture reports a pepper the account the server runs as cannot read.
//
// doctor normally runs as root, which reads every file on the box, so the
// question is not whether this process can open it. The account comes from the
// systemd unit's User= (or BODEGA_SERVICE_USER), and the test is that
// account's uid and group memberships against the pepper's mode and every
// directory above it.
func pepperPosture() host.Finding {
	st, resErr := audit.ResolvePepper(audit.DefaultPepperPaths)
	id, err := audit.ResolveServiceIdentity()
	return pepperFinding(st, resErr, id, err)
}

func pepperFinding(st audit.PepperState, resErr error, id audit.ServiceIdentity, idErr error) host.Finding {
	f := host.Finding{Check: "pepper", Status: host.StatusOK}
	if st.Path == "" {
		f.Status = host.StatusNA
		f.Detail = "no pepper on this host; the first `bodega token generate` writes one"
		return f
	}
	// A path that will not open for this process is reported ahead of the
	// account checks below, which would answer a permission question about a
	// file whose problem is not permission. Absent this branch a symlink cycle
	// read as "no pepper on this host" while the server refused every token.
	var unreadable *audit.PepperUnreadableError
	if errors.As(resErr, &unreadable) && !errors.Is(resErr, fs.ErrPermission) {
		f.Status = host.StatusFail
		f.Detail = fmt.Sprintf("%s is the pepper in force and cannot be read: %v; every token minted on this "+
			"host is answered with \"invalid token\", which names the credential rather than this file",
			st.Path, unreadable.Err)
		f.Remediation = "repair or remove " + st.Path + ", then mint again with `sudo bodega token generate`"
		return f
	}
	switch {
	case errors.Is(idErr, audit.ErrNoServiceAccount):
		f.Status = host.StatusNA
		f.Detail = st.Path + " is in force, and this host names no service account (no systemd unit with " +
			"User=, no " + audit.ServiceUserEnv + "): whoever writes the pepper is whoever reads it"
		return f
	case idErr != nil:
		f.Status = host.StatusFail
		f.Detail = "cannot tell which account serves " + st.Path + ": " + idErr.Error()
		f.Remediation = "create the account the unit names, or set " + audit.ServiceUserEnv
		return f
	}

	ok, blocker, err := id.CanRead(st.Path)
	switch {
	case ok:
		f.Detail = fmt.Sprintf("%s is readable by %q, the account %s runs the server as", st.Path, id.Name, id.Source)
		return f
	case err != nil:
		f.Status = host.StatusWarn
		f.Detail = "could not inspect " + blocker + ": " + err.Error()
		f.Remediation = "check the pepper exists and this account can stat it"
		return f
	}

	f.Status = host.StatusFail
	f.Detail = fmt.Sprintf("%s refuses %q, the account %s runs the server as: every token minted on this host "+
		"is answered with \"invalid token\", which names the credential rather than this file",
		blocker, id.Name, id.Source)
	f.Remediation = audit.PepperRemedy("sudo ", blocker, id.Group)
	return f
}

// isZeroJSON reports whether a raw value is the zero of its own shape, which
// is how a key that was written and never meant reads.
func isZeroJSON(raw json.RawMessage) bool {
	switch v := strings.TrimSpace(string(raw)); v {
	case "", "false", "0", `""`, "null", "[]", "{}":
		return true
	}
	return false
}

// postureChecks names the server-posture rows in the order doctor prints them.
// The set is fixed so the table has the same shape on a host with an install
// and one without, which is what lets a pipeline diff the output.
var postureChecks = []string{"policy-coverage", "policy-ignored", "policy-ecosystem"}

// postureStore is the read surface the posture checks need. An interface so
// they can be driven against a store built by hand, without a config file or
// a serving instance in the way.
type postureStore interface {
	ListPolicies(ctx context.Context) ([]audit.PolicyInfo, error)
	ListAgePolicies(ctx context.Context) ([]audit.AgePolicy, error)
	ListOSVPolicies(ctx context.Context) ([]audit.OSVPolicy, error)
}

// serverPostureFindings resolves this machine's install and reports on it,
// or marks every posture check N/A with the reason there is nothing to read.
func serverPostureFindings(ctx context.Context, gf *globalFlags) []host.Finding {
	cfg, err := loadConfig(gf)
	if err != nil {
		return postureSkipped("config unreadable: "+err.Error(), skipRemedy(config.ConfigPath(), err))
	}
	path := auditDBPath(cfg)
	if path == "" {
		return postureUnavailable("no audit database configured (audit_db and log_dir are both empty)")
	}
	// Stat before open: opening creates the file and seeds a fresh install's
	// default policy, and a report is not an installation.
	if _, err := os.Stat(path); err != nil {
		// Absent is a measurement: this is a client host and there is no
		// posture to read. Anything else is a path this process could not
		// resolve, and "no bodega install" would be a claim about a server
		// nobody looked at.
		if !errors.Is(err, fs.ErrNotExist) {
			return postureSkipped("could not stat the audit store at "+path+": "+err.Error(), skipRemedy(path, err))
		}
		return postureUnavailable("no bodega install on this host (" + path + " does not exist)")
	}
	// Read-only for the same reason. The read-write opener migrates whatever
	// it finds, so a doctor run against an install that predates migration 012
	// would claim the seed marker on an operator who only asked what their
	// posture was.
	db, err := audit.OpenReadOnly(path)
	if err != nil {
		return postureSkipped("could not read audit store at "+path+": "+err.Error(), skipRemedy(path, err))
	}
	defer db.Close()
	return serverPosture(ctx, db)
}

// postureUnavailable marks the posture rows N/A: this host holds nothing to
// measure, which is the answer rather than the absence of one.
func postureUnavailable(detail string) []host.Finding {
	return postureRows(host.StatusNA, detail, "")
}

// postureSkipped marks the posture rows as never run. The remediation travels
// with them because the reader's next step is a privilege, not a policy.
func postureSkipped(detail, remediation string) []host.Finding {
	return postureRows(host.StatusSkip, detail, remediation)
}

func postureRows(status host.Status, detail, remediation string) []host.Finding {
	out := make([]host.Finding, 0, len(postureChecks))
	for _, name := range postureChecks {
		out = append(out, host.Finding{Check: name, Status: status, Detail: detail, Remediation: remediation})
	}
	return out
}

// skipRemedy names what a check needs before it can run again. doctor reads
// and changes nothing, so a path it cannot open is answered by the privilege
// that opens it: /etc/bodega/config.json and /var/lib/bodega are root-owned on
// the host the service unit prescribes, and the unprivileged run that meets
// them has no host defect to fix.
func skipRemedy(path string, err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "re-run as root (`sudo bodega doctor`); " + path + " is readable only by the account that owns it"
	}
	return "make " + path + " readable by this account, then re-run `bodega doctor`"
}

// serverPosture reports what this install actually enforces. The three checks
// are the three ways an install ends up enforcing nothing: never configured,
// configured and then silenced, and configured against an ecosystem the gate
// cannot evaluate.
func serverPosture(ctx context.Context, store postureStore) []host.Finding {
	rules, err := store.ListPolicies(ctx)
	if err != nil {
		return postureSkipped("read allow-list: "+err.Error(), "repair the audit store, then re-run `bodega doctor`")
	}
	ages, err := store.ListAgePolicies(ctx)
	if err != nil {
		return postureSkipped("read age policy: "+err.Error(), "repair the audit store, then re-run `bodega doctor`")
	}
	osvs, err := store.ListOSVPolicies(ctx)
	if err != nil {
		return postureSkipped("read osv policy: "+err.Error(), "repair the audit store, then re-run `bodega doctor`")
	}
	return []host.Finding{
		policyCoverage(rules, ages, osvs),
		policyIgnored(ages, osvs),
		policyEcosystem(ages, osvs),
	}
}

// gateRow is a policy table flattened to what the posture checks read. Both
// tables answer the same two questions and neither check should care which
// one it is looking at.
type gateRow struct{ ecosystem, action string }

func ageRows(ages []audit.AgePolicy) []gateRow {
	out := make([]gateRow, 0, len(ages))
	for _, p := range ages {
		out = append(out, gateRow{p.Ecosystem, p.Action})
	}
	return out
}

func osvRows(osvs []audit.OSVPolicy) []gateRow {
	out := make([]gateRow, 0, len(osvs))
	for _, p := range osvs {
		out = append(out, gateRow{p.Ecosystem, p.Action})
	}
	return out
}

// enforcing keeps the rows that can change an admission decision. A row for an
// ecosystem outside covered is read by nothing, and counting it as enforcement
// is how an install with one dead row masks the fact that every live gate is
// off. That row has its own check, policy-ecosystem.
func enforcing(rows []gateRow, covered []string) []gateRow {
	out := make([]gateRow, 0, len(rows))
	for _, r := range rows {
		if slices.Contains(covered, r.ecosystem) {
			out = append(out, r)
		}
	}
	return out
}

// policyCoverage is the zero-policy install: a caching proxy with an audit
// trail. Every upstream fetch is admitted, and nothing in the request path
// would have refused the compromised release the audit trail then records.
// It reads every gate admit.checkVersions runs, age and OSV both: an install
// carrying one of them refuses fetches, so reporting it as wide open is a
// false statement the operator can disprove from their own logs.
func policyCoverage(rules []audit.PolicyInfo, ages []audit.AgePolicy, osvs []audit.OSVPolicy) host.Finding {
	f := host.Finding{Check: "policy-coverage", Status: host.StatusOK}
	aged := enforcing(ageRows(ages), policy.AgeEcosystems())
	scanned := enforcing(osvRows(osvs), policy.OSVEcosystems())
	gates := slices.Concat(aged, scanned)
	if len(rules) > 0 || len(gates) > 0 {
		f.Detail = fmt.Sprintf("%d allow-list rule(s), %d ecosystem(s) with a publish-age gate, %d with an OSV gate",
			len(rules), len(aged), len(scanned))
		// This check asks whether anybody ever configured a policy; whether it
		// runs is policy-ignored's question. Counting a silenced row as a gate
		// is the right answer to the first question and a false statement on
		// its own, so the count that matters at 03:00 goes on the same line.
		if inForce := len(gates) - ignoredCount(gates); inForce < len(gates) {
			f.Detail += fmt.Sprintf(" (%d in force; see policy-ignored)", inForce)
		}
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = "no allow-list rule and no publish-age or OSV gate: every upstream fetch is admitted"
	f.Remediation = "bodega policy add npm <package> to constrain what may be fetched; " +
		"bodega policy age set npm 7d warn for a publish-age cooldown"
	return f
}

func ignoredCount(rows []gateRow) int {
	n := 0
	for _, r := range rows {
		if r.action == policy.ActionIgnore {
			n++
		}
	}
	return n
}

// policyIgnored is the install that had a gate and lost it. Silencing one
// ecosystem during an incident is routine; leaving every ecosystem on ignore
// is a gate that reports as configured and has never run since.
func policyIgnored(ages []audit.AgePolicy, osvs []audit.OSVPolicy) host.Finding {
	f := host.Finding{Check: "policy-ignored", Status: host.StatusOK}
	var silenced, fixes []string
	if ecos := silencedEcosystems(ageRows(ages), policy.AgeEcosystems()); len(ecos) > 0 {
		silenced = append(silenced, "age ("+strings.Join(ecos, ", ")+")")
		fixes = append(fixes, "bodega policy age set "+ecos[0]+" 7d warn")
	}
	if ecos := silencedEcosystems(osvRows(osvs), policy.OSVEcosystems()); len(ecos) > 0 {
		silenced = append(silenced, "osv ("+strings.Join(ecos, ", ")+")")
		fixes = append(fixes, "bodega policy osv set "+ecos[0]+" warn")
	}
	if len(silenced) == 0 {
		f.Detail = "no gate is set to ignore on every ecosystem it covers"
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = strings.Join(silenced, ", ") + " set to ignore on every ecosystem: configured, enforcing nothing"
	f.Remediation = "restore an action on the silenced gate: " + strings.Join(fixes, "; ")
	return f
}

// silencedEcosystems names the rows a gate can read when every one of them is
// on ignore, and nothing when any of them still enforces or when the gate has
// no readable row at all.
func silencedEcosystems(rows []gateRow, covered []string) []string {
	live := enforcing(rows, covered)
	ecos := make([]string, 0, len(live))
	for _, r := range live {
		if r.action != policy.ActionIgnore {
			return nil
		}
		ecos = append(ecos, r.ecosystem)
	}
	return ecos
}

// policyEcosystem is the row the gate cannot read. `policy set` refuses one
// now, but a row written before that refusal survives and both `policy list`
// and this install's own inventory report it as an active gate.
func policyEcosystem(ages []audit.AgePolicy, osvs []audit.OSVPolicy) host.Finding {
	f := host.Finding{Check: "policy-ecosystem", Status: host.StatusOK}
	var stale, fixes []string
	for _, p := range ages {
		if !slices.Contains(policy.AgeEcosystems(), p.Ecosystem) {
			stale = append(stale, "age "+p.Ecosystem)
			fixes = append(fixes, "bodega policy age remove "+p.Ecosystem)
		}
	}
	for _, p := range osvs {
		if !slices.Contains(policy.OSVEcosystems(), p.Ecosystem) {
			stale = append(stale, "osv "+p.Ecosystem)
			fixes = append(fixes, "bodega policy osv remove "+p.Ecosystem)
		}
	}
	if len(stale) == 0 {
		f.Detail = "every stored policy row names an ecosystem its gate can evaluate"
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = "stored policy rows no gate can evaluate: " + strings.Join(stale, ", ") + "; listed as active, never enforced"
	f.Remediation = strings.Join(fixes, "; ")
	return f
}
