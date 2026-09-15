package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/policy"
)

// newDoctorCmd reports host-level configuration that would silently bypass
// bodega's supply-chain controls, and the server's own policy posture where
// this machine holds an install. The checks are read-only: doctor changes
// nothing it inspects and never creates the audit database it reports on.
// What a doctor run can leave behind is not a check's doing — main() writes a
// default config file, and the log directory it names, before any command runs.
// Exit code is 0 when all checks are clean (OK or N/A) and 2 when at least
// one check produced a finding (WARN or FAIL); this matches the convention
// used by other CI-gating linters.
//
// The threat model and rationale for each check is documented in
// docs/THREAT_MODEL.md.
func newDoctorCmd(gf *globalFlags) *cobra.Command {
	var writeCreds, writeAptSources, allowPlaintext bool
	var token, baseURL string
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

Where this machine holds a bodega install, doctor also reports the server's
own posture: an install with no allow-list rule and no publish-age or OSV
gate admits every upstream fetch, and one whose gates are all set to ignore
is configured but enforcing nothing. Those checks read the audit database
and report N/A on a client host that has none.

Reports only: the posture checks open the audit database read-only, so a
doctor run neither creates one nor migrates the one it finds. One caveat for
a CI runner. Every bodega command bootstraps a config file on first run,
doctor included, so a host with neither /etc/bodega/config.json nor
~/.config/bodega/config.json gains the second one (the first, as root), and
the log directory that config names, before the checks execute.

Exit code is 0 when clean and 2 when one or more findings are present, so
this command can gate CI pipelines for build hosts that are supposed to
route everything through bodega.

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

--write-apt-sources is the other write, and it is the one place a host's apt
configuration is composed from what the server knows rather than guessed at.
It asks bodega which suite this host reads — a profile that scopes apt is
served a filtered codename of its own — then installs the archive keyring and
writes that stanza to /etc/apt/sources.list.d/bodega.sources.

  bodega doctor --write-apt-sources --token bodega_ak_... --url https://bodega.internal

--token is optional: a host bound with "bodega identity bind cidr" is
identified by its address and needs none. A host bodega cannot identify gets
told which codenames exist rather than handed one.

Signed-By: goes on the line and names the keyring this command just installed.
The alternative is [trusted=yes], which turns signature verification off for
the source permanently and would discard the reason the filtered index is
signed at all. Both files need root, and the stanza scopes what a correctly
configured host sees: a host that edits it back reaches the unfiltered
codename, which is why the request predicate still runs at the pool.

See docs/THREAT_MODEL.md for the rationale behind each check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if writeCreds && writeAptSources {
				return fmt.Errorf("run one write at a time: --write-credentials places the token every client reads, " +
					"--write-apt-sources asks the server which suite this host reads and installs it")
			}
			if writeCreds {
				return writeClientCredentials(gf, token, baseURL)
			}
			if writeAptSources {
				return writeAptSourcesFile(gf, token, baseURL, allowPlaintext)
			}
			findings := make([]host.Finding, 0, len(host.AllChecks())+len(postureChecks))
			for _, fn := range host.AllChecks() {
				findings = append(findings, fn())
			}
			findings = append(findings, serverPostureFindings(backgroundCtx(), gf)...)
			findings = append(findings, retiredConfigKeys(gf), pepperPosture())

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CHECK\tSTATUS\tDETAIL")
			actionable := 0
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\n", f.Check, f.Status, f.Detail)
				if f.IsFinding() {
					actionable++
				}
			}
			_ = w.Flush()

			if actionable > 0 {
				fmt.Println()
				fmt.Println("Remediation:")
				for _, f := range findings {
					if !f.IsFinding() || f.Remediation == "" {
						continue
					}
					fmt.Printf("  [%s] %s\n", f.Check, f.Remediation)
				}
				fmt.Printf("\n%d finding(s) — host is not fully aligned with bodega's threat model.\n", actionable)
				fmt.Println("See docs/THREAT_MODEL.md for context.")
				os.Exit(2) //nolint:revive // CI-gating exit code distinct from cobra's 1
			}

			fmt.Println()
			fmt.Println("OK: host configuration aligns with bodega's threat model.")
			return nil
		},
	}
	c.Flags().BoolVar(&writeCreds, "write-credentials", false,
		"Write a read-path credential into each client's own configuration file")
	c.Flags().BoolVar(&writeAptSources, "write-apt-sources", false,
		"Install the archive keyring and the apt sources stanza this server says the host should read")
	c.Flags().StringVar(&token, "token", "",
		"The token to write (bodega token generate <label>)")
	c.Flags().StringVar(&baseURL, "url", "",
		"Base URL clients reach this bodega at; defaults to public_url from the config file")
	c.Flags().BoolVar(&allowPlaintext, "allow-plaintext", false,
		"Permit --url over http; refused by default because a bearer token would travel in the clear")
	return c
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

// aptClientConfig is the half of GET /api/v1/status this command reads. The
// server composes the stanza and this decodes it: which codename a host reads
// is a fact only the running instance holds, and every emitter that derived
// one for itself derived it wrong. internal/aptsources carries that history.
type aptClientConfig struct {
	Apt aptClientStatus `json:"apt"`
}

type aptClientStatus struct {
	Signed     bool                 `json:"signed"`
	KeyringURL string               `json:"keyring_url"`
	Suites     []string             `json:"suites"`
	Mirrored   []string             `json:"mirrored"`
	Filtered   []string             `json:"filtered"`
	Profile    string               `json:"profile"`
	Host       *aptsources.Sources  `json:"host"`
	Sources    []aptsources.Sources `json:"sources"`
}

// writeAptSourcesFile installs what the server says this host's apt
// configuration is: the keyring first, then the stanza that names it.
//
// --token is optional here and is not an oversight. The server answers with
// whatever host this request resolves to, and a host bound by `bodega identity
// bind cidr` sends no header at all — demanding a token would make one of the
// two identification modes unusable from the command that configures it. What
// a host with neither gets is the fleet-wide answer, which aptNoStanza names
// rather than installs.
func writeAptSourcesFile(gf *globalFlags, token, baseURL string, allowPlaintext bool) error {
	if baseURL == "" {
		cfg, err := loadConfig(gf)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		baseURL = cfg.PublicURL
	}
	if baseURL == "" {
		return fmt.Errorf("--write-apt-sources needs the base URL clients reach this bodega at.\n" +
			"  Pass --url https://bodega.internal, or set public_url in the config file")
	}
	client, err := NewClient(baseURL, token, allowPlaintext)
	if err != nil {
		return err
	}
	var status aptClientConfig
	if err := getJSON(client, "/api/v1/status", &status); err != nil {
		return err
	}
	apt := status.Apt
	if apt.Host == nil {
		return aptNoStanza(apt)
	}
	keyring, err := getBody(client, aptsources.KeyringRoute)
	if err != nil {
		return err
	}
	wrote, err := host.WriteAptSources("", aptsources.ClientKeyringPath, apt.Host.Deb822, keyring)
	for _, p := range wrote {
		fmt.Printf("wrote %s\n", p)
	}
	if err != nil {
		return err
	}
	if apt.Profile != "" {
		fmt.Printf("\nProfile %q: this host reads %s, a filtered view of what bodega mirrors.\n",
			apt.Profile, apt.Host.Suite)
		fmt.Println("The stanza scopes what this host is told exists. It authorizes nothing on")
		fmt.Println("its own: a host that edits it reaches the unfiltered codename, and the")
		fmt.Println("request predicate at /apt/pool/ is what refuses the artifacts behind it.")
	}
	fmt.Println("\nApply it:  apt-get update")
	return nil
}

// aptNoStanza explains a server that would not name one suite for this host,
// which is two different situations and two different repairs.
func aptNoStanza(apt aptClientStatus) error {
	if apt.Profile != "" {
		return fmt.Errorf("profile %q scopes apt and this server is serving no filtered codename for it yet.\n"+
			"  The base has to be a mirrored codename, and the index rebuilds on the hour:\n"+
			"  bodega profile show %s   (check APT BASE)\n"+
			"  Then look at the server's log for the base it refused", apt.Profile, apt.Profile)
	}
	served := slices.Concat(apt.Suites, apt.Mirrored, apt.Filtered)
	if len(served) == 0 {
		return fmt.Errorf("this bodega serves no apt suite, so there is no stanza to install")
	}
	return fmt.Errorf("no profile scopes apt for this host and this bodega serves %d codenames, so which one this host should read is your decision rather than the server's: %s.\n"+
		"  This host may simply not be identified. Pass --token, or bind its address:  bodega identity bind cidr <cidr> <name>\n"+
		"  Then give the profile a base:  bodega profile set <profile> apt --membership closed --base <codename>\n"+
		"  Or write the stanza by hand from:  bodega status apt",
		len(served), strings.Join(served, ", "))
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
		f.Status = host.StatusNA
		f.Detail = "could not read the config file: " + err.Error()
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

// pepperPosture reports a pepper the account running the server cannot read.
//
// doctor is normally run as root, which can read every pepper on the box, so
// this models readability from ownership rather than attempting the read.
// bodega never learns the service account's name — it lives in the unit file
// — so the reference is the config file beside the pepper: whatever systemd
// hands that file to is what runs the server, and the same rule decides the
// posture a new pepper is written with.
func pepperPosture() host.Finding {
	f := host.Finding{Check: "pepper", Status: host.StatusOK}

	st, _ := audit.ResolvePepper(audit.DefaultPepperPaths)
	if st.Path == "" {
		f.Status = host.StatusNA
		f.Detail = "no pepper on this host; the first `bodega token generate` writes one"
		return f
	}

	ref := filepath.Join(filepath.Dir(st.Path), audit.PepperConfigSibling)
	want, err := readersOf(ref)
	if err != nil {
		f.Status = host.StatusNA
		f.Detail = "no " + ref + " to compare " + st.Path + " against: " + err.Error()
		return f
	}
	got, err := readersOf(st.Path)
	if err != nil {
		f.Status = host.StatusWarn
		f.Detail = "could not inspect " + st.Path + ": " + err.Error()
		f.Remediation = "check the pepper exists and this account can stat it"
		return f
	}

	if got.covers(want) {
		f.Detail = st.Path + " is readable by the account that reads " + ref
		return f
	}

	f.Status = host.StatusFail
	f.Detail = fmt.Sprintf("%s is %s and %s is %s: the account running the server cannot read the pepper, "+
		"so every token minted here is refused with \"invalid token\"", st.Path, got, ref, want)
	f.Remediation = fmt.Sprintf("sudo chown :%d %s && sudo chmod 0640 %s", want.gid, st.Path, st.Path)
	return f
}

// fileReaders is the set of accounts a file's mode and ownership grant read to.
type fileReaders struct {
	uid, gid            uint32
	owner, group, world bool
}

func (r fileReaders) String() string {
	return fmt.Sprintf("uid %d gid %d mode %04o", r.uid, r.gid, r.perm())
}

func (r fileReaders) perm() uint32 {
	var m uint32
	for _, b := range []struct {
		set bool
		bit uint32
	}{{r.owner, 0o400}, {r.group, 0o040}, {r.world, 0o004}} {
		if b.set {
			m |= b.bit
		}
	}
	return m
}

// covers reports whether r grants read to everyone want grants it to.
//
// The two axes are kept apart because group membership is not knowable from
// a stat: a uid that reads the reference as its owner may or may not be in the
// pepper's group, and claiming it is would turn a real finding into an OK.
func (r fileReaders) covers(want fileReaders) bool {
	if r.world {
		return true
	}
	if want.owner && !(r.owner && r.uid == want.uid) {
		return false
	}
	if want.group && !(r.group && r.gid == want.gid) {
		return false
	}
	return true
}

func readersOf(path string) (fileReaders, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileReaders{}, err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileReaders{}, fmt.Errorf("%s: this platform reports no file ownership", path)
	}
	m := fi.Mode().Perm()
	return fileReaders{
		uid:   sys.Uid,
		gid:   sys.Gid,
		owner: m&0o400 != 0,
		group: m&0o040 != 0,
		world: m&0o004 != 0,
	}, nil
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
		return postureUnavailable("config unreadable: " + err.Error())
	}
	path := auditDBPath(cfg)
	if path == "" {
		return postureUnavailable("no audit database configured (audit_db and log_dir are both empty)")
	}
	// Stat before open: opening creates the file and seeds a fresh install's
	// default policy, and a report is not an installation.
	if _, err := os.Stat(path); err != nil {
		return postureUnavailable("no bodega install on this host (" + path + " does not exist)")
	}
	// Read-only for the same reason. The read-write opener migrates whatever
	// it finds, so a doctor run against an install that predates migration 012
	// would claim the seed marker on an operator who only asked what their
	// posture was.
	db, err := audit.OpenReadOnly(path)
	if err != nil {
		return postureUnavailable("could not read audit store at " + path + ": " + err.Error())
	}
	defer db.Close()
	return serverPosture(ctx, db)
}

func postureUnavailable(detail string) []host.Finding {
	out := make([]host.Finding, 0, len(postureChecks))
	for _, name := range postureChecks {
		out = append(out, host.Finding{Check: name, Status: host.StatusNA, Detail: detail})
	}
	return out
}

// serverPosture reports what this install actually enforces. The three checks
// are the three ways an install ends up enforcing nothing: never configured,
// configured and then silenced, and configured against an ecosystem the gate
// cannot evaluate.
func serverPosture(ctx context.Context, store postureStore) []host.Finding {
	rules, err := store.ListPolicies(ctx)
	if err != nil {
		return postureUnavailable("read allow-list: " + err.Error())
	}
	ages, err := store.ListAgePolicies(ctx)
	if err != nil {
		return postureUnavailable("read age policy: " + err.Error())
	}
	osvs, err := store.ListOSVPolicies(ctx)
	if err != nil {
		return postureUnavailable("read osv policy: " + err.Error())
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
