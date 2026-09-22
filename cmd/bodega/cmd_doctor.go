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
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/pkgrepos"
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
	var writeCreds, writeAptSources, writePkgRepo, allowPlaintext bool
	var token, baseURL, pkgABI, aptSuite string
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

--write-apt-sources is the other write, and it is the one place a host's apt
configuration is composed from what the server knows rather than guessed at.
It asks bodega which suite this host reads — a profile that scopes apt is
served a filtered codename of its own — then installs the archive keyring and
writes that stanza to /etc/apt/sources.list.d/bodega.sources.

  bodega doctor --write-apt-sources --token bodega_ak_... --url https://bodega.internal

--token is optional: a host bound with "bodega identity bind cidr" is
identified by its address and needs none. A host bodega cannot identify gets
told which codenames exist rather than handed one.

--suite is how that host gets configured anyway. An instance that mirrors
serves a codename per upstream beside the one it generates, so several
codenames is its ordinary state, and with no profile to choose between them
the server names none: which one a host reads is the operator's decision.
This flag is that decision, and the stanza is still the server's rendering
of it.

  bodega doctor --write-apt-sources --suite noble --url https://bodega.internal

A mirrored codename installs the sources file alone. bodega does not sign
what it proxies, so the archive's own signature reaches the client intact and
apt verifies it against the distro keyring already on the host; a Signed-By:
naming bodega's key there would fail every apt update on the signature. A
host whose profile scopes apt is refused instead of served: that codename is
the profile's answer, and the unfiltered base is in the same list.

--write-pkg-repo is the FreeBSD half. It asks bodega which pkg repositories
answer for this host's ABI and writes ` + pkgrepos.ClientConfPath + `,
which holds two things and not one: the bodega repository, and the overrides
that disable the repository /etc/pkg/FreeBSD.conf defines. pkg merges
definitions by tag, so a file carrying only the first leaves the host
fetching from pkg.FreeBSD.org beside bodega and nothing in "pkg update"
output says so.

  bodega doctor --write-pkg-repo --url https://bodega.internal

The ABI comes from "pkg config abi" on a FreeBSD host, or from --abi
anywhere else. The tags the override names follow the major release the ABI
carries; --release says otherwise for a host whose release is not the one
the repository is named for. signature_type is the server's answer rather
than a flag, and there are three of them: a mirror of a ports repository
verifies against the stock trust store, a mirror of a base_release_<n> one
built for FreeBSD 15 or later against the pkgbase store beside it (no older
release ships that store, so its base_release_<n> repositories verify against
the stock one), and a generated repository against bodega's own fingerprint. Naming bodega's key for a mirror fails "pkg
update" on the signature; naming the wrong one of FreeBSD's two fails
nothing at all, and the repository installs empty.

Signed-By: goes on the line and names the keyring this command just installed.
The alternative is [trusted=yes], which turns signature verification off for
the source permanently and would discard the reason the filtered index is
signed at all. Both files need root, and the stanza scopes what a correctly
configured host sees: a host that edits it back reaches the unfiltered
codename, which is why the request predicate still runs at the pool.

See docs/threat-model.md for the rationale behind each check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			writes := 0
			for _, on := range []bool{writeCreds, writeAptSources, writePkgRepo} {
				if on {
					writes++
				}
			}
			if writes > 1 {
				return fmt.Errorf("run one write at a time: --write-credentials places the token every client reads, " +
					"--write-apt-sources asks the server which suite this host reads and installs it, " +
					"--write-pkg-repo asks it which pkg repository this ABI reads and installs that")
			}
			if writeCreds {
				return writeClientCredentials(gf, token, baseURL)
			}
			if aptSuite != "" && !writeAptSources {
				return fmt.Errorf("--suite names the codename --write-apt-sources installs, and that flag is not set.\n"+
					"  Add it:  bodega doctor --write-apt-sources --suite %s", aptSuite)
			}
			if writeAptSources {
				return writeAptSourcesFile(gf, token, baseURL, aptSuite, allowPlaintext)
			}
			if writePkgRepo {
				return writePkgRepoFile(gf, token, baseURL, pkgABI, pkgRelease, allowPlaintext)
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
	c.Flags().BoolVar(&writeAptSources, "write-apt-sources", false,
		"Install the archive keyring and the apt sources stanza this server says the host should read")
	c.Flags().BoolVar(&writePkgRepo, "write-pkg-repo", false,
		"Install the pkg repository configuration this server says the host's ABI should read, and disable the upstream one")
	c.Flags().StringVar(&aptSuite, "suite", "",
		"The apt codename to install, for an instance serving several and no profile to choose between them")
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
//
// suite is the operator answering the question the server refuses to: an
// instance that mirrors serves a codename per upstream beside the one it
// generates, so several codenames is its ordinary state rather than a
// misconfiguration to clean up, and without this flag every host on such an
// instance is configured by hand. The stanza still comes from the server's
// own rendering — which components a codename carries, and whether bodega
// signs it, are facts only the running instance holds.
func writeAptSourcesFile(gf *globalFlags, token, baseURL, suite string, allowPlaintext bool) error {
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
	stanza := apt.Host
	if suite != "" {
		if stanza, err = aptSuiteChoice(apt, suite); err != nil {
			return err
		}
	}
	if stanza == nil {
		return aptNoStanza(apt)
	}
	// A mirrored codename is forwarded from its upstream with the archive's
	// own signature intact, so apt verifies it against the distro keyring the
	// host already has. Installing bodega's keyring beside a stanza that names
	// it nowhere would leave a file on disk nothing reads.
	var keyring []byte
	if !stanza.Mirrored {
		if keyring, err = getBody(client, aptsources.KeyringRoute); err != nil {
			return err
		}
	}
	wrote, err := host.WriteAptSources("", aptsources.ClientKeyringPath, stanza.Deb822, stanza.Mirrored, keyring)
	for _, p := range wrote {
		fmt.Printf("wrote %s\n", p)
	}
	if err != nil {
		return err
	}
	if stanza.Mirrored {
		fmt.Printf("\n%s reaches this host through bodega and is signed by its upstream, not by bodega.\n", stanza.Suite)
		fmt.Println(aptsources.MirroredNote)
	}
	if apt.Profile != "" {
		fmt.Printf("\nProfile %q: this host reads %s, a filtered view of what bodega mirrors.\n",
			apt.Profile, stanza.Suite)
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
		"  Name it:  bodega doctor --write-apt-sources --suite %s\n"+
		"  This host may simply not be identified. Pass --token, or bind its address:  bodega identity bind cidr <cidr> <name>\n"+
		"  Then give the profile a base:  bodega profile set <profile> apt --membership closed --base <codename>",
		len(served), strings.Join(served, ", "), served[0])
}

// aptSuiteChoice resolves --suite against what the server reported, and
// returns the stanza the server rendered for it.
//
// A host whose profile scopes apt is refused rather than served the codename
// it named. The profile exists to narrow what that host is told exists, and
// the unfiltered base sits in the same list: writing it here would hand the
// host an unfiltered index for the same packages, which is the state
// aptHostSources refuses to produce on the server's side.
func aptSuiteChoice(apt aptClientStatus, suite string) (*aptsources.Sources, error) {
	if apt.Profile != "" {
		return nil, fmt.Errorf("profile %q scopes apt for this host, so the codename it reads is the profile's answer rather than this flag's.\n"+
			"  Change what the profile is built from:  bodega profile set %s apt --base <codename>\n"+
			"  Then re-run without --suite",
			apt.Profile, apt.Profile)
	}
	for i := range apt.Sources {
		if apt.Sources[i].Suite == suite {
			return &apt.Sources[i], nil
		}
	}
	served := slices.Concat(apt.Suites, apt.Mirrored, apt.Filtered)
	if len(served) == 0 {
		return nil, fmt.Errorf("this bodega serves no apt suite, so there is no stanza to install")
	}
	return nil, fmt.Errorf("this bodega serves no codename %q, so there is no stanza to install for it. It serves %s.\n"+
		"  Pass one of those, or add the upstream this host needs to apt_upstreams and restart the server",
		suite, strings.Join(served, ", "))
}

// pkgClientConfig is the half of GET /api/v1/status this command reads. The
// server composes each repository's configuration and this decodes it:
// whether a repository is mirrored or generated, and whether a catalogue
// signing key is loaded, are facts only the running instance holds.
type pkgClientConfig struct {
	FreeBSD pkgClientStatus `json:"freebsd"`
}

type pkgClientStatus struct {
	Signed      bool             `json:"signed"`
	Fingerprint string           `json:"fingerprint"`
	KeyError    string           `json:"key_error"`
	PublicURL   string           `json:"public_url"`
	Repos       []pkgrepos.Repo  `json:"repos"`
	Refused     []pkgRepoRefusal `json:"refused"`
}

type pkgRepoRefusal struct {
	Repo  string `json:"repo"`
	ABI   string `json:"abi"`
	Error string `json:"error"`
}

// writePkgRepoFile installs what the server says this host's pkg
// configuration is: one repository definition, and the overrides that turn
// the upstream one off.
//
// --token is optional here for the reason it is optional on
// --write-apt-sources: a host bound by "bodega identity bind cidr" sends no
// header, and demanding a token would make one of the two identification
// modes unusable from the command that configures it.
func writePkgRepoFile(gf *globalFlags, token, baseURL, abi string, release int, allowPlaintext bool) error {
	if baseURL == "" {
		cfg, err := loadConfig(gf)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		baseURL = cfg.PublicURL
	}
	if baseURL == "" {
		return fmt.Errorf("--write-pkg-repo needs the base URL clients reach this bodega at.\n" +
			"  Pass --url https://bodega.internal, or set public_url in the config file")
	}
	if abi == "" {
		var err error
		if abi, err = localPkgABI(); err != nil {
			return err
		}
	}
	client, err := NewClient(baseURL, token, allowPlaintext)
	if err != nil {
		return err
	}
	var status pkgClientConfig
	if err := getJSON(client, "/api/v1/status", &status); err != nil {
		return err
	}
	repo, err := pkgRepoForABI(status.FreeBSD, abi)
	if err != nil {
		return err
	}
	if release > 0 && release != repo.Release {
		// Re-rendered rather than patched: the file is the overrides and the
		// definition together, and editing the tag list out of one half is
		// how a host ends up disabling a repository it does not define while
		// the one it does stays enabled. WithRelease rather than a State
		// rebuilt from these fields, because this side sees what crossed the
		// wire and the server's own facts did not all cross it.
		rerendered, err := repo.WithRelease(release)
		if err != nil {
			return err
		}
		repo = rerendered
	}
	conf := repo.Conf

	wrote, err := host.WritePkgRepo("", pkgrepos.ClientConfPath, conf)
	for _, p := range wrote {
		fmt.Printf("wrote %s\n", p)
	}
	if err != nil {
		return err
	}
	if status.FreeBSD.KeyError != "" {
		fmt.Printf("\nThe server has a pkg signing key it cannot load (%s), so every generated\n", status.FreeBSD.KeyError)
		fmt.Println("repository refuses its catalogue until that is fixed. A mirrored one is unaffected.")
	}
	for _, note := range repo.Notes {
		fmt.Println()
		fmt.Println(note)
	}
	fmt.Println("\nApply it:  pkg update")
	fmt.Println("Confirm the upstream repository is off:  pkg -vv | grep -A2 -E '^  (FreeBSD|bodega)'")
	return nil
}

// pkgRepoForABI picks the one configuration this host should install, or
// explains a server that would not name one.
//
// Refusing beats guessing for the reason aptNoStanza refuses: a repository
// named for this host by nobody is a host pointed somewhere nobody decided
// on, and the file it lands in looks authoritative.
func pkgRepoForABI(st pkgClientStatus, abi string) (pkgrepos.Repo, error) {
	var match []pkgrepos.Repo
	var others []string
	for _, r := range st.Repos {
		if r.ABI == abi {
			match = append(match, r)
			continue
		}
		others = append(others, r.Repo+"@"+r.ABI)
	}
	switch {
	case len(match) == 1:
		return match[0], nil
	case len(match) > 1:
		names := make([]string, 0, len(match))
		for _, r := range match {
			names = append(names, r.Repo)
		}
		return pkgrepos.Repo{}, fmt.Errorf("this bodega serves %d pkg repositories for %s, so which one this host should read is your decision rather than the server's: %s.\n"+
			"  Hide the ones this host must not read (bodega pkg hide freebsd <repo>), or write the file by hand from GET /api/v1/status",
			len(match), abi, strings.Join(names, ", "))
	}
	for _, r := range st.Refused {
		if r.ABI == abi {
			return pkgrepos.Repo{}, fmt.Errorf("this bodega serves %s for %s and will not render client configuration for it: %s", r.Repo, abi, r.Error)
		}
	}
	if len(others) == 0 {
		return pkgrepos.Repo{}, fmt.Errorf("this bodega serves no pkg repository, so there is no configuration to install")
	}
	return pkgrepos.Repo{}, fmt.Errorf("this bodega serves no pkg repository for %s. It serves %s.\n"+
		"  Pass --abi with one of those, or add an entry for this ABI on the server:  bodega pkg create freebsd <repo>",
		abi, strings.Join(others, ", "))
}

// localPkgABI asks pkg what ABI this host is, which is the only authority on
// it: the ABI string carries the release and the architecture as pkg spells
// them, and a value composed from runtime.GOARCH is wrong on every host where
// those two spellings differ.
func localPkgABI() (string, error) {
	out, err := exec.Command("pkg", "config", "abi").Output()
	if err != nil {
		return "", fmt.Errorf("--write-pkg-repo needs the ABI to configure for, and `pkg config abi` did not answer on this host (%v).\n"+
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
