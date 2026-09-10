package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/hostpkg"
)

// pinDefaultPriority is 1001 rather than 1000 because 1000 is the threshold
// above which apt will downgrade. At 1000 a package that has drifted ahead of
// its pin stays ahead; at 1001 apt pulls it back to the pinned version, which
// is what "this host runs these versions" has to mean to be worth writing down.
const pinDefaultPriority = 1001

// pinKey is one published (package, version). The architecture is deliberately
// not part of it: an "all" package is published inside binary-<arch> alongside
// the native ones, so a key carrying the architecture would miss every one of
// them. The architectures that published a key travel beside it instead.
type pinKey struct {
	name    string
	version string
}

// servedIndex is what a host row is matched against: every (name, version) a
// served suite publishes, mapped to the architectures it was published for.
type servedIndex map[pinKey][]string

// resolves reports whether a served suite publishes this host row's exact
// version for an architecture the host can install.
//
// "all" matches in both directions, because the two sides disagree about where
// an architecture-independent package lives. dpkg reports it on the host as
// "all"; the archive publishes it inside binary-<arch> with Architecture: all
// and publishes no binary-all index to look in. A match driven by the host
// row's architecture asks for an index no archive has and reports the package
// as superseded, which on one Ubuntu 22.04 host would be 158 of 635 packages.
func (idx servedIndex) resolves(row hostpkg.AptRow) bool {
	for _, a := range idx[pinKey{row.Name, row.Version}] {
		if a == row.Arch || a == "all" || row.Arch == "all" || row.Arch == "" {
			return true
		}
	}
	return false
}

func newPinCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Pin a host to the versions bodega serves",
	}
	cmd.AddCommand(newPinAptCmd(gf))
	return cmd
}

func newPinAptCmd(gf *globalFlags) *cobra.Command {
	var (
		output         string
		unresolvedPath string
		priority       int
		serverURL      string
		allowPlaintext bool
		suites         []string
	)

	cmd := &cobra.Command{
		Use:   "apt [file|-]",
		Short: "Turn a host's installed apt packages into an apt preferences file",
		Long: `pin apt reads the same host inventory 'bodega pkg convert apt' reads and
asks a bodega which of those exact versions it can still serve.

Every installed package that a served suite publishes at the installed version
becomes a preferences stanza. Every one it does not becomes a line in the
unresolved list, because a stanza naming a version no suite carries leaves apt
with no candidate for that package at all: apt update stays quiet and the next
'apt upgrade' is where it surfaces. Hold those instead.

Nothing is written to the manifest store and nothing is installed. The output
is reviewed, then copied to /etc/apt/preferences.d/ on the host.

The indices are read over HTTP the way an apt client reads them, so the answer
covers both the suites bodega generates and the ones it mirrors. Which bodega
answers, in order: --server, $BODEGA_SERVER, server_url, public_url, and
finally this host's own listener from listen_addr. The bearer token comes from
$BODEGA_TOKEN or the config file.

Examples:
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' \
    | bodega pin apt - -o bodega-pin --unresolved bodega-hold
  bodega pin apt installed.txt --server https://bodega.example
  bodega pin apt installed.txt --suite jammy --suite jammy-updates
  bodega pin apt installed.txt --priority 990`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if priority < 1 {
				return fmt.Errorf("--priority %d is not a usable apt priority: use 1001 to pin and downgrade, "+
					"1000 to pin without downgrading, or a value under 500 to deprioritize", priority)
			}

			source := "-"
			if len(args) == 1 {
				source = args[0]
			}
			data, err := readInput(source)
			if err != nil {
				return fmt.Errorf("read %s: %w", source, err)
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				return fmt.Errorf("no input on %s: pipe the host inventory in, or name a file "+
					`(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n')`, sourceLabel(source))
			}

			inv, err := hostpkg.ParseAptRows(strings.NewReader(string(data)))
			if err != nil {
				return err
			}
			errw := cmd.ErrOrStderr()
			// The same warnings 'pkg convert apt' prints, from the same parse:
			// the count of rows dropped for not being installed is the one
			// number that says whether this inventory was read as intended.
			for _, w := range inv.Warnings {
				fmt.Fprintf(errw, "apt: %s\n", w)
			}
			if len(inv.Rows) == 0 {
				return fmt.Errorf("no installed packages in %s: every row was either empty or not 'install ok installed'", sourceLabel(source))
			}

			client, target, err := pinClient(cfg, serverURL, allowPlaintext)
			if err != nil {
				return err
			}
			fmt.Fprintf(errw, "pin apt: resolving against %s (%s)\n", target.base, target.source)

			if len(suites) == 0 {
				suites, err = pinServedSuites(client)
				if err != nil {
					return err
				}
			}
			if len(suites) == 0 {
				return fmt.Errorf("%s serves no apt suite, so nothing can be pinned against it: "+
					"add apt_upstreams for the host's own archive, or apt_suites for a repository bodega generates", target.base)
			}

			idx, err := pinReadIndices(client, suites, inv.Rows, errw, cfg.Verbose)
			if err != nil {
				return err
			}
			return pinEmit(cmd, inv.Rows, idx, priority, target, output, unresolvedPath)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Write the preferences file here instead of stdout")
	cmd.Flags().StringVar(&unresolvedPath, "unresolved", "", "Write the unresolved package names here, one per line, instead of stderr")
	cmd.Flags().IntVar(&priority, "priority", pinDefaultPriority, "Pin-Priority for every stanza")
	cmd.Flags().StringVar(&serverURL, "server", "", "Read the indices from this bodega instead of the one this host's config names")
	cmd.Flags().BoolVar(&allowPlaintext, "allow-plaintext", false, "Permit --server over http; refused by default because a bearer token would travel in the clear")
	cmd.Flags().StringSliceVar(&suites, "suite", nil, "Only match against these suites (default: every suite the server reports)")
	return cmd
}

// pinTarget is the bodega whose indices answer the pin, and which setting
// named it. The source is printed because five settings can supply it and the
// wrong one produces a plausible, empty answer rather than an error.
type pinTarget struct {
	base   string
	source string
}

// pinClient resolves the target and builds the HTTP client that reads it.
//
// A loopback target is allowed over plaintext without the flag: the refusal
// exists so a bearer token does not cross a network readable by others, and on
// 127.0.0.1 there is no such network. Anything else obeys the same rule
// 'pkg import --server' does.
func pinClient(cfg *config.Config, flagURL string, allowPlaintext bool) (*Client, pinTarget, error) {
	target, loopback, err := pinResolveTarget(cfg, flagURL)
	if err != nil {
		return nil, pinTarget{}, err
	}
	client, err := NewClient(target.base, cfg.ResolveToken(), allowPlaintext || loopback)
	if err != nil {
		return nil, pinTarget{}, err
	}
	return client, target, nil
}

func pinResolveTarget(cfg *config.Config, flagURL string) (pinTarget, bool, error) {
	switch {
	case flagURL != "":
		return pinFinishTarget(strings.TrimRight(flagURL, "/"), "--server")
	case os.Getenv(config.EnvServerURL) != "":
		return pinFinishTarget(strings.TrimRight(os.Getenv(config.EnvServerURL), "/"), "$"+config.EnvServerURL)
	case cfg.ServerURL != "":
		return pinFinishTarget(strings.TrimRight(cfg.ServerURL, "/"), "server_url")
	}
	if public := cfg.ResolvePublicURL(""); public != "" {
		return pinFinishTarget(public, "public_url")
	}

	// Nothing named a server, so this is the bodega host itself and the
	// listener is the answer. A wildcard bind is reached on loopback: the
	// address it accepts on says nothing about which of this host's names
	// resolve here.
	addr := cfg.ResolveListenAddr("")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return pinTarget{}, false, fmt.Errorf("listen_addr %q does not parse as host:port, so this host's own bodega cannot be addressed: pass --server", addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if cfg.TLSCert != "" {
		return pinTarget{}, false, fmt.Errorf("this bodega serves TLS on %s and public_url is unset, so there is no name to verify its certificate against: "+
			"set public_url, or pass --server https://<the name the certificate carries>", addr)
	}
	return pinFinishTarget("http://"+net.JoinHostPort(host, port), "listen_addr")
}

// pinFinishTarget reports whether the resolved base is loopback, which is what
// decides the plaintext question.
func pinFinishTarget(base, source string) (pinTarget, bool, error) {
	u, err := url.Parse(base)
	if err != nil {
		return pinTarget{}, false, fmt.Errorf("%s %q does not parse as a URL: %w", source, base, err)
	}
	host := u.Hostname()
	loopback := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	return pinTarget{base: base, source: source}, loopback, nil
}

// pinServedSuites asks the server which apt suites it answers for, generated
// and mirrored alike. A client learns this from its own sources.list; this
// command has no sources.list to read, and guessing would silently pin against
// a subset.
func pinServedSuites(client *Client) ([]string, error) {
	resp, err := client.Get("/api/v1/status")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read /api/v1/status: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s/api/v1/status: %s\n%s\nName the suites with --suite to skip this lookup",
			client.BaseURL, resp.Status, serverError(payload))
	}
	var status struct {
		Apt struct {
			Suites   []string `json:"suites"`
			Mirrored []string `json:"mirrored"`
		} `json:"apt"`
	}
	if err := json.Unmarshal(payload, &status); err != nil {
		return nil, fmt.Errorf("parse /api/v1/status: %w", err)
	}

	seen := make(map[string]bool)
	var out []string
	for _, s := range append(append([]string{}, status.Apt.Suites...), status.Apt.Mirrored...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// pinReadIndices reads every served suite's Packages indices and keeps the
// paragraphs naming a package this host has.
//
// Only the installed names are retained. An Ubuntu universe index is tens of
// thousands of paragraphs and a host has a few hundred packages, so holding
// the whole index to answer a few hundred questions is memory spent for
// nothing.
func pinReadIndices(client *Client, suites []string, rows []hostpkg.AptRow, errw io.Writer, verbose bool) (servedIndex, error) {
	want := make(map[string]bool, len(rows))
	for _, row := range rows {
		want[row.Name] = true
	}
	idx := make(servedIndex)

	for _, suite := range suites {
		release, err := pinReadRelease(client, suite)
		if err != nil {
			return nil, err
		}
		if release == nil {
			fmt.Fprintf(errw, "pin apt: %s publishes no Release, so nothing is matched against it\n", suite)
			continue
		}
		components := strings.Fields(release["Components"])
		if len(components) == 0 {
			components = []string{"main"}
		}
		for _, component := range components {
			for _, arch := range pinArches(release, rows) {
				n, err := pinReadPackages(client, idx, want, component, arch, suite)
				if err != nil {
					return nil, err
				}
				if verbose {
					fmt.Fprintf(errw, "pin apt: %s/%s/binary-%s matched %d installed package(s)\n", suite, component, arch, n)
				}
			}
		}
	}
	return idx, nil
}

// pinArches picks the architectures worth fetching: the ones this host has
// packages for, narrowed to what the suite publishes.
//
// "all" is never fetched as a directory. No archive publishes binary-all; an
// architecture-independent package is republished inside every binary-<arch>
// index, which is where the host's "all" rows are found.
func pinArches(release map[string]string, rows []hostpkg.AptRow) []string {
	published := strings.Fields(release["Architectures"])
	hostArches := make(map[string]bool)
	for _, row := range rows {
		if row.Arch != "" && row.Arch != "all" {
			hostArches[row.Arch] = true
		}
	}
	var out []string
	for _, a := range published {
		if a == "all" {
			continue
		}
		if len(hostArches) == 0 || hostArches[a] {
			out = append(out, a)
		}
	}
	return out
}

// pinReadRelease fetches a suite's Release. A 404 is an answer: the server
// reported the suite, so a missing Release means an upstream that does not
// publish one under that name rather than a failure to report.
func pinReadRelease(client *Client, suite string) (map[string]string, error) {
	resp, err := client.Get("/apt/dists/" + suite + "/Release")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("GET %s/apt/dists/%s/Release: %s\n%s", client.BaseURL, suite, resp.Status, serverError(payload))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s Release: %w", suite, err)
	}
	fields, err := deb822.ParseSingle(body)
	if err != nil {
		return nil, fmt.Errorf("parse %s Release: %w", suite, err)
	}
	return fields, nil
}

// pinReadPackages folds one component and architecture's index into idx,
// returning how many installed packages it accounted for.
func pinReadPackages(client *Client, idx servedIndex, want map[string]bool, component, arch, suite string) (int, error) {
	dir := "/apt/dists/" + suite + "/" + component + "/binary-" + arch + "/"

	body, err := pinOpenPackages(client, dir)
	if err != nil {
		return 0, err
	}
	if body == nil {
		return 0, nil
	}
	defer func() { _ = body.Close() }()

	matched := 0
	err = deb822.ParseStream(body, func(fields map[string]string) error {
		name := fields["Package"]
		version := fields["Version"]
		if name == "" || version == "" || !want[name] {
			return nil
		}
		key := pinKey{name, version}
		pkgArch := fields["Architecture"]
		if pkgArch == "" {
			pkgArch = arch
		}
		for _, seen := range idx[key] {
			if seen == pkgArch {
				return nil
			}
		}
		idx[key] = append(idx[key], pkgArch)
		matched++
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("parse %s%s: %w", client.BaseURL, dir, err)
	}
	return matched, nil
}

// pinOpenPackages returns a reader over one index, gzip first. A nil reader
// and no error means the archive publishes neither form here, which is normal
// for a component and architecture pair a suite does not carry.
//
// Packages.xz is not read. Go has no xz decoder in its standard library, and
// every archive that publishes .xz publishes .gz beside it; an archive that
// someday publishes only .xz is named in the error rather than counted as
// empty, because an index silently read as zero packages turns every package
// in it into an unresolved one.
func pinOpenPackages(client *Client, dir string) (io.ReadCloser, error) {
	gzResp, err := client.Get(dir + "Packages.gz")
	if err != nil {
		return nil, err
	}
	if gzResp.StatusCode == http.StatusOK {
		zr, err := gzip.NewReader(gzResp.Body)
		if err != nil {
			_ = gzResp.Body.Close()
			return nil, fmt.Errorf("decompress %s%sPackages.gz: %w", client.BaseURL, dir, err)
		}
		return pinReadCloser{zr, gzResp.Body}, nil
	}
	_ = gzResp.Body.Close()

	plain, err := client.Get(dir + "Packages")
	if err != nil {
		return nil, err
	}
	if plain.StatusCode == http.StatusOK {
		return plain.Body, nil
	}
	_ = plain.Body.Close()
	if gzResp.StatusCode == http.StatusNotFound && plain.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	return nil, fmt.Errorf("no readable index at %s%s: Packages.gz answered %s, Packages answered %s\n"+
		"bodega serves a mirrored codename byte for byte, so an archive that publishes only Packages.xz cannot be read here; "+
		"any other status is the server's own answer",
		client.BaseURL, dir, gzResp.Status, plain.Status)
}

// pinReadCloser closes the gzip reader and the response body under it. Closing
// only the decompressor leaks the connection.
type pinReadCloser struct {
	io.Reader
	under io.Closer
}

func (p pinReadCloser) Close() error {
	if gz, ok := p.Reader.(io.Closer); ok {
		_ = gz.Close()
	}
	return p.under.Close()
}

// pinEmit writes both artifacts and the coverage counts.
//
// An unresolved package is not an error. It is the expected result for a
// version the archive has superseded, and failing the command on one would
// make the ordinary case look like a broken run.
func pinEmit(cmd *cobra.Command, rows []hostpkg.AptRow, idx servedIndex, priority int, target pinTarget, output, unresolvedPath string) error {
	var pinned, unresolved []hostpkg.AptRow
	for _, row := range rows {
		if idx.resolves(row) {
			pinned = append(pinned, row)
		} else {
			unresolved = append(unresolved, row)
		}
	}

	prefs := renderPreferences(pinned, priority, target, len(rows), len(unresolved))
	if output == "" || output == "-" {
		if _, err := cmd.OutOrStdout().Write(prefs); err != nil {
			return err
		}
	} else if err := os.WriteFile(output, prefs, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
	}

	names := pinNames(unresolved)
	if unresolvedPath != "" && unresolvedPath != "-" {
		body := ""
		if len(names) > 0 {
			body = strings.Join(names, "\n") + "\n"
		}
		if err := os.WriteFile(unresolvedPath, []byte(body), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", unresolvedPath, err)
		}
	}

	errw := cmd.ErrOrStderr()
	fmt.Fprintf(errw, "pin apt: %d installed, %d pinned, %d unresolved\n", len(rows), len(pinned), len(unresolved))
	if len(names) > 0 {
		// Printed on one line even when the list also went to a file: this is
		// the command's whole warning, and the operator's next act is to paste
		// these names into 'apt-mark hold'.
		fmt.Fprintf(errw, "pin apt: hold these instead, their installed version is on no served suite: apt-mark hold %s\n",
			strings.Join(names, " "))
	}
	if output != "" && output != "-" {
		fmt.Fprintf(errw, "pin apt: wrote %d stanza(s) to %s\n", len(pinned), output)
	}
	if unresolvedPath != "" && unresolvedPath != "-" {
		fmt.Fprintf(errw, "pin apt: wrote %d unresolved name(s) to %s\n", len(names), unresolvedPath)
	}
	return nil
}

// pinNames lists the distinct package names in rows, in order.
func pinNames(rows []hostpkg.AptRow) []string {
	seen := make(map[string]bool, len(rows))
	var out []string
	for _, row := range rows {
		if seen[row.Name] {
			continue
		}
		seen[row.Name] = true
		out = append(out, row.Name)
	}
	return out
}

// renderPreferences writes the apt preferences file.
//
// A name installed at one version gets a bare Package: line, which is what an
// operator reads and what apt-cache policy echoes back. A name installed at
// two versions is a multi-arch host holding both builds of one library, and
// there the stanzas are qualified with :<arch>: two bare stanzas naming one
// package at different versions contradict each other, and apt takes the last.
func renderPreferences(pinned []hostpkg.AptRow, priority int, target pinTarget, installed, unresolved int) []byte {
	versions := make(map[string]map[string]bool, len(pinned))
	for _, row := range pinned {
		if versions[row.Name] == nil {
			versions[row.Name] = make(map[string]bool, 1)
		}
		versions[row.Name][row.Version] = true
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by 'bodega pin apt' on %s against %s.\n", time.Now().UTC().Format(time.RFC3339), target.base)
	fmt.Fprintf(&b, "# %d of %d installed packages resolve to a version that server publishes.\n#\n", installed-unresolved, installed)
	if priority == pinDefaultPriority {
		b.WriteString("# Pin-Priority is 1001 rather than 1000 because 1000 is the threshold above\n" +
			"# which apt will downgrade: a package that has drifted ahead of its pin is\n" +
			"# pulled back to the version below rather than left where it is.\n")
	} else {
		fmt.Fprintf(&b, "# Pin-Priority is %d. Below 1001 apt will not downgrade, so a package that\n"+
			"# has drifted ahead of its pin stays ahead.\n", priority)
	}
	if unresolved > 0 {
		fmt.Fprintf(&b, "#\n# %d installed package(s) are deliberately absent: no served suite publishes the\n"+
			"# version this host runs, and a stanza naming one would leave apt with no\n"+
			"# candidate for that package at all. Hold them instead ('apt-mark hold').\n", unresolved)
	}

	written := make(map[string]bool, len(pinned))
	for _, row := range pinned {
		name := row.Name
		if len(versions[row.Name]) > 1 && row.Arch != "" {
			name += ":" + row.Arch
		}
		// One package installed for two architectures at one version is one
		// stanza. Repeating it says nothing new and doubles a file an operator
		// reads by eye.
		if written[name] {
			continue
		}
		written[name] = true
		fmt.Fprintf(&b, "\nPackage: %s\nPin: version %s\nPin-Priority: %d\n", name, row.Version, priority)
	}
	return []byte(b.String())
}
