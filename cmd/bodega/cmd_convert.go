package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/hostpkg"
	"github.com/ravinald/bodega/internal/manifest"
)

func newConvertCmd(gf *globalFlags) *cobra.Command {
	var output string
	var origin string
	var suite string

	cmd := &cobra.Command{
		Use:   "convert <type> [file|-]",
		Short: "Convert a package manager's installed list into bodega manifests",
		Long: `convert reads what a package manager reports as installed on a host and
writes the equivalent bodega manifests as JSON.

It reads stdin by default and writes stdout, so the output can be reviewed,
edited and diffed before anything reaches the manifest store. Feed it to
'bodega pkg import' when it looks right. Nothing is written to the store here.

Run it on the host being cataloged: the managers live there, bodega usually
does not.

Every version entry is stamped with the host the inventory came from, so a
catalog holding several hosts can still say which one contributed a package.
That defaults to this machine's hostname; --origin names another when the
input was captured elsewhere.

An apt inventory also records the release it was captured on, because Ubuntu
and Debian backport a security fix without moving the upstream version, so the
advisories that settle a version are the ones published for its own release.
That defaults to VERSION_CODENAME in this machine's /etc/os-release; --suite
names the release when the capture came from another one.

Sources per type:
  apt     dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n'
          apt list --installed
  pypi    pip list --format=json
  npm     npm ls --global --json --depth=0
  gomod   go list -m all   |   go version -m <binary>
  cargo   cargo install --list
  helm    helm list -o json

git and binary have no importer. Nothing on a host records a clone or a
downloaded binary, so those are cataloged with 'bodega pkg create' or found by
running the server with discover_mode set to "observe".

Examples:
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n' | bodega pkg convert apt > catalog.json
  apt list --installed | bodega pkg convert apt -o catalog.json
  pip list --format=json | bodega pkg convert pypi | bodega pkg import -
  bodega pkg convert apt installed.txt
  bodega pkg convert apt --origin db01 --suite noble db01-installed.txt`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			typ := args[0]
			parse, err := hostpkg.For(typ)
			if err != nil {
				return err
			}

			source := "-"
			if len(args) == 2 {
				source = args[1]
			}
			data, err := readInput(source)
			if err != nil {
				return fmt.Errorf("read %s: %w", source, err)
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				return fmt.Errorf("no input on %s: pipe the manager's output in, or name a file "+
					"(see 'bodega pkg convert --help' for the command per type)", sourceLabel(source))
			}

			res, err := convertInput(typ, parse, string(data), suite, osReleasePath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			host, err := resolveOrigin(origin)
			if err != nil {
				return err
			}
			for i := range res.Packages {
				if err := admit.ApplyOrigin(&res.Packages[i], host); err != nil {
					return err
				}
			}

			// Warnings go to stderr so stdout stays a clean JSON payload that
			// pipes into 'pkg import'. Silence here would let an operator
			// import a partial catalog believing it complete.
			for _, w := range res.Warnings {
				fmt.Fprintf(os.Stderr, "%s: %s\n", typ, w)
			}
			if len(res.Packages) == 0 {
				fmt.Fprintf(os.Stderr, "%s: nothing to convert; the input named no installed packages\n", typ)
			}

			blob, err := json.MarshalIndent(res.Packages, "", "  ")
			if err != nil {
				return fmt.Errorf("encode manifests: %w", err)
			}
			blob = append(blob, '\n')

			if output == "" || output == "-" {
				_, err = os.Stdout.Write(blob)
				return err
			}
			if err := os.WriteFile(output, blob, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", output, err)
			}
			fmt.Fprintf(os.Stderr, "%s: wrote %d package(s) to %s\n", typ, len(res.Packages), output)
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Write to this file instead of stdout")
	cmd.Flags().StringVar(&origin, "origin", "", "Host this inventory describes; defaults to this machine's hostname")
	cmd.Flags().StringVar(&suite, "suite", "", "apt only: release this inventory was captured on; defaults to VERSION_CODENAME in /etc/os-release")
	return cmd
}

// convertInput runs the type's parser, and for apt records the release the
// inventory came from.
//
// Split out of RunE because the suite is the one field the Parser dispatch
// cannot carry: no other manager reports a release, and apt reports one in
// neither of its two formats. It reaches stderr rather than being applied in
// silence, because a capture converted on the wrong machine records a release
// the host never ran and the resulting findings are about somebody else's
// packages.
func convertInput(typ string, parse hostpkg.Parser, data, suite, osRelease string, errw io.Writer) (hostpkg.Result, error) {
	if typ != manifest.TypeApt {
		if suite != "" {
			return hostpkg.Result{}, fmt.Errorf("--suite names an apt release and %s has none; drop the flag", typ)
		}
		return parse(strings.NewReader(data))
	}
	suite, why := resolveAptSuite(suite, osRelease)
	if suite == "" {
		fmt.Fprintf(errw, "%s: no release recorded on these entries: %s.\n"+
			"  The OSV gate answers an apt version from the advisories published for its own release, and warns rather than\n"+
			"  guessing one. Re-run with --suite <codename> to record it.\n", typ, why)
		return hostpkg.ParseAptWithSuite(strings.NewReader(data), "")
	}
	if err := config.ValidateAptSuite(suite); err != nil {
		return hostpkg.Result{}, fmt.Errorf("%w; --suite takes an apt codename such as jammy or bookworm", err)
	}
	fmt.Fprintf(errw, "%s: recording release %q on every entry (%s)\n", typ, suite, why)
	return hostpkg.ParseAptWithSuite(strings.NewReader(data), suite)
}

// resolveAptSuite names the release an apt inventory describes, and where that
// name came from. Convert runs on the host being cataloged in the common case,
// so /etc/os-release is right without a flag; --suite is for a capture
// converted somewhere else, and for a host whose os-release carries no
// codename.
// The path is a parameter because both branches are the behavior under test
// and neither is reproducible on the host that has the other: the fallback
// exists only on Linux, and the empty answer only off it.
func resolveAptSuite(flag, osRelease string) (suite, why string) {
	// Trimmed here and not only in the parser, or --suite "  " reports a
	// release it recorded nothing for: the parser reads whitespace as no
	// suite, and the line saying which release was recorded would be a lie.
	if flag = strings.TrimSpace(flag); flag != "" {
		return flag, "--suite"
	}
	if local := osReleaseCodename(osRelease); local != "" {
		return local, "VERSION_CODENAME in " + osRelease
	}
	return "", "no --suite, and " + osRelease + " names no VERSION_CODENAME"
}

// osReleasePath is where a Linux host names its release. Absent everywhere
// else, which is the case the empty answer covers.
const osReleasePath = "/etc/os-release"

// osReleaseCodename reads VERSION_CODENAME out of an os-release file. Empty
// covers every way that can fail: no file (convert run on a Mac), or a distro
// that publishes no codename at all, which is most of them outside Debian.
func osReleaseCodename(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || key != "VERSION_CODENAME" {
			continue
		}
		return strings.TrimSpace(strings.Trim(strings.TrimSpace(val), `"'`))
	}
	return ""
}

// resolveOrigin names the host an inventory came from. Convert runs on the
// machine being cataloged in the common case, so the hostname is right without
// a flag; --origin is for a capture converted somewhere else.
func resolveOrigin(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	name, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("read this machine's hostname to stamp the origin: %w; pass --origin <name> to set it directly", err)
	}
	return name, nil
}

func sourceLabel(source string) string {
	if source == "-" {
		return "stdin"
	}
	return source
}
