package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/hostpkg"
)

func newConvertCmd(gf *globalFlags) *cobra.Command {
	var output string
	var origin string

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

Sources per type:
  apt     dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'
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
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' | bodega pkg convert apt > catalog.json
  apt list --installed | bodega pkg convert apt -o catalog.json
  pip list --format=json | bodega pkg convert pypi | bodega pkg import -
  bodega pkg convert apt installed.txt
  bodega pkg convert apt --origin db01 db01-installed.txt`,
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

			res, err := parse(strings.NewReader(string(data)))
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
	return cmd
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
