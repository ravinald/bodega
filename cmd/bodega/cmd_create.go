package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/manifest"
)

func newCreateCmd(gf *globalFlags) *cobra.Command {
	var (
		flagName     string
		flagURL      string
		flagRef      string
		flagSHA256   string
		flagFilename string
		flagBuildCmd string
		flagDebGlob  string
		flagSrcName  string
	)

	cmd := &cobra.Command{
		Use:   "create <type>",
		Short: "Add a new entry to a manifest",
		Long: `create adds a new entry to the specified manifest type.

If flags are omitted, missing values are prompted interactively.

Examples:
  bodega create git --name myrepo --url https://github.com/org/repo.git --ref v1.0.0
  bodega create binary
  bodega create apt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := context.Background()
			r := bufio.NewReader(os.Stdin)

			var name string
			var ve manifest.VersionEntry

			switch t {
			case manifest.TypeGit:
				name, ve, err = collectGitVersion(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}

			case manifest.TypeBinary:
				name, ve, err = collectBinaryVersion(r, flagName, flagURL, flagSHA256, flagFilename)
				if err != nil {
					return err
				}

			case manifest.TypeApt:
				name, ve, err = collectAptVersion(r, flagName, flagURL, flagSrcName, flagBuildCmd, flagDebGlob)
				if err != nil {
					return err
				}

			case manifest.TypeGomod:
				name, ve, err = collectGomodVersion(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}

			case manifest.TypeHelm:
				name, ve, err = collectHelmVersion(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}

			case manifest.TypeNpm:
				name, ve, err = collectNpmVersion(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}

			case manifest.TypePypi:
				if flagName == "" {
					return fmt.Errorf("--name is required for pypi entries")
				}
				name = flagName
				ve = manifest.VersionEntry{}
			}

			if err := store.AddVersion(ctx, t, name, ve); err != nil {
				return fmt.Errorf("add version: %w", err)
			}
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save index: %w", err)
			}
			fmt.Printf("Added %s entry: %s\n", t, name)
			notifyServer(gf)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagName, "name", "", "Entry name")
	f.StringVar(&flagURL, "url", "", "URL (git remote or download URL)")
	f.StringVar(&flagRef, "ref", "", "Git ref (tag, branch, or commit SHA) / version for other types")
	f.StringVar(&flagSHA256, "sha256", "", "Expected SHA-256 of downloaded file")
	f.StringVar(&flagFilename, "filename", "", "Filename override for binary downloads")
	f.StringVar(&flagBuildCmd, "build-cmd", "", "Shell command to build the .deb")
	f.StringVar(&flagDebGlob, "deb-glob", "", "Glob pattern to locate the produced .deb")
	f.StringVar(&flagSrcName, "source-name", "", "Source package / directory name (apt)")

	return cmd
}

// prompt asks the user for a value, using defVal as the default.
func prompt(r *bufio.Reader, question, defVal string) (string, error) {
	if defVal != "" {
		fmt.Printf("%s [%s]: ", question, defVal)
	} else {
		fmt.Printf("%s: ", question)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defVal, nil
	}
	return line, nil
}

func collectGitVersion(r *bufio.Reader, name, url, ref string) (string, manifest.VersionEntry, error) {
	var err error
	if name, err = prompt(r, "Name", name); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if name == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
	}
	if url, err = prompt(r, "URL", url); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if url == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("url is required")
	}
	if ref, err = prompt(r, "Ref (tag/branch/SHA)", ref); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if ref == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("ref is required")
	}
	return name, manifest.VersionEntry{URL: url, Ref: ref}, nil
}

func collectBinaryVersion(r *bufio.Reader, name, url, sha256, filename string) (string, manifest.VersionEntry, error) {
	var err error
	if name, err = prompt(r, "Name", name); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if name == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
	}
	if url, err = prompt(r, "URL", url); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if url == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("url is required")
	}
	sha256, err = prompt(r, "SHA-256 (leave blank to skip verification)", sha256)
	if err != nil {
		return "", manifest.VersionEntry{}, err
	}
	filename, err = prompt(r, "Filename override (leave blank to use URL basename)", filename)
	if err != nil {
		return "", manifest.VersionEntry{}, err
	}
	ve := manifest.VersionEntry{URL: url, Filename: filename, SHA256: sha256}
	return name, ve, nil
}

func collectAptVersion(r *bufio.Reader, name, url, srcName, buildCmd, debGlob string) (string, manifest.VersionEntry, error) {
	var err error
	if name, err = prompt(r, "Name", name); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if name == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
	}
	if url, err = prompt(r, "Git URL (leave blank for apt-get download)", url); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if url != "" {
		if srcName, err = prompt(r, "Source directory name", srcName); err != nil {
			return "", manifest.VersionEntry{}, err
		}
		if buildCmd, err = prompt(r, "Build command", buildCmd); err != nil {
			return "", manifest.VersionEntry{}, err
		}
		if debGlob, err = prompt(r, "Deb glob pattern", debGlob); err != nil {
			return "", manifest.VersionEntry{}, err
		}
	}
	ve := manifest.VersionEntry{
		URL:        url,
		SourceName: srcName,
		BuildCmd:   buildCmd,
		DebGlob:    debGlob,
	}
	return name, ve, nil
}

func collectGomodVersion(r *bufio.Reader, name, url, version string) (string, manifest.VersionEntry, error) {
	var err error
	if name, err = prompt(r, "Module path (e.g. github.com/aws/aws-sdk-go-v2)", name); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if name == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
	}
	if version, err = prompt(r, "Version (e.g. v1.30.0)", version); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if version == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("version is required")
	}
	url, _ = prompt(r, "Upstream GOPROXY URL (leave blank for proxy.golang.org)", url)
	return name, manifest.VersionEntry{Version: version, URL: url}, nil
}

func collectHelmVersion(r *bufio.Reader, name, url, version string) (string, manifest.VersionEntry, error) {
	var err error
	if name, err = prompt(r, "Chart name", name); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if name == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
	}
	if version, err = prompt(r, "Chart version", version); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if version == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("version is required")
	}
	if url, err = prompt(r, "Chart repo or .tgz URL", url); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if url == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("url is required")
	}
	return name, manifest.VersionEntry{Version: version, URL: url}, nil
}

func collectNpmVersion(r *bufio.Reader, name, url, version string) (string, manifest.VersionEntry, error) {
	var err error
	if name, err = prompt(r, "Package name (e.g. lodash or @scope/pkg)", name); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if name == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
	}
	if version, err = prompt(r, "Version", version); err != nil {
		return "", manifest.VersionEntry{}, err
	}
	if version == "" {
		return "", manifest.VersionEntry{}, fmt.Errorf("version is required")
	}
	url, _ = prompt(r, "Registry URL (leave blank for registry.npmjs.org)", url)
	return name, manifest.VersionEntry{Version: version, URL: url}, nil
}
