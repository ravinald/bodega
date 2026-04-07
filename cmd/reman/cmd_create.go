package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
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
  reman create git --name myrepo --url https://github.com/org/repo.git --ref v1.0.0
  reman create binary
  reman create apt`,
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

			r := bufio.NewReader(os.Stdin)

			switch t {
			case manifest.TypeGit:
				entry, err := collectGitEntry(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}
				if store.FindGit(entry.Name) != nil {
					return fmt.Errorf("git entry %q already exists", entry.Name)
				}
				store.Git = append(store.Git, entry)
				if err := store.SaveGit(); err != nil {
					return err
				}
				fmt.Printf("Added git entry: %s\n", entry.Name)

			case manifest.TypeBinary:
				entry, err := collectBinaryEntry(r, flagName, flagURL, flagSHA256, flagFilename)
				if err != nil {
					return err
				}
				if store.FindBinary(entry.Name) != nil {
					return fmt.Errorf("binary entry %q already exists", entry.Name)
				}
				store.Binary = append(store.Binary, entry)
				if err := store.SaveBinary(); err != nil {
					return err
				}
				fmt.Printf("Added binary entry: %s\n", entry.Name)

			case manifest.TypeApt:
				entry, err := collectAptEntry(r, flagName, flagURL, flagSrcName, flagBuildCmd, flagDebGlob)
				if err != nil {
					return err
				}
				if store.FindApt(entry.Name) != nil {
					return fmt.Errorf("apt entry %q already exists", entry.Name)
				}
				store.Apt = append(store.Apt, entry)
				if err := store.SaveApt(); err != nil {
					return err
				}
				fmt.Printf("Added apt entry: %s\n", entry.Name)

			case manifest.TypeGomod:
				entry, err := collectGomodEntry(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}
				if store.FindGomod(entry.Name) != nil {
					return fmt.Errorf("gomod entry %q already exists", entry.Name)
				}
				store.Gomod = append(store.Gomod, entry)
				if err := store.SaveGomod(); err != nil {
					return err
				}
				fmt.Printf("Added gomod entry: %s\n", entry.Name)

			case manifest.TypeHelm:
				entry, err := collectHelmEntry(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}
				if store.FindHelm(entry.Name) != nil {
					return fmt.Errorf("helm entry %q already exists", entry.Name)
				}
				store.Helm = append(store.Helm, entry)
				if err := store.SaveHelm(); err != nil {
					return err
				}
				fmt.Printf("Added helm entry: %s\n", entry.Name)

			case manifest.TypeNpm:
				entry, err := collectNpmEntry(r, flagName, flagURL, flagRef)
				if err != nil {
					return err
				}
				if store.FindNpm(entry.Name) != nil {
					return fmt.Errorf("npm entry %q already exists", entry.Name)
				}
				store.Npm = append(store.Npm, entry)
				if err := store.SaveNpm(); err != nil {
					return err
				}
				fmt.Printf("Added npm entry: %s\n", entry.Name)

			case manifest.TypePypi:
				return fmt.Errorf("pypi uses a single manifest object — edit manifests/pypi.json directly or use 'reman --break-glass-update-md5 pypi' after editing")
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagName, "name", "", "Entry name")
	f.StringVar(&flagURL, "url", "", "URL (git remote or download URL)")
	f.StringVar(&flagRef, "ref", "", "Git ref (tag, branch, or commit SHA)")
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

func collectGitEntry(r *bufio.Reader, name, url, ref string) (manifest.GitEntry, error) {
	var err error
	if name, err = prompt(r, "Name", name); err != nil {
		return manifest.GitEntry{}, err
	}
	if name == "" {
		return manifest.GitEntry{}, fmt.Errorf("name is required")
	}
	if url, err = prompt(r, "URL", url); err != nil {
		return manifest.GitEntry{}, err
	}
	if url == "" {
		return manifest.GitEntry{}, fmt.Errorf("url is required")
	}
	if ref, err = prompt(r, "Ref (tag/branch/SHA)", ref); err != nil {
		return manifest.GitEntry{}, err
	}
	if ref == "" {
		return manifest.GitEntry{}, fmt.Errorf("ref is required")
	}
	return manifest.GitEntry{Name: name, URL: url, Ref: ref}, nil
}

func collectBinaryEntry(r *bufio.Reader, name, url, sha256, filename string) (manifest.BinaryEntry, error) {
	var err error
	if name, err = prompt(r, "Name", name); err != nil {
		return manifest.BinaryEntry{}, err
	}
	if name == "" {
		return manifest.BinaryEntry{}, fmt.Errorf("name is required")
	}
	if url, err = prompt(r, "URL", url); err != nil {
		return manifest.BinaryEntry{}, err
	}
	if url == "" {
		return manifest.BinaryEntry{}, fmt.Errorf("url is required")
	}
	sha256, err = prompt(r, "SHA-256 (leave blank to skip verification)", sha256)
	if err != nil {
		return manifest.BinaryEntry{}, err
	}
	filename, err = prompt(r, "Filename override (leave blank to use URL basename)", filename)
	if err != nil {
		return manifest.BinaryEntry{}, err
	}

	entry := manifest.BinaryEntry{Name: name, URL: url, Filename: filename}
	if sha256 != "" {
		entry.SHA256 = &sha256
	}
	return entry, nil
}

func collectAptEntry(r *bufio.Reader, name, url, srcName, buildCmd, debGlob string) (manifest.AptEntry, error) {
	var err error
	if name, err = prompt(r, "Name", name); err != nil {
		return manifest.AptEntry{}, err
	}
	if name == "" {
		return manifest.AptEntry{}, fmt.Errorf("name is required")
	}
	if url, err = prompt(r, "Git URL (leave blank for apt-get download)", url); err != nil {
		return manifest.AptEntry{}, err
	}
	if url != "" {
		if srcName, err = prompt(r, "Source directory name", srcName); err != nil {
			return manifest.AptEntry{}, err
		}
		if buildCmd, err = prompt(r, "Build command", buildCmd); err != nil {
			return manifest.AptEntry{}, err
		}
		if debGlob, err = prompt(r, "Deb glob pattern", debGlob); err != nil {
			return manifest.AptEntry{}, err
		}
	}
	return manifest.AptEntry{
		Name:       name,
		SourceName: srcName,
		URL:        url,
		BuildCmd:   buildCmd,
		DebGlob:    debGlob,
	}, nil
}

func collectGomodEntry(r *bufio.Reader, name, url, version string) (manifest.GomodEntry, error) {
	var err error
	if name, err = prompt(r, "Module path (e.g. github.com/aws/aws-sdk-go-v2)", name); err != nil {
		return manifest.GomodEntry{}, err
	}
	if name == "" {
		return manifest.GomodEntry{}, fmt.Errorf("name is required")
	}
	if version, err = prompt(r, "Version (e.g. v1.30.0)", version); err != nil {
		return manifest.GomodEntry{}, err
	}
	if version == "" {
		return manifest.GomodEntry{}, fmt.Errorf("version is required")
	}
	url, _ = prompt(r, "Upstream GOPROXY URL (leave blank for proxy.golang.org)", url)
	return manifest.GomodEntry{Name: name, Version: version, URL: url}, nil
}

func collectHelmEntry(r *bufio.Reader, name, url, version string) (manifest.HelmEntry, error) {
	var err error
	if name, err = prompt(r, "Chart name", name); err != nil {
		return manifest.HelmEntry{}, err
	}
	if name == "" {
		return manifest.HelmEntry{}, fmt.Errorf("name is required")
	}
	if version, err = prompt(r, "Chart version", version); err != nil {
		return manifest.HelmEntry{}, err
	}
	if version == "" {
		return manifest.HelmEntry{}, fmt.Errorf("version is required")
	}
	if url, err = prompt(r, "Chart repo or .tgz URL", url); err != nil {
		return manifest.HelmEntry{}, err
	}
	if url == "" {
		return manifest.HelmEntry{}, fmt.Errorf("url is required")
	}
	return manifest.HelmEntry{Name: name, Version: version, URL: url}, nil
}

func collectNpmEntry(r *bufio.Reader, name, url, version string) (manifest.NpmEntry, error) {
	var err error
	if name, err = prompt(r, "Package name (e.g. lodash or @scope/pkg)", name); err != nil {
		return manifest.NpmEntry{}, err
	}
	if name == "" {
		return manifest.NpmEntry{}, fmt.Errorf("name is required")
	}
	if version, err = prompt(r, "Version", version); err != nil {
		return manifest.NpmEntry{}, err
	}
	if version == "" {
		return manifest.NpmEntry{}, fmt.Errorf("version is required")
	}
	url, _ = prompt(r, "Registry URL (leave blank for registry.npmjs.org)", url)
	return manifest.NpmEntry{Name: name, Version: version, URL: url}, nil
}
