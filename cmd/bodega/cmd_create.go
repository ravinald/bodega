package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newCreateCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <type> [name]",
		Short: "Add a new entry to a manifest",
		Long: `create adds a new entry to the specified manifest type.

The name can be passed as a positional argument or prompted interactively.
All other fields are prompted. For automation, use 'bodega pkg import'.

Examples:
  bodega pkg create git netbox
  bodega pkg create apt python3
  bodega pkg create gomod github.com/aws/aws-sdk-go-v2
  bodega pkg create binary                              # fully interactive`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			var name string
			if len(args) > 1 {
				name = args[1]
			}
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := context.Background()
			r := bufio.NewReader(os.Stdin)

			var ve manifest.VersionEntry

			switch t {
			case manifest.TypeGit:
				name, ve, err = collectGitVersion(r, name, "", "")
				if err != nil {
					return err
				}

			case manifest.TypeBinary:
				name, ve, err = collectBinaryVersion(r, name, "", "", "")
				if err != nil {
					return err
				}

			case manifest.TypeApt:
				name, ve, err = collectAptVersion(r, name, "", "", "", "")
				if err != nil {
					return err
				}

			case manifest.TypeGomod:
				name, ve, err = collectGomodVersion(r, name, "", "")
				if err != nil {
					return err
				}

			case manifest.TypeHelm:
				name, ve, err = collectHelmVersion(r, name, "", "")
				if err != nil {
					return err
				}

			case manifest.TypeNpm:
				name, ve, err = collectNpmVersion(r, name, "", "")
				if err != nil {
					return err
				}

			case manifest.TypePypi:
				if name == "" {
					if name, err = prompt(r, "Package name", ""); err != nil {
						return err
					}
				}
				if name == "" {
					return fmt.Errorf("name is required for pypi entries")
				}
				ve = manifest.VersionEntry{}
			}

			if err := confirmPolicyOverride(ctx, r, gf, t, name, ve); err != nil {
				return err
			}

			if err := store.AddVersion(ctx, t, name, ve); err != nil {
				return fmt.Errorf("add version: %w", err)
			}
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save index: %w", err)
			}
			fmt.Printf("Added %s entry: %s\n", t, name)

			// Apt post-create: resolve concrete version + dependency discovery.
			if t == manifest.TypeApt && ve.URL == "" && ve.BuildCmd == "" && ve.SourceName != "" {
				// Auto-resolve concrete version when * (any) is used.
				if ve.Version == "*" || ve.Version == "" {
					builder.ResolveAndCreateConcreteVersion(ctx, store, ve.SourceName, os.Stdout)
				}

				depChoice, err := prompt(r, "Include dependencies? (none / direct / transitive)", "none")
				if err == nil && depChoice != "none" && depChoice != "" {
					depth := "direct"
					if depChoice == "transitive" {
						depth = "transitive"
					}
					deps := builder.DiscoverAptDeps(store, ve.SourceName, depth, os.Stdout)
					if len(deps) > 0 {
						added := builder.ImportAptDeps(ctx, store, name, deps, os.Stdout)
						fmt.Printf("Discovered %d deps, added %d new entries\n", len(deps), added)
					} else {
						fmt.Println("No dependencies found")
					}
				}
			}

			// Record create audit event with full manifest.
			if adb := openAuditDB(gf); adb != nil {
				if pm, err := store.GetPackage(ctx, t, name); err == nil && pm != nil {
					afterJSON, _ := json.MarshalIndent(pm, "", "  ")
					_ = adb.Record(ctx, audit.Event{
						EventType: audit.EventCreate,
						PkgType:   t,
						PkgName:   name,
						Status:    "success",
						Details:   audit.FormatDiff(nil, afterJSON),
					})
				}
				adb.Close()
			}

			notifyServer(gf)
			return nil
		},
	}

	return cmd
}

// confirmPolicyOverride runs the upstream allow-list on the entry that was just
// collected interactively. If a violation is found, the operator is warned and
// given a y/N prompt to proceed anyway. Confirmation writes a policy_override
// audit event. This is the ONLY policy enforcement path that allows override —
// the server API, builder fetches, and bodega pkg import all hard-reject.
func confirmPolicyOverride(ctx context.Context, r *bufio.Reader, gf *globalFlags, t, name string, ve manifest.VersionEntry) error {
	adb := openAuditDB(gf)
	if adb == nil {
		return nil
	}
	defer adb.Close()

	checker := policy.NewChecker(adb)
	candidate := policy.CandidateFor(t, name, ve.URL)
	if candidate == "" {
		return nil
	}
	err := checker.Check(ctx, t, candidate)
	if err == nil {
		return nil
	}
	if !policy.IsViolation(err) {
		return fmt.Errorf("policy check: %w", err)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  WARNING: upstream not in allow-list\n")
	fmt.Fprintf(os.Stderr, "    type:      %s\n", t)
	fmt.Fprintf(os.Stderr, "    candidate: %s\n", candidate)
	fmt.Fprintf(os.Stderr, "    fix:       bodega policy add %s %s\n", t, candidate)
	fmt.Fprintln(os.Stderr)

	answer, pErr := prompt(r, "Proceed anyway? [y/N]", "N")
	if pErr != nil {
		return pErr
	}
	if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
		return fmt.Errorf("aborted: upstream violates policy")
	}

	_ = adb.Record(ctx, audit.Event{
		EventType:  audit.EventCreate,
		PkgType:    t,
		PkgName:    name,
		PkgVersion: ve.Version,
		Status:     "policy_override",
		Details:    fmt.Sprintf("candidate=%s", candidate),
	})
	return nil
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
	if url, err = prompt(r, "Source URL", url); err != nil {
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
	if url, err = prompt(r, "Source URL", url); err != nil {
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

	mode, err := prompt(r, "Mode (package-name / direct-url / source-build)", "package-name")
	if err != nil {
		return "", manifest.VersionEntry{}, err
	}

	ve := manifest.VersionEntry{}

	switch mode {
	case "package-name", "":
		if srcName, err = prompt(r, "Package Name (e.g. nginx)", srcName); err != nil {
			return "", manifest.VersionEntry{}, err
		}
		if srcName == "" {
			return "", manifest.VersionEntry{}, fmt.Errorf("package name is required")
		}
		if name == "" {
			name = srcName
		}
		if name, err = prompt(r, "Name", name); err != nil {
			return "", manifest.VersionEntry{}, err
		}
		ve.SourceName = srcName

	case "direct-url":
		if url, err = prompt(r, "Source URL (.deb URL)", url); err != nil {
			return "", manifest.VersionEntry{}, err
		}
		if url == "" {
			return "", manifest.VersionEntry{}, fmt.Errorf("URL is required")
		}
		if name, err = prompt(r, "Name", name); err != nil {
			return "", manifest.VersionEntry{}, err
		}
		if name == "" {
			return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
		}
		ve.URL = url

	case "source-build":
		buildFrom, err := prompt(r, "Build from (git / apt-source)", "git")
		if err != nil {
			return "", manifest.VersionEntry{}, err
		}

		switch buildFrom {
		case "git":
			if url, err = prompt(r, "Git Source URL", url); err != nil {
				return "", manifest.VersionEntry{}, err
			}
			if url == "" {
				return "", manifest.VersionEntry{}, fmt.Errorf("git URL is required")
			}
			if name, err = prompt(r, "Name", name); err != nil {
				return "", manifest.VersionEntry{}, err
			}
			if name == "" {
				return "", manifest.VersionEntry{}, fmt.Errorf("name is required")
			}
			if buildCmd, err = prompt(r, "Build command", buildCmd); err != nil {
				return "", manifest.VersionEntry{}, err
			}
			if debGlob, err = prompt(r, "Deb glob pattern", debGlob); err != nil {
				return "", manifest.VersionEntry{}, err
			}
			ve.URL = url
			ve.BuildCmd = buildCmd
			ve.DebGlob = debGlob

		case "apt-source":
			if srcName, err = prompt(r, "Package Name", srcName); err != nil {
				return "", manifest.VersionEntry{}, err
			}
			if srcName == "" {
				return "", manifest.VersionEntry{}, fmt.Errorf("package name is required")
			}
			if name == "" {
				name = srcName
			}
			if name, err = prompt(r, "Name", name); err != nil {
				return "", manifest.VersionEntry{}, err
			}
			ve.SourceName = srcName
			ve.BuildCmd = "dpkg-buildpackage -us -uc"

		default:
			return "", manifest.VersionEntry{}, fmt.Errorf("unknown build source: %s (expected git or apt-source)", buildFrom)
		}

	default:
		return "", manifest.VersionEntry{}, fmt.Errorf("unknown mode: %s (expected package-name, direct-url, or source-build)", mode)
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
