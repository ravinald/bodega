package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const defaultCratesAPI = "https://crates.io"

// PublishedBackfillInterval spaces the upstream requests BackfillPublished
// makes. A store holding a few thousand versions otherwise fires a few
// thousand registry reads back to back, which is what gets an address
// throttled by the registries this reads.
const PublishedBackfillInterval = 250 * time.Millisecond

// formatPublishedAt is the one rendering of a publish time the manifest holds:
// RFC 3339 in UTC, to the second.
func formatPublishedAt(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// upstreamPublishedAt reads a version's publish time from the registry it is
// fetched from, through the same calls the age gate makes. upstream is the
// entry's own url, which for npm, pypi and gomod is the registry root; crates
// publish their times on an API host that the download and index hosts are
// not, so cargo reads CratesAPI instead.
func (c *Config) upstreamPublishedAt(ctx context.Context, typ, name, version, upstream string) (string, error) {
	ac := policy.NewAgeChecker(nil)
	upstream = strings.TrimRight(strings.TrimSpace(upstream), "/")
	switch typ {
	case manifest.TypeNpm:
		ac.NpmRegistry = orDefault(upstream, defaultNpmRegistry)
	case manifest.TypePypi:
		ac.PypiBase = orDefault(upstream, defaultPypiIndex)
	case manifest.TypeGomod:
		ac.GoProxy = orDefault(upstream, defaultGoProxy)
	case manifest.TypeCargo:
		ac.CratesBase = orDefault(strings.TrimRight(c.CratesAPI, "/"), defaultCratesAPI)
	}
	t, err := ac.PublishedAt(ctx, typ, name, version)
	if err != nil {
		return "", err
	}
	return formatPublishedAt(t), nil
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// gomodInfoPublishedAt reads Time out of a .info file a fetch already stored,
// which is the document the age gate would otherwise request again.
func gomodInfoPublishedAt(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the fetch's own destination
	if err != nil {
		return "", err
	}
	var info struct {
		Time string `json:"Time"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if info.Time == "" {
		return "", fmt.Errorf("%s has no Time field", filepath.Base(path))
	}
	t, err := time.Parse(time.RFC3339Nano, info.Time)
	if err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return formatPublishedAt(t), nil
}

// stampPublishedAt records a publish time the fetch read, or says on out why
// it read none. A version left undated is served undated, and a client's
// release-age cooldown passes it, so the line is a warning rather than
// silence. Never a failure: the artifact the fetch stored is good either way.
func stampPublishedAt(ctx context.Context, out io.Writer, store *manifest.Store, typ, name, label string,
	ve manifest.VersionEntry, published string, err error) {
	if err != nil {
		_, _ = fmt.Fprintf(out, "  [%s] %s: WARNING: no publish time recorded: %v\n", typ, label, err)
		return
	}
	_, _ = fmt.Fprintf(out, "  [%s] %s: published %s\n", typ, label, published)
	updateVersionEntry(ctx, store, typ, name, ve, func(v *manifest.VersionEntry) {
		v.PublishedAt = published
	})
}

// stampPypiPublished dates every closure artifact a manifest entry names by
// version. The closure is resolved as a whole, so a distribution that arrives
// only as another's dependency has no entry to carry a time and is skipped.
func (c *Config) stampPypiPublished(ctx context.Context, store *manifest.Store) {
	out := c.stdout()
	pins, err := readPypiLock(pypiLockPath(c.rootFor(manifest.TypePypi)))
	if err != nil {
		_, _ = fmt.Fprintf(out, "  [pypi] WARNING: no publish times recorded: %v\n", err)
		return
	}
	root, err := pypiIndexRoot(ctx, store)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  [pypi] WARNING: no publish times recorded: %v\n", err)
		return
	}
	for spec := range pins {
		dist, version, ok := strings.Cut(spec, "==")
		if !ok {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypePypi, dist)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.PublishedAt != "" || ve.Frozen || !samePyVersion(ve.Version, version) {
				continue
			}
			published, err := c.upstreamPublishedAt(ctx, manifest.TypePypi, pm.Name, version, root)
			stampPublishedAt(ctx, out, store, manifest.TypePypi, pm.Name, pm.Name+"@"+version, ve, published, err)
		}
	}
}

// PublishedBackfill is what BackfillPublished reports.
type PublishedBackfill struct {
	// Filled counts the versions that gained a publish time.
	Filled int
	// Failed counts the versions still undated afterwards, each of which the
	// run named with its reason.
	Failed int
}

// BackfillPublished records published_at on every version in types that a
// fetch dated before the field existed, reading each from upstream with
// interval between requests. A gomod version whose .info is on disk is read
// from that file and costs no request.
//
// Only fills: a recorded time is left alone, and a version that names no
// single release (unset, "*", "any", or an npm dist-tag) is not a version any
// registry can date, so it is passed over rather than counted as a failure.
// Frozen versions are counted as failures, because frozen forbids the edit
// and the version stays undated.
func BackfillPublished(cfg *Config, store *manifest.Store, types []string, entryFilter string, interval time.Duration) PublishedBackfill {
	ctx := context.Background()
	out := cfg.stdout()
	var res PublishedBackfill
	var last time.Time

	pace := func() {
		if wait := interval - time.Since(last); !last.IsZero() && wait > 0 {
			time.Sleep(wait)
		}
		last = time.Now()
	}

	for _, typ := range types {
		pypiRoot := ""
		if typ == manifest.TypePypi {
			if r, err := pypiIndexRoot(ctx, store); err == nil {
				pypiRoot = r
			}
		}
		for _, name := range store.ListPackages(typ) {
			if entryFilter != "" && name != entryFilter {
				continue
			}
			pm, err := store.GetPackage(ctx, typ, name)
			if err != nil || pm == nil {
				continue
			}
			filled := 0
			for i := range pm.Versions {
				ve := &pm.Versions[i]
				if ve.PublishedAt != "" {
					continue
				}
				label := pm.Name + "@" + ve.Version
				if publishedUnpinned(typ, ve.Version) {
					continue
				}
				if ve.Frozen {
					_, _ = fmt.Fprintf(out, "  [%s] %s: WARNING: no publish time recorded: the version is frozen\n", typ, label)
					res.Failed++
					continue
				}

				var published string
				switch {
				case typ == manifest.TypeGomod && fileExists(gomodInfoPath(cfg, name, ve.Version)):
					published, err = gomodInfoPublishedAt(gomodInfoPath(cfg, name, ve.Version))
				default:
					upstream := ve.URL
					if typ == manifest.TypePypi {
						upstream = orDefault(strings.TrimSpace(ve.URL), pypiRoot)
					}
					pace()
					published, err = cfg.upstreamPublishedAt(ctx, typ, pm.Name, ve.Version, upstream)
				}
				if err != nil {
					_, _ = fmt.Fprintf(out, "  [%s] %s: WARNING: no publish time recorded: %v\n", typ, label, err)
					res.Failed++
					continue
				}
				ve.PublishedAt = published
				filled++
				_, _ = fmt.Fprintf(out, "  [%s] %s: published %s\n", typ, label, published)
			}
			if filled == 0 {
				continue
			}
			if err := store.SavePackage(ctx, pm); err != nil {
				_, _ = fmt.Fprintf(out, "  [%s] %s: ERROR saving: %v\n", typ, pm.Name, err)
				res.Failed += filled
				continue
			}
			res.Filled += filled
		}
	}
	return res
}

// publishedUnpinned reports a version string that names no single release.
func publishedUnpinned(typ, version string) bool {
	v := strings.TrimSpace(version)
	if v == "" || v == "*" || v == manifest.ConstraintAny {
		return true
	}
	return typ == manifest.TypeNpm && isNpmDistTag(v)
}

func gomodInfoPath(cfg *Config, name, version string) string {
	return filepath.Join(gomodDir(buildDirs(cfg.rootFor(manifest.TypeGomod)), name), version+".info")
}
