// Package inventory answers "which object backs this manifest entry, and is it
// there?" for every package type.
//
// It lives outside internal/s3 because the answer is not S3-specific: the key
// derivations here are shared by the local backend, by every named backend, and
// by 'bodega pkg move', which needs the same keys to copy. Taking a concrete S3
// client was the reason 'bodega build status' could not see a local install at
// all.
//
// Placement is read from the manifest, never from the config hierarchy. An
// entry records the backend holding its bytes; probing anywhere else reports a
// present artifact as missing the moment a placement rule changes.
package inventory

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const (
	aptPrefix     = "packages/apt/"
	aptPoolPrefix = aptPrefix + "pool/"

	// pypiSentinel is the one object a pypi upload always writes. Wheels are
	// synced as a directory with no per-version key, so this stands in for the
	// whole tree.
	pypiSentinel = "pypi/wheels/MANIFEST.sha256"
)

// EntryStatus describes one manifest entry compared against the backend that
// records it.
type EntryStatus struct {
	Type    string
	Name    string
	Key     string
	Backend string
	Present bool
	Frozen  bool
	ETag    string
	Size    int64

	// Error is the backend's failure for this row, if any. A probe that fails
	// is reported here rather than aborting the walk: a diagnostic exists to
	// say which backend is broken, so it reports every backend it could reach
	// and marks the ones it could not.
	Error string
}

// CheckStatus compares the local manifests against the backends their entries
// record, one row per entry.
//
// The returned error covers only failures that make the report meaningless — a
// manifest that will not load. A backend that will not answer lands in the row
// it belongs to, so one unreachable backend does not hide the other's rows.
func CheckStatus(ctx context.Context, stores storage.Resolver, store *manifest.Store, types []string) ([]EntryStatus, error) {
	c := &checker{stores: stores, store: store, pools: map[string]map[string]string{}}
	var out []EntryStatus
	for _, t := range types {
		rows, err := c.walk(ctx, t)
		out = append(out, rows...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// Failures counts rows whose backend could not answer. Callers exit non-zero on
// a non-zero count: a status report that looks clean because half of it never
// ran is worse than no report.
func Failures(statuses []EntryStatus) int {
	n := 0
	for _, s := range statuses {
		if s.Error != "" {
			n++
		}
	}
	return n
}

// checker carries the per-run state the walks share: the resolver, and one
// lazily-built apt pool listing per backend. The listing is needed only by
// entries predating the _pool_path metadata key, so it is never fetched until
// one turns up.
type checker struct {
	stores storage.Resolver
	store  *manifest.Store
	pools  map[string]map[string]string
}

func (c *checker) walk(ctx context.Context, typ string) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, name := range c.store.ListPackages(typ) {
		pm, err := c.store.GetPackage(ctx, typ, name)
		if err != nil {
			return out, fmt.Errorf("get %s/%s: %w", typ, name, err)
		}
		if pm == nil {
			continue
		}
		if typ == manifest.TypePypi {
			out = append(out, c.pypiRow(ctx, pm))
			continue
		}
		for _, ve := range pm.Versions {
			out = append(out, c.row(ctx, pm, ve))
		}
	}
	return out, nil
}

// row probes one version on the backend its entry records.
func (c *checker) row(ctx context.Context, pm *manifest.PackageManifest, ve manifest.VersionEntry) EntryStatus {
	status := EntryStatus{
		Type:    pm.Type,
		Name:    ve.VersionedName(pm.Name),
		Backend: EffectiveBackend(ve.Storage),
		Frozen:  ve.Frozen,
	}
	store, err := c.stores.ByName(ve.Storage)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	keys, err := ArtifactKeys(ctx, store, pm, ve)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if len(keys) == 0 {
		// No object resolves for this entry; nothing to probe. An apt entry
		// whose .deb was never built lands here.
		return status
	}
	status.Key = keys[0]
	info, err := store.Head(ctx, status.Key)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Present = info.Exists
	status.ETag = info.ETag
	status.Size = info.Size
	return status
}

// pypiRow reports one row per pypi package against the wheel-tree sentinel.
// Wheels are uploaded as a directory with no per-version key, so there is no
// per-version object to probe.
func (c *checker) pypiRow(ctx context.Context, pm *manifest.PackageManifest) EntryStatus {
	recorded := ""
	if len(pm.Versions) > 0 {
		recorded = pm.Versions[0].Storage
	}
	status := EntryStatus{
		Type:    manifest.TypePypi,
		Name:    pm.Name,
		Key:     pypiSentinel,
		Backend: EffectiveBackend(recorded),
	}
	store, err := c.stores.ByName(recorded)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	info, err := store.Head(ctx, pypiSentinel)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Present = info.Exists
	status.ETag = info.ETag
	status.Size = info.Size
	return status
}

// EffectiveBackend applies the empty-means-default rule to a recorded name.
func EffectiveBackend(recorded string) string {
	if recorded == "" {
		return storage.DefaultName
	}
	return recorded
}

// ArtifactKeys returns every object key holding this version's bytes, primary
// first. Empty (with no error) means the entry resolves to no object yet.
//
// store is consulted only by apt, and only for entries predating the
// _pool_path metadata key, which need a pool listing to find their .deb.
//
// This is the one derivation of these keys. 'bodega build status' probes them
// and 'bodega pkg move' copies them; a second copy would let the two disagree
// about which object backs an entry, which is how a move silently leaves bytes
// behind.
func ArtifactKeys(ctx context.Context, store storage.ObjectStore, pm *manifest.PackageManifest, ve manifest.VersionEntry) ([]string, error) {
	// Every key below is the one the uploader writes, derived from the safe
	// name because that is what builder's *ArtifactPaths are handed —
	// Store.ListPackages returns safe names. Deriving from pm.Name instead
	// silently misses every package whose name contains a slash.
	safe := manifest.SafeName(pm.Name)
	switch pm.Type {
	case manifest.TypeBinary:
		filename := ve.Filename
		if filename == "" {
			filename = lastSegment(ve.URL)
		}
		if ve.Version != "" {
			return []string{fmt.Sprintf("binaries/%s/%s/%s", safe, ve.Version, filename)}, nil
		}
		return []string{fmt.Sprintf("binaries/%s/%s", safe, filename)}, nil

	case manifest.TypeGit:
		ext := ".bundle"
		if ve.IsRelease() {
			ext = ".tar.gz"
		}
		ref := ve.Ref
		if ref == "" {
			ref = ve.Version
		}
		return []string{fmt.Sprintf("repos/%s/%s-%s%s", safe, safe, ref, ext)}, nil

	case manifest.TypeApt:
		rel, err := aptPoolPath(ctx, store, pm, ve)
		if err != nil || rel == "" {
			return nil, err
		}
		return []string{aptPrefix + rel}, nil

	case manifest.TypeGomod:
		// The .zip is the artifact; .info and .mod are small siblings that
		// must travel with it or the module is unresolvable once moved.
		prefix := fmt.Sprintf("gomod/%s/@v/%s", safe, ve.Version)
		return []string{prefix + ".zip", prefix + ".info", prefix + ".mod"}, nil

	case manifest.TypeHelm:
		return []string{fmt.Sprintf("charts/%s-%s.tgz", safe, ve.Version)}, nil

	case manifest.TypeNpm:
		return []string{fmt.Sprintf("npm/%s/%s-%s.tgz", safe, safe, ve.Version)}, nil

	case manifest.TypeCargo:
		return []string{fmt.Sprintf("cargo/crates/%s-%s.crate", safe, ve.Version)}, nil

	case manifest.TypePypi:
		return nil, fmt.Errorf("pypi wheels are uploaded as a directory and have no per-version object key")
	}
	return nil, fmt.Errorf("unknown package type %q", pm.Type)
}

// aptPoolPath resolves a version's path relative to packages/apt/, preferring
// the recorded _pool_path and falling back to a listing for entries that
// predate it.
func aptPoolPath(ctx context.Context, store storage.ObjectStore, pm *manifest.PackageManifest, ve manifest.VersionEntry) (string, error) {
	if rel := ve.Metadata["_pool_path"]; rel != "" {
		return rel, nil
	}
	srcName := ve.SourceName
	if srcName == "" {
		srcName = pm.Name
	}
	pool, err := listAptPool(ctx, store)
	if err != nil {
		return "", err
	}
	return findDebInPool(pool, srcName, ve.Version, ve.Metadata["Architecture"]), nil
}

// listAptPool maps each pooled .deb basename to its path relative to
// packages/apt/, matching the Filename form the server emits into Packages.
func listAptPool(ctx context.Context, store storage.ObjectStore) (map[string]string, error) {
	keys, err := store.List(ctx, aptPoolPrefix)
	if err != nil {
		return nil, err
	}
	pool := make(map[string]string, len(keys))
	for _, key := range keys {
		base := path.Base(key)
		if !strings.HasSuffix(base, ".deb") {
			continue
		}
		pool[base] = strings.TrimPrefix(key, aptPrefix)
	}
	return pool, nil
}

// findDebInPool mirrors the server's lookup so status and the served Packages
// index agree on which object backs an entry.
func findDebInPool(pool map[string]string, pkgName, version, arch string) string {
	if rel, ok := pool[pkgName+"_"+version+"_"+arch+".deb"]; ok {
		return rel
	}
	prefix := pkgName + "_" + version
	for base, rel := range pool {
		if strings.HasPrefix(base, prefix) {
			return rel
		}
	}
	return ""
}

// PrintStatus writes a formatted status table to out.
func PrintStatus(out io.Writer, statuses []EntryStatus) {
	_, _ = fmt.Fprintf(out, "\n%-8s %-30s %-10s %-8s %-6s %s\n",
		"TYPE", "NAME", "BACKEND", "PRESENT", "FROZEN", "KEY")
	_, _ = fmt.Fprintf(out, "%s\n", strings.Repeat("-", 96))
	for _, s := range statuses {
		present := "no"
		if s.Present {
			present = "yes"
		}
		if s.Error != "" {
			present = "ERROR"
		}
		frozen := ""
		if s.Frozen {
			frozen = "yes"
		}
		_, _ = fmt.Fprintf(out, "%-8s %-30s %-10s %-8s %-6s %s\n",
			s.Type, s.Name, s.Backend, present, frozen, s.Key)
		if s.Error != "" {
			_, _ = fmt.Fprintf(out, "%-8s %-30s %s\n", "", "", s.Error)
		}
	}
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}
