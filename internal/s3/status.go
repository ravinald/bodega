package s3

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// ObjectProber is the object-store surface the status check needs. *Client
// satisfies it; tests substitute a fake so the per-type key derivation can be
// exercised without an S3 endpoint.
type ObjectProber interface {
	HeadObject(ctx context.Context, key string) (*ObjectStatus, error)
	ListPrefix(ctx context.Context, prefix string) ([]string, error)
}

// EntryStatus describes one manifest entry compared against S3.
type EntryStatus struct {
	Type   string
	Name   string
	S3Key  string
	InS3   bool
	Frozen bool
	ETag   string
	SizeS3 int64
}

// CheckStatus compares the local manifests against S3 and returns a per-entry
// status report. Missing entries are marked InS3=false.
func CheckStatus(ctx context.Context, client ObjectProber, store *manifest.Store, types []string) ([]EntryStatus, error) {
	var statuses []EntryStatus

	for _, t := range types {
		var (
			s   []EntryStatus
			err error
		)
		switch t {
		case manifest.TypeBinary:
			s, err = checkBinaryStatus(ctx, client, store)
		case manifest.TypeGit:
			s, err = checkGitStatus(ctx, client, store)
		case manifest.TypeApt:
			s, err = checkAptStatus(ctx, client, store)
		case manifest.TypePypi:
			s, err = checkPypiStatus(ctx, client, store)
		case manifest.TypeGomod:
			s, err = checkGomodStatus(ctx, client, store)
		case manifest.TypeHelm:
			s, err = checkHelmStatus(ctx, client, store)
		case manifest.TypeNpm:
			s, err = checkNpmStatus(ctx, client, store)
		}
		statuses = append(statuses, s...)
		if err != nil {
			return statuses, err
		}
	}

	return statuses, nil
}

func checkBinaryStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, name := range store.ListPackages(manifest.TypeBinary) {
		pm, err := store.GetPackage(ctx, manifest.TypeBinary, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		safeName := manifest.SafeName(pm.Name)
		for _, ve := range pm.Versions {
			filename := ve.Filename
			if filename == "" {
				filename = lastSegment(ve.URL)
			}
			var key string
			if ve.Version != "" {
				key = fmt.Sprintf("binaries/%s/%s/%s", safeName, ve.Version, filename)
			} else {
				key = fmt.Sprintf("binaries/%s/%s", safeName, filename)
			}
			s3stat, err := client.HeadObject(ctx, key)
			if err != nil {
				return out, err
			}
			out = append(out, EntryStatus{
				Type:   manifest.TypeBinary,
				Name:   ve.VersionedName(pm.Name),
				S3Key:  key,
				InS3:   s3stat.Exists,
				Frozen: ve.Frozen,
				ETag:   s3stat.ETag,
				SizeS3: s3stat.Size,
			})
		}
	}
	return out, nil
}

func checkGitStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, name := range store.ListPackages(manifest.TypeGit) {
		pm, err := store.GetPackage(ctx, manifest.TypeGit, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		sn := manifest.SafeName(pm.Name)
		for _, ve := range pm.Versions {
			ext := ".bundle"
			if ve.IsRelease() {
				ext = ".tar.gz"
			}
			ref := ve.Ref
			if ref == "" {
				ref = ve.Version
			}
			key := fmt.Sprintf("repos/%s/%s-%s%s", sn, sn, ref, ext)
			s3stat, err := client.HeadObject(ctx, key)
			if err != nil {
				return out, err
			}
			out = append(out, EntryStatus{
				Type:   manifest.TypeGit,
				Name:   ve.VersionedName(pm.Name),
				S3Key:  key,
				InS3:   s3stat.Exists,
				Frozen: ve.Frozen,
				ETag:   s3stat.ETag,
				SizeS3: s3stat.Size,
			})
		}
	}
	return out, nil
}

const (
	aptPrefix     = "packages/apt/"
	aptPoolPrefix = aptPrefix + "pool/"
)

// checkAptStatus probes the pool object each manifest entry resolves to.
// dists/ holds no stored objects: the server generates Release and Packages
// per request, so there is nothing repository-wide to HEAD and probing one
// reported every entry missing on every install.
func checkAptStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	// Listing the pool is only needed for entries predating _pool_path, so
	// defer it until one turns up.
	var poolMap map[string]string

	for _, name := range store.ListPackages(manifest.TypeApt) {
		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			rel := ve.Metadata["_pool_path"]
			if rel == "" {
				if poolMap == nil {
					poolMap, err = listAptPool(ctx, client)
					if err != nil {
						return out, err
					}
				}
				srcName := ve.SourceName
				if srcName == "" {
					srcName = pm.Name
				}
				rel = findDebInPool(poolMap, srcName, ve.Version, ve.Metadata["Architecture"])
			}

			status := EntryStatus{
				Type:   manifest.TypeApt,
				Name:   ve.VersionedName(pm.Name),
				Frozen: ve.Frozen,
			}
			if rel == "" {
				// No pool object resolves for this entry; nothing to HEAD.
				out = append(out, status)
				continue
			}
			status.S3Key = aptPrefix + rel
			s3stat, err := client.HeadObject(ctx, status.S3Key)
			if err != nil {
				return out, err
			}
			status.InS3 = s3stat.Exists
			status.ETag = s3stat.ETag
			status.SizeS3 = s3stat.Size
			out = append(out, status)
		}
	}
	return out, nil
}

// listAptPool maps each pooled .deb basename to its path relative to
// packages/apt/, matching the Filename form the server emits into Packages.
func listAptPool(ctx context.Context, client ObjectProber) (map[string]string, error) {
	keys, err := client.ListPrefix(ctx, aptPoolPrefix)
	if err != nil {
		return nil, err
	}
	poolMap := make(map[string]string, len(keys))
	for _, key := range keys {
		base := path.Base(key)
		if !strings.HasSuffix(base, ".deb") {
			continue
		}
		poolMap[base] = strings.TrimPrefix(key, aptPrefix)
	}
	return poolMap, nil
}

// findDebInPool resolves a pooled .deb for entries whose manifest predates
// _pool_path. Mirrors the server's lookup so status and the served Packages
// index agree on which object backs an entry.
func findDebInPool(poolMap map[string]string, pkgName, version, arch string) string {
	if rel, ok := poolMap[pkgName+"_"+version+"_"+arch+".deb"]; ok {
		return rel
	}
	prefix := pkgName + "_" + version
	for base, rel := range poolMap {
		if strings.HasPrefix(base, prefix) {
			return rel
		}
	}
	return ""
}

func checkPypiStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	// One status entry per package: check for the wheel MANIFEST.sha256 sentinel.
	const key = "pypi/wheels/MANIFEST.sha256"
	s3stat, err := client.HeadObject(ctx, key)
	if err != nil {
		return nil, err
	}
	var out []EntryStatus
	for _, name := range store.ListPackages(manifest.TypePypi) {
		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		out = append(out, EntryStatus{
			Type:   manifest.TypePypi,
			Name:   pm.Name,
			S3Key:  key,
			InS3:   s3stat.Exists,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

func checkGomodStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, name := range store.ListPackages(manifest.TypeGomod) {
		pm, err := store.GetPackage(ctx, manifest.TypeGomod, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			key := fmt.Sprintf("gomod/%s/@v/%s.zip", pm.Name, ve.Version)
			s3stat, err := client.HeadObject(ctx, key)
			if err != nil {
				return out, err
			}
			out = append(out, EntryStatus{
				Type:   manifest.TypeGomod,
				Name:   ve.VersionedName(pm.Name),
				S3Key:  key,
				InS3:   s3stat.Exists,
				Frozen: ve.Frozen,
				ETag:   s3stat.ETag,
				SizeS3: s3stat.Size,
			})
		}
	}
	return out, nil
}

func checkHelmStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, name := range store.ListPackages(manifest.TypeHelm) {
		pm, err := store.GetPackage(ctx, manifest.TypeHelm, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		safeName := manifest.SafeName(pm.Name)
		for _, ve := range pm.Versions {
			key := fmt.Sprintf("charts/%s/%s/%s-%s.tgz", safeName, ve.Version, pm.Name, ve.Version)
			s3stat, err := client.HeadObject(ctx, key)
			if err != nil {
				return out, err
			}
			out = append(out, EntryStatus{
				Type:   manifest.TypeHelm,
				Name:   ve.VersionedName(pm.Name),
				S3Key:  key,
				InS3:   s3stat.Exists,
				Frozen: ve.Frozen,
				ETag:   s3stat.ETag,
				SizeS3: s3stat.Size,
			})
		}
	}
	return out, nil
}

func checkNpmStatus(ctx context.Context, client ObjectProber, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, name := range store.ListPackages(manifest.TypeNpm) {
		pm, err := store.GetPackage(ctx, manifest.TypeNpm, name)
		if err != nil {
			return out, err
		}
		if pm == nil {
			continue
		}
		safeName := manifest.SafeName(pm.Name)
		for _, ve := range pm.Versions {
			key := fmt.Sprintf("npm/%s/%s/%s-%s.tgz", safeName, ve.Version, pm.Name, ve.Version)
			s3stat, err := client.HeadObject(ctx, key)
			if err != nil {
				return out, err
			}
			out = append(out, EntryStatus{
				Type:   manifest.TypeNpm,
				Name:   ve.VersionedName(pm.Name),
				S3Key:  key,
				InS3:   s3stat.Exists,
				Frozen: ve.Frozen,
				ETag:   s3stat.ETag,
				SizeS3: s3stat.Size,
			})
		}
	}
	return out, nil
}

// PrintStatus writes a formatted status table to out.
func PrintStatus(out io.Writer, statuses []EntryStatus) {
	_, _ = fmt.Fprintf(out, "\n%-8s %-30s %-6s %-6s %s\n",
		"TYPE", "NAME", "IN_S3", "FROZEN", "S3_KEY")
	_, _ = fmt.Fprintf(out, "%s\n", repeat("-", 80))
	for _, s := range statuses {
		inS3 := "no"
		if s.InS3 {
			inS3 = "yes"
		}
		frozen := ""
		if s.Frozen {
			frozen = "yes"
		}
		_, _ = fmt.Fprintf(out, "%-8s %-30s %-6s %-6s %s\n",
			s.Type, s.Name, inS3, frozen, s.S3Key)
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

func repeat(c string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += c
	}
	return out
}
