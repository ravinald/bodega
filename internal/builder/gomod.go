package builder

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const defaultGoProxy = "https://proxy.golang.org"

// gomodDir returns the local directory for a Go module's version artifacts.
func gomodDir(d dirs, name string) string {
	// Module paths use slashes (example.com/example-corp/...) which map to nested dirs.
	return filepath.Join(d.gomod, name, "@v")
}

// CheckGomodStage inspects the local filesystem for fetched Go module artifacts.
func CheckGomodStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))
	dir := gomodDir(d, name)

	infoPath := filepath.Join(dir, ve.Version+".info")
	if _, err := os.Stat(infoPath); err != nil {
		return StageStatus{}
	}

	modPath := filepath.Join(dir, ve.Version+".mod")
	zipPath := filepath.Join(dir, ve.Version+".zip")
	modExists := fileExists(modPath)
	zipExists := fileExists(zipPath)

	return StageStatus{
		Fetched:  true,
		Built:    modExists && zipExists,
		Packaged: modExists && zipExists,
	}
}

// FetchGomod downloads Go module artifacts (.info, .mod, .zip) from an upstream
// GOPROXY for each gomod package version in the manifest.
func FetchGomod(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))

	for _, name := range store.ListPackages(manifest.TypeGomod) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeGomod, name)
		if err != nil || pm == nil {
			cfg.logf("  [gomod] %s: ERROR loading package: %v", name, err)
			summary.loadFailed(manifest.TypeGomod, name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [gomod] %s: SKIPPED (frozen)", name)
				continue
			}
			// The module path, not the safe name: the checksum database and the
			// allow-list's prefix rules key by it, and the digest pin the fetch
			// takes names the row it attaches to by it.
			admission, err := cfg.enforceAdmission(ctx, manifest.TypeGomod, pm.Name, ve)
			if err != nil {
				cfg.logf("  [gomod] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeGomod, Name: name, Err: err})
				continue
			}
			if !cfg.Force {
				stage := CheckGomodStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [gomod] %s: already fetched, skipping", name)
					if err := cfg.verifyFetched(ctx, store, manifest.TypeGomod, name, ve); err != nil {
						cfg.logf("  [gomod] %s: %v", name, err)
						summary.Failures++
						summary.Results = append(summary.Results, Result{Type: manifest.TypeGomod, Name: name, Err: err})
					}
					continue
				}
			}

			result := Result{Type: manifest.TypeGomod, Name: name}
			start := time.Now()
			out := cfg.entryWriter(manifest.TypeGomod, name)

			dir := gomodDir(d, name)
			if err := mkdirAll(dir); err != nil {
				result.Err = err
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				summary.Failures++
				continue
			}

			proxy := ve.URL
			if proxy == "" {
				proxy = defaultGoProxy
			}

			// Use pm.Name (original module path with slashes) for the upstream URL,
			// not the safe name from the index which has slashes replaced with --,
			// escaped as the proxy protocol requires of an uppercase letter.
			base := proxy + "/" + manifest.GomodEscapedPath(pm.Name) + "/@v/" + ve.Version

			signed := admit.ChecksumDatabaseEntry(admission.Admission)
			if signed != nil && signed.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
				_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum database %s, so the fetched bytes are not compared with it\n", name, signed.ChecksumDatabase.Outcome)
			}

			var fetchErr error
			for _, ext := range []string{".info", ".mod", ".zip"} {
				url := base + ext
				dest := filepath.Join(dir, ve.Version+ext)
				_, _ = fmt.Fprintf(out, "  [gomod] %s: fetching %s\n", name, url)
				if err := downloadURL(dest, url); err != nil {
					_, _ = fmt.Fprintf(out, "  [gomod] %s: ERROR fetching %s: %v\n", name, ext, err)
					fetchErr = err
					break
				}
				result.Artifacts = append(result.Artifacts, dest)

				// The .mod and .zip are both on disk once the .zip is, and are
				// held to the database before anything records the zip's digest.
				if ext == ".zip" && signed != nil && signed.ChecksumDatabase.Outcome == audit.ProvenanceVerified {
					if err := cfg.compareGomodWithDatabase(ctx, dir, pm.Name, ve.Version, admission.Admission, *signed.ChecksumDatabase); err != nil {
						_, _ = fmt.Fprintf(out, "  [gomod] %s: %v\n", name, err)
						result.Artifacts = nil
						fetchErr = err
						break
					}
					_, _ = fmt.Fprintf(out, "  [gomod] %s: .zip and .mod match the checksum database\n", name)
				}

				// Verify checksum for the .zip (primary artifact).
				if ext == ".zip" {
					computed, err := computeFileSHA256(dest)
					if err != nil {
						_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not compute checksum: %v\n", name, err)
					} else if ve.Checksum != nil {
						if err := verifyChecksum(ve.Checksum, computed); err != nil {
							_, _ = fmt.Fprintf(out, "  [gomod] %s: CHECKSUM MISMATCH: %v\n", name, err)
							fetchErr = fmt.Errorf("checksum verification failed for %s: %w", name, err)
							break
						}
						_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum verified (%s)\n", name, ve.Checksum.Algorithm)
						if !ve.ChecksumVerified {
							if e := cfg.findAndUpdateGomodChecksum(store, name, ve, ve.Checksum, true); e != nil {
								_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not save verified status: %v\n", name, e)
							}
						}
					} else if computed != "" {
						// Auto-populate checksum on first fetch.
						cs := newSHA256Checksum(computed)
						_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum recorded (sha256:%s...)\n", name, computed[:12])
						if e := cfg.findAndUpdateGomodChecksum(store, name, ve, cs, false); e != nil {
							_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not save checksum: %v\n", name, e)
						}
					}
				}
			}

			// Update the @v/list file with this version.
			if fetchErr == nil {
				listPath := filepath.Join(dir, "list")
				if err := appendVersionToList(listPath, ve.Version); err != nil {
					_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not update list: %v\n", name, err)
				}
				cfg.StampGomodEntry(store, name, ve)
				// Stamp artifact size from the .zip file.
				zipPath := filepath.Join(dir, ve.Version+".zip")
				stampArtifactSize(context.Background(), store, manifest.TypeGomod, name, ve, zipPath)
				if ve.PublishedAt == "" {
					published, pErr := gomodInfoPublishedAt(filepath.Join(dir, ve.Version+".info"))
					stampPublishedAt(ctx, out, store, manifest.TypeGomod, name, pm.Name+"@"+ve.Version, ve, published, pErr)
				}
			}

			result.Err = fetchErr
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			if result.Err != nil {
				summary.Failures++
			}
			goStatus := "success"
			if result.Err != nil {
				goStatus = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeGomod, name, ve.Version, goStatus, result.Elapsed, result.Err)
		}
	}

	return summary
}

// compareGomodWithDatabase holds the fetched .zip and .mod of module@version
// to the hashes the checksum database signed. On a disagreement it removes
// the version's three files, so GomodArtifactPaths uploads none of them, and
// writes the policy_blocked row; no policy or override applies.
func (cfg *Config) compareGomodWithDatabase(ctx context.Context, dir, module, version string, admitted audit.Admission, signed audit.ChecksumDatabase) error {
	for _, f := range []struct{ ext, want string }{{".zip", signed.ZipHash}, {".mod", signed.ModHash}} {
		path := filepath.Join(dir, version+f.ext)
		got, err := gomodFileHash(path, f.ext)
		if err != nil {
			got = "an error (" + err.Error() + ")"
		}
		if err == nil && got == f.want {
			continue
		}
		for _, ext := range []string{".info", ".mod", ".zip"} {
			_ = os.Remove(filepath.Join(dir, version+ext))
		}
		_, incident := admit.RecordChecksumMismatch(ctx, cfg.AuditDB, admitted, version+f.ext, got,
			admit.Who{Actor: audit.CurrentActor()})
		return fmt.Errorf("CHECKSUM DATABASE MISMATCH: %s@%s: the fetched %s hashes to %s, but %s signed %s; the version's .info, .mod and .zip were removed and nothing was stored. Incident %s: do not fetch around it; compare what the upstream GOPROXY serves with %s/lookup/%s@%s before trusting either",
			module, version, version+f.ext, got, signed.Database, f.want, incident, cfg.sumdbURL(), manifest.GomodEscapedPath(module), version)
	}
	return nil
}

// gomodFileHash is the go command's h1: hash of a module zip, or of a go.mod
// on its own.
func gomodFileHash(path, ext string) (string, error) {
	if ext == ".zip" {
		return dirhash.HashZip(path, dirhash.Hash1)
	}
	return dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return os.Open(path) }) //nolint:gosec // a build-root path the fetch derived
}

func (cfg *Config) sumdbURL() string {
	if cfg.app != nil && cfg.app.GomodSumdbURL != "" {
		return cfg.app.GomodSumdbURL
	}
	return "https://sum.golang.org"
}

// GomodArtifactPaths returns local/S3 path pairs for upload.
func GomodArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))
	var paths []ArtifactPath

	for _, name := range store.ListPackages(manifest.TypeGomod) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeGomod, name)
		if err != nil || pm == nil {
			continue
		}

		// Keys are derived from pm.Name, not the safe name this loop iterates.
		// A Go client requests the module path with its slashes intact and the
		// server has no way to re-encode it, so the uploader is the side that
		// has to write the wire form.
		for _, ve := range pm.Versions {
			dir := gomodDir(d, name)

			for _, ext := range []string{".info", ".mod", ".zip"} {
				local := filepath.Join(dir, ve.Version+ext)
				if fileExists(local) {
					paths = append(paths, ArtifactPath{
						Local:     local,
						ObjectKey: manifest.GomodKey(pm.Name, ve.Version, ext),
						Package:   name,
						Version:   ve.Version,
					})
				}
			}

			// Include @v/list if it exists.
			listPath := filepath.Join(dir, "list")
			if fileExists(listPath) {
				paths = append(paths, ArtifactPath{
					Local:     listPath,
					ObjectKey: manifest.GomodListKey(pm.Name),
				})
			}
		}
	}

	return paths
}

// downloadURL fetches a URL and writes it to dest.
func downloadURL(dest, url string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return f.Close()
}

// appendVersionToList appends a version to the @v/list file if not already present.
func appendVersionToList(listPath, version string) error {
	existing, _ := os.ReadFile(listPath)
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == version {
			return nil // already listed
		}
	}

	f, err := os.OpenFile(listPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = fmt.Fprintln(f, version)
	return err
}

// fileExists returns true if path exists and is not a directory.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
