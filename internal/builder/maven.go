package builder

import (
	"context"
	"crypto/md5"  //nolint:gosec // G501: the repository layout's own companion, which Maven compares; it guards nothing here.
	"crypto/sha1" //nolint:gosec // G505: as above, and the upstream's fallback checksum when it publishes no .sha256.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// mavenHTTP bounds one upstream request. Transport is left nil so it is read
// from http.DefaultTransport per request, which is what tests substitute.
var mavenHTTP = &http.Client{Timeout: 10 * time.Minute}

// mavenChecksumMaxBytes caps a checksum companion. Central's are 40 or 64
// hex characters, some followed by the file name.
const mavenChecksumMaxBytes = 1024

// mavenPOMMaxBytes caps the POM read for its packaging. The largest on
// Central run to a few hundred kilobytes.
const mavenPOMMaxBytes = 8 * 1024 * 1024

// mavenRepoRoot is the repository a fetch reads: maven_upstream, the root the
// /maven/ route proxies, so a catalog-mode version holds the bytes a proxied
// one would have been handed.
func mavenRepoRoot(cfg *Config) string {
	if root := strings.TrimRight(cfg.MavenUpstream, "/"); root != "" {
		return root
	}
	return config.DefaultMavenUpstream
}

// mavenLocalPath is where one repository path is kept under maven_root: the
// repository layout itself, so the upload keys each file where the route
// reads it.
func mavenLocalPath(d dirs, repoPath string) string {
	return filepath.Join(d.maven, filepath.FromSlash(repoPath))
}

// mavenMainPath returns the local path of a version's main file, the one its
// checksum describes, or "" when the name and version form no path.
func mavenMainPath(d dirs, name string, ve manifest.VersionEntry) string {
	files, err := manifest.MavenVersionFiles(name, ve)
	if err != nil {
		return ""
	}
	return mavenLocalPath(d, files[0])
}

// MavenArtifactPaths returns every file under maven_root a fetched version
// recorded, checksum companions included, keyed where the /maven/ route reads
// it. A version no fetch has recorded the packaging of names nothing.
func MavenArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeMaven))
	var paths []ArtifactPath
	for _, name := range store.ListPackages(manifest.TypeMaven) {
		if entryFilter != "" && name != entryFilter {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypeMaven, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Metadata[manifest.MetaMavenExtension] == "" {
				continue
			}
			files, err := manifest.MavenVersionFiles(pm.Name, ve)
			if err != nil {
				continue
			}
			for _, f := range files {
				for _, rel := range append([]string{f}, mavenCompanionPaths(f)...) {
					local := mavenLocalPath(d, rel)
					if !fileExists(local) {
						continue
					}
					paths = append(paths, ArtifactPath{
						Local:     local,
						ObjectKey: manifest.MavenKey(rel),
						Package:   name,
						Version:   ve.Version,
					})
				}
			}
		}
	}
	return paths
}

func mavenCompanionPaths(repoPath string) []string {
	out := make([]string, 0, len(manifest.MavenChecksumCompanions))
	for _, c := range manifest.MavenChecksumCompanions {
		out = append(out, repoPath+"."+c)
	}
	return out
}

// CheckMavenStage reports a version fetched when a fetch recorded its
// packaging and every file it names, companions included, is on disk.
func CheckMavenStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	if ve.Metadata[manifest.MetaMavenExtension] == "" {
		return StageStatus{}
	}
	files, err := manifest.MavenVersionFiles(name, ve)
	if err != nil {
		return StageStatus{}
	}
	d := buildDirs(cfg.rootFor(manifest.TypeMaven))
	for _, f := range files {
		for _, rel := range append([]string{f}, mavenCompanionPaths(f)...) {
			if !fileExists(mavenLocalPath(d, rel)) {
				return StageStatus{}
			}
		}
	}
	return StageStatus{Fetched: true, Built: true, Packaged: true}
}

// FetchMaven downloads each maven version's POM, its main artifact as the
// POM's packaging names it, any Gradle module metadata, and the classifiers
// the entry lists, into maven_root in the repository layout. Upload keys them
// where the /maven/ route reads, so a catalog-mode version needs no upstream
// at request time.
//
// Every file is checked against the upstream's .sha256, or its .sha1 where it
// publishes no SHA-256, before it is kept. The SHA-256 of each is pinned under
// its own key, and the main file's is recorded on the entry.
func FetchMaven(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeMaven))

	for _, name := range store.ListPackages(manifest.TypeMaven) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeMaven, name)
		if err != nil || pm == nil {
			cfg.logf("  [maven] %s: ERROR loading package: %v", name, err)
			summary.loadFailed(manifest.TypeMaven, name, err)
			continue
		}
		if strings.HasSuffix(pm.Name, ":"+manifest.MavenGroupWildcard) {
			cfg.logf("  [maven] %s: SKIPPED (a groupId-wide entry names no files to fetch)", name)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [maven] %s: SKIPPED (frozen)", name)
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeMaven, name, ve); err != nil {
				cfg.logf("  [maven] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeMaven, Name: name, Err: err})
				continue
			}
			if !cfg.Force && CheckMavenStage(cfg, pm.Name, ve).Fetched {
				cfg.logf("  [maven] %s@%s: already fetched, skipping", pm.Name, ve.Version)
				if err := cfg.verifyFetchedMaven(ctx, store, d, pm, name, ve); err != nil {
					cfg.logf("  [maven] %s@%s: %v", pm.Name, ve.Version, err)
					summary.Failures++
					summary.Results = append(summary.Results, Result{Type: manifest.TypeMaven, Name: name, Err: err})
				}
				continue
			}

			result := Result{Type: manifest.TypeMaven, Name: name}
			start := time.Now()
			result.Err = fetchMavenVersion(ctx, cfg, store, d, pm, name, ve, &result)
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			status := "success"
			if result.Err != nil {
				summary.Failures++
				status = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeMaven, name, ve.Version, status, result.Elapsed, result.Err)
		}
	}
	return summary
}

// verifyFetchedMaven is verifyFetched for every file of a version: the main
// file against the entry's checksum, and each of the others against its pin.
func (c *Config) verifyFetchedMaven(ctx context.Context, store *manifest.Store, d dirs,
	pm *manifest.PackageManifest, name string, ve manifest.VersionEntry) error {
	if err := c.verifyFetched(ctx, store, manifest.TypeMaven, name, ve); err != nil {
		return err
	}
	files, err := manifest.MavenVersionFiles(pm.Name, ve)
	if err != nil {
		return err
	}
	for _, f := range files[1:] {
		sum, err := computeFileSHA256(mavenLocalPath(d, f))
		if err != nil {
			return fmt.Errorf("maven/%s: %w", name, err)
		}
		if err := c.pinArtifactDigest(ctx, manifest.MavenKey(f), manifest.TypeMaven, pm.Name, ve.Version, newSHA256Checksum(sum), ve.RequiredBy); err != nil {
			return err
		}
	}
	return nil
}

// mavenFile is one file of a version on its way into maven_root.
type mavenFile struct {
	rel     string // repository path
	part    string // where it was downloaded, before it is verified
	digests map[string]string
}

// fetchMavenVersion downloads, verifies and records one version. Nothing is
// moved into maven_root until every file has matched the upstream's checksum
// and any digest already pinned for it, because upload publishes whatever
// sits there.
func fetchMavenVersion(ctx context.Context, cfg *Config, store *manifest.Store, d dirs,
	pm *manifest.PackageManifest, name string, ve manifest.VersionEntry, result *Result) (err error) {
	out := cfg.entryWriter(manifest.TypeMaven, name)
	var got []mavenFile
	defer func() {
		for _, f := range got {
			_ = os.Remove(f.part)
		}
		if err != nil {
			_, _ = fmt.Fprintf(out, "  [maven] %s: ERROR: %v\n", name, err)
		}
	}()

	if strings.HasSuffix(ve.Version, "-SNAPSHOT") {
		return fmt.Errorf("maven %s@%s: a SNAPSHOT is redeployed under the same name, so no digest can be pinned for it; serve it in proxy mode", pm.Name, ve.Version)
	}
	pomRel, ok := manifest.MavenArtifactPath(pm.Name, ve.Version)
	if !ok || manifest.ValidateMavenVersion(pm.Name, ve) != nil {
		return fmt.Errorf("maven %q@%q: the name or version names no repository path; want <groupId>:<artifactId> and a release version", pm.Name, ve.Version)
	}
	root := mavenRepoRoot(cfg)

	fetch := func(rel string, optional bool) (bool, error) {
		f, found, err := fetchMavenFile(root, d, rel, optional, out)
		if found {
			got = append(got, f)
		}
		return found, err
	}

	if _, err := fetch(pomRel, false); err != nil {
		return err
	}
	ext, err := readPOMExtension(got[0].part)
	if err != nil {
		return err
	}
	meta := map[string]string{manifest.MetaMavenExtension: ext}
	if ext != "pom" {
		mainRel, _ := manifest.MavenFilePath(pm.Name, ve.Version, "", ext)
		if _, err := fetch(mainRel, false); err != nil {
			return fmt.Errorf("%w (the POM's packaging names a .%s)", err, ext)
		}
	}
	moduleRel, _ := manifest.MavenFilePath(pm.Name, ve.Version, "", "module")
	if found, err := fetch(moduleRel, true); err != nil {
		return err
	} else if found {
		meta[manifest.MetaMavenModule] = "true"
	}
	for _, c := range ve.Classifiers {
		cls, cext, err := manifest.ParseMavenClassifier(c)
		if err != nil {
			return err
		}
		rel, _ := manifest.MavenFilePath(pm.Name, ve.Version, cls, cext)
		if _, err := fetch(rel, false); err != nil {
			return err
		}
	}

	recorded := ve
	recorded.Metadata = mergeMetadata(ve.Metadata, meta)
	files, err := manifest.MavenVersionFiles(pm.Name, recorded)
	if err != nil {
		return err
	}
	byRel := make(map[string]mavenFile, len(got))
	for _, f := range got {
		byRel[f.rel] = f
	}
	main := byRel[files[0]]

	// Checked before anything is written: updateVersionChecksum saves the
	// entry and only then enforces the pin, which would leave a refused digest
	// on the entry for the next fetch to "verify" against.
	if ve.Checksum != nil {
		if err := verifyChecksum(ve.Checksum, main.digests["sha256"]); err != nil {
			return fmt.Errorf("checksum verification failed for %s: %w", files[0], err)
		}
	}
	if cfg.AuditDB != nil {
		for _, rel := range files {
			key := manifest.MavenKey(rel)
			prior, err := cfg.AuditDB.GetChecksum(ctx, key)
			if err != nil {
				return fmt.Errorf("read pinned checksum for %s: %w", key, err)
			}
			if prior != nil && prior.Value != "" && strings.EqualFold(prior.Algorithm, "sha256") && !strings.EqualFold(prior.Value, byRel[rel].digests["sha256"]) {
				return fmt.Errorf("maven/%s@%s: sha256 mismatch against the pinned digest for %s: pinned=%s fetched=%s",
					pm.Name, ve.Version, key, prior.Value, byRel[rel].digests["sha256"])
			}
		}
	}

	for _, rel := range files {
		f := byRel[rel]
		dest := mavenLocalPath(d, rel)
		if err := os.Rename(f.part, dest); err != nil {
			return fmt.Errorf("move %s into place: %w", dest, err)
		}
		for _, c := range manifest.MavenChecksumCompanions {
			if err := os.WriteFile(dest+"."+c, []byte(f.digests[c]), 0o644); err != nil { //nolint:gosec // G306: served to every client, as the repository is
				return fmt.Errorf("write %s.%s: %w", dest, c, err)
			}
		}
		result.Artifacts = append(result.Artifacts, dest)
	}

	if err := recordMavenVersion(ctx, cfg, store, out, pm, name, ve, recorded, files, byRel); err != nil {
		for _, rel := range files {
			dest := mavenLocalPath(d, rel)
			_ = os.Remove(dest)
			for _, c := range manifest.MavenChecksumCompanions {
				_ = os.Remove(dest + "." + c)
			}
		}
		result.Artifacts = nil
		return err
	}
	_, _ = fmt.Fprintf(out, "  [maven] %s@%s: ok (%d file(s))\n", pm.Name, ve.Version, len(files))
	return nil
}

// recordMavenVersion writes what the fetch learned onto the entry: the
// packaging, the main file's digest and size, and a pin for every file.
func recordMavenVersion(ctx context.Context, cfg *Config, store *manifest.Store, out io.Writer,
	pm *manifest.PackageManifest, name string, ve, recorded manifest.VersionEntry, files []string, byRel map[string]mavenFile) error {
	updateVersionEntry(ctx, store, manifest.TypeMaven, name, ve, func(e *manifest.VersionEntry) {
		e.Metadata = recorded.Metadata
	})
	sum := byRel[files[0]].digests["sha256"]
	if ve.Checksum != nil {
		_, _ = fmt.Fprintf(out, "  [maven] %s@%s: checksum verified\n", pm.Name, ve.Version)
		if err := cfg.updateVersionChecksum(ctx, store, manifest.TypeMaven, name, recorded, ve.Checksum, true); err != nil {
			return err
		}
	} else {
		_, _ = fmt.Fprintf(out, "  [maven] %s@%s: checksum recorded (sha256:%s...)\n", pm.Name, ve.Version, sum[:12])
		if err := cfg.updateVersionChecksum(ctx, store, manifest.TypeMaven, name, recorded, newSHA256Checksum(sum), false); err != nil {
			return err
		}
	}
	for _, rel := range files[1:] {
		cs := newSHA256Checksum(byRel[rel].digests["sha256"])
		if err := cfg.pinArtifactDigest(ctx, manifest.MavenKey(rel), manifest.TypeMaven, pm.Name, ve.Version, cs, ve.RequiredBy); err != nil {
			return err
		}
	}
	d := buildDirs(cfg.rootFor(manifest.TypeMaven))
	stampVersion(ctx, store, manifest.TypeMaven, name, recorded, cfg.GetBuildEnv(), "any")
	stampFetchRecord(ctx, store, manifest.TypeMaven, name, recorded, mavenLocalPath(d, files[0]), sum, nil)
	return nil
}

func mergeMetadata(base, add map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(add))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

// errMavenNotPublished is an optional file the upstream answered 404 for.
var errMavenNotPublished = errors.New("not published")

// fetchMavenFile downloads one repository path beside its final place and
// checks it against the upstream's checksum. found is false only for an
// optional file the upstream does not publish.
func fetchMavenFile(root string, d dirs, rel string, optional bool, out io.Writer) (mavenFile, bool, error) {
	dest := mavenLocalPath(d, rel)
	if err := mkdirAll(filepath.Dir(dest)); err != nil {
		return mavenFile{}, false, err
	}
	f := mavenFile{rel: rel, part: dest + ".part"}
	url := root + "/" + rel
	_, _ = fmt.Fprintf(out, "  [maven] fetching %s\n", url)
	if err := mavenDownload(url, f.part); err != nil {
		_ = os.Remove(f.part)
		if optional && errors.Is(err, errMavenNotPublished) {
			return mavenFile{}, false, nil
		}
		return mavenFile{}, false, err
	}
	digests, err := mavenDigests(f.part)
	if err != nil {
		_ = os.Remove(f.part)
		return mavenFile{}, false, err
	}
	f.digests = digests
	alg, want, err := mavenUpstreamChecksum(url)
	if err != nil {
		_ = os.Remove(f.part)
		return mavenFile{}, false, err
	}
	if !strings.EqualFold(digests[alg], want) {
		_ = os.Remove(f.part)
		return mavenFile{}, false, fmt.Errorf("%s: %s mismatch against the upstream's %s.%s: upstream=%s fetched=%s; the bytes were discarded",
			rel, alg, url, alg, want, digests[alg])
	}
	return f, true, nil
}

// mavenDownload writes url to dest. A 404 is errMavenNotPublished, which a
// caller fetching an optional file reads as absence.
func mavenDownload(url, dest string) error {
	resp, err := mavenHTTP.Get(url) //nolint:noctx // bounded by mavenHTTP's timeout; the host is maven_upstream
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("GET %s: %w by the upstream (HTTP 404)", url, errMavenNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
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

// mavenUpstreamChecksum reads the upstream's checksum for url: its .sha256,
// or its .sha1 when it publishes none. Central publishes .sha1 for every
// file and .sha256 only for newer ones, so the weaker one is accepted only in
// the absence of the stronger.
func mavenUpstreamChecksum(url string) (alg, value string, err error) {
	for _, a := range []struct {
		name   string
		hexLen int
	}{{"sha256", 64}, {"sha1", 40}} {
		resp, err := mavenHTTP.Get(url + "." + a.name) //nolint:noctx // as mavenDownload
		if err != nil {
			return "", "", fmt.Errorf("GET %s.%s: %w", url, a.name, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, mavenChecksumMaxBytes))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", "", fmt.Errorf("GET %s.%s: HTTP %d", url, a.name, resp.StatusCode)
		}
		if err != nil {
			return "", "", fmt.Errorf("read %s.%s: %w", url, a.name, err)
		}
		fields := strings.Fields(string(body))
		if len(fields) == 0 {
			return "", "", fmt.Errorf("%s.%s is empty", url, a.name)
		}
		v := strings.ToLower(fields[0])
		if _, decErr := hex.DecodeString(v); decErr != nil || len(v) != a.hexLen {
			return "", "", fmt.Errorf("%s.%s does not open with a %d-character hex digest: %q", url, a.name, a.hexLen, fields[0])
		}
		return a.name, v, nil
	}
	return "", "", fmt.Errorf("%s: the upstream publishes neither .sha256 nor .sha1 for it, so its bytes cannot be checked and were not kept", url)
}

// mavenDigests computes every checksum companion of a file in one read.
func mavenDigests(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	hs := map[string]hash.Hash{
		"md5":    md5.New(),  //nolint:gosec // G401: see the import
		"sha1":   sha1.New(), //nolint:gosec // G401: see the import
		"sha256": sha256.New(),
		"sha512": sha512.New(),
	}
	ws := make([]io.Writer, 0, len(hs))
	for _, h := range hs {
		ws = append(ws, h)
	}
	if _, err := io.Copy(io.MultiWriter(ws...), f); err != nil {
		return nil, fmt.Errorf("hash %s: %w", path, err)
	}
	out := make(map[string]string, len(hs))
	for alg, h := range hs {
		out[alg] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}

// readPOMExtension reads a POM's <packaging> and returns the extension its
// main artifact is published under, or "pom" for a POM-only version.
func readPOMExtension(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	var doc struct {
		Packaging string `xml:"packaging"`
	}
	if err := xml.NewDecoder(io.LimitReader(f, mavenPOMMaxBytes)).Decode(&doc); err != nil {
		return "", fmt.Errorf("read the POM's packaging: %w", err)
	}
	return manifest.MavenPackagingExtension(doc.Packaging), nil
}
