package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/distinfo"
	"github.com/ravinald/bodega/internal/manifest"
)

// This is the DISTDIR deployment: every distfiles entry is fetched into
// <distfiles_root>/distfiles/<distinfo name>, which is a DISTDIR in layout, and
// a client that reads that directory (NFS, a copy, poudriere's
// DISTFILES_CACHE) never contacts a site at all. do-fetch.sh skips a distfile
// already present in DISTDIR before it consults any site list, which makes this
// the one deployment that stops a build reaching the internet. The HTTP route
// in internal/server only preempts the port's own sites.
//
// A file lands under its final name only after its size and SHA256 match the
// ports tree's distinfo. That ordering is not tidiness: do-fetch.sh tests
// existence and nothing else, so a partial or wrong file under the final name
// would be skipped by the client's fetch and fail only later, at checksum.

// distfilesClient fetches distfiles. No overall timeout, because a distfile
// can run to gigabytes; the dial and header bounds are what stop a dead host
// from holding the run.
var distfilesClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	},
}

func distfilesDestPath(d dirs, name string) string {
	return filepath.Join(d.distfiles, filepath.FromSlash(name))
}

// CheckDistfilesStage reports whether a distfile is present in the DISTDIR.
// The download is the artifact, so all three stages move together.
func CheckDistfilesStage(cfg *Config, name string) StageStatus {
	if manifest.DistfilesValidName(name) != nil {
		return StageStatus{}
	}
	d := buildDirs(cfg.rootFor(manifest.TypeDistfiles))
	if fi, err := os.Stat(distfilesDestPath(d, name)); err == nil && fi.Mode().IsRegular() {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchDistfiles writes every distfiles entry into the DISTDIR under
// <distfiles_root>/distfiles/, admitting each one against the configured ports
// tree's distinfo and refusing any file a port forbids redistributing.
//
// A file already present is re-hashed rather than trusted, because the DISTDIR
// is a directory other tools write into too, and one that no longer matches
// distinfo is replaced.
func FetchDistfiles(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeDistfiles))

	names := []string{}
	for _, safe := range store.ListPackages(manifest.TypeDistfiles) {
		pm, err := store.GetPackage(ctx, manifest.TypeDistfiles, safe)
		if err != nil || pm == nil {
			cfg.logf("  [distfiles] %s: ERROR loading package: %v", safe, err)
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter && safe != entryFilter {
			continue
		}
		if len(pm.Versions) > 0 && pm.Versions[0].Frozen {
			cfg.logf("  [distfiles] %s: SKIPPED (frozen)", pm.Name)
			continue
		}
		names = append(names, pm.Name)
	}
	if len(names) == 0 {
		return summary
	}

	fail := func(name string, err error, elapsed time.Duration) {
		cfg.logf("  [distfiles] %s: ERROR: %v", name, err)
		summary.Total++
		summary.Failures++
		summary.Results = append(summary.Results, Result{Type: manifest.TypeDistfiles, Name: name, Err: err, Elapsed: elapsed})
		cfg.RecordAudit(audit.EventFetch, manifest.TypeDistfiles, name, "", "failure", elapsed, err)
	}

	if cfg.DistfilesPortsTree == "" {
		err := errors.New("distfiles_ports_tree is not set, so there is no distinfo to admit a distfile against; set it to the root of a FreeBSD ports tree at the clients' revision")
		for _, name := range names {
			fail(name, err, 0)
		}
		return summary
	}
	cfg.logf("  [distfiles] reading distinfo under %s", cfg.DistfilesPortsTree)
	ix, err := distinfo.Load(cfg.DistfilesPortsTree)
	if err != nil {
		for _, name := range names {
			fail(name, err, 0)
		}
		return summary
	}
	if err := mkdirAll(d.distfiles); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, name := range names {
		start := time.Now()
		out := cfg.entryWriter(manifest.TypeDistfiles, name)
		_, _ = fmt.Fprintf(out, "\n>>> [distfiles] fetch %s\n", name)

		entry, err := ix.Lookup(name)
		if err != nil {
			// Restricted, not listed, or pinned ambiguously. None of the three
			// leaves a digest this run may admit bytes against.
			fail(name, err, time.Since(start))
			continue
		}
		dest := distfilesDestPath(d, name)
		if !cfg.Force {
			if ok, err := distfileMatches(dest, entry); err == nil && ok {
				cfg.logf("  [distfiles] %s: present and matches distinfo, skipping (use 'force' to re-fetch)", name)
				continue
			}
		}
		src := cfg.DistfilesUpstream + manifest.DistfilesURLPath(name)
		_, _ = fmt.Fprintf(out, "    URL: %s\n    Destination: %s\n", src, dest)
		if err := fetchDistfile(ctx, src, dest, entry); err != nil {
			fail(name, err, time.Since(start))
			continue
		}
		elapsed := time.Since(start)
		_, _ = fmt.Fprintf(out, "    SHA-256: %s (matches distinfo from %s)\n    Size: %s\n    Done (%s)\n",
			entry.SHA256, strings.Join(entry.Ports, ", "), humanBytes(entry.Size), elapsed.Round(time.Millisecond))
		summary.Total++
		summary.Results = append(summary.Results, Result{Type: manifest.TypeDistfiles, Name: name, Artifacts: []string{dest}, Elapsed: elapsed})
		cfg.RecordAudit(audit.EventFetch, manifest.TypeDistfiles, name, "", "success", elapsed, nil)
	}
	return summary
}

// distfileMatches reports whether path holds exactly the bytes entry pins.
func distfileMatches(path string, entry distinfo.Entry) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() != entry.Size {
		return false, nil
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return false, err
	}
	return sum == entry.SHA256, nil
}

// fetchDistfile downloads src into a temporary sibling of dest, holds it to
// entry's size and digest, and renames it into place only when both match.
func fetchDistfile(ctx context.Context, src, dest string, entry distinfo.Entry) error {
	// Plain http is admitted for the reason config.DefaultDistfilesUpstream
	// gives: the digest below, not the transport, decides what is written.
	if u, err := url.Parse(src); err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("refusing %s: distfiles are fetched over http or https", src)
	}
	if err := mkdirAll(filepath.Dir(dest)); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	// The digest is over the file as served; a transport that decoded a
	// content encoding would hash different bytes than `make checksum` reads.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := distfilesClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: upstream returned %d", src, resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != entry.Size {
		return fmt.Errorf("fetch %s: upstream declares %d bytes and distinfo pins %d; nothing was written", src, resp.ContentLength, entry.Size)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".bodega-distfile-*")
	if err != nil {
		return fmt.Errorf("create a temporary file beside %s: %w", dest, err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	// One byte past the pinned size is enough to know the body is wrong, and
	// stops an upstream streaming without end from filling the disk.
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, entry.Size+1))
	if err != nil {
		return fmt.Errorf("read %s after %d bytes: %w; nothing was written", src, n, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if n != entry.Size || got != entry.SHA256 {
		return fmt.Errorf("%s does not match distinfo from %s: got %d bytes with SHA256 %s, want %d bytes with SHA256 %s; nothing was written",
			src, strings.Join(entry.Ports, ", "), n, got, entry.Size, entry.SHA256)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	// 0644 rather than CreateTemp's 0600: the point of a DISTDIR is that a
	// client's build, often as another user, reads it.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("move %s into place: %w", dest, err)
	}
	keep = true
	return nil
}

// DistfilesArtifactPaths returns every distfile present in the DISTDIR, keyed
// for upload. Uploading them prepopulates what the HTTP route would otherwise
// fetch on a miss. Each was admitted against distinfo on its way in, and the
// server still checks distinfo before it serves one.
func DistfilesArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeDistfiles))
	var paths []ArtifactPath
	for _, safe := range store.ListPackages(manifest.TypeDistfiles) {
		pm, err := store.GetPackage(ctx, manifest.TypeDistfiles, safe)
		if err != nil || pm == nil || manifest.DistfilesValidName(pm.Name) != nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter && safe != entryFilter {
			continue
		}
		local := distfilesDestPath(d, pm.Name)
		if fi, err := os.Stat(local); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		version := ""
		if len(pm.Versions) > 0 {
			version = pm.Versions[0].Version
		}
		paths = append(paths, ArtifactPath{
			Local:     local,
			ObjectKey: manifest.DistfilesKey(pm.Name),
			Package:   pm.Name,
			Version:   version,
		})
	}
	return paths
}
