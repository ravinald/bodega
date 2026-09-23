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
	"syscall"
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
	logUnowned(cfg, ix)
	if err := mkdirAll(d.distfiles); err != nil {
		err = fmt.Errorf("create the DISTDIR %s: %w; nothing was fetched", d.distfiles, err)
		for _, name := range names {
			fail(name, err, 0)
		}
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
		// A digest says the bytes are right; it does not say the operator
		// agreed to contact the host that would supply them.
		if err := cfg.EnforcePolicy(ctx, manifest.TypeDistfiles, name, "", src); err != nil {
			fail(name, fmt.Errorf("%w; allow the host with 'bodega policy add distfiles <host>'", err), time.Since(start))
			continue
		}
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
// for upload, with the release the caller runs once the upload is over.
// Uploading them prepopulates what the HTTP route would otherwise fetch on a
// miss.
//
// Presence in the DISTDIR is not admission. The directory is one other tools
// write into, a file may predate a tree update that repinned or restricted it,
// and an entry may be frozen so FetchDistfiles never re-checked it. So every
// file is held to the current distinfo here, and any one that is restricted,
// unlisted or wrong refuses the whole upload with an error naming each, rather
// than being dropped from the list where nobody would see it go.
//
// The check has to cover the bytes PutFile later reads, not the path. Each
// file is copied into a private directory beside the DISTDIR, created 0700 and
// written O_EXCL, and that copy is what is hashed and uploaded, so no other
// writer can change it between the check and the upload. A hard link would
// share the inode with the DISTDIR, where another process may rewrite the file
// in place after it passed. The copy stops at one byte past the pinned size,
// so a source that grows while it is read cannot fill the disk.
func DistfilesArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) ([]ArtifactPath, func(), error) {
	noRelease := func() {}
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeDistfiles))
	type candidate struct{ name, local, version string }
	var found []candidate
	for _, safe := range store.ListPackages(manifest.TypeDistfiles) {
		pm, err := store.GetPackage(ctx, manifest.TypeDistfiles, safe)
		if err != nil || pm == nil || manifest.DistfilesValidName(pm.Name) != nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter && safe != entryFilter {
			continue
		}
		local := distfilesDestPath(d, pm.Name)
		if fi, err := os.Lstat(local); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		version := ""
		if len(pm.Versions) > 0 {
			version = pm.Versions[0].Version
		}
		found = append(found, candidate{pm.Name, local, version})
	}
	if len(found) == 0 {
		return nil, noRelease, nil
	}
	if cfg.DistfilesPortsTree == "" {
		return nil, noRelease, fmt.Errorf("%d distfile(s) under %s cannot be uploaded: distfiles_ports_tree is not set, so there is no distinfo to hold them to", len(found), d.distfiles)
	}
	ix, err := distinfo.Load(cfg.DistfilesPortsTree)
	if err != nil {
		return nil, noRelease, fmt.Errorf("distfiles cannot be uploaded without their distinfo: %w", err)
	}
	logUnowned(cfg, ix)
	pinDir, err := os.MkdirTemp(filepath.Dir(d.distfiles), ".bodega-distfiles-upload-*")
	if err != nil {
		return nil, noRelease, fmt.Errorf("create a directory to pin distfiles for upload beside %s: %w", d.distfiles, err)
	}
	release := func() { _ = os.RemoveAll(pinDir) }

	var paths []ArtifactPath
	var refused []string
	for _, c := range found {
		entry, err := ix.Lookup(c.name)
		if err != nil {
			refused = append(refused, err.Error())
			continue
		}
		pinned := filepath.Join(pinDir, filepath.FromSlash(c.name))
		if err := pinDistfile(c.local, pinned, entry.Size); err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", c.name, err))
			continue
		}
		if ok, err := distfileMatches(pinned, entry); err != nil || !ok {
			why := "does not match distinfo"
			if err != nil {
				why = err.Error()
			}
			refused = append(refused, fmt.Sprintf("%s: %s %s (want %d bytes with SHA256 %s from %s); 'bodega build fetch distfiles' replaces it",
				c.name, c.local, why, entry.Size, entry.SHA256, strings.Join(entry.Ports, ", ")))
			continue
		}
		paths = append(paths, ArtifactPath{
			Local:     pinned,
			ObjectKey: manifest.DistfilesKey(c.name),
			Package:   c.name,
			Version:   c.version,
		})
	}
	if len(refused) > 0 {
		release()
		return nil, noRelease, fmt.Errorf("refusing to upload distfiles the ports tree at %s does not admit, and uploading none:\n  %s",
			cfg.DistfilesPortsTree, strings.Join(refused, "\n  "))
	}
	return paths, release, nil
}

// pinDistfile copies at most limit+1 bytes of src into dst, a file it creates.
// The extra byte lets the size check that follows see a source longer than
// its pin. src is opened without following a symlink, and must be a regular
// file once open.
func pinDistfile(src, dst string, limit int64) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a DISTDIR path built from a validated distinfo name.
	if err != nil {
		return err
	}
	defer in.Close()
	if fi, err := in.Stat(); err != nil {
		return err
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: under a directory this call created.
	if err != nil {
		return err
	}
	if _, err := io.CopyN(out, in, limit+1); err != nil && !errors.Is(err, io.EOF) {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// logUnowned names the restricted ports whose restriction may not reach every
// distfile they read, so the operator learns it from bodega.
func logUnowned(cfg *Config, ix *distinfo.Index) {
	if u := ix.Unowned(); len(u) > 0 {
		cfg.logf("  [distfiles] WARNING: %d restricted ports read a distinfo bodega cannot place, so distfiles they share with another port are not refused on their account: %s", len(u), strings.Join(u, "; "))
	}
}
