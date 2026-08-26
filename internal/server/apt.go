package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"compress/gzip"
	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- APT repository (dynamic index generation) ----------------------------

// handleAptPool proxies .deb files from S3 pool/main/...
func (s *Server) handleAptPool(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if !isSafePath(p) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := "packages/apt/pool/" + p
	setCacheImmutable(w, path.Base(p))
	s.proxyS3(w, r, key)
}

// handleAptDists routes /apt/dists/{distpath...} to the appropriate handler
// based on the path structure. Go's ServeMux doesn't support mid-segment
// wildcards like "binary-{arch}", so we parse the path here.
func (s *Server) handleAptDists(w http.ResponseWriter, r *http.Request) {
	distpath := r.PathValue("distpath")
	parts := strings.Split(distpath, "/")

	if len(parts) == 2 {
		switch parts[1] {
		case "Release":
			s.handleAptRelease(w, r, parts[0])
			return
		case "InRelease", "Release.gpg":
			// Both are signature-bearing documents by definition, and this
			// repository is unsigned. apt fetches InRelease first and falls
			// back to Release on 404, the ordinary path for every archive
			// predating InRelease. Serving unsigned bytes here instead would
			// put a malformed document at a well-known URL.
			http.NotFound(w, r)
			return
		}
	}

	// <suite>/<component>/binary-<arch>/Packages[.gz]
	if len(parts) == 4 && strings.HasPrefix(parts[2], "binary-") {
		suite := parts[0]
		component := parts[1]
		arch := strings.TrimPrefix(parts[2], "binary-")
		file := parts[3]
		switch file {
		case "Packages":
			s.handleAptPackages(w, r, suite, component, arch)
			return
		case "Packages.gz":
			s.handleAptPackagesGz(w, r, suite, component, arch)
			return
		}
	}

	http.NotFound(w, r)
}

// handleAptRelease serves the snapshot's Release for a suite.
func (s *Server) handleAptRelease(w http.ResponseWriter, r *http.Request, suite string) {
	idx, snap, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}

	// A snapshot approaching Valid-Until means the refresh loop has stopped:
	// nothing else lets it age. Past that instant every client fails apt
	// update at once, including with [trusted=yes], because
	// Acquire::Check-Valid-Until is independent of trust.
	if remaining := time.Until(snap.validUntil); remaining < aptExpiryWarn {
		s.logger.Warn("apt Release nears Valid-Until; the index refresh loop is not running",
			"suite", suite,
			"valid_until", snap.validUntil.Format(time.RFC1123Z),
			"built_at", snap.builtAt.Format(time.RFC1123Z),
			"remaining", remaining.Round(time.Minute).String())
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(idx.release)
}

// handleAptPackages serves the snapshot's Packages index for one architecture.
func (s *Server) handleAptPackages(w http.ResponseWriter, r *http.Request, suite, component, arch string) {
	idx, _, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}
	data, found := idx.packages[arch]
	if component != "main" || !found {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleAptPackagesGz serves the gzip-compressed Packages index.
func (s *Server) handleAptPackagesGz(w http.ResponseWriter, r *http.Request, suite, component, arch string) {
	idx, _, ok := s.aptIndex(w, r, suite)
	if !ok {
		return
	}
	data, found := idx.packagesGz[arch]
	if component != "main" || !found {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// aptIndex looks a suite up in the loaded snapshot, writing the response
// itself and returning ok=false when it cannot. An unserved suite is a 404;
// no snapshot at all is a 503, because the suite may well be served and the
// operator's next step is to look at why the build failed, not at their
// sources.list.
func (s *Server) aptIndex(w http.ResponseWriter, r *http.Request, suite string) (*aptSuiteIndex, *aptSnapshot, bool) {
	snap := s.aptSnap.Load()
	if snap == nil {
		s.logger.Error("apt index requested before any snapshot was built", "suite", suite)
		http.Error(w, "apt index unavailable: no snapshot has been built", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	idx := snap.suites[suite]
	if idx == nil {
		http.NotFound(w, r)
		return nil, nil, false
	}
	return idx, snap, true
}

// ---- Index snapshot --------------------------------------------------------

const (
	// aptClockSkew backdates Date so a client running behind the server's
	// clock does not reject a Release stamped in its own future.
	aptClockSkew = 24 * time.Hour

	// aptValidity is the Valid-Until window, measured from the backdated Date.
	// It has to cover any plausible gap between rebuilds: the snapshot's
	// expiry is fixed at build time while real time keeps moving, so a server
	// whose refresh loop dies serves an expired Release from then on.
	aptValidity = 14 * 24 * time.Hour

	// aptRefreshInterval is how often the index is regenerated with no other
	// trigger. Well inside aptValidity so a handful of missed ticks cost
	// nothing.
	aptRefreshInterval = time.Hour

	// aptExpiryWarn is how long before Valid-Until the server starts logging
	// at Warn, so a dead refresh loop surfaces while apt update still works.
	aptExpiryWarn = 24 * time.Hour

	// aptAuditLogLimit caps how many entries one audit warning names.
	aptAuditLogLimit = 10
)

// aptSuiteIndex is one suite's generated dists/<suite>/ tree.
type aptSuiteIndex struct {
	release    []byte
	packages   map[string][]byte // arch -> Packages
	packagesGz map[string][]byte // arch -> Packages.gz
}

// aptSnapshot is one internally consistent generation of every served suite's
// index. Release carries SHA256 digests of the Packages bodies beside it and
// apt fetches the two in separate requests, so they have to be generated
// together and retired together: bytes from two generations are what a
// client reports as "Hash Sum mismatch".
type aptSnapshot struct {
	suites     map[string]*aptSuiteIndex
	builtAt    time.Time
	validUntil time.Time
}

// rebuildAptSnapshot regenerates the index and publishes it to every
// subsequent request. On failure the previous snapshot keeps serving: a stale
// index is a smaller problem than a truncated one, which would have clients
// remove packages that are still published.
func (s *Server) rebuildAptSnapshot(ctx context.Context) {
	snap, err := s.buildAptSnapshot(ctx)
	if err != nil {
		s.logger.Error("apt index rebuild failed, previous snapshot still serving",
			"error", err, "have_snapshot", s.aptSnap.Load() != nil)
		return
	}
	s.aptSnap.Store(snap)
	s.logger.Debug("apt index rebuilt",
		"suites", len(snap.suites), "valid_until", snap.validUntil.Format(time.RFC1123Z))
}

// aptRefreshLoop rebuilds on a ticker until ctx is cancelled. Valid-Until is
// fixed when a snapshot is built, so without this the index expires in place.
func (s *Server) aptRefreshLoop(ctx context.Context) {
	t := time.NewTicker(aptRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.rebuildAptSnapshot(ctx)
		}
	}
}

// buildAptSnapshot generates every served suite's index from current manifest
// and pool state.
func (s *Server) buildAptSnapshot(ctx context.Context) (*aptSnapshot, error) {
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list apt pool keys: %w", err)
	}

	date := time.Now().UTC().Add(-aptClockSkew)
	snap := &aptSnapshot{
		suites:     make(map[string]*aptSuiteIndex),
		builtAt:    time.Now().UTC(),
		validUntil: date.Add(aptValidity),
	}
	served := s.cfg.ServedAptSuites()
	for _, suite := range served {
		snap.suites[suite] = s.buildAptSuiteIndex(ctx, suite, debKeys, date, snap.validUntil)
	}
	s.auditAptEntries(ctx, served)
	return snap, nil
}

// buildAptSuiteIndex generates one suite's Packages bodies and the Release
// that vouches for them.
func (s *Server) buildAptSuiteIndex(ctx context.Context, suite string, debKeys []string, date, validUntil time.Time) *aptSuiteIndex {
	// Collect unique architectures from manifest metadata.
	arches := s.aptArchitectures(ctx, suite)
	if len(arches) == 0 {
		arches = []string{"amd64"}
	}

	idx := &aptSuiteIndex{
		packages:   make(map[string][]byte, len(arches)),
		packagesGz: make(map[string][]byte, len(arches)),
	}

	// Generate Packages content for each arch to compute checksums.
	type indexEntry struct {
		path string
		data []byte
	}
	var entries []indexEntry
	for _, arch := range arches {
		pkgData := s.generateAptPackages(ctx, suite, arch, debKeys)
		entries = append(entries, indexEntry{
			path: "main/binary-" + arch + "/Packages",
			data: pkgData,
		})
		// Gzip variant.
		var gz bytes.Buffer
		gw := gzip.NewWriter(&gz)
		_, _ = gw.Write(pkgData)
		_ = gw.Close()
		entries = append(entries, indexEntry{
			path: "main/binary-" + arch + "/Packages.gz",
			data: gz.Bytes(),
		})
		idx.packages[arch] = pkgData
		idx.packagesGz[arch] = gz.Bytes()
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Origin: bodega\n")
	fmt.Fprintf(&buf, "Label: bodega\n")
	fmt.Fprintf(&buf, "Suite: %s\n", suite)
	fmt.Fprintf(&buf, "Codename: %s\n", suite)
	fmt.Fprintf(&buf, "Components: main\n")
	fmt.Fprintf(&buf, "Architectures: %s\n", strings.Join(arches, " "))
	fmt.Fprintf(&buf, "Date: %s\n", date.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Valid-Until: %s\n", validUntil.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "SHA256:\n")
	for _, e := range entries {
		h := sha256.Sum256(e.data)
		fmt.Fprintf(&buf, " %s %d %s\n", hex.EncodeToString(h[:]), len(e.data), e.path)
	}
	idx.release = buf.Bytes()
	return idx
}

// auditAptEntries reports manifest entries the generator dropped. Both cases
// are silent to the client and produce "Unable to locate package", the same
// message a typo in the package name produces, so without a log line the
// operator has nothing to work from. Neither is an error: staging an entry
// before adding its suite to apt_suites is a legitimate order, and an
// unresolved entry is a normal intermediate state.
//
// Runs once per rebuild rather than inside the per-suite, per-arch generator
// loop, which would repeat every line N times.
func (s *Server) auditAptEntries(ctx context.Context, served []string) {
	servedSet := make(map[string]bool, len(served))
	for _, suite := range served {
		servedSet[suite] = true
	}

	var unserved, unresolved []string
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" {
				continue
			}
			if ve.Version == "" {
				unresolved = append(unresolved, name)
				continue
			}
			if len(ve.Suites) == 0 {
				continue // the default suite, which is always served
			}
			matched := false
			for _, suite := range ve.EffectiveSuites(s.cfg.AptCodename) {
				if servedSet[suite] {
					matched = true
					break
				}
			}
			if !matched {
				unserved = append(unserved, name+"@"+ve.Version+" ["+strings.Join(ve.Suites, ",")+"]")
			}
		}
	}

	if len(unserved) > 0 {
		s.logger.Warn("apt entries name no served suite and reach no index; add the suite to apt_suites or correct the entry",
			"count", len(unserved), "served", strings.Join(served, ","), "entries", capForLog(unserved))
	}
	if len(unresolved) > 0 {
		s.logger.Warn("apt entries have no version and reach no index; no CLI verb can address a versionless entry, so resolve or remove them",
			"count", len(unresolved), "packages", capForLog(unresolved))
	}
}

// capForLog sorts and truncates a list for a single log field, so a hundred
// staged entries do not produce a hundred-line record.
func capForLog(items []string) string {
	sort.Strings(items)
	if len(items) > aptAuditLogLimit {
		return strings.Join(items[:aptAuditLogLimit], " ") + fmt.Sprintf(" (+%d more)", len(items)-aptAuditLogLimit)
	}
	return strings.Join(items, " ")
}

// aptPoolKeys returns all S3 keys under the apt pool prefix.
func (s *Server) aptPoolKeys(ctx context.Context) ([]string, error) {
	if s.objects == nil {
		return nil, nil
	}
	return s.objects.List(ctx, "packages/apt/pool/")
}

// aptArchitectures returns sorted unique architectures from the apt manifest
// entries published to suite.
func (s *Server) aptArchitectures(ctx context.Context, suite string) []string {
	seen := map[string]bool{}
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" || !ve.InSuite(suite, s.cfg.AptCodename) {
				continue
			}
			if arch := ve.Metadata["Architecture"]; arch != "" && arch != "all" {
				seen[arch] = true
			}
		}
	}
	var arches []string
	for a := range seen {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	return arches
}

// generateAptPackages builds a Debian Packages file for the given suite and
// architecture from manifest metadata and the S3 pool key listing.
func (s *Server) generateAptPackages(ctx context.Context, suite, arch string, debKeys []string) []byte {
	// Build a map of source-name+version → S3 pool key for Filename lookup.
	poolMap := make(map[string]string) // "pkgname_version" → relative pool path
	for _, key := range debKeys {
		filename := path.Base(key)
		if !strings.HasSuffix(filename, ".deb") {
			continue
		}
		// Key is like "packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb"
		// We want the relative path after "packages/apt/" for the Filename field.
		relPath := strings.TrimPrefix(key, "packages/apt/")
		// Index by base filename for matching.
		poolMap[filename] = relPath
	}

	var buf bytes.Buffer
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil || isPackageHidden(pm) {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" || !ve.InSuite(suite, s.cfg.AptCodename) {
				continue
			}
			// An entry with no Version is unresolved. Its metadata may carry a
			// Version that would produce a complete-looking stanza, but no CLI
			// verb can address the entry to hide, freeze or remove it, so
			// publishing it hands clients a package nobody can withdraw.
			// auditAptEntries reports these once per rebuild.
			if ve.Version == "" {
				continue
			}
			veArch := ve.Metadata["Architecture"]
			if veArch == "" {
				continue
			}
			// Include if arch matches request or package is arch "all".
			if veArch != arch && veArch != "all" {
				continue
			}

			pkgName := ve.SourceName
			if pkgName == "" {
				pkgName = pm.Name
			}

			// Determine the pool path: prefer stored _pool_path, fall back to S3 lookup.
			poolPath := ve.Metadata["_pool_path"]
			if poolPath == "" {
				poolPath = s.findDebInPool(poolMap, pkgName, ve.Version, veArch)
			}
			if poolPath == "" {
				continue // no .deb uploaded yet
			}

			// Emit canonical apt fields from the manifest in Debian Policy §5.3
			// order. Package/Version/Architecture fall back to manifest fields
			// when metadata doesn't carry them (e.g., freshly edited entries).
			if ve.Metadata["Package"] == "" {
				writeDebField(&buf, "Package", pkgName)
			} else {
				writeDebField(&buf, "Package", ve.Metadata["Package"])
			}
			if ve.Metadata["Version"] == "" {
				writeDebField(&buf, "Version", ve.Version)
			} else {
				writeDebField(&buf, "Version", ve.Metadata["Version"])
			}
			writeDebField(&buf, "Architecture", veArch)

			canonical := []string{
				"Source", "Essential",
				"Maintainer", "Original-Maintainer", "Installed-Size",
				"Pre-Depends", "Depends", "Recommends", "Suggests", "Enhances",
				"Breaks", "Conflicts", "Replaces", "Provides",
				"Section", "Priority", "Multi-Arch", "Homepage",
			}
			// Fields the generator emits itself, from bodega's own record of
			// the artifact. Suppressed in the extras loop below so a metadata
			// copy scraped from upstream cannot land a second, contradictory
			// occurrence in the stanza. deb822 does not define a repeated
			// field, so which one a client keeps is a parser's choice.
			// Origin belongs to Release and names the wrong repository when
			// it arrives here from an upstream scrape.
			seen := map[string]bool{
				"Package": true, "Version": true, "Architecture": true,
				"Description": true, "Filename": true, "Size": true,
				"MD5sum": true, "SHA1": true, "SHA256": true, "Origin": true,
			}
			for _, f := range canonical {
				seen[f] = true
				writeDebField(&buf, f, ve.Metadata[f])
			}

			// Catch-all for less common fields (Built-Using, Python-Version, etc.)
			// so rare-but-legal Debian fields survive the round-trip.
			extras := make([]string, 0)
			for k := range ve.Metadata {
				if strings.HasPrefix(k, "_") || seen[k] {
					continue
				}
				extras = append(extras, k)
			}
			sort.Strings(extras)
			for _, k := range extras {
				writeDebField(&buf, k, ve.Metadata[k])
			}

			writeDebField(&buf, "Filename", poolPath)
			if ve.ArtifactSize > 0 {
				fmt.Fprintf(&buf, "Size: %d\n", ve.ArtifactSize)
			}
			if md5 := ve.Metadata["_md5"]; md5 != "" {
				fmt.Fprintf(&buf, "MD5sum: %s\n", md5)
			}
			if sha1 := ve.Metadata["_sha1"]; sha1 != "" {
				fmt.Fprintf(&buf, "SHA1: %s\n", sha1)
			}
			if sha256 := ve.Metadata["_sha256"]; sha256 != "" {
				fmt.Fprintf(&buf, "SHA256: %s\n", sha256)
			} else if ve.Checksum != nil && ve.Checksum.Algorithm == "sha256" {
				writeDebField(&buf, "SHA256", ve.Checksum.Value)
			}

			// Description goes last and re-introduces the continuation prefix
			// that deb822.ParseSingle stripped. A manifest-level description
			// is used only when metadata has none.
			desc := ve.Metadata["Description"]
			if desc == "" {
				desc = ve.Description
			}
			if desc == "" {
				desc = pm.Description
			}
			if desc != "" {
				writeDebDescription(&buf, desc)
			}
			buf.WriteString("\n")
		}
	}
	return buf.Bytes()
}

// findDebInPool searches the pool map for a .deb matching the given package name,
// version, and architecture.
func (s *Server) findDebInPool(poolMap map[string]string, pkgName, version, arch string) string {
	// Try the standard Debian naming convention first.
	candidate := pkgName + "_" + version + "_" + arch + ".deb"
	if rel, ok := poolMap[candidate]; ok {
		return rel
	}
	// Fallback: scan all pool entries for a match containing name and version.
	prefix := pkgName + "_" + version
	for filename, rel := range poolMap {
		if strings.HasPrefix(filename, prefix) {
			return rel
		}
	}
	return ""
}

// writeDebField writes a single "Key: Value" line to buf, sanitizing val to
// prevent field injection via embedded newlines.
func writeDebField(buf *bytes.Buffer, key, val string) {
	if val == "" {
		return
	}
	// Strip newlines and carriage returns to prevent field injection.
	val = strings.ReplaceAll(val, "\n", " ")
	val = strings.ReplaceAll(val, "\r", "")
	fmt.Fprintf(buf, "%s: %s\n", key, val)
}

// writeDebDescription emits a multi-line Description field using Debian's
// single-space continuation convention. Empty interior lines become " .",
// preserving paragraph breaks in long descriptions.
func writeDebDescription(buf *bytes.Buffer, val string) {
	lines := strings.Split(val, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if i == 0 {
			fmt.Fprintf(buf, "Description: %s\n", line)
			continue
		}
		if line == "" {
			buf.WriteString(" .\n")
		} else {
			buf.WriteString(" ")
			buf.WriteString(line)
			buf.WriteString("\n")
		}
	}
}

// isSafePath rejects path values that contain traversal sequences or encoded
// traversal attempts. Use on any {path...} wildcard before constructing S3 keys.
func isSafePath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	if strings.Contains(p, "%2e") || strings.Contains(p, "%2E") {
		return false
	}
	return p != ""
}

// requireS3 returns true if S3 is available. If not, it writes a 503 and returns false.
func (s *Server) requireS3(w http.ResponseWriter) bool {
	if s.objects == nil {
		http.Error(w, "S3 backend not configured — package serving unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}
