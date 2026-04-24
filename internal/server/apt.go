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

// handleAptGPGKey proxies the GPG public key from S3.
func (s *Server) handleAptGPGKey(w http.ResponseWriter, r *http.Request) {
	s.proxyS3(w, r, "packages/apt/gpg-key.asc")
}

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

	// <codename>/Release or <codename>/InRelease
	if len(parts) == 2 && (parts[1] == "Release" || parts[1] == "InRelease") {
		s.handleAptRelease(w, r, parts[0])
		return
	}

	// <codename>/<component>/binary-<arch>/Packages[.gz]
	if len(parts) == 4 && strings.HasPrefix(parts[2], "binary-") {
		codename := parts[0]
		component := parts[1]
		arch := strings.TrimPrefix(parts[2], "binary-")
		file := parts[3]
		switch file {
		case "Packages":
			s.handleAptPackages(w, r, codename, component, arch)
			return
		case "Packages.gz":
			s.handleAptPackagesGz(w, r, codename, component, arch)
			return
		}
	}

	http.NotFound(w, r)
}

// handleAptRelease generates a Debian Release file from the manifest store.
func (s *Server) handleAptRelease(w http.ResponseWriter, r *http.Request, codename string) {
	if codename != s.cfg.AptCodename {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		s.logger.Error("apt release: list pool keys", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Collect unique architectures from manifest metadata.
	arches := s.aptArchitectures(ctx)
	if len(arches) == 0 {
		arches = []string{"amd64"}
	}

	// Generate Packages content for each arch to compute checksums.
	type indexEntry struct {
		path string
		data []byte
	}
	var entries []indexEntry
	for _, arch := range arches {
		pkgData := s.generateAptPackages(ctx, arch, debKeys)
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
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Origin: bodega\n")
	fmt.Fprintf(&buf, "Label: bodega\n")
	fmt.Fprintf(&buf, "Codename: %s\n", codename)
	fmt.Fprintf(&buf, "Components: main\n")
	fmt.Fprintf(&buf, "Architectures: %s\n", strings.Join(arches, " "))
	now := time.Now().UTC().Add(-24 * time.Hour) // backdate to tolerate client clock skew
	fmt.Fprintf(&buf, "Date: %s\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Valid-Until: %s\n", now.Add(7*24*time.Hour).Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "SHA256:\n")
	for _, e := range entries {
		h := sha256.Sum256(e.data)
		fmt.Fprintf(&buf, " %s %d %s\n", hex.EncodeToString(h[:]), len(e.data), e.path)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// handleAptPackages generates a Debian Packages index for a specific architecture.
func (s *Server) handleAptPackages(w http.ResponseWriter, r *http.Request, codename, component, arch string) {
	if codename != s.cfg.AptCodename || component != "main" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		s.logger.Error("apt packages: list pool keys", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	data := s.generateAptPackages(ctx, arch, debKeys)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleAptPackagesGz serves the gzip-compressed Packages index.
func (s *Server) handleAptPackagesGz(w http.ResponseWriter, r *http.Request, codename, component, arch string) {
	if codename != s.cfg.AptCodename || component != "main" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		s.logger.Error("apt packages.gz: list pool keys", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	data := s.generateAptPackages(ctx, arch, debKeys)
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(data)
	_ = gw.Close()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(gz.Bytes())
}

// aptPoolKeys returns all S3 keys under the apt pool prefix.
func (s *Server) aptPoolKeys(ctx context.Context) ([]string, error) {
	if s.objects == nil {
		return nil, nil
	}
	return s.objects.List(ctx, "packages/apt/pool/")
}

// aptArchitectures returns sorted unique architectures from all apt manifest entries.
func (s *Server) aptArchitectures(ctx context.Context) []string {
	seen := map[string]bool{}
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" {
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

// generateAptPackages builds a Debian Packages file for the given architecture
// from manifest metadata and the S3 pool key listing.
func (s *Server) generateAptPackages(ctx context.Context, arch string, debKeys []string) []byte {
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
			if ve.Hidden || ve.Version == "*" {
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
			seen := map[string]bool{
				"Package": true, "Version": true, "Architecture": true,
				"Description": true,
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
