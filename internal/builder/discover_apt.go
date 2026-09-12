package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/manifest"
)

// DiscoverAptDeps queries the local apt cache to find dependencies of pkgName.
// depth is "direct" for immediate deps only, or "transitive" for the full
// closure. Returns nil if apt-cache is not available (e.g. macOS).
func DiscoverAptDeps(store *manifest.Store, pkgName, depth string, out io.Writer) []DiscoveredDep {
	ctx := context.Background()

	if _, err := exec.LookPath("apt-cache"); err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] apt-cache not found; skipping dependency discovery\n")
		return nil
	}

	recurse := depth == "transitive"

	args := []string{"depends",
		"--no-recommends", "--no-suggests",
		"--no-conflicts", "--no-breaks",
		"--no-replaces", "--no-enhances",
	}
	if recurse {
		args = append(args, "--recurse")
	}
	args = append(args, pkgName)

	_, _ = fmt.Fprintf(out, "  [apt] resolving %s dependencies for %s\n", depth, pkgName)

	cmd := exec.Command("apt-cache", args...)
	output, err := cmd.Output()
	if err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] ERROR: apt-cache depends failed: %v\n", err)
		return nil
	}

	names := parseAptCacheDepends(string(output), pkgName)
	_, _ = fmt.Fprintf(out, "  [apt] found %d dependencies\n", len(names))

	// `apt-cache depends` answers which packages, never which releases of
	// them, and "which release" is the whole of what a pin needs: postgresql-14
	// held at 14.9 holds libpq5 still only because it was declared
	// `Depends: libpq5 (= 14.9)`. The relation lives in the control stanza, so
	// read it from there and leave `depends` to enumerate the names.
	rels := fetchAptRelations(pkgName)

	var deps []DiscoveredDep
	for _, name := range names {
		d := DiscoveredDep{
			Ecosystem:  manifest.TypeApt,
			Name:       name,
			RawSpec:    name,
			RequiredBy: "apt/" + pkgName,
		}
		if r, ok := rels[name]; ok {
			d.RawSpec = r.Raw
			// Only an equality relation holds a release still. A `>=` floor
			// says the dependency may move upward and pinning the parent does
			// nothing to stop it, so recording a version there would invent a
			// hold nobody declared.
			if r.Operator == "=" {
				d.Version = r.Version
				d.Constraint = manifest.ConstraintExact
			}
		}
		// Check if already in the store.
		if pm, err := store.GetPackage(ctx, manifest.TypeApt, name); err == nil && pm != nil {
			d.Exists = true
		}
		deps = append(deps, d)
	}

	return deps
}

// parseAptCacheDepends parses the output of `apt-cache depends` (with or
// without --recurse) and returns a deduplicated, sorted list of concrete
// package names. Virtual packages (angle-bracket names) and the queried
// package itself are filtered out.
//
// Sample non-recursive output:
//
//	curl
//	  Depends: libc6
//	  Depends: libcurl4t64
//	  Depends: zlib1g
//	  PreDepends: dpkg
//
// Sample recursive output (indented deps, package headers flush-left):
//
//	curl
//	  Depends: libc6
//	  Depends: libcurl4t64
//	libc6
//	  Depends: libgcc-s1
//	  PreDepends: <libc-any>
func parseAptCacheDepends(output, self string) []string {
	seen := make(map[string]bool)
	seen[self] = true // exclude the queried package

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Lines that start without a dep type prefix are package headers
		// in recursive output (e.g. "libc6"). These are themselves deps.
		if !strings.Contains(line, ":") {
			name := strings.TrimSpace(line)
			if name != "" && !isVirtualPkg(name) && !seen[name] {
				seen[name] = true
			}
			continue
		}

		// Dependency lines: "  Depends: libfoo" or "  PreDepends: libbar"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		depType := strings.TrimSpace(parts[0])
		depName := strings.TrimSpace(parts[1])

		// Only process hard dependencies.
		switch depType {
		case "Depends", "PreDepends":
			// ok
		default:
			continue
		}

		if depName == "" || isVirtualPkg(depName) || seen[depName] {
			continue
		}
		seen[depName] = true
	}

	// Remove self from the result set (it was added to prevent self-reference).
	delete(seen, self)

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// isVirtualPkg returns true for virtual package names like "<libc-dev>".
func isVirtualPkg(name string) bool {
	return strings.HasPrefix(name, "<") && strings.HasSuffix(name, ">")
}

// aptRelation is one dependency as the control stanza declares it: the package
// named, and the version relation that names a release of it.
type aptRelation struct {
	Name string
	// Operator is the Debian relation ("=", ">=", "<=", ">>", "<<"), empty for
	// a dependency declared by name alone.
	Operator string
	Version  string
	// Raw is the relation as written, so a report shows the operator the
	// specifier they would recognize from the package metadata.
	Raw string
}

// addAptEdge records one dependency edge, versioned where the relation named a
// release.
//
// Any edge this parent already held to the same package is removed first. The
// graph dedupes on the exact (parent, child) pair, so a rebuild after the
// declared version moved would leave 14.9 and 15.1 both recorded and the
// closure walk would answer with whichever the file happened to list first.
func addAptEdge(store *manifest.Store, parentName string, d DiscoveredDep) {
	parent := "apt/" + parentName
	child := "apt/" + d.Name
	for _, e := range store.Edges() {
		if e.Parent != parent {
			continue
		}
		if e.Child == child || strings.HasPrefix(e.Child, child+"@") {
			store.RemoveEdge(e.Parent, e.Child)
		}
	}
	if d.Version != "" {
		child += "@" + d.Version
	}
	store.AddEdge(manifest.DepEdge{
		Parent:     parent,
		Child:      child,
		Constraint: d.Constraint,
		RawSpec:    d.RawSpec,
	})
}

// fetchAptRelations reads one package's declared dependency relations from its
// control stanza. Returns nil when apt-cache is unavailable or the package is
// unknown, which leaves every dependency recorded by name alone.
func fetchAptRelations(pkgName string) map[string]aptRelation {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return nil
	}
	out, err := exec.Command("apt-cache", "show", pkgName).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	return parseAptRelationStanzas(string(out))
}

// parseAptRelationStanzas reads the Depends and Pre-Depends relations from the
// first stanza of `apt-cache show` output.
//
// The first stanza alone: apt prints one per candidate version, newest first,
// and merging them would mix the relations of releases that declared different
// ones. Only the candidate is the release bodega is about to catalog.
func parseAptRelationStanzas(output string) map[string]aptRelation {
	var fields map[string]string
	stop := errors.New("first stanza read")
	err := deb822.ParseStream(strings.NewReader(output), func(f map[string]string) error {
		fields = f
		return stop
	})
	if err != nil && !errors.Is(err, stop) {
		return nil
	}
	if fields == nil {
		return nil
	}
	rels := map[string]aptRelation{}
	for _, key := range []string{"Depends", "Pre-Depends"} {
		for _, r := range parseAptRelationField(fields[key]) {
			// A package named by both fields keeps the first relation read.
			// Debian does not define which wins, and a Pre-Depends repeating a
			// Depends declares the same release in practice.
			if _, seen := rels[r.Name]; !seen {
				rels[r.Name] = r
			}
		}
	}
	if len(rels) == 0 {
		return nil
	}
	return rels
}

// parseAptRelationField parses a Depends-style field value:
//
//	libpq5 (= 14.9), libssl3 (>= 3.0.0), libc6 | libc6-udeb, python3:any
//
// Alternatives are each returned. An alternative is another way to satisfy the
// dependency, so both are packages the parent may be built against and the one
// bodega cataloged is the one the edge lands on.
func parseAptRelationField(field string) []aptRelation {
	var out []aptRelation
	for _, group := range strings.Split(field, ",") {
		for _, alt := range strings.Split(group, "|") {
			if r, ok := parseAptRelation(alt); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// parseAptRelation parses one relation: "libpq5 (= 14.9)", "libc6",
// "python3:any (>= 3.12)". The architecture qualifier is dropped; it names
// which build satisfies the dependency, not which release.
func parseAptRelation(s string) (aptRelation, bool) {
	raw := strings.Join(strings.Fields(s), " ")
	if raw == "" {
		return aptRelation{}, false
	}
	r := aptRelation{Raw: raw}
	rest := raw
	if open := strings.Index(rest, "("); open >= 0 {
		end := strings.Index(rest[open:], ")")
		if end < 0 {
			return aptRelation{}, false
		}
		op, version, found := strings.Cut(strings.TrimSpace(rest[open+1:open+end]), " ")
		if !found {
			return aptRelation{}, false
		}
		switch op {
		case "=", ">=", "<=", ">>", "<<":
			r.Operator, r.Version = op, strings.TrimSpace(version)
		default:
			return aptRelation{}, false
		}
		rest = rest[:open]
	}
	name, _, _ := strings.Cut(strings.TrimSpace(rest), ":")
	if name == "" || isVirtualPkg(name) {
		return aptRelation{}, false
	}
	r.Name = name
	return r, true
}

// ImportAptDeps creates manifest entries and graph edges for discovered apt
// dependencies. Only imports deps where Exists is false. Returns count added.
func ImportAptDeps(ctx context.Context, store *manifest.Store, parentName string, deps []DiscoveredDep, out io.Writer) int {
	// The graph is read before it is written. A Store that never loaded it
	// starts from an empty one, and SaveGraph then replaces graph.json with
	// whatever this run discovered: every edge an earlier run recorded is
	// destroyed, with no error and nothing in the output to say so. A pin's
	// closure would then be the last import alone.
	if err := store.LoadGraph(ctx); err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not read the dependency graph, so no edge was recorded: %v\n", err)
		return 0
	}

	added := 0
	wroteEdge := false
	for _, d := range deps {
		// The edge is written whether or not the package is new. A dependency
		// already in the catalog is still a dependency, and a graph that
		// recorded only first sightings would report a pin on a mature
		// package as implying nothing.
		addAptEdge(store, parentName, d)
		wroteEdge = true

		if d.Exists {
			_, _ = fmt.Fprintf(out, "  [apt] %s: already in store, skipping\n", d.Name)
			continue
		}

		// Create a * policy entry for the dependency.
		ve := manifest.VersionEntry{
			Version:           "*",
			VersionConstraint: manifest.ConstraintAny,
			SourceName:        d.Name,
			RequiredBy:        []string{d.RequiredBy},
		}
		if err := store.AddVersion(ctx, manifest.TypeApt, d.Name, ve); err != nil {
			_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not add %s: %v\n", d.Name, err)
			continue
		}
		added++

		// Resolve the concrete version with full metadata.
		ResolveAndCreateConcreteVersion(ctx, store, d.Name, out)
	}

	if added > 0 {
		_, _ = fmt.Fprintf(out, "  [apt] added %d new packages\n", added)
		if err := store.SaveIndex(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not save index: %v\n", err)
		}
	}
	if wroteEdge {
		if err := store.SaveGraph(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not save dependency graph: %v\n", err)
		}
	}

	return added
}

// ValidateAptPackage checks if a package exists in the local apt cache.
// Returns an error message string, or "" if valid.
func ValidateAptPackage(pkgName string) string {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return "" // can't validate, don't block
	}
	cmd := exec.Command("apt-cache", "show", pkgName)
	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("package %q not found in apt cache", pkgName)
	}
	return ""
}

// ValidateAptSource checks if a source package exists in the local apt cache.
// Returns an error message string, or "" if valid.
func ValidateAptSource(pkgName string) string {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return "" // can't validate, don't block
	}
	cmd := exec.Command("apt-cache", "showsrc", pkgName)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return fmt.Sprintf("source package %q not found in apt cache", pkgName)
	}
	return ""
}

// ResolveAptVersion queries the local apt cache for the candidate version of
// a package (what would be installed by `apt-get install`). Returns empty
// string if apt-cache is unavailable or the package is not found.
func ResolveAptVersion(pkgName string) string {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return ""
	}
	cmd := exec.Command("apt-cache", "policy", pkgName)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	// Parse "Candidate: 3.12.3-0ubuntu2.1" from apt-cache policy output.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Candidate:") {
			ver := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			if ver != "(none)" {
				return ver
			}
		}
	}
	return ""
}

// FetchAptMetadata runs `apt-cache show <pkgName>` and parses the output into
// a VersionEntry populated with Description, Platform, and Metadata map.
// Returns nil if apt-cache is unavailable or the package is not found.
func FetchAptMetadata(pkgName string) *manifest.VersionEntry {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return nil
	}
	cmd := exec.Command("apt-cache", "show", pkgName)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	return parseAptShowOutput(string(out), pkgName)
}

// parseAptShowOutput parses the output of `apt-cache show` into a VersionEntry.
// Extracts Version, Description, Architecture, and all other fields into Metadata.
//
// Sample output:
//
//	Package: python3
//	Version: 3.12.3-0ubuntu2.1
//	Architecture: amd64
//	Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
//	Installed-Size: 92
//	Section: python
//	Priority: important
//	Description: interactive high-level object-oriented language (default version)
//	 Python, the high-level, interactive object oriented language,
//	 includes an extensive class library with lots of goodies.
func parseAptShowOutput(output, pkgName string) *manifest.VersionEntry {
	// apt prints Source: only when the source package differs from the binary
	// one, so its absence in a stanza is the statement that the two are equal
	// rather than a field nobody captured. Default accordingly, and the OSV
	// gate reads a name this path confirmed rather than warning on it.
	ve := &manifest.VersionEntry{
		SourceName:    pkgName,
		SourcePackage: pkgName,
		Metadata:      make(map[string]string),
	}

	// Fields we promote to VersionEntry fields rather than Metadata.
	promoted := map[string]bool{
		"Package": true, "Version": true, "Description": true,
		"Architecture": true, "Size": true,
	}

	lines := strings.Split(output, "\n")
	var currentKey string
	var descLines []string
	inDescription := false

	for _, line := range lines {
		// Continuation lines start with a space (part of multi-line Description).
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if inDescription {
				descLines = append(descLines, strings.TrimSpace(line))
			}
			continue
		}

		// End of previous multi-line field.
		inDescription = false

		// Empty line or new package stanza — stop at first stanza.
		if line == "" {
			if ve.Version != "" {
				break // we have a complete stanza
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		currentKey = key

		switch key {
		case "Version":
			ve.Version = val
		case "Source":
			ve.SourcePackage = aptSourceName(val)
			ve.Metadata[key] = val
		case "Architecture":
			ve.Platform = "linux/" + val
			ve.Metadata[key] = val
		case "Size":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				ve.ArtifactSize = n
			}
			ve.Metadata[key] = val
		case "Description":
			// First line of description.
			descLines = []string{val}
			inDescription = true
		default:
			if !promoted[key] {
				ve.Metadata[key] = val
			}
		}
		_ = currentKey // used implicitly by continuation handling
	}

	// Set description from collected lines.
	if len(descLines) > 0 {
		ve.Description = descLines[0] // short description (first line)
		// Store full description in metadata if multi-line.
		if len(descLines) > 1 {
			ve.Metadata["Description-Full"] = strings.Join(descLines, "\n")
		}
	}

	if ve.Version == "" {
		return nil
	}
	return ve
}

// ResolveAndCreateConcreteVersion queries apt for the concrete version of a
// package and creates a fully-populated VersionEntry. Called after creating
// a * (any) policy entry to auto-create the resolved version alongside it.
func ResolveAndCreateConcreteVersion(ctx context.Context, store *manifest.Store, pkgName string, out io.Writer) {
	version := ResolveAptVersion(pkgName)
	if version == "" {
		_, _ = fmt.Fprintf(out, "  [apt] could not resolve version for %s\n", pkgName)
		return
	}

	// Check if this concrete version already exists.
	if pm, err := store.GetPackage(ctx, manifest.TypeApt, pkgName); err == nil && pm != nil {
		for i, existing := range pm.Versions {
			if existing.Version == version {
				// Backfill ArtifactSize and Metadata if missing.
				if existing.ArtifactSize == 0 || len(existing.Metadata) == 0 {
					fresh := FetchAptMetadata(pkgName)
					if fresh != nil {
						if existing.ArtifactSize == 0 && fresh.ArtifactSize > 0 {
							pm.Versions[i].ArtifactSize = fresh.ArtifactSize
						}
						if len(existing.Metadata) == 0 && len(fresh.Metadata) > 0 {
							pm.Versions[i].Metadata = fresh.Metadata
						}
						if existing.Description == "" && fresh.Description != "" {
							pm.Versions[i].Description = fresh.Description
						}
						if existing.Platform == "" && fresh.Platform != "" {
							pm.Versions[i].Platform = fresh.Platform
						}
						_ = store.SavePackage(ctx, pm)
						_, _ = fmt.Fprintf(out, "  [apt] %s@%s: backfilled metadata\n", pkgName, version)
					}
				} else {
					_, _ = fmt.Fprintf(out, "  [apt] %s@%s already exists\n", pkgName, version)
				}
				dropAptPlaceholders(ctx, store, pkgName, out)
				return
			}
		}
	}

	// Fetch full metadata.
	ve := FetchAptMetadata(pkgName)
	if ve == nil {
		// Fallback: create with just the version.
		ve = &manifest.VersionEntry{
			Version:    version,
			SourceName: pkgName,
		}
	}

	// A version-less entry is the placeholder cmd_create wrote before the
	// version was known, not a second package. Fill it in place: adding
	// beside it publishes two stanzas for one package, and no CLI verb can
	// reach the placeholder afterwards because every one of them addresses a
	// version by name.
	if placeholder := fillResolvedVersion(ctx, store, pkgName, ve); placeholder {
		_, _ = fmt.Fprintf(out, "  [apt] resolved %s > %s\n", pkgName, version)
	} else if err := store.AddVersion(ctx, manifest.TypeApt, pkgName, *ve); err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not add %s@%s: %v\n", pkgName, version, err)
		return
	} else {
		_, _ = fmt.Fprintf(out, "  [apt] resolved %s > %s\n", pkgName, version)
	}
	dropAptPlaceholders(ctx, store, pkgName, out)

	// Also set the package-level description if not already set.
	if ve.Description != "" {
		if pm, err := store.GetPackage(ctx, manifest.TypeApt, pkgName); err == nil && pm != nil {
			if pm.Description == "" {
				pm.Description = ve.Description
				_ = store.SavePackage(ctx, pm)
			}
		}
	}
}

// fillResolvedVersion writes resolved onto the first version-less entry for
// pkgName, preserving anything the operator set that the upstream fetch does
// not carry. Reports whether such an entry existed.
func fillResolvedVersion(ctx context.Context, store *manifest.Store, pkgName string, resolved *manifest.VersionEntry) bool {
	pm, err := store.GetPackage(ctx, manifest.TypeApt, pkgName)
	if err != nil || pm == nil {
		return false
	}
	for i, existing := range pm.Versions {
		if existing.Version != "" {
			continue
		}
		merged := existing
		merged.Version = resolved.Version
		if resolved.SourceName != "" {
			merged.SourceName = resolved.SourceName
		}
		if resolved.SourcePackage != "" {
			merged.SourcePackage = resolved.SourcePackage
		}
		if resolved.ArtifactSize > 0 {
			merged.ArtifactSize = resolved.ArtifactSize
		}
		if len(resolved.Metadata) > 0 {
			merged.Metadata = resolved.Metadata
		}
		if resolved.Description != "" {
			merged.Description = resolved.Description
		}
		if resolved.Platform != "" {
			merged.Platform = resolved.Platform
		}
		pm.Versions[i] = merged
		if err := store.SavePackage(ctx, pm); err != nil {
			return false
		}
		return true
	}
	return false
}

// dropAptPlaceholders discards placeholders this resolve left behind and
// reports what it removed. Two paths reach it: a second create for a package
// whose resolved version already exists returns before filling anything, and
// a fill only consumes the first placeholder of however many accumulated.
func dropAptPlaceholders(ctx context.Context, store *manifest.Store, pkgName string, out io.Writer) {
	n, err := DropVersionlessAptEntries(ctx, store, pkgName)
	if err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not drop version-less entries for %s: %v\n", pkgName, err)
		return
	}
	if n > 0 {
		_, _ = fmt.Fprintf(out, "  [apt] dropped %d version-less entry(s) for %s\n", n, pkgName)
	}
}

// DropVersionlessAptEntries removes version-less entries from an apt package
// that also carries at least one resolved version, and reports how many it
// removed.
//
// A version-less entry is the placeholder 'pkg create apt' writes before the
// upstream version is known. Once a resolved entry exists beside it nothing
// can address it: pkg remove, pkg delete, hide and freeze all name a version,
// and the index generator refuses to publish it. Only a sweep can reach it,
// which is why 'bodega repair' calls this too.
//
// A package whose only entry is version-less is left alone. That one is still
// a staging record an operator can resolve; removing it would discard their
// work with nothing to put in its place.
func DropVersionlessAptEntries(ctx context.Context, store *manifest.Store, pkgName string) (int, error) {
	pm, err := store.GetPackage(ctx, manifest.TypeApt, pkgName)
	if err != nil {
		return 0, err
	}
	if pm == nil {
		return 0, nil
	}
	kept := make([]manifest.VersionEntry, 0, len(pm.Versions))
	blank := 0
	for _, ve := range pm.Versions {
		if ve.Version == "" {
			blank++
			continue
		}
		kept = append(kept, ve)
	}
	if blank == 0 || len(kept) == 0 {
		return 0, nil
	}
	pm.Versions = kept
	if err := store.SavePackage(ctx, pm); err != nil {
		return 0, err
	}
	return blank, nil
}

// aptSourceName strips the version a Source: field carries when the source
// package was built at a version the binary does not share: dpkg writes
// "expat (2.4.7-1)" in that case and the bare name otherwise. Advisories are
// keyed on the name alone, so the parenthesized half is noise the OSV lookup
// would query and miss on.
func aptSourceName(val string) string {
	if i := strings.IndexByte(val, '('); i > 0 {
		val = val[:i]
	}
	return strings.TrimSpace(val)
}
