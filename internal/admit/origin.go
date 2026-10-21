package admit

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// MetaOrigin is the VersionEntry metadata key naming the hosts a version was
// cataloged from.
//
// The value is a comma-separated list rather than one name because a package
// installed on db01 and db02 came from both. A catalog holding four hosts'
// inventories that records only the last writer cannot answer which machine
// contributed a row, which is the first question anyone asks of it.
//
// The leading underscore marks it as bodega's own record rather than a field
// of the ecosystem being served, which is what keeps it out of a generated
// index: the apt Packages generator copies unrecognized metadata keys into the
// stanza verbatim, and that file is served unauthenticated to every host
// pointed at bodega. deb822 field names are also case-insensitive, so a bare
// "origin" is the Origin field the generator suppresses on purpose.
const MetaOrigin = "_origin"

// Origins lists the hosts recorded on a version entry, in the order they were
// added. First-seen order is kept so the machine that introduced a package
// stays identifiable after later hosts merge into it.
func Origins(ve manifest.VersionEntry) []string {
	raw := ve.Metadata[MetaOrigin]
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// ApplyOrigin records origin on every version entry of pm that carries none.
//
// An entry naming hosts that do not include origin fails rather than being
// overwritten. The flag and the payload are two claims about where the row
// came from, and silently preferring either discards the fact the field exists
// to hold. An entry that already lists origin among its hosts agrees with the
// flag: re-importing a merged export of db01 and db02 with --origin db01 is a
// restatement, not a contradiction.
func ApplyOrigin(pm *manifest.PackageManifest, origin string) error {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return nil
	}
	if err := ValidateOrigin(origin); err != nil {
		return err
	}
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		have := Origins(*ve)
		if len(have) == 0 {
			setOrigins(ve, []string{origin})
			continue
		}
		if slices.Contains(have, origin) {
			continue
		}
		return fmt.Errorf("%s/%s version %s: --origin %s disagrees with the origin already on the payload (%s); "+
			"drop the flag to keep what the file records, or re-run 'bodega pkg convert --origin' against the inventory",
			pm.Type, pm.Name, versionLabel(*ve), origin, strings.Join(have, ", "))
	}
	return nil
}

// ValidateOrigin rejects a name the comma-separated encoding cannot carry.
func ValidateOrigin(origin string) error {
	if strings.ContainsRune(origin, ',') {
		return fmt.Errorf("origin %q contains a comma; origins are stored as one comma-separated list, so a single name cannot hold one", origin)
	}
	return nil
}

// MergeVersions adds the versions existing does not carry and unions the
// origins onto the ones it does, and reports how many incoming entries it
// appended and how many it folded into a stored one.
//
// A recorded version is never overwritten, which keeps a hosted entry from
// being downgraded to proxy by a re-import of the host that first named it.
// The origins are the exception: a second host reporting the same version is
// new information, and replacing rather than adding would lose the fact that
// both machines have it.
//
// A ref-only entry (git) is matched by its Ref: matched by Version, every one
// of them reads as "" and an incoming ref merges into whichever ref came first.
//
// An apt entry with a URL is matched by version and URL. One apt version is
// published as one .deb per architecture, entries that differ only by URL, so
// matching by version alone folds the second architecture into the first and
// its .deb is never fetched. A stored entry with no URL (what a host capture
// records) still takes it, as it takes a URL-less incoming entry. Other types
// stay matched by version: an npm or pypi URL names a registry rather than an
// artifact, and a re-import from a second registry would add a duplicate.
func MergeVersions(existing, incoming *manifest.PackageManifest) (added, folded int) {
	for _, ve := range incoming.Versions {
		if i := mergeTarget(existing, ve); i >= 0 {
			addOrigins(&existing.Versions[i], Origins(ve))
			folded++
			continue
		}
		existing.Versions = append(existing.Versions, ve)
		added++
	}
	return added, folded
}

// mergeTarget is the index of the stored entry ve folds into, or -1 when ve is
// an entry of its own. An apt URL match beats a URL-less stored entry, so a
// re-import of both architectures folds each onto its own.
func mergeTarget(existing *manifest.PackageManifest, ve manifest.VersionEntry) int {
	byURL := existing.Type == manifest.TypeApt && ve.URL != ""
	urlless := -1
	for i, stored := range existing.Versions {
		if admissionVersion(stored) != admissionVersion(ve) {
			continue
		}
		if !byURL || stored.URL == ve.URL {
			return i
		}
		if stored.URL == "" && urlless < 0 {
			urlless = i
		}
	}
	return urlless
}

// addOrigins unions names into ve's recorded origins, keeping first-seen order.
func addOrigins(ve *manifest.VersionEntry, names []string) {
	if len(names) == 0 {
		return
	}
	merged := Origins(*ve)
	for _, name := range names {
		if !slices.Contains(merged, name) {
			merged = append(merged, name)
		}
	}
	setOrigins(ve, merged)
}

// setOrigins writes names onto ve, allocating the metadata map only when there
// is something to record.
func setOrigins(ve *manifest.VersionEntry, names []string) {
	if len(names) == 0 {
		return
	}
	if ve.Metadata == nil {
		ve.Metadata = map[string]string{}
	}
	ve.Metadata[MetaOrigin] = strings.Join(names, ",")
}
