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
const MetaOrigin = "origin"

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
// An entry already naming a different host fails rather than being
// overwritten. The flag and the payload are two claims about where the row
// came from, and silently preferring either discards the fact the field exists
// to hold.
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
		if len(have) == 1 && have[0] == origin {
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
// origins onto the ones it does.
//
// A recorded version is never overwritten, which keeps a hosted entry from
// being downgraded to proxy by a re-import of the host that first named it.
// The origins are the exception: a second host reporting the same version is
// new information, and replacing rather than adding would lose the fact that
// both machines have it.
func MergeVersions(existing, incoming *manifest.PackageManifest) {
	for _, ve := range incoming.Versions {
		found := false
		for i := range existing.Versions {
			if existing.Versions[i].Version == ve.Version {
				addOrigins(&existing.Versions[i], Origins(ve))
				found = true
				break
			}
		}
		if !found {
			existing.Versions = append(existing.Versions, ve)
		}
	}
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
