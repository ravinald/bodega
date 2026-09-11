package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// aptOSVEcosystem maps an apt suite's codename onto the OSV ecosystem that
// answers for it. Those ecosystems are sourced from USN and DSA, so the fixed
// versions they carry are the distro's own backported revisions rather than
// the upstream release that first carried the fix.
//
// Keyed on the release and not on one distro-wide name, because a backported
// fix is a fact about a release: jammy's openssl and noble's openssl are
// different source packages with different fixed versions. OSV's aggregate
// `Ubuntu` export carries every release at once and cannot tell them apart.
//
// A codename OSV carries no release's worth of records for is absent rather
// than approximated to its nearest neighbor. The gate warns on it, which is the
// honest answer; a neighbor's advisories would be the wrong ones.
//
// A superseded interim Ubuntu release is absent for the same reason even though
// OSV answers for it: measured 2026-09-11, mantic, oracular and plucky each
// carry a handful of records against a release's thousands (3, 3 and 4 across
// ten probed source packages, against 421 for xenial). A handful is worse than
// none, because it distills to a non-empty index that passes sync's own
// no-packages check and then reports the rest of the release clean for the
// whole osv_db_max_age window.
var aptOSVEcosystem = map[string]string{
	"trusty":   "Ubuntu:14.04:LTS",
	"xenial":   "Ubuntu:16.04:LTS",
	"bionic":   "Ubuntu:18.04:LTS",
	"focal":    "Ubuntu:20.04:LTS",
	"jammy":    "Ubuntu:22.04:LTS",
	"noble":    "Ubuntu:24.04:LTS",
	"questing": "Ubuntu:25.10",
	"resolute": "Ubuntu:26.04:LTS",
	"wheezy":   "Debian:7",
	"jessie":   "Debian:8",
	"stretch":  "Debian:9",
	"buster":   "Debian:10",
	"bullseye": "Debian:11",
	"bookworm": "Debian:12",
	"trixie":   "Debian:13",
	"forky":    "Debian:14",
}

// aptPockets are the suffixes a suite name carries when it names a pocket
// rather than the release itself. bodega serves whatever name apt_suites
// holds, and "jammy-security" is the same Ubuntu release as "jammy".
var aptPockets = []string{"-security", "-updates", "-backports", "-proposed"}

// AptOSVEcosystem returns the OSV ecosystem that answers for one apt suite, or
// "" when OSV publishes no export for the release it names.
func AptOSVEcosystem(suite string) string {
	base := strings.ToLower(strings.TrimSpace(suite))
	for _, pocket := range aptPockets {
		base = strings.TrimSuffix(base, pocket)
	}
	return aptOSVEcosystem[base]
}

// OSVExportsFor returns the OSV exports a registry type is answered from, and
// the apt suites no export covers.
//
// Every language ecosystem is one export. apt is one per suite: an entry
// published to jammy and one published to noble are answered from different
// exports. unmapped is returned rather than dropped so a sync reports the
// suites it skipped instead of fetching a smaller set in silence.
func OSVExportsFor(registryType string, aptSuites []string) (exports, unmapped []string) {
	if registryType != manifest.TypeApt {
		if eco := osvEcosystemFor[registryType]; eco != "" {
			return []string{eco}, nil
		}
		return nil, nil
	}
	seen := map[string]bool{}
	for _, suite := range aptSuites {
		eco := AptOSVEcosystem(suite)
		if eco == "" {
			unmapped = append(unmapped, suite)
			continue
		}
		if seen[eco] {
			continue
		}
		seen[eco] = true
		exports = append(exports, eco)
	}
	sort.Strings(exports)
	return exports, unmapped
}

// OSVExportSource names the export archive an ecosystem's records come out of.
//
// OSV publishes a per-release archive for every Ubuntu and Debian release and
// stopped writing them in October 2024: measured 2026-09-11,
// Ubuntu:22.04:LTS/all.zip was last written 2024-10-09 and its newest advisory
// is from 2024-10-08, while Ubuntu/all.zip was rebuilt that morning. The
// aggregate carries the same records with the release in each `affected`
// entry's ecosystem string, so the release keying lives in the distill filter
// and nowhere else. Fetching the per-release archive would have shipped a gate
// reporting "synced two minutes ago" over two-year-old advisories, which is
// the shape the max-age warn exists to prevent and cannot see: the age is
// measured on the fetch, not on the contents.
func OSVExportSource(ecosystem string) string {
	if base, _, found := strings.Cut(ecosystem, ":"); found && isDistroEcosystem(ecosystem) {
		return base
	}
	return ecosystem
}

// osvTarget is one (ecosystem, package name) a lookup is made against.
type osvTarget struct {
	ecosystem string
	name      string
}

// osvLookup is what one version entry resolves to before anything is queried.
type osvLookup struct {
	targets []osvTarget
	// queried names the package and the ecosystems the answer came from. A
	// finding an operator cannot trace back to the package they installed is
	// a finding they will not act on, and for apt the name queried is often
	// not the name on the manifest.
	queried string
	// note qualifies a partial answer: a suite with no OSV export sitting
	// beside suites that have one.
	note string
	// unverifiedName marks an apt lookup made under the binary package name
	// because nothing recorded the source. See emptyAnswerReason.
	unverifiedName string
	// reason means nothing could be queried at all.
	reason string
}

// osvLookupFor resolves the lookups one version entry is answered from.
//
// For a language ecosystem that is the registry type's own OSV identifier and
// the package name. For apt it is the source package, because advisories are
// issued against the source and one source builds the several binaries a host
// reports, queried against the ecosystem of every suite the entry itself
// names. The entry's suites and not the server's apt_codename: a catalog
// holding a jammy entry and a noble entry answered from one codename is wrong
// about one of them, in the direction that reports a vulnerable host clean.
//
// defaultSuite covers the entry that names no suite, which is every apt entry
// written before the field existed. The server publishes those under
// apt_codename, so that is the release whose advisories cover them, and it is
// already in the synced set because ServedAptSuites always includes it. Empty
// when the caller holds no Config, and then the entry is unanswerable rather
// than answered from a release nothing chose.
//
// A reason means nothing can answer. B34's rule holds here: the caller warns
// with it rather than passing.
func osvLookupFor(pm *manifest.PackageManifest, ve *manifest.VersionEntry, defaultSuite string) osvLookup {
	if pm.Type != manifest.TypeApt {
		eco := osvEcosystemFor[pm.Type]
		if eco == "" {
			return osvLookup{reason: fmt.Sprintf("%s has no OSV ecosystem", pm.Type)}
		}
		return osvLookup{targets: []osvTarget{{ecosystem: eco, name: pm.Name}}}
	}

	name, kind := ve.SourcePackage, "source package"
	if name == "" {
		name, kind = pm.Name, "binary package"
	}
	suites := ve.EffectiveSuites(defaultSuite)
	exports, unmapped := OSVExportsFor(manifest.TypeApt, suites)
	if len(exports) == 0 {
		return osvLookup{reason: aptUnmappedReason(pm.Name, suites, unmapped)}
	}
	out := osvLookup{
		queried: fmt.Sprintf("%s %s in %s", kind, name, strings.Join(exports, ", ")),
	}
	if ve.SourcePackage == "" {
		out.unverifiedName = aptUnverifiedNameReason(pm.Name, exports)
	}
	for _, eco := range exports {
		out.targets = append(out.targets, osvTarget{ecosystem: eco, name: name})
	}
	if len(unmapped) > 0 {
		out.note = fmt.Sprintf("suite(s) %s were not queried: OSV publishes no Ubuntu or Debian export for them",
			strings.Join(unmapped, ", "))
	}
	return out
}

// aptUnverifiedNameReason is the warn an empty answer under a binary package
// name earns, and it has to name the capture that would fix it: an operator
// told only that the gate could not answer has nowhere to go.
//
// OSV's Ubuntu and Debian ecosystems are keyed on the source package alone, so
// "libexpat1" matches nothing there whether the host is patched or not. Of the
// 101 packages installed in a stock ubuntu:22.04 container, 73 have a source
// name the binary name does not equal; the other 28 answer correctly under
// either. A match therefore settles it: the name that returned records is a
// source package, and only the empty answer is ambiguous.
func aptUnverifiedNameReason(name string, exports []string) string {
	return fmt.Sprintf("apt entry %s was queried under its binary name in %s and matched nothing, "+
		"but Ubuntu and Debian advisories are issued against the source package, "+
		"so an empty answer here is not a clean one; re-capture the host with "+
		"dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Status}\\t${source:Package}\\n' "+
		"and re-import, or set source_package on the version entry",
		name, strings.Join(exports, ", "))
}

// aptUnmappedReason says which suite stopped the lookup, and what to do about
// it. "apt is not covered" would send the operator to the gate's configuration
// for a problem that lives on one version entry.
//
// The no-suite branch is reachable only from a caller holding no default: a
// server resolves an entry naming none to apt_codename before it gets here.
func aptUnmappedReason(name string, suites, unmapped []string) string {
	if len(suites) == 0 {
		return fmt.Sprintf("apt entry %s names no suite, so no Ubuntu or Debian release identifies the advisories that cover it; set suites on the version entry", name)
	}
	return fmt.Sprintf("apt entry %s names suite(s) %s, which OSV publishes no Ubuntu or Debian export for",
		name, strings.Join(unmapped, ", "))
}

// emptyAnswerReason names why an empty result cannot be read as clean, or ""
// when it can.
//
// B34's rule, applied to the one case the lookup itself cannot rule out: a
// binary package name queried against a source-keyed ecosystem answers empty
// for a patched host and for a name that was never in the index, and nothing
// in the answer tells the two apart. A non-empty answer is self-validating and
// needs no warn, which is what keeps the packages whose source and binary
// names agree reporting normally.
func (lk osvLookup) emptyAnswerReason(vulns []osvVuln) string {
	if len(vulns) > 0 {
		return ""
	}
	return lk.unverifiedName
}
