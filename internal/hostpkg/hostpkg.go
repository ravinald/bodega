// Package hostpkg turns a package manager's own report of what a host has
// installed into bodega manifests.
//
// It exists because the alternative did not work. discover_mode watched a
// proxy and recorded what clients fetched, which sees only cache misses during
// an observation window: a host that has been stable for months fetches
// nothing and reports nothing. The host itself knows its whole inventory and
// every manager will print it, so reading that is complete on the first run.
//
// Every parser takes the manager's output rather than executing it. bodega
// runs on the server and the manager runs on the host, so the two are usually
// different machines, and a parser that shells out cannot be driven by a
// captured fixture.
package hostpkg

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Parser converts one manager's output into manifests. Warnings are for
// entries that converted with something missing, and reach the operator on
// stderr rather than being dropped: a catalog silently missing a URL looks
// complete until the first fetch.
type Parser func(io.Reader) (Result, error)

// Result is what one conversion produced.
type Result struct {
	Packages []manifest.PackageManifest
	Warnings []string
}

// parsers maps a bodega package type to the converter for that ecosystem.
// git and binary are deliberately absent: neither has a host manifest to read.
// A raw curl of a tarball into /usr/local/bin leaves no record any manager
// keeps, which is the gap discover_mode's observe still covers.
var parsers = map[string]Parser{
	manifest.TypeApt:   ParseApt,
	manifest.TypePypi:  ParsePip,
	manifest.TypeNpm:   ParseNpm,
	manifest.TypeGomod: ParseGomod,
	manifest.TypeCargo: ParseCargo,
	manifest.TypeHelm:  ParseHelm,
}

// For returns the parser for a package type.
func For(typ string) (Parser, error) {
	p, ok := parsers[typ]
	if !ok {
		return nil, fmt.Errorf("no host importer for %q; %s", typ, whyNot(typ))
	}
	return p, nil
}

// Types lists the package types a host can be imported for, in bodega's
// canonical order so the help text and the error messages agree.
func Types() []string {
	out := make([]string, 0, len(parsers))
	for _, t := range manifest.AllTypes {
		if _, ok := parsers[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

// whyNot explains an absent importer in terms the operator can act on. A bare
// "unsupported" invites a bug report for something that cannot exist.
func whyNot(typ string) string {
	switch typ {
	case manifest.TypeGit, manifest.TypeBinary:
		return typ + " has no host package manager to read: nothing records a clone or a downloaded binary. " +
			"Catalog these with 'bodega pkg create', or let discover_mode=observe record what clients reach for. " +
			"Importable types: " + strings.Join(Types(), ", ")
	default:
		return "importable types: " + strings.Join(Types(), ", ")
	}
}

// pkg builds a single-version manifest. Every importer produces this shape:
// one package, the one version the host has.
func pkg(typ, name, version, url, mode string) manifest.PackageManifest {
	ve := manifest.VersionEntry{Version: version, URL: url, Mode: mode}
	if typ == manifest.TypeApt {
		// The apt builder resolves an entry with no URL through
		// 'apt-get download <source_name>', which is how an imported host
		// package reaches the pool without anyone naming a mirror.
		ve.SourceName = name
	}
	return manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          name,
		Type:          typ,
		Versions:      []manifest.VersionEntry{ve},
	}
}

// sortPackages orders by name so a re-import of an unchanged host produces a
// byte-identical file. An operator diffs this output against last week's run,
// and map iteration order would make every line look changed.
func sortPackages(pms []manifest.PackageManifest) {
	sort.Slice(pms, func(i, j int) bool { return pms[i].Name < pms[j].Name })
}
