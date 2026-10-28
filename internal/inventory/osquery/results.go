package osquery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
)

// Query is one entry in an osquery schedule.
type Query struct {
	Query    string `json:"query"`
	Interval int64  `json:"interval"`
	Snapshot bool   `json:"snapshot"`
	Platform string `json:"platform"`
}

// AutoTable is one entry in osquery's auto_table_construction config: a
// table osquery builds at config load by running query against the SQLite
// file at path.
type AutoTable struct {
	Query    string   `json:"query"`
	Path     string   `json:"path"`
	Columns  []string `json:"columns"`
	Platform string   `json:"platform"`
}

// TableFreeBSDPkg is the table the FreeBSD query reads. osquery's FreeBSD
// build registers no pkg_packages table, and pkg's own database is SQLite, so
// the config mounts that database as this table instead.
const TableFreeBSDPkg = "bodega_pkg_packages"

// TableFreeBSDOrigins mounts the same database's repository annotation: the
// name of the repository pkg installed each package from, as pkg.conf names
// it.
const TableFreeBSDOrigins = "bodega_pkg_origins"

const freebsdPkgDB = "/var/db/pkg/local.sqlite"

// AutoTables is the auto_table_construction block every config carries
// beside the schedule. platform keeps a Linux host from mounting a path it
// does not have. origins adds the repository annotation table the origins
// schedule joins.
func AutoTables(origins bool) map[string]AutoTable {
	out := map[string]AutoTable{
		TableFreeBSDPkg: {
			Query:    "SELECT name, version FROM packages",
			Path:     freebsdPkgDB,
			Columns:  []string{"name", "version"},
			Platform: "freebsd",
		},
	}
	if origins {
		out[TableFreeBSDOrigins] = AutoTable{
			Query: "SELECT p.name, p.version, v.annotation AS repository FROM packages p" +
				" JOIN pkg_annotation pa ON pa.package_id = p.id" +
				" JOIN annotation t ON t.annotation_id = pa.tag_id AND t.annotation = 'repository'" +
				" JOIN annotation v ON v.annotation_id = pa.value_id",
			Path:     freebsdPkgDB,
			Columns:  []string{"name", "version", "repository"},
			Platform: "freebsd",
		}
	}
	return out
}

// The schedule's query names, one per platform. A result line is read as
// inventory when its query name contains QueryMarker, which covers both and
// any name a fleet manager builds around them (osquery packs prefix
// "pack_<pack>_").
const (
	QueryLinux   = "bodega_packages_linux"
	QueryFreeBSD = "bodega_packages_freebsd"
	QueryMarker  = "bodega_packages"
)

// Schedule is the schedule a host scanning dirs is handed. Each platform
// gets one snapshot query unioning every table it has, so one run yields one
// result event and one report holds the host's whole installed set. Separate
// per-table queries would each fire on their own timer, and a report holding
// only the python packages would read as a host whose debs were removed.
//
// deb_packages lists every package dpkg remembers, so the Linux select keeps
// only installed ones: a package removed with its config left behind reads
// "deinstall ok config-files" and is not on the host.
//
// origins adds an origin column, filled from bodega's extension tables and
// the pkg repository annotation. Without it the queries name none of them:
// osquery fails a query naming a table the host has not loaded, whole, so a
// host without the extension would report nothing at all.
//
// The output depends on its arguments alone, with directories sorted and
// deduplicated, so the schedule changes only when the plan does.
func Schedule(dirs config.OsqueryDirs, interval time.Duration, origins bool) map[string]Query {
	secs := int64(interval / time.Second)
	lang := languageSelects(dirs, origins)
	linux := []string{
		"SELECT 'apt' AS ecosystem, name, version, '' AS path FROM deb_packages WHERE status = 'install ok installed'",
		"SELECT 'rpm', name, version || '-' || release, '' FROM rpm_packages",
	}
	freebsd := []string{"SELECT 'freebsd' AS ecosystem, name, version, '' AS path FROM " + TableFreeBSDPkg}
	if origins {
		linux = []string{
			"SELECT 'apt' AS ecosystem, name, version, '' AS path, '' AS origin FROM deb_packages WHERE status = 'install ok installed'",
			"SELECT 'rpm', name, version || '-' || release, '', '' FROM rpm_packages",
		}
		freebsd = []string{"SELECT 'freebsd' AS ecosystem, p.name, p.version, '' AS path, o.repository AS origin FROM " + TableFreeBSDPkg +
			" p LEFT JOIN " + TableFreeBSDOrigins + " o ON o.name = p.name AND o.version = p.version"}
	}
	return map[string]Query{
		QueryLinux: {
			Query:    unionAll(append(linux, lang...)),
			Interval: secs, Snapshot: true, Platform: "linux",
		},
		QueryFreeBSD: {
			Query:    unionAll(append(freebsd, lang...)),
			Interval: secs, Snapshot: true, Platform: "freebsd",
		},
	}
}

// languageSelects queries python_packages and npm_packages only over the
// declared directories. With none declared the table is left out: unfiltered,
// python_packages walks only the interpreter's default paths and npm_packages
// only global modules, which would read as a scan that found nothing.
//
// Under origins each joins the extension's table over the same directories.
// The origin rows sit in a subquery because SQLite never flattens one holding
// a virtual table into the right side of a LEFT JOIN: it is read once per
// run, not once per package, and a package with no origin row still reports.
func languageSelects(dirs config.OsqueryDirs, origins bool) []string {
	var out []string
	if in := sqlList(dirs.Python); in != "" {
		if origins {
			out = append(out, "SELECT 'pypi', p.name, p.version, p.path, o.url FROM python_packages p"+
				" LEFT JOIN (SELECT path, url FROM "+TablePipOrigins+" WHERE directory IN ("+in+")) o ON o.path = p.path"+
				" WHERE p.directory IN ("+in+")")
		} else {
			out = append(out, "SELECT 'pypi', name, version, path FROM python_packages WHERE directory IN ("+in+")")
		}
	}
	if in := sqlList(dirs.NPM); in != "" {
		if origins {
			out = append(out, "SELECT 'npm', n.name, n.version, n.path, o.resolved FROM npm_packages n"+
				" LEFT JOIN (SELECT path, resolved FROM "+TableNPMOrigins+" WHERE directory IN ("+in+")) o ON o.path = n.path"+
				" WHERE n.directory IN ("+in+")")
		} else {
			out = append(out, "SELECT 'npm', name, version, path FROM npm_packages WHERE directory IN ("+in+")")
		}
	}
	return out
}

func unionAll(selects []string) string { return strings.Join(selects, " UNION ALL ") + ";" }

// CleanDirs is dirs sorted, deduplicated and without empty entries, never
// nil: the form the schedule and the plan both state them in.
func CleanDirs(dirs []string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d != "" {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// sqlList renders dirs as a list of SQL string literals. Load already
// refuses a quote in a directory; doubling it here keeps a Config built in
// code from writing one into the query.
func sqlList(dirs []string) string {
	clean := CleanDirs(dirs)
	quoted := make([]string, len(clean))
	for i, d := range clean {
		quoted[i] = "'" + strings.ReplaceAll(d, "'", "''") + "'"
	}
	return strings.Join(quoted, ", ")
}

// event is one osquery result-log line, as the filesystem logger writes it
// and as the tls logger posts it in data.
type event struct {
	Name           string           `json:"name"`
	HostIdentifier string           `json:"hostIdentifier"`
	UnixTime       json.RawMessage  `json:"unixTime"`
	Action         string           `json:"action"`
	Snapshot       []map[string]any `json:"snapshot"`
}

// decodeNDJSON reads one event per line. The decoder takes any whitespace
// between values, so a trailing newline or a blank line is not an error.
func decodeNDJSON(doc []byte) ([]event, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	var out []event
	for n := 1; ; n++ {
		var ev event
		err := dec.Decode(&ev)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("result line %d is not an osquery result event: %w", n, err)
		}
		out = append(out, ev)
	}
}

// normalize turns snapshot events of bodega's queries into one report each.
// Every other line is skipped: a results log shipped from a host whose
// osquery config someone else owns carries that owner's queries too. A
// differential event of a bodega query is skipped as well, since it holds a
// change rather than a whole installed set.
//
// externalID, when set, is the host every report is for and each line's
// hostIdentifier is ignored: a node_key authenticated the host, and a line
// cannot claim another. When it is empty the line's hostIdentifier names it.
func normalize(events []event, externalID string) (inventory.Batch, error) {
	var b inventory.Batch
	for i, ev := range events {
		if !strings.Contains(ev.Name, QueryMarker) || ev.Action != "snapshot" {
			continue
		}
		host := externalID
		if host == "" {
			host = ev.HostIdentifier
		}
		if host == "" {
			return inventory.Batch{}, fmt.Errorf("result event %d (%s) names no hostIdentifier, so it belongs to no host", i+1, ev.Name)
		}
		rep := inventory.Report{ExternalID: host, ObservedAt: unixTime(ev.UnixTime), Components: []inventory.Component{}}
		for _, row := range ev.Snapshot {
			if c, ok := component(row); ok {
				rep.Components = append(rep.Components, c)
			}
		}
		b.Reports = append(b.Reports, rep)
	}
	return b, nil
}

// component maps one row of a bodega query into the common model. The
// ecosystem column is the literal each SELECT writes; rpm has no bodega type,
// so it lands in "other" with a purl that keeps what it was. The origin
// column, present under an origins schedule, is a URL for npm and pypi, kept
// as its host, and a repository name for FreeBSD.
func component(row map[string]any) (inventory.Component, bool) {
	c := inventory.Component{Name: str(row["name"]), Version: str(row["version"]), Path: str(row["path"])}
	if c.Name == "" {
		return c, false
	}
	switch eco := str(row["ecosystem"]); eco {
	case manifest.TypeApt:
		c.Ecosystem = eco
	case manifest.TypePypi, manifest.TypeNpm:
		c.Ecosystem = eco
		c.Origin = OriginHost(str(row["origin"]))
	case manifest.TypeFreeBSD:
		c.Ecosystem = eco
		c.Origin = strings.TrimSpace(str(row["origin"]))
	case "rpm":
		c.Ecosystem = inventory.EcosystemOther
		c.PURL = "pkg:rpm/" + c.Name
		if c.Version != "" {
			c.PURL += "@" + c.Version
		}
	default:
		c.Ecosystem = inventory.EcosystemOther
	}
	return c, true
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

// unixTime reads unixTime, which osquery writes as a number or, with
// numerics off, as a string. Anything else is the zero time, which the frame
// replaces with the arrival time.
func unixTime(raw json.RawMessage) time.Time {
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}
