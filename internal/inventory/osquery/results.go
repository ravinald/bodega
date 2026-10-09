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
// The output depends on dirs and interval alone, with directories sorted and
// deduplicated, so the schedule changes only when the plan does.
func Schedule(dirs config.OsqueryDirs, interval time.Duration) map[string]Query {
	secs := int64(interval / time.Second)
	lang := languageSelects(dirs)
	return map[string]Query{
		QueryLinux: {
			Query: unionAll(append([]string{
				"SELECT 'apt' AS ecosystem, name, version, '' AS path FROM deb_packages",
				"SELECT 'rpm', name, version || '-' || release, '' FROM rpm_packages",
			}, lang...)),
			Interval: secs, Snapshot: true, Platform: "linux",
		},
		QueryFreeBSD: {
			Query: unionAll(append([]string{
				"SELECT 'freebsd' AS ecosystem, name, version, '' AS path FROM pkg_packages",
			}, lang...)),
			Interval: secs, Snapshot: true, Platform: "freebsd",
		},
	}
}

// languageSelects queries python_packages and npm_packages only over the
// declared directories. With none declared the table is left out: unfiltered,
// python_packages walks only the interpreter's default paths and npm_packages
// only global modules, which would read as a scan that found nothing.
func languageSelects(dirs config.OsqueryDirs) []string {
	var out []string
	if in := sqlList(dirs.Python); in != "" {
		out = append(out, "SELECT 'pypi', name, version, path FROM python_packages WHERE directory IN ("+in+")")
	}
	if in := sqlList(dirs.NPM); in != "" {
		out = append(out, "SELECT 'npm', name, version, path FROM npm_packages WHERE directory IN ("+in+")")
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
// so it lands in "other" with a purl that keeps what it was.
func component(row map[string]any) (inventory.Component, bool) {
	c := inventory.Component{Name: str(row["name"]), Version: str(row["version"]), Path: str(row["path"])}
	if c.Name == "" {
		return c, false
	}
	switch eco := str(row["ecosystem"]); eco {
	case manifest.TypeApt, manifest.TypeFreeBSD, manifest.TypePypi, manifest.TypeNpm:
		c.Ecosystem = eco
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
