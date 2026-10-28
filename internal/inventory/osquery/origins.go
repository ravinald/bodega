package osquery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	osq "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// The tables bodega's osquery extension registers. Each reports what a
// package manager recorded about where a package came from, keyed on the
// path osquery's own table reports for the same package, so the schedule
// joins the two.
const (
	TableNPMOrigins = "bodega_npm_origins"
	TablePipOrigins = "bodega_pip_origins"
)

// ExtensionName is the name the extension registers with osqueryd under.
const ExtensionName = "bodega"

// maxOriginFile bounds one lockfile or direct_url.json read. A hidden
// lockfile for a large monorepo runs to a few MiB.
const maxOriginFile = 64 << 20

// ExtensionOptions are the flags osqueryd passes an autoloaded extension.
type ExtensionOptions struct {
	Socket   string
	Timeout  time.Duration
	Interval time.Duration
	// Log receives one line per file that could not be read or parsed.
	Log io.Writer
}

// RunExtension registers the origin tables with the osqueryd listening on
// opts.Socket and serves them until osqueryd goes away.
func RunExtension(opts ExtensionOptions) error {
	if opts.Socket == "" {
		return fmt.Errorf("no --socket: osqueryd passes the path of its extensions socket when it autoloads an extension; run by hand, pass the path osqueryd's --extensions_socket names")
	}
	srv, err := osq.NewExtensionManagerServer(ExtensionName, opts.Socket,
		osq.ServerTimeout(opts.Timeout), osq.ServerPingInterval(opts.Interval))
	if err != nil {
		return fmt.Errorf("connect to osqueryd at %s: %w", opts.Socket, err)
	}
	srv.RegisterPlugin(OriginTables(opts.Log)...)
	return srv.Run()
}

// OriginTables are the extension's table plugins. log receives a line for
// each file skipped because it could not be read or parsed.
func OriginTables(log io.Writer) []osq.OsqueryPlugin {
	if log == nil {
		log = io.Discard
	}
	return []osq.OsqueryPlugin{
		table.NewPlugin(TableNPMOrigins, []table.ColumnDefinition{
			table.TextColumn("directory"), table.TextColumn("name"), table.TextColumn("version"),
			table.TextColumn("path"), table.TextColumn("resolved"),
		}, func(_ context.Context, qc table.QueryContext) ([]map[string]string, error) {
			return NPMOrigins(constrainedDirs(qc), log), nil
		}, table.WithDescription("The resolved URL npm recorded for each package in <directory>/node_modules/.package-lock.json. Requires directory in the WHERE clause.")),
		table.NewPlugin(TablePipOrigins, []table.ColumnDefinition{
			table.TextColumn("directory"), table.TextColumn("name"), table.TextColumn("version"),
			table.TextColumn("path"), table.TextColumn("url"),
		}, func(_ context.Context, qc table.QueryContext) ([]map[string]string, error) {
			return PipOrigins(constrainedDirs(qc), log), nil
		}, table.WithDescription("The URL pip recorded in each <directory>/*.dist-info/direct_url.json (PEP 610). Requires directory in the WHERE clause.")),
	}
}

// constrainedDirs is every directory the WHERE clause pins with = or IN.
// Anything else (LIKE, a range, no constraint) names no directory, so the
// table walks nothing, as osquery's own npm_packages and python_packages do.
func constrainedDirs(qc table.QueryContext) []string {
	var out []string
	for _, c := range qc.Constraints["directory"].Constraints {
		if (c.Operator == table.OperatorEquals || c.Operator == table.OperatorIn) && c.Expression != "" {
			out = append(out, c.Expression)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// NPMOrigins reads <dir>/node_modules/.package-lock.json, the hidden lockfile
// npm 7 and later keeps beside what it installed, for each dir. path is the
// package.json path, the value npm_packages reports for the same package.
func NPMOrigins(dirs []string, log io.Writer) []map[string]string {
	var rows []map[string]string
	for _, dir := range dirs {
		lock := filepath.Join(dir, "node_modules", ".package-lock.json")
		raw, err := readBounded(lock)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			skipped(log, lock, err)
			continue
		}
		var doc struct {
			Packages map[string]struct {
				Name     string `json:"name"`
				Version  string `json:"version"`
				Resolved string `json:"resolved"`
				Link     bool   `json:"link"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			skipped(log, lock, err)
			continue
		}
		keys := make([]string, 0, len(doc.Packages))
		for k := range doc.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := doc.Packages[k]
			i := strings.LastIndex(k, "node_modules/")
			if i < 0 || p.Link || strings.Contains(k, "..") {
				continue
			}
			name := p.Name
			if name == "" {
				name = k[i+len("node_modules/"):]
			}
			rows = append(rows, map[string]string{
				"directory": dir, "name": name, "version": p.Version,
				"path":     filepath.Join(dir, filepath.FromSlash(k), "package.json"),
				"resolved": p.Resolved,
			})
		}
	}
	return rows
}

// PipOrigins reads every <dir>/*.dist-info/direct_url.json, which pip writes
// (PEP 610) only for a package installed from a URL, a VCS or a local path
// rather than from an index. path is the .dist-info directory, the value
// python_packages reports for the same package.
func PipOrigins(dirs []string, log io.Writer) []map[string]string {
	var rows []map[string]string
	for _, dir := range dirs {
		infos, err := filepath.Glob(filepath.Join(dir, "*.dist-info"))
		if err != nil {
			continue
		}
		sort.Strings(infos)
		for _, info := range infos {
			du := filepath.Join(info, "direct_url.json")
			raw, err := readBounded(du)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				skipped(log, du, err)
				continue
			}
			var doc struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				skipped(log, du, err)
				continue
			}
			name, version := distInfoMetadata(info)
			rows = append(rows, map[string]string{
				"directory": dir, "name": name, "version": version, "path": info, "url": doc.URL,
			})
		}
	}
	return rows
}

// distInfoMetadata reads Name and Version from METADATA, falling back to the
// directory's own name-version.dist-info.
func distInfoMetadata(info string) (name, version string) {
	base := strings.TrimSuffix(filepath.Base(info), ".dist-info")
	if i := strings.LastIndex(base, "-"); i > 0 {
		name, version = base[:i], base[i+1:]
	}
	f, err := os.Open(filepath.Join(info, "METADATA"))
	if err != nil {
		return name, version
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if v, ok := strings.CutPrefix(line, "Name: "); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Version: "); ok {
			version = strings.TrimSpace(v)
		}
	}
	return name, version
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxOriginFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxOriginFile {
		return nil, fmt.Errorf("larger than %d bytes", maxOriginFile)
	}
	return raw, nil
}

func skipped(log io.Writer, path string, err error) {
	_, _ = fmt.Fprintf(log, "bodega osquery extension: skipped %s: %v\n", path, err)
}

// OriginHost is the host a recorded origin URL names, port kept and
// credentials dropped: what the normalizer stores in Component.Origin for
// npm and pypi. A value that is not an absolute URL with a host, a local
// path from a pip install of a directory for one, yields "".
func OriginHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}
