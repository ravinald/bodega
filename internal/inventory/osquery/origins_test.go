package osquery

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "testdata", "osquery", name))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func byPath(rows []map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, r := range rows {
		out[r["path"]] = r
	}
	return out
}

func TestNPMOrigins(t *testing.T) {
	public, bodega, broken := fixture(t, "npm-public"), fixture(t, "npm-bodega"), fixture(t, "npm-broken")
	var log bytes.Buffer
	rows := byPath(NPMOrigins([]string{public, bodega, broken, fixture(t, "no-such-tree")}, &log))
	if len(rows) != 3 {
		t.Fatalf("rows = %v, want left-pad, @types/node and lodash", rows)
	}
	pad := rows[filepath.Join(public, "node_modules", "left-pad", "package.json")]
	if pad["name"] != "left-pad" || pad["version"] != "1.3.0" || pad["directory"] != public ||
		pad["resolved"] != "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" {
		t.Errorf("left-pad = %v", pad)
	}
	if scoped := rows[filepath.Join(public, "node_modules", "@types", "node", "package.json")]; scoped["name"] != "@types/node" {
		t.Errorf("a scoped package lost its scope: %v", scoped)
	}
	lodash := rows[filepath.Join(bodega, "node_modules", "lodash", "package.json")]
	if OriginHost(lodash["resolved"]) != "bodega.example:8443" {
		t.Errorf("lodash resolved = %q, host %q", lodash["resolved"], OriginHost(lodash["resolved"]))
	}
	// A lock that does not parse is skipped and named, never the table's
	// failure, and a missing one is no finding at all.
	if got := log.String(); !strings.Contains(got, filepath.Join(broken, "node_modules", ".package-lock.json")) || strings.Count(got, "\n") != 1 {
		t.Errorf("stderr = %q, want one line naming the broken lock", got)
	}
}

func TestPipOrigins(t *testing.T) {
	dir := fixture(t, "pip")
	var log bytes.Buffer
	rows := PipOrigins([]string{dir}, &log)
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want six alone: requests has no direct_url.json and broken_pkg's does not parse", rows)
	}
	six := rows[0]
	if six["name"] != "six" || six["version"] != "1.17.0" || six["path"] != filepath.Join(dir, "six-1.17.0.dist-info") ||
		six["url"] != "https://github.com/benjaminp/six.git" || six["directory"] != dir {
		t.Errorf("six = %v", six)
	}
	if !strings.Contains(log.String(), filepath.Join(dir, "broken_pkg-1.0.dist-info", "direct_url.json")) {
		t.Errorf("stderr = %q, want the broken direct_url.json named", log.String())
	}
}

// A query without a directory constraint reads nothing, as npm_packages and
// python_packages do, so no query walks the whole disk.
func TestOriginTablesNeedDirectory(t *testing.T) {
	dir := fixture(t, "npm-public")
	eq := table.QueryContext{Constraints: map[string]table.ConstraintList{
		"directory": {Constraints: []table.Constraint{{Operator: table.OperatorEquals, Expression: dir}}},
	}}
	like := table.QueryContext{Constraints: map[string]table.ConstraintList{
		"directory": {Constraints: []table.Constraint{{Operator: table.OperatorLike, Expression: "/%"}}},
	}}
	if got := constrainedDirs(eq); !reflect.DeepEqual(got, []string{dir}) {
		t.Errorf("directory = constraint read as %v", got)
	}
	for name, qc := range map[string]table.QueryContext{"none": {}, "like": like} {
		if got := constrainedDirs(qc); len(got) != 0 {
			t.Errorf("%s: directories = %v, want none", name, got)
		}
	}
	if names := []string{OriginTables(nil)[0].Name(), OriginTables(nil)[1].Name()}; !reflect.DeepEqual(names, []string{TableNPMOrigins, TablePipOrigins}) {
		t.Errorf("tables = %v", names)
	}
}

func TestOriginHost(t *testing.T) {
	for raw, want := range map[string]string{
		"https://registry.npmjs.org/x/-/x-1.tgz":          "registry.npmjs.org",
		"https://ci:s3cret@Bodega.Example:8443/npm/x.tgz": "bodega.example:8443",
		"git+https://github.com/benjaminp/six.git":        "github.com",
		"git+ssh://git@github.com/o/r.git":                "github.com",
		"file:///home/me/src/pkg":                         "",
		"":                                                "",
		"::not a url":                                     "",
	} {
		if got := OriginHost(raw); got != want {
			t.Errorf("OriginHost(%q) = %q, want %q", raw, got, want)
		}
	}
}

// Without origins the schedule is the one hosts were handed before the key
// existed, byte for byte: a query naming a table the host has not loaded
// fails whole, and the host would report nothing.
func TestScheduleWithoutOriginsUnchanged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "osquery", "schedule-without-origins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		None map[string]Query     `json:"none"`
		Dirs map[string]Query     `json:"dirs"`
		ATC  map[string]AutoTable `json:"atc"`
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	dirs := config.OsqueryDirs{Python: []string{"/opt/b", "/opt/a"}, NPM: []string{"/srv/app"}}
	if got := Schedule(config.OsqueryDirs{}, time.Hour, false); !reflect.DeepEqual(got, want.None) {
		t.Errorf("schedule with no trees =\n%+v\nwant\n%+v", got, want.None)
	}
	if got := Schedule(dirs, 30*time.Minute, false); !reflect.DeepEqual(got, want.Dirs) {
		t.Errorf("schedule with trees =\n%+v\nwant\n%+v", got, want.Dirs)
	}
	if got := AutoTables(false); !reflect.DeepEqual(got, want.ATC) {
		t.Errorf("auto tables = %+v, want %+v", got, want.ATC)
	}
}

func TestScheduleWithOrigins(t *testing.T) {
	dirs := config.OsqueryDirs{Python: []string{"/opt/a"}, NPM: []string{"/srv/app"}}
	s := Schedule(dirs, time.Hour, true)
	lin, fbsd := s[QueryLinux].Query, s[QueryFreeBSD].Query
	for _, q := range []string{lin, fbsd} {
		for _, want := range []string{
			"LEFT JOIN (SELECT path, url FROM " + TablePipOrigins + " WHERE directory IN ('/opt/a')) o ON o.path = p.path WHERE p.directory IN ('/opt/a')",
			"LEFT JOIN (SELECT path, resolved FROM " + TableNPMOrigins + " WHERE directory IN ('/srv/app')) o ON o.path = n.path WHERE n.directory IN ('/srv/app')",
		} {
			if !strings.Contains(q, want) {
				t.Errorf("query lacks %q:\n%s", want, q)
			}
		}
	}
	if !strings.Contains(lin, "'' AS path, '' AS origin FROM deb_packages") {
		t.Errorf("linux query names no origin column: %s", lin)
	}
	if !strings.Contains(fbsd, "o.repository AS origin FROM "+TableFreeBSDPkg+" p LEFT JOIN "+TableFreeBSDOrigins+" o ON o.name = p.name AND o.version = p.version") {
		t.Errorf("freebsd query does not join the repository annotation: %s", fbsd)
	}
	atc := AutoTables(true)
	o, ok := atc[TableFreeBSDOrigins]
	if !ok || o.Path != "/var/db/pkg/local.sqlite" || o.Platform != "freebsd" ||
		!reflect.DeepEqual(o.Columns, []string{"name", "version", "repository"}) ||
		!strings.Contains(o.Query, "AS repository") || !strings.Contains(o.Query, "annotation = 'repository'") {
		t.Errorf("auto tables = %+v, want %s over the repository annotation", atc, TableFreeBSDOrigins)
	}
	if _, ok := atc[TableFreeBSDPkg]; !ok {
		t.Error("the origins auto tables dropped the package table")
	}
	// Without declared trees the extension's tables are not named, so a
	// host that loads no extension still reports its system packages.
	bare := Schedule(config.OsqueryDirs{}, time.Hour, true)[QueryLinux].Query
	if strings.Contains(bare, "bodega_npm_origins") || strings.Contains(bare, "bodega_pip_origins") {
		t.Errorf("no trees declared, yet the query names an extension table: %s", bare)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	//nolint:gosec // G101: the credential in lodash's URL is the fixture proving the normalizer drops it
	ev := `{"name":"bodega_packages_linux","action":"snapshot","snapshot":[
 {"ecosystem":"apt","name":"curl","version":"8","path":"","origin":""},
 {"ecosystem":"npm","name":"left-pad","version":"1.3.0","path":"/a","origin":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
 {"ecosystem":"npm","name":"lodash","version":"4.17.21","path":"/b","origin":"https://ci:s3cret@bodega.example:8443/npm/lodash.tgz"},
 {"ecosystem":"npm","name":"chalk","version":"5","path":"/c","origin":""},
 {"ecosystem":"pypi","name":"six","version":"1.17.0","path":"/d","origin":"git+https://github.com/benjaminp/six.git"},
 {"ecosystem":"pypi","name":"local","version":"1","path":"/e","origin":"file:///src/local"},
 {"ecosystem":"freebsd","name":"curl","version":"8","path":"","origin":"FreeBSD"},
 {"ecosystem":"freebsd","name":"bash","version":"5","path":"","origin":"bodega-latest"},
 {"ecosystem":"freebsd","name":"git","version":"2","path":"","origin":""}
]}`
	b, err := (&Source{}).Normalize([]byte(ev), "host")
	if err != nil || len(b.Reports) != 1 {
		t.Fatalf("Normalize = %+v, %v", b, err)
	}
	got := map[string]string{}
	for _, c := range b.Reports[0].Components {
		got[c.Ecosystem+"/"+c.Name] = c.Origin
	}
	want := map[string]string{
		"apt/curl": "", "npm/left-pad": "registry.npmjs.org", "npm/lodash": "bodega.example:8443", "npm/chalk": "",
		"pypi/six": "github.com", "pypi/local": "", "freebsd/curl": "FreeBSD", "freebsd/bash": "bodega-latest", "freebsd/git": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("origins = %v\nwant %v", got, want)
	}
	if strings.Contains(b.Reports[0].Components[2].Origin, "s3cret") {
		t.Error("a credential in the resolved URL reached the stored origin")
	}
}

func TestOriginsSetting(t *testing.T) {
	for _, tc := range []struct {
		raw     config.InventorySource
		want    bool
		wantErr string
	}{
		{config.InventorySource{"type": TypeName, "mode": ModeServer}, false, ""},
		{config.InventorySource{"type": TypeName, "mode": ModeServer, "origins": true}, true, ""},
		{config.InventorySource{"type": TypeName, "mode": ModeShipper, "origins": true}, true, ""},
		{config.InventorySource{"type": TypeName, "mode": ModeServer, "origins": "yes"}, false, "inventory_sources.osq.origins"},
	} {
		insts, err := inventory.Configure(map[string]config.InventorySource{"osq": tc.raw})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%v: err = %v, want one naming %q", tc.raw, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%v: %v", tc.raw, err)
		}
		if got := insts[0].Source.(*Source).Origins(); got != tc.want {
			t.Errorf("%v: Origins() = %v", tc.raw, got)
		}
	}
}
