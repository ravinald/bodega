package policy

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultOSVExportBase is OSV's per-ecosystem export bucket. Each mapped
// ecosystem publishes <base>/<ecosystem>/all.zip, one JSON record per entry.
const DefaultOSVExportBase = "https://osv-vulnerabilities.storage.googleapis.com"

// DefaultOSVMaxAge is how old a synced ecosystem may be before the gate stops
// trusting a clean answer from it. A week is the window a weekly cron leaves,
// with room for one missed run.
const DefaultOSVMaxAge = 7 * 24 * time.Hour

// ErrOSVDBMissing reports that an ecosystem has never been synced into the
// local database. The checker turns it into a warn naming `policy osv sync`
// rather than a pass, so an unsynced gate is visible instead of silent.
var ErrOSVDBMissing = errors.New("ecosystem not present in the local OSV database")

// OSVDBMeta is what a sync wrote for one ecosystem. It lives in its own small
// file beside the archive so `bodega policy osv list` can report the fetch
// time without decompressing several hundred megabytes of records.
type OSVDBMeta struct {
	Ecosystem string    `json:"ecosystem"`
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
	Records   int       `json:"records"`
	Packages  int       `json:"packages"`
	Bytes     int64     `json:"bytes"`
}

// Age reports how long ago the ecosystem was fetched, relative to now.
func (m OSVDBMeta) Age(now time.Time) time.Duration { return now.Sub(m.FetchedAt) }

// osvRecord is one advisory as the local database stores it: the fields the
// verdict needs plus the affected ranges the matcher walks. Everything else
// OSV publishes (details, references, credits) is dropped at sync, which is
// what keeps the npm archive from costing 222 MB on disk and in memory.
type osvRecord struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary,omitempty"`
	Severity []osvSeverity `json:"severity,omitempty"`
	Affected []osvAffected `json:"affected"`
}

// osvIndex is the on-disk archive: every record that names a package in this
// ecosystem, grouped by the key a lookup builds from the package name.
type osvIndex struct {
	Ecosystem string                 `json:"ecosystem"`
	FetchedAt time.Time              `json:"fetched_at"`
	Packages  map[string][]osvRecord `json:"packages"`
}

// OSVDatabase is the local mirror of OSV's per-ecosystem exports: one archive
// and one metadata file per ecosystem under a configured directory. Sync is
// the only method that reaches the network; Match and Meta read the directory
// and nothing else, which is what makes the gate work on a host that cannot
// resolve api.osv.dev.
//
// A whole ecosystem is loaded into memory on first match and kept there, so a
// bulk import pays one decompression rather than one round trip per version.
// That costs a long-running process what it holds: measured on the 2026-09
// exports, npm is 85 MB resident, PyPI 47 MB, Go 6 MB and crates.io 1.5 MB.
// Nothing loads until a package of that type is checked, so an instance with
// one ecosystem under policy pays for one.
type OSVDatabase struct {
	dir string

	// ExportBase is the bucket Sync fetches from; overridden in tests.
	ExportBase string
	HTTP       *http.Client

	mu     sync.Mutex
	loaded map[string]cachedIndex
}

// cachedIndex is a decompressed ecosystem plus the identity of the archive it
// was read from. `policy osv sync` is its own process, so a server that
// trusted its first load would answer from the copy it held while Meta read
// the newer fetch time off disk: a gate reporting current and matching stale.
type cachedIndex struct {
	idx  *osvIndex
	size int64
	mod  time.Time
}

func (c cachedIndex) current(st os.FileInfo) bool {
	return c.size == st.Size() && c.mod.Equal(st.ModTime())
}

// sharedDBs holds one database per directory for the life of the process.
var sharedDBs sync.Map // dir -> *OSVDatabase

// SharedOSVDatabase returns the process-wide database for dir. The decompressed
// index is cached on the instance, and the gate builds its checker once per
// package admitted, so a per-caller database re-reads the whole ecosystem for
// every package: measured on the 2026-09 npm export, 404ms and a fresh 85 MB
// heap per package against 33µs on a reused one. Revalidating against the
// archive's size and modtime is what makes one instance safe to keep across a
// `policy osv sync`; see cachedIndex.
//
// `policy osv sync` builds its own with NewOSVDatabase: it overrides the
// transport, and a fetch has nothing to reuse.
func SharedOSVDatabase(dir string) *OSVDatabase {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	if db, ok := sharedDBs.Load(dir); ok {
		return db.(*OSVDatabase)
	}
	db, _ := sharedDBs.LoadOrStore(dir, NewOSVDatabase(dir))
	return db.(*OSVDatabase)
}

// NewOSVDatabase returns a database rooted at dir. A nil return means the
// directory is unconfigured, which callers read as "no local database".
func NewOSVDatabase(dir string) *OSVDatabase {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	return &OSVDatabase{
		dir:        dir,
		ExportBase: DefaultOSVExportBase,
		// Generous next to the 15s admission timeout: this is one operator
		// command pulling a few hundred megabytes, not a per-version query.
		HTTP:   &http.Client{Timeout: 10 * time.Minute},
		loaded: map[string]cachedIndex{},
	}
}

// Dir returns the configured directory, for error text an operator can act on.
func (d *OSVDatabase) Dir() string {
	if d == nil {
		return ""
	}
	return d.dir
}

// OSVSyncResult is one ecosystem's outcome from a sync run. Ecosystems that
// share an export share its failure: a download that never arrived is one
// error, reported against every ecosystem that was waiting on it.
type OSVSyncResult struct {
	Ecosystem string
	Meta      OSVDBMeta
	Err       error
}

// Sync downloads one ecosystem's export, distills it and replaces what the
// directory holds for that ecosystem.
func (d *OSVDatabase) Sync(ctx context.Context, ecosystem string) (OSVDBMeta, error) {
	res := d.SyncGroup(ctx, []string{ecosystem})
	if len(res) == 0 {
		return OSVDBMeta{}, fmt.Errorf("invalid OSV ecosystem %q", ecosystem)
	}
	return res[0].Meta, res[0].Err
}

// SyncGroup downloads each export once and writes an index per ecosystem
// distilled from it, in the order given. Several ecosystems can share one
// export (every Ubuntu release is distilled out of Ubuntu/all.zip), so
// fetching per ecosystem would pull 681 MB once per release.
//
// Each archive is written under a temporary name and renamed, so an
// interrupted sync leaves the previous copy in place rather than a
// half-written one the matcher would read as truth.
func (d *OSVDatabase) SyncGroup(ctx context.Context, ecosystems []string) []OSVSyncResult {
	out := make([]OSVSyncResult, 0, len(ecosystems))
	fail := func(eco string, err error) { out = append(out, OSVSyncResult{Ecosystem: eco, Err: err}) }
	if d == nil {
		for _, eco := range ecosystems {
			fail(eco, errors.New("no OSV database directory configured (set osv_db_dir)"))
		}
		return out
	}
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		for _, eco := range ecosystems {
			fail(eco, fmt.Errorf("create %s: %w", d.dir, err))
		}
		return out
	}

	// Group by export, preserving the caller's order within each group so the
	// report reads the way the command was written.
	bySource := map[string][]string{}
	var sources []string
	for _, eco := range ecosystems {
		if err := validEcosystemFile(eco); err != nil {
			fail(eco, err)
			continue
		}
		src := OSVExportSource(eco)
		if _, seen := bySource[src]; !seen {
			sources = append(sources, src)
		}
		bySource[src] = append(bySource[src], eco)
	}

	for _, source := range sources {
		group := bySource[source]
		src := fmt.Sprintf("%s/%s/all.zip", strings.TrimSuffix(d.ExportBase, "/"), source)
		zipPath, err := d.download(ctx, src)
		if err != nil {
			for _, eco := range group {
				fail(eco, err)
			}
			continue
		}
		indexes, records, err := distill(group, zipPath)
		os.Remove(zipPath)
		if err != nil {
			for _, eco := range group {
				fail(eco, err)
			}
			continue
		}
		fetchedAt := time.Now().UTC()
		for _, eco := range group {
			idx := indexes[eco]
			// An export that distills to nothing would be written with a
			// current fetch time, and the gate would then report every
			// version of every package in the ecosystem clean, inside the
			// max-age window, forever. That is the one failure shape the
			// warn-on-missing rule exists to prevent, so a sync that produced
			// no index fails instead of replacing a working copy.
			if idx == nil || len(idx.Packages) == 0 {
				fail(eco, fmt.Errorf("%s yielded no packages for ecosystem %q (%d advisory record(s) named it); refusing to write a database that would report every version clean",
					src, eco, records[eco]))
				continue
			}
			idx.FetchedAt = fetchedAt
			n, err := d.writeIndex(eco, idx)
			if err != nil {
				fail(eco, err)
				continue
			}
			meta := OSVDBMeta{
				Ecosystem: eco,
				Source:    src,
				FetchedAt: fetchedAt,
				Records:   records[eco],
				Packages:  len(idx.Packages),
				Bytes:     n,
			}
			if err := d.writeMeta(meta); err != nil {
				fail(eco, err)
				continue
			}
			d.mu.Lock()
			delete(d.loaded, eco)
			d.mu.Unlock()
			out = append(out, OSVSyncResult{Ecosystem: eco, Meta: meta})
		}
	}
	return out
}

// Meta reads what the last sync recorded for an ecosystem. It returns
// ErrOSVDBMissing when the ecosystem was never synced or its archive is gone,
// which the caller must not read as "nothing is vulnerable".
func (d *OSVDatabase) Meta(ecosystem string) (OSVDBMeta, error) {
	if d == nil {
		return OSVDBMeta{}, ErrOSVDBMissing
	}
	if err := validEcosystemFile(ecosystem); err != nil {
		return OSVDBMeta{}, err
	}
	raw, err := os.ReadFile(d.metaPath(ecosystem))
	if errors.Is(err, os.ErrNotExist) {
		return OSVDBMeta{}, ErrOSVDBMissing
	}
	if err != nil {
		return OSVDBMeta{}, err
	}
	var meta OSVDBMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return OSVDBMeta{}, fmt.Errorf("parse %s: %w", d.metaPath(ecosystem), err)
	}
	if _, err := os.Stat(d.indexPath(ecosystem)); err != nil {
		return OSVDBMeta{}, ErrOSVDBMissing
	}
	return meta, nil
}

// Match returns the records covering one (ecosystem, name, version), the same
// answer POST /v1/query gives for the same triple, plus the records that name
// the package and could not be evaluated against it.
//
// A skipped record is neither a hit nor a clean answer. OSV publishes a small
// number of range bounds no ordering can place ("4.1.0-NA", "2.6.0-cu124",
// "0.8.3ubuntu7.5"), and api.osv.dev drops those ranges silently; the caller
// reports them instead, because a record naming this exact package that
// nothing evaluated is what a pass would be hiding.
func (d *OSVDatabase) Match(ecosystem, name, version string) (vulns []osvVuln, skipped []string, err error) {
	if d == nil {
		return nil, nil, ErrOSVDBMissing
	}
	idx, err := d.index(ecosystem)
	if err != nil {
		return nil, nil, err
	}
	order := osvVersionOrder(ecosystem)
	for _, rec := range idx.Packages[osvPackageKey(ecosystem, name)] {
		hit, unorderable := false, ""
		for _, aff := range rec.Affected {
			matched, bad := aff.affects(order, version)
			if matched {
				hit = true
				break
			}
			if bad != "" && unorderable == "" {
				unorderable = bad
			}
		}
		switch {
		case hit:
			vulns = append(vulns, osvVuln{ID: rec.ID, Summary: rec.Summary, Severity: rec.Severity})
		case unorderable != "":
			skipped = append(skipped, fmt.Sprintf("%s (bound %q)", rec.ID, unorderable))
		}
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID })
	sort.Strings(skipped)
	return vulns, skipped, nil
}

func (d *OSVDatabase) index(ecosystem string) (*osvIndex, error) {
	if err := validEcosystemFile(ecosystem); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := os.Open(d.indexPath(ecosystem))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrOSVDBMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Stat the open handle rather than the path: Sync replaces the archive by
	// rename, so this describes the bytes about to be read and cannot record a
	// fingerprint for content that was swapped out mid-load.
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if c, ok := d.loaded[ecosystem]; ok && c.current(st) {
		return c.idx, nil
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", d.indexPath(ecosystem), err)
	}
	defer func() { _ = zr.Close() }()
	var idx osvIndex
	if err := json.NewDecoder(zr).Decode(&idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", d.indexPath(ecosystem), err)
	}
	if d.loaded == nil {
		d.loaded = map[string]cachedIndex{}
	}
	d.loaded[ecosystem] = cachedIndex{idx: &idx, size: st.Size(), mod: st.ModTime()}
	return &idx, nil
}

func (d *OSVDatabase) download(ctx context.Context, src string) (string, error) {
	//nolint:gosec // G704: src is ExportBase (operator config, defaulting to
	// OSV's bucket) plus an ecosystem validEcosystemFile has already refused a
	// path separator in. Nothing from a manifest or a request reaches it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	client := d.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	//nolint:gosec // G704: see the comment on NewRequestWithContext above.
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", src, resp.StatusCode)
	}
	// A temp file rather than memory: archive/zip needs an io.ReaderAt, and
	// npm's export is several hundred megabytes.
	tmp, err := os.CreateTemp(d.dir, ".osv-download-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("fetch %s: %w", src, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// distill reads the export once and keeps only what a verdict needs: the
// records that name a package in each requested ecosystem, grouped by package.
//
// Several ecosystems come out of one archive. OSV stopped writing the
// per-release Ubuntu and Debian exports in October 2024 and kept rebuilding
// the aggregate daily, so the release a record applies to is read out of the
// `affected` entry's own ecosystem string rather than out of the URL it was
// fetched from. See OSVExportSource.
//
// Withdrawn records are dropped, which is one deliberate divergence from
// api.osv.dev: it still returns some of them (PYSEC-2024-115, retracted in
// July 2026, comes back on a langchain-community query) and filters others.
// A retracted advisory blocking an import is a false positive the operator
// cannot clear, so the local database does not carry them.
func distill(ecosystems []string, zipPath string) (map[string]*osvIndex, map[string]int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", zipPath, err)
	}
	defer func() { _ = zr.Close() }()

	indexes := make(map[string]*osvIndex, len(ecosystems))
	records := make(map[string]int, len(ecosystems))
	for _, eco := range ecosystems {
		indexes[eco] = &osvIndex{Ecosystem: eco, Packages: map[string][]osvRecord{}}
	}

	for _, entry := range zr.File {
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("read %s in %s: %w", entry.Name, zipPath, err)
		}
		var raw struct {
			ID        string        `json:"id"`
			Summary   string        `json:"summary"`
			Withdrawn string        `json:"withdrawn"`
			Severity  []osvSeverity `json:"severity"`
			Affected  []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Versions []string   `json:"versions"`
				Ranges   []osvRange `json:"ranges"`
			} `json:"affected"`
		}
		err = json.NewDecoder(rc).Decode(&raw)
		rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s in %s: %w", entry.Name, zipPath, err)
		}
		if raw.ID == "" || raw.Withdrawn != "" {
			continue
		}

		// One record can name several packages and several ecosystems; each
		// gets its own entry holding only the ranges that apply to it.
		byEcosystem := map[string]map[string][]osvAffected{}
		for _, aff := range raw.Affected {
			eco := distillEcosystem(ecosystems, aff.Package.Ecosystem)
			if eco == "" {
				continue
			}
			var ranges []osvRange
			for _, r := range aff.Ranges {
				if r.Type == "GIT" {
					continue
				}
				ranges = append(ranges, r)
			}
			if len(aff.Versions) == 0 && len(ranges) == 0 {
				continue
			}
			if byEcosystem[eco] == nil {
				byEcosystem[eco] = map[string][]osvAffected{}
			}
			key := osvPackageKey(eco, aff.Package.Name)
			byEcosystem[eco][key] = append(byEcosystem[eco][key], osvAffected{Versions: aff.Versions, Ranges: ranges})
		}
		for eco, byPackage := range byEcosystem {
			records[eco]++
			for key, affected := range byPackage {
				indexes[eco].Packages[key] = append(indexes[eco].Packages[key], osvRecord{
					ID: raw.ID, Summary: raw.Summary, Severity: raw.Severity, Affected: affected,
				})
			}
		}
	}
	return indexes, records, nil
}

// distillEcosystem picks which requested ecosystem an `affected` entry belongs
// to, or "" for one nothing asked about.
//
// An OSV ecosystem string can carry a release suffix ("Debian:12",
// "Alpine:v3.19"). A language ecosystem is requested under the bare name and
// takes everything under it; a distro release is requested in full and takes
// only its own release, because folding every Ubuntu release into one index
// would answer a jammy host with advisories that are not about it.
//
// Its own release is two strings, not one: see ubuntuProEcosystem.
func distillEcosystem(ecosystems []string, recorded string) string {
	base, _, _ := strings.Cut(recorded, ":")
	for _, eco := range ecosystems {
		if recorded == eco || base == eco || recorded == ubuntuProEcosystem(eco) {
			return eco
		}
	}
	return ""
}

// ubuntuProEcosystem is the second string OSV files one Ubuntu release's
// advisories under, or "" for an ecosystem that has none.
//
// OSV splits a release across Ubuntu:22.04:LTS, which carries main, and
// Ubuntu:Pro:22.04:LTS, which carries universe and on the ESM releases very
// nearly everything. The two sets are disjoint, so an index built from the
// first alone answers a jammy imagemagick with 4 records where 183 exist, and a
// xenial expat with none at all. Both halves are about the same host and both
// name stock revisions as their fixed versions, so they belong in one index.
//
// Matched as an exact pair and never as a prefix. OSV also publishes
// Ubuntu:Pro:FIPS:22.04:LTS and Ubuntu:Pro:FIPS-updates:22.04:LTS, whose
// versions are FIPS builds: a prefix match reports those against a host that
// never installed one.
func ubuntuProEcosystem(ecosystem string) string {
	rel, found := strings.CutPrefix(ecosystem, "Ubuntu:")
	if !found {
		return ""
	}
	return "Ubuntu:Pro:" + rel
}

func (d *OSVDatabase) writeIndex(ecosystem string, idx *osvIndex) (int64, error) {
	path := d.indexPath(ecosystem)
	tmp, err := os.CreateTemp(d.dir, ".osv-index-*.tmp")
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(tmp)
	if err := json.NewEncoder(gz).Encode(idx); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return 0, err
	}
	if err := gz.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return 0, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return 0, err
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return 0, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func (d *OSVDatabase) writeMeta(meta OSVDBMeta) error {
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.metaPath(meta.Ecosystem), append(blob, '\n'), 0o644)
}

func (d *OSVDatabase) indexPath(ecosystem string) string {
	return filepath.Join(d.dir, OSVEcosystemFile(ecosystem)+".json.gz")
}

func (d *OSVDatabase) metaPath(ecosystem string) string {
	return filepath.Join(d.dir, OSVEcosystemFile(ecosystem)+".meta.json")
}

// OSVEcosystemFile is the base name an ecosystem's archive and metadata are
// written under. OSV's per-release distro ecosystems carry colons
// ("Ubuntu:22.04:LTS"), and a filename does not have to: the air-gapped
// runbook copies this directory between hosts with whatever archiver is to
// hand, and a colon in a member name is where that copy stops being portable.
// The language ecosystems have no colon, so their files keep the names an
// earlier sync wrote.
func OSVEcosystemFile(ecosystem string) string {
	return strings.ReplaceAll(ecosystem, ":", "-")
}

// validEcosystemFile refuses an ecosystem name that would escape the database
// directory. Every caller passes a value from osvEcosystemFor today; the check
// is here so a future one cannot turn a package type into a path.
func validEcosystemFile(ecosystem string) error {
	if ecosystem == "" || ecosystem == "." || ecosystem == ".." ||
		strings.ContainsAny(ecosystem, `/\`) {
		return fmt.Errorf("invalid OSV ecosystem %q", ecosystem)
	}
	return nil
}

// osvPackageKey normalizes a package name to the form the index is keyed by.
// PyPI matches per PEP 503, npm and crates.io are case-insensitive, and Go
// module paths are case-sensitive and are left alone.
func osvPackageKey(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		return normalizePyPI503(name)
	case "Go":
		return name
	}
	return strings.ToLower(name)
}

// normalizePyPI503 applies the full PEP 503 rule: lowercase, then collapse any
// run of `-`, `_` and `.` to a single `-`. normalizePyPI stops short of the
// runs, which is enough for the allow-list and not for matching an OSV index
// key built from a published distribution name.
func normalizePyPI503(name string) string {
	lower := strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(lower))
	prevSep := false
	for _, r := range lower {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}
