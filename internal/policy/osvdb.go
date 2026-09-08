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

// Sync downloads one ecosystem's export, distills it and replaces what the
// directory holds for that ecosystem. The archive is written under a temporary
// name and renamed, so an interrupted sync leaves the previous copy in place
// rather than a half-written one the matcher would read as truth.
func (d *OSVDatabase) Sync(ctx context.Context, ecosystem string) (OSVDBMeta, error) {
	if d == nil {
		return OSVDBMeta{}, errors.New("no OSV database directory configured (set osv_db_dir)")
	}
	if err := validEcosystemFile(ecosystem); err != nil {
		return OSVDBMeta{}, err
	}
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return OSVDBMeta{}, fmt.Errorf("create %s: %w", d.dir, err)
	}

	src := fmt.Sprintf("%s/%s/all.zip", strings.TrimSuffix(d.ExportBase, "/"), ecosystem)
	zipPath, err := d.download(ctx, src)
	if err != nil {
		return OSVDBMeta{}, err
	}
	defer os.Remove(zipPath)

	idx, records, err := distill(ecosystem, zipPath)
	if err != nil {
		return OSVDBMeta{}, err
	}
	idx.FetchedAt = time.Now().UTC()

	n, err := d.writeIndex(ecosystem, idx)
	if err != nil {
		return OSVDBMeta{}, err
	}
	meta := OSVDBMeta{
		Ecosystem: ecosystem,
		Source:    src,
		FetchedAt: idx.FetchedAt,
		Records:   records,
		Packages:  len(idx.Packages),
		Bytes:     n,
	}
	if err := d.writeMeta(meta); err != nil {
		return OSVDBMeta{}, err
	}
	d.mu.Lock()
	delete(d.loaded, ecosystem)
	d.mu.Unlock()
	return meta, nil
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
// answer POST /v1/query gives for the same triple.
func (d *OSVDatabase) Match(ecosystem, name, version string) ([]osvVuln, error) {
	if d == nil {
		return nil, ErrOSVDBMissing
	}
	idx, err := d.index(ecosystem)
	if err != nil {
		return nil, err
	}
	order := osvVersionOrder(ecosystem)
	var out []osvVuln
	for _, rec := range idx.Packages[osvPackageKey(ecosystem, name)] {
		for _, aff := range rec.Affected {
			if aff.affects(order, version) {
				out = append(out, osvVuln{ID: rec.ID, Summary: rec.Summary, Severity: rec.Severity})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
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

// distill reads the export and keeps only what a verdict needs: the records
// that name a package in this ecosystem, grouped by package.
//
// Withdrawn records are dropped, which is one deliberate divergence from
// api.osv.dev: it still returns some of them (PYSEC-2024-115, retracted in
// July 2026, comes back on a langchain-community query) and filters others.
// A retracted advisory blocking an import is a false positive the operator
// cannot clear, so the local database does not carry them.
func distill(ecosystem, zipPath string) (*osvIndex, int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", zipPath, err)
	}
	defer func() { _ = zr.Close() }()

	idx := &osvIndex{Ecosystem: ecosystem, Packages: map[string][]osvRecord{}}
	records := 0
	for _, entry := range zr.File {
		if !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return nil, 0, fmt.Errorf("read %s in %s: %w", entry.Name, zipPath, err)
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
			return nil, 0, fmt.Errorf("parse %s in %s: %w", entry.Name, zipPath, err)
		}
		if raw.ID == "" || raw.Withdrawn != "" {
			continue
		}
		records++

		// One record can name several packages; each gets its own entry
		// holding only the ranges that apply to it.
		byPackage := map[string][]osvAffected{}
		for _, aff := range raw.Affected {
			// An OSV ecosystem string can carry a suffix ("Debian:12",
			// "Alpine:v3.19"); the part before the colon is the ecosystem.
			if eco, _, _ := strings.Cut(aff.Package.Ecosystem, ":"); eco != ecosystem {
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
			key := osvPackageKey(ecosystem, aff.Package.Name)
			byPackage[key] = append(byPackage[key], osvAffected{Versions: aff.Versions, Ranges: ranges})
		}
		for key, affected := range byPackage {
			idx.Packages[key] = append(idx.Packages[key], osvRecord{
				ID: raw.ID, Summary: raw.Summary, Severity: raw.Severity, Affected: affected,
			})
		}
	}
	return idx, records, nil
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
	return filepath.Join(d.dir, ecosystem+".json.gz")
}

func (d *OSVDatabase) metaPath(ecosystem string) string {
	return filepath.Join(d.dir, ecosystem+".meta.json")
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
