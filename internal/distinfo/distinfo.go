// Package distinfo reads the digests a FreeBSD ports tree pins for every
// distfile, and the redistribution limits its ports declare.
//
// This is what separates the distfiles type from binary. A binary entry pins
// whatever its first fetch returned, so a poisoned first fetch is served
// faithfully forever and bodega is the only party that ever vouched for the
// bytes. A distfile's SHA256 and size are already written down in
// <category>/<port>/distinfo, git-tracked in the ports tree before bodega
// fetches anything, and the client's own `make checksum` compares against the
// same line. A distfiles mirror therefore admits bytes against a digest it did
// not produce and cannot be talked into producing. Folding this type into
// binary, or into the checksum table's first-fetch pin, would keep every
// feature and drop that one property with no test noticing.
package distinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
)

// Entry is one distfile as the ports tree pins it.
type Entry struct {
	// Name is the string inside the distinfo line's parentheses:
	// "${DIST_SUBDIR}/<file>" when the port sets DIST_SUBDIR, "<file>" when
	// it does not. It is the object key under manifest.DistfilesPrefix and
	// the path under DISTDIR, so it is never split.
	Name   string
	SHA256 string // lowercase hex
	Size   int64

	// Ports lists every origin whose distinfo names this file, sorted.
	Ports []string

	// Restricted is empty when the file may be redistributed, and otherwise
	// names the port and the variable that forbids it.
	Restricted string
}

// ErrNotListed reports a name no distinfo in the tree carries. With no digest
// to hold the bytes to, the mirror refuses rather than falling back to
// pinning the first fetch.
var ErrNotListed = errors.New("no distinfo in the ports tree lists this distfile")

// ErrRestricted reports a distfile a port marks RESTRICTED or NO_CDROM.
var ErrRestricted = errors.New("the port forbids redistributing this distfile")

// ErrUnusable reports a name the tree pins in a way no digest can be taken
// from: two distinfo files pinning it to different bytes, which happens when a
// tree is read partway through an update, or a distinfo line that does not
// parse. Neither case says which bytes a client holds, so neither is admitted.
var ErrUnusable = errors.New("the ports tree does not pin this distfile to one digest")

// ErrNotReady reports that the first read of the ports tree has not finished,
// or has failed. A cold walk of a full tree takes the better part of a minute.
var ErrNotReady = errors.New("the distinfo index is not loaded yet")

// Index is every distfile one ports tree pins, keyed by distinfo name.
type Index struct {
	entries map[string]*Entry
	refused map[string]string // name -> why ErrUnusable
}

// Lookup returns the entry for name, or an error wrapping ErrNotListed,
// ErrUnusable or ErrRestricted. A restricted entry is returned alongside its
// error so a caller can report which port forbade it.
func (ix *Index) Lookup(name string) (Entry, error) {
	if why, ok := ix.refused[name]; ok {
		return Entry{}, fmt.Errorf("%w: %s: %s", ErrUnusable, name, why)
	}
	e, ok := ix.entries[name]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %s", ErrNotListed, name)
	}
	if e.Restricted != "" {
		return *e, fmt.Errorf("%w: %s: %s", ErrRestricted, name, e.Restricted)
	}
	return *e, nil
}

// Len is the number of distfiles the index can admit or refuse by name.
func (ix *Index) Len() int { return len(ix.entries) + len(ix.refused) }

// Parse reads one distinfo file into the entries it pins and the names it
// mentions without pinning. Lines other than SHA256 and SIZE (TIMESTAMP,
// blank lines) are skipped.
//
// A bad line costs its own name and nothing else. The tree carries at least
// one distinfo with a SIZE line missing its "=", and refusing the whole file,
// or the whole tree, over it would refuse thousands of distfiles to protect
// one. A line too broken to name its file is dropped, which leaves that file
// with half a pin and so refuses it all the same.
func Parse(r io.Reader) (entries map[string]Entry, unusable map[string]string, err error) {
	sums := map[string]string{}
	sizes := map[string]int64{}
	unusable = map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		field, rest, ok := strings.Cut(line, " (")
		if !ok || (field != "SHA256" && field != "SIZE") {
			continue
		}
		// The last ") = ", not the first: a filename may hold parentheses.
		i := strings.LastIndex(rest, ") = ")
		if i < 0 {
			if j := strings.LastIndex(rest, ")"); j > 0 && manifest.DistfilesValidName(rest[:j]) == nil {
				unusable[rest[:j]] = fmt.Sprintf("line %d does not parse: %q", n, line)
			}
			continue
		}
		name, val := rest[:i], strings.TrimSpace(rest[i+len(") = "):])
		// A name that is not a legal key is never recorded, not even as
		// unusable: it would reach an object key and a DISTDIR path.
		if manifest.DistfilesValidName(name) != nil {
			continue
		}
		switch field {
		case "SHA256":
			if !isSHA256(val) {
				unusable[name] = fmt.Sprintf("line %d: %q is not a SHA256 digest", n, val)
				continue
			}
			sums[name] = strings.ToLower(val)
		case "SIZE":
			sz, err := strconv.ParseInt(val, 10, 64)
			if err != nil || sz < 0 {
				unusable[name] = fmt.Sprintf("line %d: %q is not a size", n, val)
				continue
			}
			sizes[name] = sz
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	entries = make(map[string]Entry, len(sums))
	for name, sum := range sums {
		if _, bad := unusable[name]; bad {
			continue
		}
		// Both halves or nothing. bsd.port.mk has written SIZE beside SHA256
		// for as long as SHA256 has existed, and admitting on the digest alone
		// would accept a file no client's `make checksum` has seen described.
		sz, ok := sizes[name]
		if !ok {
			unusable[name] = "a SHA256 line and no SIZE line"
			continue
		}
		entries[name] = Entry{Name: name, SHA256: sum, Size: sz}
	}
	for name := range sizes {
		if _, ok := sums[name]; !ok {
			if _, bad := unusable[name]; !bad {
				unusable[name] = "a SIZE line and no SHA256 line"
			}
		}
	}
	return entries, unusable, nil
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Ports forbid redistributing a distfile in three spellings, and a mirror has
// to read all of them:
//
//   - RESTRICTED or NO_CDROM, set directly.
//   - LICENSE_PERMS (or LICENSE_PERMS_<lic>) lacking dist-mirror or dist-sell.
//     Mk/bsd.licenses.mk is default-deny: its own comment says a port with
//     dist-mirror "is not RESTRICTED" and one with dist-sell "does not need
//     to set NO_CDROM", and it moves the distfiles onto RESTRICTED_FILES when
//     either is missing. This is the common form: on the 15.1 test tree 2
//     ports set RESTRICTED or NO_CDROM literally, and hundreds set
//     LICENSE_PERMS without one of the two.
//   - LICENSE naming a license whose default permissions in
//     Mk/bsd.licenses.db.mk lack either, such as the CC-BY-NC family.
//
// All three are read lexically, at any indentation, so an assignment inside
// an .if counts. That over-refuses a port that sets one only under a
// condition, and a value holding a make variable is refused because it cannot
// be evaluated here. Both are the right direction to be wrong in: evaluating a
// port needs make and the whole of Mk/, which a Linux server has neither of,
// and a mirror that under-refuses redistributes something it may not.
var (
	restrictionVar  = regexp.MustCompile(`(?m)^[ \t]*(RESTRICTED|NO_CDROM)[ \t]*[?:+!]?=[ \t]*(.*)$`)
	licensePermsVar = regexp.MustCompile(`(?m)^[ \t]*(LICENSE_PERMS(?:_[A-Za-z0-9.+-]+)?)[ \t]*[?:+!]?=[ \t]*(.*)$`)
	licenseVar      = regexp.MustCompile(`(?m)^[ \t]*LICENSE[ \t]*[?:+!]?=[ \t]*(.*)$`)
	licenseDBPerms  = regexp.MustCompile(`(?m)^_LICENSE_PERMS_([A-Za-z0-9.+-]+)[ \t]*[?:]?=[ \t]*(.*)$`)
)

// masterDirVar matches a slave port naming its master relative to itself,
// which is how nearly every slave in the tree spells it. A slave reads the
// master's distinfo, so a slave that is restricted restricts those names.
var masterDirVar = regexp.MustCompile(`(?m)^[ \t]*MASTERDIR[ \t]*[?:]?=[ \t]*\$\{\.CURDIR\}/(\S+)`)

// withholdsDistfiles reports whether a permission list, as bsd.licenses.mk
// reads one, fails to grant both dist-mirror and dist-sell.
func withholdsDistfiles(perms string) bool {
	if strings.Contains(perms, "$") {
		return true
	}
	have := map[string]bool{}
	for _, tok := range strings.Fields(perms) {
		have[tok] = true
	}
	return !have["dist-mirror"] || !have["dist-sell"] || have["no-dist-mirror"] || have["no-dist-sell"]
}

// loadLicenseDB reads the license names whose default permissions withhold
// redistribution.
func loadLicenseDB(portsTree string) (map[string]bool, error) {
	file := filepath.Join(portsTree, "Mk", "bsd.licenses.db.mk")
	b, err := os.ReadFile(file) //nolint:gosec // G304: a fixed file under the configured ports tree.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w; distfiles_ports_tree must name the root of a FreeBSD ports tree", file, err)
	}
	out := map[string]bool{}
	for _, m := range licenseDBPerms.FindAllSubmatch(joinContinuations(b), -1) {
		if string(m[1]) == "DEFAULT" {
			continue
		}
		if withholdsDistfiles(string(m[2])) {
			out[string(m[1])] = true
		}
	}
	return out, nil
}

func joinContinuations(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\\\n", " "))
}

// restriction names why a port's Makefiles forbid redistributing its
// distfiles, or returns "".
func restriction(origin string, makefile []byte, deniedLicenses map[string]bool) string {
	if m := restrictionVar.FindSubmatch(makefile); m != nil {
		return fmt.Sprintf("%s sets %s=%s", origin, m[1], strings.TrimSpace(string(m[2])))
	}
	for _, m := range licensePermsVar.FindAllSubmatch(makefile, -1) {
		if withholdsDistfiles(string(m[2])) {
			return fmt.Sprintf("%s sets %s=%s, which withholds dist-mirror or dist-sell", origin, m[1], strings.TrimSpace(string(m[2])))
		}
	}
	for _, m := range licenseVar.FindAllSubmatch(makefile, -1) {
		for _, lic := range strings.Fields(string(m[1])) {
			if deniedLicenses[lic] {
				return fmt.Sprintf("%s is licensed %s, whose default permissions in Mk/bsd.licenses.db.mk withhold dist-mirror or dist-sell", origin, lic)
			}
		}
	}
	return ""
}

// Load walks <portsTree>/<category>/<port>/distinfo* and returns the index.
// A tree with no distinfo at all fails, because it is not a ports tree and
// every request would 404 with nothing saying why.
func Load(portsTree string) (*Index, error) {
	cats, err := os.ReadDir(portsTree)
	if err != nil {
		return nil, fmt.Errorf("read ports tree %s: %w", portsTree, err)
	}
	denied, err := loadLicenseDB(portsTree)
	if err != nil {
		return nil, err
	}
	ix := &Index{entries: map[string]*Entry{}, refused: map[string]string{}}
	byPort := map[string][]string{}   // origin -> names its distinfo pins
	restricted := map[string]string{} // origin -> reason
	for _, cat := range cats {
		if !cat.IsDir() || strings.HasPrefix(cat.Name(), ".") || cat.Name() == "distfiles" || cat.Name() == "packages" {
			continue
		}
		ports, err := os.ReadDir(filepath.Join(portsTree, cat.Name()))
		if err != nil {
			return nil, fmt.Errorf("read category %s: %w", cat.Name(), err)
		}
		for _, p := range ports {
			if !p.IsDir() {
				continue
			}
			origin := cat.Name() + "/" + p.Name()
			dir := filepath.Join(portsTree, cat.Name(), p.Name())
			files, err := os.ReadDir(dir)
			if err != nil {
				return nil, fmt.Errorf("read port %s: %w", origin, err)
			}
			var makefiles []byte
			for _, f := range files {
				n := f.Name()
				switch {
				case f.IsDir():
				case n == "distinfo" || strings.HasPrefix(n, "distinfo."):
					if err := ix.addDistinfo(filepath.Join(dir, n), origin, byPort); err != nil {
						return nil, err
					}
				case n == "Makefile" || strings.HasPrefix(n, "Makefile."):
					b, err := os.ReadFile(filepath.Join(dir, n)) //nolint:gosec // G304: a Makefile under the configured ports tree.
					if err != nil {
						return nil, fmt.Errorf("read %s/%s: %w", origin, n, err)
					}
					makefiles = append(append(makefiles, joinContinuations(b)...), '\n')
				}
			}
			if why := restriction(origin, makefiles, denied); why != "" {
				restricted[origin] = why
				// A slave reads its master's distinfo, so its restriction
				// has to reach the names filed under the master.
				if mm := masterDirVar.FindSubmatch(makefiles); mm != nil {
					master := path.Clean(origin + "/" + string(mm[1]))
					if !strings.HasPrefix(master, "..") && strings.Count(master, "/") == 1 {
						if _, ok := restricted[master]; !ok {
							restricted[master] = why
						}
					}
				}
			}
		}
	}
	if ix.Len() == 0 {
		return nil, fmt.Errorf("%s holds no <category>/<port>/distinfo; distfiles_ports_tree must name the root of a FreeBSD ports tree", portsTree)
	}
	for origin, why := range restricted {
		for _, name := range byPort[origin] {
			if e, ok := ix.entries[name]; ok && e.Restricted == "" {
				e.Restricted = why
			}
		}
	}
	return ix, nil
}

func (ix *Index) addDistinfo(file, origin string, byPort map[string][]string) error {
	f, err := os.Open(file) //nolint:gosec // G304: file is a distinfo under the configured ports tree.
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer f.Close()
	parsed, unusable, err := Parse(f)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for name, why := range unusable {
		ix.refused[name] = origin + "/" + filepath.Base(file) + ": " + why
		delete(ix.entries, name)
	}
	for name, e := range parsed {
		byPort[origin] = append(byPort[origin], name)
		if _, bad := ix.refused[name]; bad {
			continue
		}
		have, ok := ix.entries[name]
		if !ok {
			e.Ports = []string{origin}
			ix.entries[name] = &e
			continue
		}
		if have.SHA256 != e.SHA256 || have.Size != e.Size {
			ix.refused[name] = fmt.Sprintf("%s and %s pin different digests", strings.Join(have.Ports, ","), origin)
			delete(ix.entries, name)
			continue
		}
		have.Ports = append(have.Ports, origin)
		sort.Strings(have.Ports)
	}
	return nil
}

// Tree is an Index over one ports tree, read in the background and re-read
// once it is older than ttl, so a server neither waits out a cold walk at
// startup nor holds a request while a stale index reloads. A reload that fails
// keeps the previous index: a server that refused every distfile because a
// `git pull` was halfway through would turn a transient state into an outage.
type Tree struct {
	root string
	ttl  time.Duration
	logf func(format string, args ...any)

	mu      sync.Mutex
	ix      *Index
	loadErr error
	loaded  time.Time
	loading bool

	ready     chan struct{} // closed when the first read finishes, either way
	readyOnce sync.Once
}

// NewTree starts the first read of root and returns at once. logf receives
// one line per completed or failed read; nil discards them.
func NewTree(root string, ttl time.Duration, logf func(format string, args ...any)) *Tree {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &Tree{root: root, ttl: ttl, logf: logf, ready: make(chan struct{})}
	t.mu.Lock()
	t.startLoadLocked()
	t.mu.Unlock()
	return t
}

// Root is the ports tree this index reads.
func (t *Tree) Root() string { return t.root }

func (t *Tree) startLoadLocked() {
	if t.loading {
		return
	}
	t.loading = true
	t.loaded = time.Now()
	go func() {
		start := time.Now()
		ix, err := Load(t.root)
		t.mu.Lock()
		defer t.mu.Unlock()
		defer t.readyOnce.Do(func() { close(t.ready) })
		t.loading = false
		t.loaded = time.Now()
		if err != nil {
			t.loadErr = err
			t.logf("distinfo: reading %s failed after %s, keeping the previous index: %v", t.root, time.Since(start).Round(time.Millisecond), err)
			return
		}
		t.ix, t.loadErr = ix, nil
		t.logf("distinfo: indexed %d distfiles from %s in %s", ix.Len(), t.root, time.Since(start).Round(time.Millisecond))
	}()
}

// Wait blocks until the first read has finished, for a caller with nothing to
// serve until it has. It returns the read's error, if any.
func (t *Tree) Wait() error {
	<-t.ready
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ix != nil {
		return nil
	}
	return t.loadErr
}

// firstReadWait is how long a lookup waits for the first read before
// answering ErrNotReady. A warm tree reads in about a second, so a request that
// arrives soon after startup is answered rather than refused; a cold one does
// not hold a client for the better part of a minute.
const firstReadWait = 5 * time.Second

// Lookup answers from the current index, starting a background re-read when
// it is stale. Before the first read completes it waits up to firstReadWait,
// then returns ErrNotReady.
func (t *Tree) Lookup(name string) (Entry, error) {
	select {
	case <-t.ready:
	case <-time.After(firstReadWait):
	}
	t.mu.Lock()
	if t.ttl > 0 && time.Since(t.loaded) > t.ttl {
		t.startLoadLocked()
	}
	ix, loadErr := t.ix, t.loadErr
	t.mu.Unlock()
	if ix == nil {
		if loadErr != nil {
			return Entry{}, fmt.Errorf("%w: reading %s failed: %v", ErrNotReady, t.root, loadErr)
		}
		return Entry{}, fmt.Errorf("%w: still reading %s", ErrNotReady, t.root)
	}
	return ix.Lookup(name)
}

// Names lists every distfile the index can answer for, sorted.
func (ix *Index) Names() []string {
	out := make([]string, 0, ix.Len())
	for n := range ix.entries {
		out = append(out, n)
	}
	for n := range ix.refused {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
