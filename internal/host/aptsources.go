package host

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	aptSourcesList = "/etc/apt/sources.list"
	aptSourcesDir  = "/etc/apt/sources.list.d"
)

// aptSourcePaths lists the sources files apt reads, unrooted, in the order
// it reads them: sources.list, then sources.list.d's .list and .sources files.
func aptSourcePaths(root string) []string {
	paths := []string{aptSourcesList}
	entries, err := os.ReadDir(filepath.Join(root, aptSourcesDir))
	if err != nil {
		return paths
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".list") && !strings.HasSuffix(n, ".sources")) {
			continue
		}
		paths = append(paths, filepath.Join(aptSourcesDir, n))
	}
	return paths
}

// AptSource is one enabled source apt reads: a deb822 stanza or a one-line
// entry.
type AptSource struct {
	// File is the sources file, unrooted.
	File string
	// Line is the stanza's first field line, or the entry's own line,
	// counted from 1.
	Line   int
	Deb822 bool
	URIs   []string
	// Public is the public archive host the source names, directly or
	// through the mirror list a mirror+file URI points at, and empty for
	// any other source.
	Public string
	// SetsEnabled says the stanza carries an Enabled field of its own.
	SetsEnabled bool
}

// AptSources returns every enabled source under root by the rules the
// apt-sources check reads them with. A mirror list it cannot read is an
// error: the source behind it can be neither kept nor disabled on a guess.
func AptSources(root string) ([]AptSource, error) {
	var out []AptSource
	for _, p := range aptSourcePaths(root) {
		data, err := os.ReadFile(filepath.Join(root, p))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		deb822 := strings.HasSuffix(p, ".sources")
		entries := oneLineEntries(string(data))
		if deb822 {
			entries = deb822Stanzas(string(data))
		}
		for _, e := range entries {
			if !e.enabled {
				continue
			}
			s := AptSource{File: p, Line: e.line, Deb822: deb822, URIs: e.uris, SetsEnabled: e.setsEnabled}
			for _, uri := range e.uris {
				pub, err := aptPublicHost(root, uri)
				if err != nil {
					return nil, fmt.Errorf("%s line %d: %w", p, e.line, err)
				}
				if pub != "" {
					s.Public = pub
					break
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

func aptPublicHost(root, uri string) (string, error) {
	mirror, ok := aptMirrorFile(uri)
	if !ok {
		return publicHost(uri, publicUpstreams["apt"]), nil
	}
	mirrors, err := aptMirrorURIs(filepath.Join(root, mirror))
	if err != nil {
		return "", fmt.Errorf("could not read apt mirror list %s, named by %s: %w", mirror, uri, err)
	}
	for _, m := range mirrors {
		if h := publicHost(m, publicUpstreams["apt"]); h != "" {
			return h, nil
		}
	}
	return "", nil
}

const (
	aptDisabledField = "Enabled: no\n"
	aptCommentPrefix = "# "
)

// AptEdit takes sources in one file out of apt's path, and puts them back.
// In a deb822 file it inserts an Enabled: no line at the head of each
// stanza; in a one-line file it comments each entry out. Lines are counted
// in the edited file, so the edit's String names exactly the lines Revert
// removes or uncomments, and Revert refuses a file whose lines no longer
// read as the edit left them rather than guessing.
type AptEdit struct {
	Path   string
	Deb822 bool
	Lines  []int
}

// DisableAptSources plans the edit that disables the sources at lines, as
// AptSource.Line reports them, in path.
func DisableAptSources(path string, deb822 bool, lines []int) AptEdit {
	e := AptEdit{Path: path, Deb822: deb822, Lines: slices.Sorted(slices.Values(lines))}
	if deb822 {
		// Each insertion pushes every later stanza down a line.
		for i := range e.Lines {
			e.Lines[i] += i
		}
	}
	return e
}

func (e AptEdit) kind() string {
	if e.Deb822 {
		return "deb822"
	}
	return "one-line"
}

// String is the edit's name in the record --restore-apt-sources reads.
func (e AptEdit) String() string {
	nums := make([]string, len(e.Lines))
	for i, l := range e.Lines {
		nums[i] = strconv.Itoa(l)
	}
	return e.kind() + " " + e.Path + " " + strings.Join(nums, ",")
}

// ParseAptEdit reads a name String wrote. It accepts only a path apt reads
// sources from, so a record edited by hand cannot point the restore at any
// other file.
func ParseAptEdit(s string) (AptEdit, error) {
	f := strings.Fields(s)
	if len(f) != 3 || (f[0] != "deb822" && f[0] != "one-line") {
		return AptEdit{}, fmt.Errorf("%q is not <deb822|one-line> <path> <lines>", s)
	}
	e := AptEdit{Path: f[1], Deb822: f[0] == "deb822"}
	ext := ".list"
	if e.Deb822 {
		ext = ".sources"
	}
	inDir := filepath.Dir(e.Path) == aptSourcesDir && strings.HasSuffix(e.Path, ext)
	if filepath.Clean(e.Path) != e.Path || !(inDir || (!e.Deb822 && e.Path == aptSourcesList)) {
		return AptEdit{}, fmt.Errorf("%q names %s, which is not a %s apt sources file", s, e.Path, e.kind())
	}
	for _, n := range strings.Split(f[2], ",") {
		l, err := strconv.Atoi(n)
		if err != nil || l < 1 || (len(e.Lines) > 0 && l <= e.Lines[len(e.Lines)-1]) {
			return AptEdit{}, fmt.Errorf("%q: lines must be ascending numbers from 1", s)
		}
		e.Lines = append(e.Lines, l)
	}
	return e, nil
}

// Apply makes the edit to the file under root.
func (e AptEdit) Apply(root string) error {
	path, lines, err := e.read(root)
	if err != nil {
		return err
	}
	for _, l := range e.Lines {
		i := l - 1
		switch {
		case e.Deb822 && i < len(lines):
			lines = slices.Insert(lines, i, aptDisabledField)
		case !e.Deb822 && i < len(lines) && !strings.HasPrefix(lines[i], "#"):
			lines[i] = aptCommentPrefix + lines[i]
		default:
			return fmt.Errorf("%s has no line %d to disable; nothing in it was changed. Re-run doctor to plan against the file as it is now", path, l)
		}
	}
	return e.write(path, lines)
}

// Revert undoes Apply, byte for byte, provided nothing else changed those
// lines since.
func (e AptEdit) Revert(root string) error {
	path, lines, err := e.read(root)
	if err != nil {
		return err
	}
	for _, l := range slices.Backward(e.Lines) {
		i := l - 1
		switch {
		case e.Deb822 && i < len(lines) && lines[i] == aptDisabledField:
			lines = slices.Delete(lines, i, i+1)
		case !e.Deb822 && i < len(lines) && strings.HasPrefix(lines[i], aptCommentPrefix):
			lines[i] = strings.TrimPrefix(lines[i], aptCommentPrefix)
		default:
			want := "the line Enabled: no"
			if !e.Deb822 {
				want = "a line commented out with " + strconv.Quote(aptCommentPrefix)
			}
			return fmt.Errorf("line %d of %s is not %s, so it changed since doctor disabled it and nothing in the file was restored. "+
				"Restore the file by hand, then remove %q from the record", l, path, want, e.String())
		}
	}
	return e.write(path, lines)
}

func (e AptEdit) read(root string) (string, []string, error) {
	path := filepath.Join(root, e.Path)
	data, err := os.ReadFile(path)
	if err != nil {
		return path, nil, fmt.Errorf("read %s: %w", path, err)
	}
	return path, strings.SplitAfter(string(data), "\n"), nil
}

func (e AptEdit) write(path string, lines []string) error {
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
