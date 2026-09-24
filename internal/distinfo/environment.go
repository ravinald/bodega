package distinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Absent is the alternative that declares a client-host file missing.
const Absent = "absent"

// Environment is the supported client environment: what bodega is told a
// client's make holds that its ports tree does not. A stock port reads files on
// the client host, outside the tree (the aspell dictionaries include
// ${LOCALBASE}/etc/aspell.ver), and variables that make.conf, the environment
// or the framework set (ARCH, NODEJS_VERSION). Those can change a port's
// redistribution terms and which distinfo it reads, and the server has no way
// to observe them on a client. So they are declared, and admission is decided
// against the declaration and nothing else: never against the server host's
// own files, and never against an absence nobody declared.
//
// A variable lists every value it may hold where a port reads it, on every
// supported client; an empty list declares it undefined everywhere, so make
// expands it to nothing. A file lists its alternatives: Absent, and the path of
// a snapshot holding the bytes a client may have there. A file with several
// alternatives is read as every one of them, the way a conditional include is.
// The snapshots are read once, here, and the digest covers every declared
// byte, so a reload can tell the environment it admits against has not moved.
type Environment struct {
	vars      map[string][]string
	undefined map[string]bool
	files     map[string]envFile
	digest    string
}

type envFile struct {
	absent  bool
	sources []string // snapshot paths, in declared order
	texts   [][]byte
}

// EnvironmentSpec is the operator's declaration, as configuration spells it.
// Variables maps a make variable to its values; Files maps an absolute
// client-host path to its alternatives.
type EnvironmentSpec struct {
	Variables map[string][]string
	Files     map[string][]string
}

var makeVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reservedEnvVars are the variables the reader derives itself, or reads as a
// port's own declaration. A client make.conf that set one would change every
// port at once, which the reader does not model, so declaring one is refused
// rather than half-applied.
var reservedEnvVars = map[string]string{
	"PORTSDIR":      "the reader sets it to the ports tree bodega reads",
	"MASTERDIR":     "the framework derives it per port",
	"FILESDIR":      "the framework derives it per port",
	"PKGDIR":        "the framework derives it per port",
	"DISTINFO_FILE": "the framework derives it per port, and a value set for every port would place every distinfo in one file",
	"RESTRICTED":    "it is a port's redistribution term, and one set for every port is not modeled",
	"NO_CDROM":      "it is a port's redistribution term, and one set for every port is not modeled",
	"LICENSE":       "it is a port's redistribution term, and one set for every port is not modeled",
}

// Validate checks the declaration without reading any snapshot, so a
// configuration that could never load is refused where it is written.
func (s EnvironmentSpec) Validate() error {
	_, err := s.load(false)
	return err
}

// Load reads every snapshot the spec names and returns the environment, or
// says which declaration is unusable. An empty spec is the empty environment:
// no variable declared and no file outside the tree readable, which refuses
// every port that reads one.
func (s EnvironmentSpec) Load() (*Environment, error) { return s.load(true) }

func (s EnvironmentSpec) load(read bool) (*Environment, error) {
	env := &Environment{vars: map[string][]string{}, undefined: map[string]bool{}, files: map[string]envFile{}}
	h := sha256.New()
	names := make([]string, 0, len(s.Variables))
	for name := range s.Variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vals := s.Variables[name]
		if !makeVarName.MatchString(name) {
			return nil, fmt.Errorf("distfiles_environment_variables: %q is not a make variable name bodega can declare", name)
		}
		if why, ok := reservedEnvVars[name]; ok || strings.HasPrefix(name, "LICENSE_PERMS") {
			if !ok {
				why = "it is a port's redistribution term, and one set for every port is not modeled"
			}
			return nil, fmt.Errorf("distfiles_environment_variables: %s cannot be declared: %s", name, why)
		}
		if len(vals) > maxPathValues {
			return nil, fmt.Errorf("distfiles_environment_variables: %s declares %d values, more than the %d one path may expand to", name, len(vals), maxPathValues)
		}
		fmt.Fprintf(h, "var %q\n", name)
		if len(vals) == 0 {
			env.undefined[name] = true
			continue
		}
		for _, v := range vals {
			if strings.ContainsAny(v, "\n") {
				return nil, fmt.Errorf("distfiles_environment_variables: %s has a value holding a newline", name)
			}
			fmt.Fprintf(h, "\t%q\n", v)
		}
		env.vars[name] = dedupe(append([]string(nil), vals...))
	}

	paths := make([]string, 0, len(s.Files))
	for p := range s.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		alts := s.Files[p]
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("distfiles_environment_files: %q must be an absolute, clean path on the client host", p)
		}
		if len(alts) == 0 {
			return nil, fmt.Errorf("distfiles_environment_files: %s lists no alternative; declare %q or the path of a snapshot of the file", p, Absent)
		}
		var f envFile
		fmt.Fprintf(h, "file %q\n", p)
		for _, alt := range alts {
			if alt == Absent {
				f.absent = true
				fmt.Fprintf(h, "\tabsent\n")
				continue
			}
			if !filepath.IsAbs(alt) {
				return nil, fmt.Errorf("distfiles_environment_files: %s: alternative %q must be %q or an absolute path to a snapshot of the file", p, alt, Absent)
			}
			if !read {
				continue
			}
			b, err := os.ReadFile(alt) //nolint:gosec // G304: a snapshot path the operator declared.
			if err != nil {
				return nil, fmt.Errorf("distfiles_environment_files: %s: read the snapshot %s: %w", p, alt, err)
			}
			sum := sha256.Sum256(b)
			fmt.Fprintf(h, "\t%s\n", hex.EncodeToString(sum[:]))
			f.sources = append(f.sources, alt)
			f.texts = append(f.texts, b)
		}
		env.files[p] = f
	}
	env.digest = hex.EncodeToString(h.Sum(nil))
	return env, nil
}

// Digest identifies the declared environment, snapshot bytes included.
func (e *Environment) Digest() string { return e.digest }

// emptyEnvironment declares nothing, which is what Load admits against.
func emptyEnvironment() *Environment {
	env, _ := EnvironmentSpec{}.Load() // an empty spec reads nothing and cannot fail
	return env
}
