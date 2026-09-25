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
//
// A declaration binds nothing by itself: bodega cannot see a client, and a
// client whose file changes after the declaration would otherwise be served
// against terms it no longer holds. ClientCheck is what binds it. The client's
// own make measures every declared input and names the digest only when all of
// them hold, and both deliveries are keyed by that name.
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
	sums    []string // SHA256 of each text, which is what a client's check compares
}

// EnvironmentSpec is the operator's declaration, as configuration spells it.
// Variables maps a make variable to its values; Files maps an absolute
// client-host path to its alternatives.
type EnvironmentSpec struct {
	Variables map[string][]string
	Files     map[string][]string
}

var (
	makeVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// clientPath is what ClientCheck can write into a make conditional and a
	// shell argument without quoting: no space, quote, "$", "#", ":", glob or
	// parenthesis.
	clientPath = regexp.MustCompile(`^/[A-Za-z0-9._/+@%,=-]+$`)
)

// clientCheckVersion is hashed into every digest, so a client check written
// under different rules never names an environment this one admits against.
const clientCheckVersion = "bodega distfiles client check 3"

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
	fmt.Fprintf(h, "%s\n", clientCheckVersion)
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
		if strings.HasPrefix(name, "_BODEGA_") || strings.HasPrefix(name, "BODEGA_DISTFILES_") {
			return nil, fmt.Errorf("distfiles_environment_variables: %s cannot be declared: the client check bodega generates uses that name", name)
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
			if strings.ContainsAny(v, "\n#\\") || strings.TrimSpace(v) != v {
				return nil, fmt.Errorf("distfiles_environment_variables: %s has the value %q, which holds a newline, \"#\", a backslash or surrounding space; make would not read it back as written in the client check", name, v)
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
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || !clientPath.MatchString(p) {
			return nil, fmt.Errorf("distfiles_environment_files: %q must be an absolute, clean path on the client host, spelled with letters, digits and ._/+@%%,=- alone so the client check can test it unquoted", p)
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
			f.sums = append(f.sums, hex.EncodeToString(sum[:]))
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

// clientReserved are the variables every port is read with unset outside the
// tree: the reserved names a declaration may not carry, bar PORTSDIR, which a
// client may point at its own copy of the tree.
var clientReserved = []string{"DISTINFO_FILE", "FILESDIR", "LICENSE", "LICENSE_PERMS", "MASTERDIR", "NO_CDROM", "PKGDIR", "RESTRICTED"}

// ClientCheck is the make fragment that binds a client to this environment.
// A client includes it at the end of /etc/make.conf, and it sets
// BODEGA_DISTFILES_ENV to Digest only while that client holds what admission
// assumed, and to "unsupported" otherwise:
//
//   - every declared file is absent where the declaration allows it, or holds
//     the bytes of one of its snapshots;
//   - no reserved variable, no variable declared undefined, and no
//     LICENSE_PERMS_<license> is set by make.conf, the environment or the
//     command line;
//   - every declared variable make.conf, the environment or the command line
//     sets, and every one make holds a value for when the fetch expands its
//     sites, holds a declared value;
//   - the command line sets no variable but a declared one or one the
//     framework passes on (frameworkPinned), because a command-line variable
//     overrides every assignment a port makes to it;
//   - make runs without -e or -I, from .CURDIR, with .PATH and .SYSPATH as a
//     stock host has them, so a relative include is looked for where the
//     reader looks for it;
//   - no makefile make.conf reads changes how make parses (.MAKEFLAGS, .PATH,
//     .READONLY and the like) or sets a license, and every makefile read after
//     make.conf is under /usr/share/mk, under the ports tree as make.conf left
//     PORTSDIR, or declared with a snapshot.
//
// The inputs are measured as make.conf is read, before the port, and again
// wherever BODEGA_DISTFILES_ENV is expanded, which is when the fetch builds
// its site list or its DISTDIR. Neither sees bytes make read in between that
// were written and put back, so neither binds them. A path declared absent is
// bound by .MAKE.MAKEFILES, make's own list of what it read, which nothing
// undoes. A snapshot path is bound by its writers (see writers) and by the
// reader, which refuses one read after a command could have run. The port is
// read after this fragment, so every variable it sets is .READONLY. Each delivery is
// keyed by the name this sets: the HTTP route admits only under the digest the
// server admitted against, and the builder writes its DISTDIR under a directory
// named by it. A client that has drifted names "unsupported", which neither
// serves, and falls through to the port's own sites.
func (e *Environment) ClientCheck() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `# bodega distfiles client check for environment %s.
#
# Generated by bodega from distfiles_environment_variables and
# distfiles_environment_files; fetch it again whenever either changes. Include
# it as the last line of /etc/make.conf and key the delivery you use on the
# environment it measures:
#
#   MASTER_SITE_OVERRIDE?=	https://<bodega>/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/
#   DISTDIR=	<distfiles_root>/distfiles/@${BODEGA_DISTFILES_ENV}
#
# BODEGA_DISTFILES_ENV is "unsupported" when this host no longer holds what
# bodega admitted against, and bodega serves nothing under that name.
# BODEGA_DISTFILES_DRIFT names what differed:
# make -V BODEGA_DISTFILES_ENV -V BODEGA_DISTFILES_DRIFT.
BODEGA_DISTFILES_DRIFT=
`, e.digest)

	undefined := append([]string(nil), clientReserved...)
	for name := range e.undefined {
		undefined = append(undefined, name)
	}
	sort.Strings(undefined)
	fmt.Fprintf(&b, ".for _bodega_v in %s\n.  if defined(${_bodega_v})\nBODEGA_DISTFILES_DRIFT+=\t${_bodega_v}\n.  endif\n.endfor\n", strings.Join(undefined, " "))

	names := make([]string, 0, len(e.vars))
	for name := range e.vars {
		names = append(names, name)
	}
	sort.Strings(names)
	var allowed strings.Builder
	for _, name := range append(append([]string(nil), names...), frameworkPinned...) {
		allowed.WriteString(":N" + name)
	}
	// A license's permissions may be set under a name built from it, which
	// no list can enumerate: refuse any spelling of one outside the tree.
	fmt.Fprintf(&b, `_BODEGA_DISTFILES_ENVIRON!=	/usr/bin/env
.if !empty(_BODEGA_DISTFILES_ENVIRON:MLICENSE_PERMS_*=*)
BODEGA_DISTFILES_DRIFT+=	LICENSE_PERMS_*
.endif
_BODEGA_DISTFILES_ARGS:=	${.MAKEOVERRIDES:O:u%s}
.if !empty(_BODEGA_DISTFILES_ARGS)
BODEGA_DISTFILES_DRIFT+=	${_BODEGA_DISTFILES_ARGS}
.endif
_BODEGA_DISTFILES_FLAGS:=	${.MAKEFLAGS:M-[eI]*}
.if !empty(_BODEGA_DISTFILES_FLAGS)
BODEGA_DISTFILES_DRIFT+=	${_BODEGA_DISTFILES_FLAGS}
.endif
_BODEGA_DISTFILES_CONF!=	/usr/bin/grep -lE '%s' ${.MAKE.MAKEFILES:N/usr/share/mk/*:N${.PARSEDIR}/${.PARSEFILE}} /dev/null 2>/dev/null || :
.if !empty(_BODEGA_DISTFILES_CONF)
BODEGA_DISTFILES_DRIFT+=	${_BODEGA_DISTFILES_CONF}
.endif
_BODEGA_DISTFILES_READ:=	${.MAKE.MAKEFILES:@_bodega_f@N${_bodega_f}@:ts:}
_BODEGA_DISTFILES_TREE:=	${PORTSDIR:U/usr/ports}
`, allowed.String(), confPattern)

	// .MAKEFLAGS is read above, once: it holds each -V argument unexpanded,
	// and -V '${BODEGA_DISTFILES_ENV}' would make a later read recursive.
	late := []string{
		`${"${.SYSPATH}" == "` + clientSysPath + `":?:.SYSPATH}`,
		`${"${.PATH}" == ". ${.CURDIR}":?:.PATH}`,
		`${"${.OBJDIR}" == "${.CURDIR}":?:.OBJDIR}`,
	}
	for i, name := range names {
		var eq []string
		for j, v := range e.vars[name] {
			ref := fmt.Sprintf("_BODEGA_DISTFILES_V%d_%d", i, j)
			fmt.Fprintf(&b, "%s=\t%s\n", ref, v)
			eq = append(eq, fmt.Sprintf(`"${%s}" == "${%s}"`, name, ref))
		}
		fmt.Fprintf(&b, ".if defined(%s) && !(%s)\nBODEGA_DISTFILES_DRIFT+=\t%s\n.endif\n", name, strings.Join(eq, " || "), name)
		late = append(late, fmt.Sprintf("${(!defined(%s) || %s):?:%s}", name, strings.Join(eq, " || "), name))
	}

	paths := make([]string, 0, len(e.files))
	for p := range e.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var declared strings.Builder
	for i, p := range paths {
		f := e.files[p]
		// make's own list of what it read is the one record a change undone
		// before the fetch cannot erase, so a path declared absent alone may
		// not appear on it. A path with a snapshot may, and which bytes make
		// read there rests on writers: see writers below.
		if len(f.sums) > 0 {
			declared.WriteString(":N" + p)
		}
		// A file is hashed only while it is a regular one: a FIFO or a device
		// at a declared path would hold every make on the client open.
		measure := fmt.Sprintf("if [ -f %[1]s ]; then /usr/bin/timeout 10 /sbin/sha256 -q %[1]s 2>/dev/null || echo unreadable; elif [ -e %[1]s ]; then echo irregular; else echo absent; fi", p)
		holds := func(ref string) string {
			var eq []string
			for _, sum := range f.sums {
				eq = append(eq, fmt.Sprintf(`"${%s}" == "%s"`, ref, sum))
			}
			if f.absent {
				eq = append(eq, fmt.Sprintf(`"${%s}" == "absent"`, ref))
			}
			return strings.Join(eq, " || ")
		}
		early, again := fmt.Sprintf("_BODEGA_DISTFILES_F%d", i), fmt.Sprintf("_BODEGA_DISTFILES_L%d", i)
		fmt.Fprintf(&b, "%s!=\t%s\n.if !(%s)\nBODEGA_DISTFILES_DRIFT+=\t%s\n.endif\n", early, measure, holds(early), p)
		if len(f.sums) > 0 {
			w := fmt.Sprintf("_BODEGA_DISTFILES_W%d", i)
			fmt.Fprintf(&b, "%s!=\t%s\n.if !empty(%s)\nBODEGA_DISTFILES_DRIFT+=\t${%s:@_bodega_w@writable:${_bodega_w}@}\n.endif\n", w, writers(p), w, w)
		}
		fmt.Fprintf(&b, "%s=\t${:!%s!}\n", again, measure)
		late = append(late, fmt.Sprintf("${(%s):?:%s}", holds(again), p))
	}
	late = append(late, fmt.Sprintf("${.MAKE.MAKEFILES:M/*:N%s/*:N${_BODEGA_DISTFILES_TREE}/*%s:${_BODEGA_DISTFILES_READ}}", clientSysPath, declared.String()))

	// Everything above that reads a variable, a file or the makefile list
	// is expanded again wherever BODEGA_DISTFILES_ENV is, after the port has
	// been read: += does not expand what it appends.
	fmt.Fprintf(&b, "BODEGA_DISTFILES_DRIFT+=\t%s\n", strings.Join(late, " "))
	fmt.Fprintf(&b, "BODEGA_DISTFILES_ENV=\t${\"${BODEGA_DISTFILES_DRIFT:M*}\" == \"\":?%s:%s}\n", e.digest, ClientUnsupported)
	// The port is read after this, and a port that assigned any of these
	// could name the digest whatever it read. .READONLY holds against every
	// assignment form base make has, .MAKEFLAGS included, and the reader
	// refuses a port that lifts it with .NOREADONLY.
	fmt.Fprintf(&b, ".READONLY:\t%s\n", strings.Join(checkVariables(b.String()), " "))
	return []byte(b.String())
}

// writers is the shell command that prints each component of p, the file
// and every directory above it, that someone other than root and the user
// running make may change: one owned by another user, one writable by its
// group or by everyone, and a symlink, whose target's directories the walk
// would not see. Both measurements read a declared snapshot path by name, so
// neither sees bytes make read in between that were written and put back;
// only a path no third party can write makes the two a statement about those
// bytes. Root and the user running make can change it unmeasured, and are the
// parties a check run on their own host already trusts. A command in the port
// runs as that user too, which is why the reader refuses a port that runs one
// before an include. A path declared absent alone needs none of this: make
// lists every file it reads in .MAKE.MAKEFILES, and nothing a writer undoes
// takes a name off that list.
func writers(p string) string {
	return fmt.Sprintf(`u=$$(/usr/bin/id -u); d=%s; while :; do if [ -L "$$d" ]; then echo "$$d"; elif [ -e "$$d" ]; then /usr/bin/find "$$d" -maxdepth 0 \( \( ! -user 0 ! -user "$$u" \) -o -perm -020 -o -perm -002 \) -print; fi; [ "$$d" = / ] && break; d=$${d%%/*}; d=$${d:-/}; done`, p)
}

var checkAssignment = regexp.MustCompile(`(?m)^(_?BODEGA_DISTFILES_[A-Za-z0-9_]+)[ \t]*[!:+]?=`)

// checkVariables lists every variable the check text assigns, sorted.
func checkVariables(check string) []string {
	var out []string
	for _, m := range checkAssignment.FindAllStringSubmatch(check, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return dedupe(out)
}

// confPattern is what the check refuses in a makefile make.conf reads: a
// license setting, which would change every port's terms at once, and a
// special target or variable that changes how make parses the port after it.
const confPattern = `LICENSE|^[[:space:]]*\.[[:space:]]*(MAKEFLAGS|MFLAGS|READONLY|NOREADONLY|PATH|OBJDIR|POSIX|SYSPATH|CURDIR|PARSEDIR|PARSEFILE|MAKEOVERRIDES)`

// ClientUnsupported is the environment a client check names when the client
// no longer holds what admission assumed.
const ClientUnsupported = "unsupported"
