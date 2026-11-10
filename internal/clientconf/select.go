package clientconf

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The functions here answer one question for a client that can take its
// trust from several places: which of them it reads. The plan that installs
// a CA and the probe that judges one both ask here, so a certificate is never
// installed into, or counted from, a place the client passes over.

// PipHost is the host a pip runs on.
type PipHost struct {
	GOOS string
	// Root is the directory pip's absolute paths sit under, "" for the
	// host's own. Home is used as given.
	Root, Home string
	Getenv     func(string) string
	// Prefix is the sys.prefix of the interpreter pip runs under, as pip
	// reports it, "" when it was not asked. VIRTUAL_ENV names it first.
	Prefix string
}

func (h PipHost) env(key string) string {
	if h.Getenv == nil {
		return ""
	}
	return h.Getenv(key)
}

// PipConfigFiles lists the configuration files pip loads, in the order it
// loads them, a later file's option replacing an earlier one's, and how many
// of them lead the list as the global files. They are pip's own
// get_configuration_files: the global files (under each XDG_CONFIG_DIRS entry
// and then /etc, or /Library/Application Support on macOS, which reads
// neither), the per-user files (~/.pip, then the XDG directory, which on macOS
// is ~/Library/Application Support/pip only when that directory exists), the
// interpreter's own sys.prefix/pip.conf, and last the file PIP_CONFIG_FILE
// names. When that file exists pip skips the per-user files, and when it is
// the null device pip loads no file at all.
//
// The prefix is VIRTUAL_ENV, else Prefix, else where the platform's packaged
// Python lives; an interpreter installed anywhere else has a pip.conf beside
// it that only asking pip finds.
func PipConfigFiles(h PipHost) (files []string, global int) {
	explicit := h.env("PIP_CONFIG_FILE")
	if explicit == os.DevNull {
		return nil, 0
	}
	if h.GOOS == OSDarwin {
		files = append(files, filepath.Join(h.Root, "/Library/Application Support/pip/pip.conf"))
	} else {
		dirs := h.env("XDG_CONFIG_DIRS")
		if dirs == "" {
			dirs = "/etc/xdg"
		}
		for _, d := range strings.Split(dirs, ":") {
			if d != "" {
				files = append(files, filepath.Join(h.Root, d, "pip", "pip.conf"))
			}
		}
		files = append(files, filepath.Join(h.Root, "/etc/pip.conf"))
	}
	global = len(files)
	skipUser := false
	if explicit != "" {
		_, err := os.Stat(explicit)
		skipUser = err == nil
	}
	if h.Home != "" && !skipUser {
		user := filepath.Join(h.Home, ".config", "pip")
		mac := filepath.Join(h.Home, "Library", "Application Support", "pip")
		switch info, err := os.Stat(mac); {
		case h.GOOS == OSDarwin && err == nil && info.IsDir():
			user = mac
		case h.GOOS != OSDarwin && h.env("XDG_CONFIG_HOME") != "":
			user = filepath.Join(h.env("XDG_CONFIG_HOME"), "pip")
		}
		files = append(files, filepath.Join(h.Home, ".pip", "pip.conf"), filepath.Join(user, "pip.conf"))
	}
	prefix := h.env("VIRTUAL_ENV")
	if prefix == "" {
		prefix = h.Prefix
	}
	if prefix == "" {
		switch h.GOOS {
		case OSLinux:
			prefix = filepath.Join(h.Root, "/usr")
		case OSFreeBSD:
			prefix = filepath.Join(h.Root, "/usr/local")
		}
	}
	if prefix != "" {
		files = append(files, filepath.Join(prefix, "pip.conf"))
	}
	if explicit != "" {
		files = append(files, explicit)
	}
	return files, global
}

// PodmanCertDir is the directory podman, buildah and CRI-O read CA
// certificates for the registry at hostPort from: the first that exists of
// the per-user certs.d, /etc/containers/certs.d and /etc/docker/certs.d, as
// containers/image picks it. The directories are not combined, so an existing
// one hides every one after it even when it is empty. "" when none exists,
// where those clients read no certificate of their own.
func PodmanCertDir(home, root, hostPort string) string {
	var dirs []string
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", "containers", "certs.d"))
	}
	dirs = append(dirs, filepath.Join(root, "/etc/containers/certs.d"), filepath.Join(root, "/etc/docker/certs.d"))
	for _, d := range dirs {
		full := filepath.Join(d, hostPort)
		if _, err := os.Stat(full); err == nil {
			return full
		}
	}
	return ""
}

// GitConfigFiles lists the configuration files git reads outside a
// repository, in the order it reads them: the system file, unless
// GIT_CONFIG_NOSYSTEM turns it off, then the per-user files, the XDG one
// ahead of ~/.gitconfig. GIT_CONFIG_SYSTEM and GIT_CONFIG_GLOBAL each name a
// file read in place of those. A repository's own config, the entries
// GIT_CONFIG_COUNT carries and files an [include] names are not listed.
func GitConfigFiles(getenv func(string) string, home, root string) []string {
	env := func(key string) string {
		if getenv == nil {
			return ""
		}
		return getenv(key)
	}
	var files []string
	nosystem := strings.ToLower(env("GIT_CONFIG_NOSYSTEM"))
	switch {
	case nosystem != "" && !slices.Contains([]string{"0", "false", "no", "off"}, nosystem):
	case env("GIT_CONFIG_SYSTEM") != "":
		files = append(files, env("GIT_CONFIG_SYSTEM"))
	default:
		files = append(files, filepath.Join(root, "/etc/gitconfig"))
	}
	switch {
	case env("GIT_CONFIG_GLOBAL") != "":
		files = append(files, env("GIT_CONFIG_GLOBAL"))
	case home != "":
		xdg := env("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		files = append(files, filepath.Join(xdg, "git", "config"), filepath.Join(home, ".gitconfig"))
	}
	return files
}

// GitCA is one http.sslCAInfo a git configuration file sets.
type GitCA struct {
	// Value is the file it names and File the configuration file setting it.
	Value, File string
	// Header is the section's header as the file writes it, and Pattern the
	// URL it scopes the setting to, "" for a plain [http].
	Header, Pattern string
}

var gitSection = regexp.MustCompile(`^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]$`)

// gitCAInfos reads every http.sslCAInfo out of a git config body, in order,
// telling settings from continuation lines by the rule the merge edits the
// file with.
func gitCAInfos(lines []string, file, home string) []GitCA {
	var out []GitCA
	scan := lineScan{rules: slashRules, keyIndent: -1}
	var header, pattern string
	inHTTP := false
	for _, l := range lines {
		if scan.continues(l) {
			continue
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			m := gitSection.FindStringSubmatch(t)
			inHTTP = m != nil && strings.EqualFold(m[1], "http")
			if inHTTP {
				header, pattern = t, strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[2])
			}
			continue
		}
		if !inHTTP || slashRules.key(l) != "sslcainfo" {
			continue
		}
		_, v, _ := strings.Cut(t, "=")
		for _, mark := range []string{" #", " ;", "\t#", "\t;"} {
			if i := strings.Index(v, mark); i >= 0 && !strings.Contains(v[:i], `"`) {
				v = v[:i]
			}
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		if rest, ok := strings.CutPrefix(v, "~/"); ok && home != "" {
			v = filepath.Join(home, rest)
		}
		out = append(out, GitCA{Value: v, File: file, Header: header, Pattern: pattern})
	}
	return out
}

// gitURL is a URL as git's urlmatch compares one: scheme and host lowercased,
// the scheme's default port dropped, and a path ending in a slash.
type gitURL struct {
	scheme, host, port, user, path string
}

func parseGitURL(s string) (gitURL, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return gitURL{}, false
	}
	g := gitURL{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(u.Hostname()), port: u.Port(), user: u.User.String()}
	if g.port == "443" && g.scheme == "https" || g.port == "80" && g.scheme == "http" {
		g.port = ""
	}
	g.path = strings.TrimRight(u.Path, "/") + "/"
	return g, true
}

// hostMatch reports whether pattern names host, a * standing for one label,
// and whether it does so without one.
func (g gitURL) hostMatch(pattern string) (match, exact bool) {
	if pattern == g.host {
		return true, true
	}
	want, have := strings.Split(pattern, "."), strings.Split(g.host, ".")
	if len(want) != len(have) {
		return false, false
	}
	for i := range want {
		if want[i] != "*" && want[i] != have[i] {
			return false, false
		}
	}
	return true, false
}

// under reports whether pattern scopes a setting to URLs at or below g on
// g's own host: the sections that outrank or tie with one scoped to g for
// some URL below it.
func (g gitURL) under(pattern string) bool {
	p, ok := parseGitURL(pattern)
	return ok && p.scheme == g.scheme && p.host == g.host && p.port == g.port && strings.HasPrefix(p.path, g.path)
}

// GitCAInfo resolves which http.sslCAInfo git applies to URLs under base, from
// the files in the order git reads them. own is the setting git picks for
// base itself, by urlmatch's rule: an exact host outranks a wildcard, then
// the longer path wins, a scoped section outranks a plain [http], and between
// equals the later one stands. Nil means git verifies base against its
// default store. narrower holds each setting scoped more tightly than base,
// to a path below it or to one user, which git reads in own's place for the
// URLs it covers.
func GitCAInfo(files []string, base, home string) (own *GitCA, narrower []GitCA) {
	b, ok := parseGitURL(base)
	if !ok {
		return nil, nil
	}
	ownRank := [3]int{-1}
	byPattern := map[string]GitCA{}
	var order []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, ca := range gitCAInfos(splitBody(data), f, home) {
			rank := [3]int{}
			if ca.Pattern != "" {
				p, ok := parseGitURL(ca.Pattern)
				if !ok || p.scheme != b.scheme || p.port != b.port {
					continue
				}
				match, exact := b.hostMatch(p.host)
				if !match {
					continue
				}
				if exact && b.under(ca.Pattern) && (p.user != "" || len(p.path) > len(b.path)) {
					if _, seen := byPattern[ca.Pattern]; !seen {
						order = append(order, ca.Pattern)
					}
					byPattern[ca.Pattern] = ca
					continue
				}
				if p.user != "" || !strings.HasPrefix(b.path, p.path) {
					continue
				}
				rank = [3]int{1, 0, len(p.path)}
				if exact {
					rank[1] = 1
				}
			}
			if slices.Compare(rank[:], ownRank[:]) >= 0 {
				ownRank, own = rank, &ca
			}
		}
	}
	for _, p := range order {
		narrower = append(narrower, byPattern[p])
	}
	return own, narrower
}

// gitShadowHeaders lists the headers of the [http "<url>"] sections of a git
// config body that set sslCAInfo for URLs at or below base: each is read in
// place of, or on equal terms with, the section a plan scopes to base.
func gitShadowHeaders(lines []string, base string) []string {
	b, ok := parseGitURL(base)
	if !ok {
		return nil
	}
	var out []string
	for _, ca := range gitCAInfos(lines, "", "") {
		if ca.Pattern != "" && b.under(ca.Pattern) && !slices.Contains(out, ca.Header) {
			out = append(out, ca.Header)
		}
	}
	return out
}
