package clientconf

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// GoEnv is the host the go command resolves GOPROXY on.
type GoEnv struct {
	// Getenv reads the environment the go command starts in. Nil is an
	// empty one.
	Getenv func(string) string
	// ConfigDir is os.UserConfigDir for the account go runs as. Nil, or an
	// error, is an account with no such directory, which has no user file.
	ConfigDir func() (string, error)
	// Planned is the content a plan gives each go env file it writes, by
	// path, read in place of what is on disk: the policy the host has once
	// the plan is applied.
	Planned map[string][]byte
}

// GoProxyPolicy is the GOPROXY the go command runs with, and what it makes of
// the list. The row that reports on GOPROXY, the trust verdict and the CA
// install all read this one result, so none can certify a list another
// refuses.
type GoProxyPolicy struct {
	// Value is the setting as the go command resolves it, and Source the
	// environment or the file that set it.
	Value, Source string
	// Found is false when nothing sets the key. Dist says the file is
	// GOROOT/go.env, the defaults a Go distribution ships, which `go env -w`
	// overrides.
	Found, Dist bool
	// Proxies are the entries the go command can reach, in order, through
	// the "off" or "direct" that ends the walk. Nil when Err is set.
	Proxies []string
	// Err is the go command's refusal of the list: it validates every entry
	// before it asks the first proxy, so one bad entry anywhere before the
	// terminator fails every module download. URL passwords are redacted.
	Err error
}

func (e GoEnv) env(key string) string {
	if e.Getenv == nil {
		return ""
	}
	return e.Getenv(key)
}

// Proxy resolves GOPROXY as go1.27.4's cmd/go/internal/cfg does (Getenv,
// EnvFile, initEnvCache, readEnvFile): a non-empty value in the environment,
// else the user's go env file when it assigns the key, an empty assignment
// included, else GOROOT/go.env. A file that is absent or does not read sets
// nothing, GOENV=off and a missing user configuration directory mean no user
// file, and none of those stops the go command reading GOROOT/go.env. The
// value then goes through GoProxyList, the check the go command runs on it
// before any download, which refuses an empty assignment as it refuses any
// other list holding no entry.
func (e GoEnv) Proxy() GoProxyPolicy {
	p := e.setting()
	// With nothing found, what the go command runs with is not known here,
	// and an empty list would be a guess at it.
	if p.Found {
		p.Proxies, p.Err = GoProxyList(p.Value)
	}
	return p
}

func (e GoEnv) setting() GoProxyPolicy {
	const key = "GOPROXY"
	if val := e.env(key); val != "" {
		return GoProxyPolicy{Value: val, Source: "the environment", Found: true}
	}
	file := e.File()
	user := e.read(file)
	if val, ok := user[key]; ok {
		return GoProxyPolicy{Value: val, Source: file, Found: true}
	}
	if goroot := findGoroot(user["GOROOT"], e.env); goroot != "" {
		dist := filepath.Join(goroot, "go.env")
		if val, ok := e.read(dist)[key]; ok {
			return GoProxyPolicy{Value: val, Source: dist, Found: true, Dist: true}
		}
	}
	return GoProxyPolicy{Source: "the environment"}
}

// File is cfg.EnvFile: $GOENV, or go/env under the user configuration
// directory. "" is no file: GOENV=off, or no such directory.
func (e GoEnv) File() string {
	switch file := e.env("GOENV"); file {
	case "off":
		return ""
	case "":
	default:
		return file
	}
	if e.ConfigDir == nil {
		return ""
	}
	dir, err := e.ConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "go", "env")
}

// read is cfg.readEnvFile: KEY=VALUE lines, untrimmed, the last assignment
// winning, a line with no '=' or not opening with an uppercase letter
// skipped. A file that does not read holds nothing, which is what the go
// command makes of it.
func (e GoEnv) read(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	data, planned := e.Planned[path]
	if !planned {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return out
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || line[0] < 'A' || line[0] > 'Z' {
			continue
		}
		out[k] = v
	}
	return out
}

// findGoroot is cfg.findGOROOT for a caller that is not the go command: the
// GOROOT the user's go env file sets, else the environment's, else the tree
// around the go on PATH, tried as cmd/go tries its own executable: two and
// three directories up, as PATH names it and then with its symlinks resolved.
// The go command is located, never run. "" is no go, or one whose GOROOT its
// path does not show.
func findGoroot(fromUserFile string, getenv func(string) string) string {
	env := fromUserFile
	if env == "" {
		env = getenv("GOROOT")
	}
	if env != "" {
		return filepath.Clean(env)
	}
	// around is the GOROOT holding exe in its bin directory, which cmd/go
	// knows by the pkg/tool beside it.
	around := func(exe string) string {
		for _, up := range []string{"../..", "../../.."} {
			root := filepath.Join(exe, up)
			if info, err := os.Stat(filepath.Join(root, "pkg", "tool")); err == nil && info.IsDir() {
				return root
			}
		}
		return ""
	}
	for _, dir := range filepath.SplitList(getenv("PATH")) {
		exe := filepath.Join(dir, "go")
		if info, err := os.Stat(exe); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			continue
		}
		exe, err := filepath.Abs(exe)
		if err != nil {
			return ""
		}
		if root := around(exe); root != "" {
			return root
		}
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			return around(exe)
		}
		return ""
	}
	return ""
}

// GoProxyList is proxyList of go1.27.4's cmd/go/internal/modfetch/proxy.go
// (lines 60-123) with the newProxyRepo check it runs on each entry (lines
// 196-214). Entries are separated by ',' or '|', each trimmed and empties
// skipped; the walk ends at "off" or "direct" inclusive, since nothing after
// either is consulted or checked; an entry with no ":/" that is not a single
// word or an absolute path is read as https. Every entry before the
// terminator must then parse as a URL whose scheme is http, https or file,
// a file URL holding a path and nothing else. The go command runs that check
// over the whole list before it asks the first proxy, so the error is for
// the list, not for the entry: a valid first proxy does not get used. A walk
// that ends holding no entry, the empty string or separators and spaces alone,
// is the list's last error (lines 116-123). GONOPROXY's implicit "noproxy"
// entry does not count there, so it is not modeled.
//
// The separator only decides which errors fall through, so it is not
// returned. An error names the entry with any URL password redacted.
func GoProxyList(val string) ([]string, error) {
	var reached []string
	for val != "" {
		var entry string
		if i := strings.IndexAny(val, ",|"); i >= 0 {
			entry, val = val[:i], val[i+1:]
		} else {
			entry, val = val, ""
		}
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "off" || entry == "direct" {
			reached = append(reached, entry)
			break
		}
		if strings.ContainsAny(entry, ".:/") && !strings.Contains(entry, ":/") && !filepath.IsAbs(entry) && !path.IsAbs(entry) {
			entry = "https://" + entry
		}
		if err := goProxyURL(entry); err != nil {
			return nil, err
		}
		reached = append(reached, entry)
	}
	if len(reached) == 0 {
		return nil, errors.New("GOPROXY list is not the empty string, but contains no entries")
	}
	return reached, nil
}

// goProxyURL is the URL check of newProxyRepo.
func goProxyURL(entry string) error {
	base, err := url.Parse(entry)
	if err != nil {
		// url.Parse quotes the whole input, password included, so the
		// error is rebuilt around the redacted entry.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("invalid proxy URL %s: %w", redactURLPassword(entry), err)
	}
	redacted := base.Redacted()
	switch base.Scheme {
	case "http", "https":
	case "file":
		if *base != (url.URL{Scheme: base.Scheme, Path: base.Path, RawPath: base.RawPath}) {
			return fmt.Errorf("invalid file:// proxy URL with non-path elements: %s", redacted)
		}
	case "":
		return fmt.Errorf("invalid proxy URL missing scheme: %s", redacted)
	default:
		return fmt.Errorf("invalid proxy URL scheme (must be https, http, file): %s", redacted)
	}
	return nil
}

// redactURLPassword hides the password of a URL that does not parse, which
// url.URL.Redacted cannot be asked for: everything between the first ':' of
// the userinfo and the last '@' of the authority.
func redactURLPassword(raw string) string {
	start := strings.Index(raw, "://")
	if start < 0 {
		return raw
	}
	start += len("://")
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
		end = start + i
	}
	at := strings.LastIndex(raw[start:end], "@")
	if at < 0 {
		return raw
	}
	colon := strings.Index(raw[start:start+at], ":")
	if colon < 0 {
		return raw
	}
	return raw[:start+colon+1] + "xxxxx" + raw[start+at:]
}
