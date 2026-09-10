package host

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Credential writing. The checks in this package report; this file is the one
// surface that writes, and only when an operator asks for it by name
// (`bodega doctor --write-credentials`). It exists because a feature nobody
// can adopt without hand-editing eight files does not get adopted.
//
// Five files serve the eight clients, because four of them read the same one.
// netrc is not a shortcut here: pip (through requests), the go toolchain, git
// (libcurl, CURLOPT_NETRC optional) and curl/wget all consult ~/.netrc for the
// host they are talking to, and one host-scoped entry is what they each want.
// Writing four near-identical secrets to four paths would be four things to
// rotate.

// managedBegin and managedEnd fence what bodega owns inside a file it shares
// with the operator. Rewriting the block in place is what keeps a second
// --write-credentials run idempotent instead of additive; nothing outside the
// fence is read or altered.
//
// The fence is not the only anchor, because bodega does not own these files.
// cargo, helm and npm each re-serialize their own configuration as part of
// ordinary use (`cargo login`, `helm repo add`, `npm config set`) and drop
// comments when they do, which takes the fence with it. A run that then
// appended would leave two bodega entries, the first holding the pre-rotation
// token: cargo rejects the whole file as a duplicate key, helm resolves charts
// through the stale one and puts it on the wire, npm grows a dead line per
// rotation. So each of those targets also carries an `owned` locator that
// finds bodega's entry by its own key, marker or no marker. See CredentialTarget.
//
// Every format below takes `#` to end of line as a comment: netrc (apt's
// parser and Go's both strip it, confirmed against apt 2.8.3 on noble), npm's
// ini, cargo's TOML, and YAML.
const (
	managedBegin = "# BEGIN bodega credential — written by bodega doctor --write-credentials"
	managedEnd   = "# END bodega credential"
)

// CredentialTarget is one client, the file it reads its credential from, and
// the lines bodega puts there.
type CredentialTarget struct {
	// Client is the name the doctor table prints, one of the eight routes.
	Client string

	// Path is the file this client reads. Several clients share one path.
	Path string

	// Mode is what the file is created with. Every one of these holds a
	// secret, so every one of them is 0600.
	Mode os.FileMode

	// Note is what an operator still has to do by hand, empty when nothing is.
	Note string

	// body renders the managed block's interior for this base URL and token.
	body func(base *url.URL, token string) string

	// whole, when set, means the file is bodega's alone: the block is the
	// file, and there is no operator content to preserve around it.
	whole bool

	// appendGuard refuses an append into a file whose shape would not carry
	// the block. Only helm has one; nil means appending is always legal.
	appendGuard func(existing string) error

	// createDoc wraps the block in the surrounding document a client needs
	// when bodega is the one creating the file. nil means the block stands
	// alone, which is true of every format here that a client reads line by
	// line. Only helm, which unmarshals the whole file into a struct, needs
	// keys around the entry before its parser will accept it.
	createDoc func(block string) string

	// owned returns existing with bodega's own entry removed, found by the
	// key that entry carries rather than by the fence around it. Set on the
	// three targets whose client rewrites the file and discards the fence;
	// nil where nothing but bodega ever writes the entry, which is true of
	// netrc (no client rewrites it) and of apt (whole, replaced every run).
	owned func(existing string, base *url.URL) string
}

// CredentialTargets returns every target in a stable order, resolved against
// home. A caller passes os.UserHomeDir(); the parameter is there so a test can
// drive the whole set against a scratch directory.
//
// The apt target is deliberately outside home: apt reads /etc/apt/auth.conf.d
// and nowhere else, so a doctor run as a normal user reports that write as the
// permission error it is rather than writing somewhere apt will never look.
func CredentialTargets(home string) []CredentialTarget {
	netrc := filepath.Join(home, ".netrc")
	return []CredentialTarget{
		{
			Client: "apt",
			Path:   "/etc/apt/auth.conf.d/bodega.conf",
			Mode:   0o600,
			whole:  true,
			body:   aptNetrcEntry,
		},
		{
			Client: "pip",
			Path:   netrc,
			Mode:   0o600,
			body:   netrcEntry,
			Note:   "pip reads netrc through requests; no index-url change is needed for the credential",
		},
		{
			Client: "npm",
			Path:   filepath.Join(home, ".npmrc"),
			Mode:   0o600,
			body:   npmEntry,
			owned:  npmOwned,
		},
		{
			Client: "gomod",
			Path:   netrc,
			Mode:   0o600,
			body:   netrcEntry,
			Note:   "the go toolchain reads netrc for the GOPROXY host",
		},
		{
			Client: "cargo",
			Path:   filepath.Join(home, ".cargo", "credentials.toml"),
			Mode:   0o600,
			body:   cargoEntry,
			owned:  cargoOwned,
			Note:   "point cargo at the registry too: [registries.bodega] index = \"sparse+<base>/cargo/\" in config.toml",
		},
		{
			Client:      "helm",
			Path:        helmConfigPath(home, runtime.GOOS, os.Getenv),
			Mode:        0o600,
			body:        helmEntry,
			appendGuard: helmAppendable,
			createDoc:   helmDocument,
			owned:       helmOwned,
		},
		{
			Client: "git",
			Path:   netrc,
			Mode:   0o600,
			body:   netrcEntry,
			Note:   "git reads netrc through libcurl; no credential helper is required",
		},
		{
			Client: "binary",
			Path:   netrc,
			Mode:   0o600,
			body:   netrcEntry,
			Note:   "curl needs --netrc to consult it; wget consults it already",
		},
	}
}

func netrcEntry(base *url.URL, token string) string {
	return fmt.Sprintf("machine %s\n  login bodega\n  password %s", base.Hostname(), token)
}

// aptNetrcEntry annotates the machine line with the scheme, which is apt's own
// extension to netrc and the reason apt has a file to itself.
//
// A bare `machine <host>` matches, and apt then declines to send it over plain
// HTTP: "Credentials for <host> match, but the protocol is not encrypted.
// Annotate with http:// to use." Unannotated, the entry is inert on every
// plaintext deployment and the request falls through to whatever the address
// resolves to. Annotated, it also narrows the credential to the scheme bodega
// told clients to use rather than offering it on both.
//
// The four clients sharing ~/.netrc get netrcEntry instead: libcurl, requests
// and the go toolchain each read plain netrc, where a scheme in the machine
// name is not a host they will ever match.
func aptNetrcEntry(base *url.URL, token string) string {
	if base.Scheme == "" {
		return netrcEntry(base, token)
	}
	return fmt.Sprintf("machine %s://%s\n  login bodega\n  password %s", base.Scheme, base.Hostname(), token)
}

func npmEntry(base *url.URL, token string) string {
	// npm keys the credential on the registry path, not the host, so the
	// _authToken is scoped to bodega's npm route and travels with nothing else.
	return fmt.Sprintf("//%s/npm/:_authToken=%s", base.Host, token)
}

func cargoEntry(_ *url.URL, token string) string {
	// Bare, with no scheme: cargo sends the stored token as the whole
	// Authorization header value, which is the credential form the serve path
	// parses for cargo and nothing else.
	return fmt.Sprintf("[registries.bodega]\ntoken = %q", token)
}

func helmEntry(base *url.URL, token string) string {
	return fmt.Sprintf("- name: bodega\n  url: %s/helm\n  username: bodega\n  password: %s\n  insecure_skip_tls_verify: false",
		strings.TrimSuffix(base.String(), "/"), token)
}

// Render returns the file contents this target lands on a host that has none.
// For every target but helm that is the fenced block alone; helm's parser
// needs the surrounding document, so createDoc supplies it.
//
// Exported so a caller can see what a client will read without writing
// anything, which is the only way to inspect the apt target: it resolves to
// /etc/apt/auth.conf.d and nowhere else.
func (t CredentialTarget) Render(base *url.URL, token string) string {
	block := managedBegin + "\n" + t.body(base, token) + "\n" + managedEnd + "\n"
	if t.createDoc != nil {
		return t.createDoc(block)
	}
	return block
}

// WriteCredential renders t's block for base and token and lands it in t.Path,
// reporting whether the file's contents changed.
//
// A file bodega does not own is read first and rewritten with the managed
// block replaced or appended; everything outside the fence survives byte for
// byte. helm's repositories.yaml is the one target where appending is not
// always legal, and it refuses rather than corrupting the file.
func WriteCredential(t CredentialTarget, base *url.URL, token string) (bool, error) {
	if base == nil {
		return false, fmt.Errorf("%s: no base URL to write a credential for", t.Client)
	}
	if token == "" {
		return false, fmt.Errorf("%s: no token to write", t.Client)
	}
	block := managedBegin + "\n" + t.body(base, token) + "\n" + managedEnd + "\n"

	existing := ""
	if data, err := os.ReadFile(t.Path); err == nil {
		existing = string(data)
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("%s: read %s: %w", t.Client, t.Path, err)
	}

	var next string
	switch {
	case t.whole || existing == "":
		next = t.Render(base, token)
	default:
		before, after, fenced, err := cutManaged(existing)
		if err != nil {
			return false, fmt.Errorf("%s: %s: %w", t.Client, t.Path, err)
		}
		// Anything bodega left behind that the client's own rewrite carried
		// out of the fence goes too, on both sides of where the fence was.
		// Removing it before the block is placed is what makes the second run
		// a rotation rather than a second credential.
		if t.owned != nil {
			before, after = t.owned(before, base), t.owned(after, base)
		}
		if fenced {
			// Replacing a block already in the file puts it back exactly
			// where it was, so only the append below can land in a bad place.
			next = before + block + after
			break
		}
		if t.appendGuard != nil {
			if err := t.appendGuard(before); err != nil {
				return false, fmt.Errorf("%s: %s: %w", t.Client, t.Path, err)
			}
		}
		if before != "" && !strings.HasSuffix(before, "\n") {
			before += "\n"
		}
		next = before + block
	}
	if next == existing {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(t.Path), 0o700); err != nil {
		return false, fmt.Errorf("%s: create %s: %w", t.Client, filepath.Dir(t.Path), err)
	}
	if err := os.WriteFile(t.Path, []byte(next), t.Mode); err != nil {
		return false, fmt.Errorf("%s: write %s: %w", t.Client, t.Path, err)
	}
	// WriteFile leaves an existing file's mode alone, and one of these may
	// predate bodega with a mode that lets the group read a secret.
	if err := os.Chmod(t.Path, t.Mode); err != nil {
		return false, fmt.Errorf("%s: chmod %s: %w", t.Client, t.Path, err)
	}
	return true, nil
}

// cutManaged splits existing around the fenced block and reports whether one
// was there. An unterminated begin marker is an error rather than something to
// guess at: writing past it would nest one block inside another and the next
// run would replace both.
func cutManaged(existing string) (before, after string, found bool, err error) {
	start := strings.Index(existing, managedBegin)
	if start < 0 {
		return existing, "", false, nil
	}
	rest := existing[start:]
	end := strings.Index(rest, managedEnd)
	if end < 0 {
		return "", "", false, fmt.Errorf("has a %q line with no %q after it; remove the partial block and run again",
			managedBegin, managedEnd)
	}
	end += len(managedEnd)
	if strings.HasPrefix(rest[end:], "\n") {
		end++
	}
	return existing[:start], rest[end:], true, nil
}

// helmDocument is the repositories.yaml bodega writes when the host has none.
//
// helm unmarshals this file into a struct, so a bare YAML sequence is not a
// partial file it tolerates: it is rejected whole, and every later
// `helm repo add` fails with it until someone deletes the file. The entry
// needs the top-level keys around it, which is the same rule helmAppendable
// enforces on a file that already exists. The zero timestamp keeps a second
// --write-credentials run byte-identical; helm rewrites it on its own next
// write.
func helmDocument(block string) string {
	return "apiVersion: \"\"\ngenerated: \"0001-01-01T00:00:00Z\"\nrepositories:\n" + block
}

// helmAppendable refuses to append a repository under a repositories.yaml
// whose shape would not carry it. helm's own file ends with the repositories
// list, so appending a list item lands inside it; a file where another
// top-level key follows would take bodega's entry into that key instead.
func helmAppendable(existing string) error {
	idx := -1
	lines := strings.Split(existing, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "repositories:") {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("has no top-level repositories: key, so there is no list to add a repository to; " +
			"run helm repo add bodega <url> --username bodega --password <token> instead")
	}
	for _, l := range lines[idx+1:] {
		if l == "" || strings.HasPrefix(l, " ") || strings.HasPrefix(l, "-") || strings.HasPrefix(l, "#") {
			continue
		}
		return fmt.Errorf("has the top-level key %q after repositories:, so an appended entry would land under it; "+
			"run helm repo add bodega <url> --username bodega --password <token> instead", strings.TrimSpace(l))
	}
	return nil
}

// helmConfigPath resolves repositories.yaml the way helm resolves it. It is
// the one target here whose location is not the same everywhere: helm reads
// $HELM_REPOSITORY_CONFIG first, then XDG, and its per-platform default is
// ~/Library/Preferences/helm on macOS rather than ~/.config/helm. Writing the
// Linux path on a Mac lands the credential in a file helm never opens, and
// doctor prints "written" over it.
//
// goos and env are parameters so a test can drive every platform from one.
func helmConfigPath(home, goos string, env func(string) string) string {
	if p := env("HELM_REPOSITORY_CONFIG"); p != "" {
		return p
	}
	if p := env("XDG_CONFIG_HOME"); p != "" {
		return filepath.Join(p, "helm", "repositories.yaml")
	}
	if goos == "darwin" {
		return filepath.Join(home, "Library", "Preferences", "helm", "repositories.yaml")
	}
	return filepath.Join(home, ".config", "helm", "repositories.yaml")
}

// npmOwned drops the _authToken line bodega wrote for this registry path.
// npm's ini is last-wins, so a stacked duplicate is inert rather than wrong,
// but it is still a live credential sitting in a file after its rotation.
func npmOwned(existing string, base *url.URL) string {
	key := fmt.Sprintf("//%s/npm/:_authToken=", base.Host)
	return keepLines(existing, func(line string) bool {
		return !strings.HasPrefix(strings.TrimSpace(line), key)
	})
}

// cargoOwned drops an existing [registries.bodega] table and everything under
// it, up to the next table header. A second one is not a stale entry cargo
// ignores: it is a duplicate key, and cargo refuses to parse the file at all,
// taking the operator's unrelated crates.io token down with it.
func cargoOwned(existing string, _ *url.URL) string {
	skipping := false
	return keepLines(existing, func(line string) bool {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "[") {
			skipping = trimmed == "[registries.bodega]"
		}
		return !skipping
	})
}

// helmOwned drops the repository entry named bodega, wherever helm's own
// serializer left it. helm resolves a chart reference through the first entry
// matching the name, so a stale duplicate does not sit idle: it is the one
// whose credential goes on the wire, and `helm repo update` fetches the index
// once per copy.
func helmOwned(existing string, _ *url.URL) string {
	lines := strings.Split(existing, "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(strings.TrimSpace(lines[i]), "-") {
			out = append(out, lines[i])
			continue
		}
		end := i + 1
		for indent := yamlIndent(lines[i]); end < len(lines); end++ {
			if strings.TrimSpace(lines[end]) == "" || yamlIndent(lines[end]) <= indent {
				break
			}
		}
		if !helmEntryNamed(lines[i:end], "bodega") {
			out = append(out, lines[i:end]...)
		}
		i = end - 1
	}
	return strings.Join(out, "\n")
}

func yamlIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// helmEntryNamed reports whether a repositories list item carries name: want,
// on either the item's own dash line or a line under it.
func helmEntryNamed(item []string, want string) bool {
	for _, l := range item {
		field := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "-"))
		name, ok := strings.CutPrefix(field, "name:")
		if ok && strings.Trim(strings.TrimSpace(name), `"'`) == want {
			return true
		}
	}
	return false
}

// keepLines returns existing with every line keep rejects removed, preserving
// whether the input ended in a newline.
func keepLines(existing string, keep func(line string) bool) string {
	lines := strings.Split(existing, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if keep(l) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
