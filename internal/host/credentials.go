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
// with the operator, in the formats that can carry a comment anywhere. What
// keeps a second --write-credentials run idempotent instead of additive is
// removing bodega's own entry before placing the fresh one; nothing else in
// the file is read or altered.
//
// The fence is not the only anchor, because bodega does not own these files.
// cargo, helm and npm each re-serialize their own configuration as part of
// ordinary use (`cargo login`, `helm repo add`, `npm config set`) and drop
// comments when they do, which takes the fence with it. A run that then
// appended would leave two bodega entries, the first holding the pre-rotation
// token: cargo rejects the whole file as a duplicate key, helm resolves charts
// through the stale one and puts it on the wire, npm grows a dead line per
// rotation. So each of those targets also carries an `owned` locator that
// finds bodega's entry by its own key, marker or no marker. ~/.netrc carries
// one for the other reason an unfenced entry is there: the operator who
// configured bodega before this command existed wrote it. See CredentialTarget.
//
// The fence goes only where a comment is safe wherever an append can put it.
// ~/.netrc is not such a file. Python's netrc module rejects a `#` line
// preceded by a blank one, and rejects the whole file rather than the entry,
// so pip loses every credential in it — silently, because requests catches
// NetrcParseError and hands back no credential at all. A blank line between
// stanzas is how a netrc is idiomatically written, so that is the shape an
// append lands in. Go's parser is no safer a home for one: cmd/go's
// parseNetrc scans strings.Fields in pairs and ignores `#` rather than
// stripping it, which makes a fence inert there only while no keyword lands
// on an even index. So the netrc targets write the stanza alone and let
// netrcOwned be the anchor, which is what it already was.
//
// apt keeps its fence: that file is bodega's alone and replaced whole, its
// fence is line 1, and apt's parser does strip `#` (confirmed against apt
// 2.8.3 on noble). npm's ini, cargo's TOML and YAML take `#` to end of line
// with no positional rule.
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

	// bare, when set, means the entry is written with no fence around it,
	// because a comment is not safe everywhere an append can land it. Only
	// the netrc targets; owned is their anchor instead. See managedBegin.
	bare bool

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
	// key that entry carries rather than by the fence around it. Set
	// everywhere an entry for this host can already be in the file without a
	// fence around it: the three targets whose client rewrites the file and
	// discards comments, and netrc, where the operator who configured bodega
	// by hand wrote one. nil only on apt, which is bodega's file alone and
	// replaced whole every run.
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
			bare:   true,
			owned:  netrcOwned,
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
			bare:   true,
			owned:  netrcOwned,
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
			bare:   true,
			owned:  netrcOwned,
			Note:   "git reads netrc through libcurl; no credential helper is required",
		},
		{
			Client: "binary",
			Path:   netrc,
			Mode:   0o600,
			body:   netrcEntry,
			bare:   true,
			owned:  netrcOwned,
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
	block := t.block(base, token)
	if t.createDoc != nil {
		return t.createDoc(block)
	}
	return block
}

// block is what bodega owns inside t.Path: the entry, fenced unless t is bare.
func (t CredentialTarget) block(base *url.URL, token string) string {
	if t.bare {
		return t.body(base, token) + "\n"
	}
	return managedBegin + "\n" + t.body(base, token) + "\n" + managedEnd + "\n"
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
	block := t.block(base, token)

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
		if fenced && !t.bare {
			// Replacing a block already in the file puts it back exactly
			// where it was, so only the append below can land in a bad place.
			next = before + block + after
			break
		}
		// A bare target has no fence to replace, so what a fence written by
		// an earlier build left around rejoins and the entry goes to the end.
		// after is empty whenever no fence was found, which is every other
		// route to this line.
		before += after
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

// AptSourcesPath is the file bodega's own deb822 stanza is installed as, and
// AptSourcesMode is what it and the keyring beside it are created with.
//
// A .sources file of its own rather than a line appended to
// /etc/apt/sources.list: the file is bodega's alone and replaced whole, so a
// profile moved to a different codename leaves nothing behind. Both files are
// world-readable on purpose — neither holds a secret, the keyring is a public
// key, and apt reads them as a user that is not always root.
const (
	AptSourcesPath = "/etc/apt/sources.list.d/bodega.sources"
	AptSourcesMode = os.FileMode(0o644)
)

// WriteAptSources installs the stanza a bodega instance said this host should
// read, and the keyring its Signed-By: names. It reports the paths it wrote,
// in order, and stops at the first failure.
//
// The keyring goes first. A stanza naming a Signed-By: path that does not
// exist fails `apt update` outright with "The following signatures couldn't be
// verified", and a host left in that state has no working sources at all —
// where the reverse order leaves the previous sources working until the file
// that replaces them is complete.
//
// Neither file is merged with what is there. keyringPath is where the archive
// key lives on the client and the stanza is bodega's own document; an operator
// who wants a second source writes a second file, which is what the .list.d
// directory is for.
//
// root prefixes both paths and is empty everywhere but a test. Both of them
// are absolute and outside home — apt reads /etc/apt and nowhere else — so
// without it the only way to exercise the guards and the ordering below is to
// write the running host's real sources.
func WriteAptSources(root, keyringPath, stanza string, keyring []byte) ([]string, error) {
	if len(keyring) == 0 {
		return nil, fmt.Errorf("no keyring to install: this bodega serves its apt index unsigned, and a stanza with no Signed-By: would need [trusted=yes], which turns verification off for the source permanently.\n" +
			"  Sign it on the server:  bodega apt key generate")
	}
	if !strings.Contains(stanza, keyringPath) {
		return nil, fmt.Errorf("the stanza this bodega returned does not name %s in a Signed-By: line, so installing the keyring there would leave it unread", keyringPath)
	}
	var wrote []string
	for _, f := range []struct {
		path string
		data []byte
	}{
		{filepath.Join(root, keyringPath), keyring},
		{filepath.Join(root, AptSourcesPath), []byte(strings.TrimRight(stanza, "\n") + "\n")},
	} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return wrote, fmt.Errorf("create %s: %w", filepath.Dir(f.path), err)
		}
		if err := os.WriteFile(f.path, f.data, AptSourcesMode); err != nil {
			return wrote, fmt.Errorf("write %s: %w", f.path, err)
		}
		if err := os.Chmod(f.path, AptSourcesMode); err != nil {
			return wrote, fmt.Errorf("chmod %s: %w", f.path, err)
		}
		wrote = append(wrote, f.path)
	}
	return wrote, nil
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
// top-level key follows would take bodega's entry into that key instead, and
// one whose repositories: holds an inline value has no list to append under.
func helmAppendable(existing string) error {
	idx := -1
	lines := strings.Split(existing, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "repositories:") {
			continue
		}
		// `helm repo remove <last>` leaves `repositories: []`. A block
		// sequence written after that is a second value for one key, which
		// helm rejects whole: `helm repo list` reports no repositories and
		// exits 0, and the damage surfaces at the next `helm repo add`.
		if v := strings.TrimSpace(strings.TrimPrefix(l, "repositories:")); v != "" && !strings.HasPrefix(v, "#") {
			return fmt.Errorf("has repositories: %s, a value rather than a list to add a repository to; "+
				"run helm repo add bodega <url> --username bodega --password <token> instead", v)
		}
		idx = i
		break
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

// netrcOwned drops the stanza an operator wrote for bodega's own host.
//
// The other locators exist because the client rewrites the file. This one
// exists because a person did: anyone who configured bodega by hand before
// --write-credentials shipped already has a `machine <bodega-host>` stanza in
// ~/.netrc, and appending beside it leaves two credentials for one host in a
// file four clients read two different ways. libcurl takes the first match and
// Python's netrc module the last, so git, curl and wget would keep presenting
// the pre-rotation secret while pip presented the new one, and the doctor
// table would report four successes.
//
// apt's `machine <scheme>://<host>` spelling goes too. apt has its own file,
// but a hand-written ~/.netrc can carry either form and both name this host.
func netrcOwned(existing string, base *url.URL) string {
	names := map[string]bool{base.Hostname(): true}
	if base.Scheme != "" {
		names[base.Scheme+"://"+base.Hostname()] = true
	}

	var cuts [][2]int
	start, last := -1, -1
	// A stanza runs from its `machine` keyword to the next `machine`,
	// `default` or `macdef`, which netrc allows on the same line. Cutting the
	// whole line is right for the usual file and wrong for that one, so the
	// end is the next keyword when it shares the line and the line end
	// otherwise. Everything outside the cut survives byte for byte.
	closeAt := func(next int) {
		if start < 0 {
			return
		}
		end := netrcLineEnd(existing, last)
		if next >= 0 && next < end {
			end = next
		}
		cuts = append(cuts, [2]int{start, end})
		start, last = -1, -1
	}

	toks := netrcTokens(existing)
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		switch tok.text {
		case "machine":
			closeAt(tok.start)
			if i+1 >= len(toks) {
				continue
			}
			i++
			if names[toks[i].text] {
				start, last = netrcLineStart(existing, tok.start), toks[i].end
			}
		case "default":
			closeAt(tok.start)
		case "macdef":
			// A macro body is arbitrary text ending at a blank line, so its
			// words are not keywords and must not open a stanza.
			closeAt(tok.start)
			body := strings.Index(existing[tok.end:], "\n\n")
			if body < 0 {
				return netrcCut(existing, cuts)
			}
			for i+1 < len(toks) && toks[i+1].start < tok.end+body {
				i++
			}
		case "login", "password", "account":
			// Consume the value with its keyword: a password that reads
			// `machine` is a secret, not the start of a stanza.
			if i+1 < len(toks) {
				i++
			}
			if start >= 0 {
				last = toks[i].end
			}
		default:
			if start >= 0 {
				last = tok.end
			}
		}
	}
	closeAt(-1)
	return netrcCut(existing, cuts)
}

// netrcToken is one whitespace-separated word and where it sits in the file.
type netrcToken struct {
	text       string
	start, end int
}

// netrcTokens splits a netrc file into tokens, skipping a `#` comment to the
// end of its line. Only a `#` that opens a token starts one, so a password
// carrying the character survives intact.
func netrcTokens(s string) []netrcToken {
	var toks []netrcToken
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			i++
		case '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		default:
			start := i
			for i < len(s) && !netrcSpace(s[i]) {
				i++
			}
			toks = append(toks, netrcToken{text: s[start:i], start: start, end: i})
		}
	}
	return toks
}

func netrcSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// netrcLineStart returns the offset the cut begins at: the start of pos's line
// when nothing but whitespace precedes the token there, and the token itself
// when another stanza shares the line.
func netrcLineStart(s string, pos int) int {
	bol := strings.LastIndexByte(s[:pos], '\n') + 1
	if strings.TrimSpace(s[bol:pos]) != "" {
		return pos
	}
	return bol
}

// netrcLineEnd returns the offset just past the newline ending pos's line.
func netrcLineEnd(s string, pos int) int {
	if nl := strings.IndexByte(s[pos:], '\n'); nl >= 0 {
		return pos + nl + 1
	}
	return len(s)
}

// netrcCut removes the ordered, non-overlapping ranges from s.
func netrcCut(s string, cuts [][2]int) string {
	if len(cuts) == 0 {
		return s
	}
	var b strings.Builder
	prev := 0
	for _, c := range cuts {
		b.WriteString(s[prev:c[0]])
		prev = c[1]
	}
	b.WriteString(s[prev:])
	return b.String()
}
