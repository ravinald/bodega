package host

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
// with the operator. Rewriting the block in place is what makes a second
// --write-credentials run idempotent instead of additive; nothing outside the
// fence is read or altered.
//
// Every format below takes `#` to end of line as a comment: netrc (apt's
// parser and Go's both strip it), npm's ini, cargo's TOML, and YAML.
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
			body:   netrcEntry,
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
			Note:   "point cargo at the registry too: [registries.bodega] index = \"sparse+<base>/cargo/\" in config.toml",
		},
		{
			Client:      "helm",
			Path:        filepath.Join(home, ".config", "helm", "repositories.yaml"),
			Mode:        0o600,
			body:        helmEntry,
			appendGuard: helmAppendable,
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
		next = block
	default:
		if t.appendGuard != nil && !strings.Contains(existing, managedBegin) {
			// Only an append can land in the wrong place. Replacing a block
			// already in the file puts it back exactly where it was.
			if err := t.appendGuard(existing); err != nil {
				return false, fmt.Errorf("%s: %s: %w", t.Client, t.Path, err)
			}
		}
		var err error
		if next, err = spliceManaged(existing, block); err != nil {
			return false, fmt.Errorf("%s: %s: %w", t.Client, t.Path, err)
		}
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

// spliceManaged replaces the fenced block in existing, or appends it. An
// unterminated begin marker is an error rather than something to guess at:
// appending past it would nest one block inside another and the next run would
// replace both.
func spliceManaged(existing, block string) (string, error) {
	start := strings.Index(existing, managedBegin)
	if start < 0 {
		if !strings.HasSuffix(existing, "\n") {
			existing += "\n"
		}
		return existing + block, nil
	}
	rest := existing[start:]
	end := strings.Index(rest, managedEnd)
	if end < 0 {
		return "", fmt.Errorf("has a %q line with no %q after it; remove the partial block and run again",
			managedBegin, managedEnd)
	}
	end += len(managedEnd)
	if strings.HasPrefix(rest[end:], "\n") {
		end++
	}
	return existing[:start] + block + rest[end:], nil
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
