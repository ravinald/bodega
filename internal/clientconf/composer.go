package clientconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// The keys Composer's global config.json disables Packagist under. Composer
// reads "packagist" as an alias of "packagist.org".
const (
	composerPackagist      = "packagist.org"
	composerPackagistAlias = "packagist"
	composerBodegaRepo     = "bodega"
	composerSecureHTTP     = "secure-http"
)

// Composer renders Composer's global config.json with bodega as its one
// repository. "packagist.org": false is what turns off the default
// repository; without it a package bodega refuses resolves from Packagist
// instead. Composer merges this file under every project's composer.json, so
// no project needs editing.
//
// The paths are where Composer puts its home with COMPOSER_HOME unset and no
// home directory created yet: under ~/.config on Linux, where /etc/xdg exists,
// and ~/.composer elsewhere. doctor and the setup script write wherever
// ComposerHome resolves on the host instead, and MergeComposerConfig keeps an
// existing file's other settings.
func Composer(base string) File {
	root := trim(base) + "/composer"
	repo := joinObject([]member{{"type", json.RawMessage(`"composer"`)}, {"url", json.RawMessage(jsonString(root))}})
	doc := []member{{"repositories", joinObject([]member{{composerBodegaRepo, repo}, {composerPackagist, json.RawMessage("false")}})}}
	notes := []string{
		"An existing config.json keeps its auth, platform, cache and every other setting: bodega's repository is added or updated and packagist.org set false",
		"bodega doctor writes the file in Composer's home on the host ($COMPOSER_HOME, or the directory Composer picks without it); the setup script resolves the same directory, and leaves an existing file to doctor, since merging it takes a JSON parser",
	}
	if strings.HasPrefix(root, "http://") {
		doc = append([]member{{"config", json.RawMessage(`{"` + composerSecureHTTP + `":false}`)}}, doc...)
		notes = append(notes, "secure-http is set false, because Composer refuses an http:// repository without it; the setting is global, so Composer also follows any other http:// URL a project names")
	}
	content, _ := indentComposer(doc)
	return File{
		System: manifest.TypeComposer,
		Label:  "Composer global config",
		Paths: map[string]string{
			OSLinux:   "~/.config/composer/config.json",
			OSFreeBSD: "~/.composer/config.json",
			OSDarwin:  "~/.composer/config.json",
		},
		Content: string(content),
		Notes:   notes,
	}
}

// ComposerHome is the directory Composer reads its global config.json from,
// resolved as Composer 2's Factory::getHomeDir does on a unix host:
// COMPOSER_HOME when set; otherwise the first of $XDG_CONFIG_HOME/composer
// (~/.config/composer without it) and ~/.composer that exists, where the XDG
// directory is a candidate only when some XDG_ variable is set or /etc/xdg
// exists; and when neither exists, the first candidate, which is where
// Composer creates it. "" when neither COMPOSER_HOME nor home is known.
//
// Composer reads the second candidate on a macOS host with no XDG_ variable
// even when ~/.config/composer exists, so a file written there by path alone
// would be ignored with no error.
func ComposerHome(getenv func(string) string, environ []string, home string, isDir func(string) bool) string {
	if h := getenv("COMPOSER_HOME"); h != "" {
		return h
	}
	if home == "" {
		return ""
	}
	home = strings.TrimRight(home, "/")
	var dirs []string
	if composerUsesXDG(environ, isDir) {
		xdg := getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		dirs = append(dirs, filepath.Join(xdg, "composer"))
	}
	dirs = append(dirs, filepath.Join(home, ".composer"))
	for _, d := range dirs {
		if isDir(d) {
			return d
		}
	}
	return dirs[0]
}

// HostComposerHome is ComposerHome for this process's own environment, for
// the account whose home directory is home.
func HostComposerHome(home string) string {
	return ComposerHome(os.Getenv, os.Environ(), home, func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && info.IsDir()
	})
}

func composerUsesXDG(environ []string, isDir func(string) bool) bool {
	for _, kv := range environ {
		if strings.HasPrefix(kv, "XDG_") {
			return true
		}
	}
	return isDir("/etc/xdg")
}

// member is one key of a JSON object, its value kept as the bytes it was
// written with.
type member struct {
	key   string
	value json.RawMessage
}

// MergeComposerConfig returns existing with planned's repositories merged in:
// bodega's repository added or replaced, and packagist.org set false. Every
// other key (auth, platform, cache settings, the operator's own repositories)
// is kept with its value as written and in its order; the whole document is
// re-indented the way Composer writes it. A repositories object gains bodega
// first, since Composer asks repositories in order. A repositories list, the
// form Composer 2.10's own `config -g` writes, gets bodega's entry first,
// named bodega as Composer names list entries, and a {"packagist.org": false}
// entry last, with any earlier copy of either removed. An empty existing file gets planned.
//
// A file that is not a JSON object, or whose repositories is neither form, is
// refused rather than replaced: Composer cannot read it either, so it is the
// operator's to repair, and it may hold the only copy of a credential.
func MergeComposerConfig(existing, planned []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return planned, nil
	}
	plan, err := objectMembers(planned)
	if err != nil {
		return nil, fmt.Errorf("the planned config.json: %w", err)
	}
	planRepos, err := objectMembers(lookup(plan, "repositories"))
	if err != nil {
		return nil, fmt.Errorf("the planned config.json's repositories: %w", err)
	}
	doc, err := objectMembers(existing)
	if err != nil {
		return nil, fmt.Errorf("it is not a JSON object Composer can read (%w); repair it or move it aside, then re-run. Nothing was written", err)
	}
	reposAt := -1
	for i, m := range doc {
		if m.key == "repositories" {
			reposAt = i
		}
	}
	if doc, err = mergeComposerSettings(doc, lookup(plan, "config")); err != nil {
		return nil, err
	}
	if reposAt < 0 {
		doc = append(doc, member{"repositories", lookup(plan, "repositories")})
		return indentComposer(doc)
	}
	current := doc[reposAt].value
	switch trimmed := bytes.TrimSpace(current); {
	case len(trimmed) > 0 && trimmed[0] == '{':
		repos, err := objectMembers(current)
		if err != nil {
			return nil, fmt.Errorf("its repositories: %w", err)
		}
		for _, p := range planRepos {
			repos = setMember(repos, p, p.key == composerBodegaRepo)
		}
		doc[reposAt].value = joinObject(repos)
	case len(trimmed) > 0 && trimmed[0] == '[':
		var list []json.RawMessage
		if err := json.Unmarshal(current, &list); err != nil {
			return nil, fmt.Errorf("its repositories: %w", err)
		}
		bodega := lookup(planRepos, composerBodegaRepo)
		fields, err := objectMembers(bodega)
		if err != nil {
			return nil, fmt.Errorf("the planned repository: %w", err)
		}
		out := []json.RawMessage{joinObject(append([]member{{"name", json.RawMessage(jsonString(composerBodegaRepo))}}, fields...))}
		for _, r := range list {
			if !sameComposerRepo(r, bodega) && !disablesPackagist(r) {
				out = append(out, r)
			}
		}
		out = append(out, json.RawMessage(`{"`+composerPackagist+`":false}`))
		joined, err := json.Marshal(out)
		if err != nil {
			return nil, err
		}
		doc[reposAt].value = joined
	default:
		return nil, fmt.Errorf("its repositories is %s, and Composer reads an object or a list there; repair it or move it aside, then re-run. Nothing was written", trimmed)
	}
	return indentComposer(doc)
}

// mergeComposerSettings sets each key of planned, the plan's config object,
// in doc's config object, adding that object when doc has none. A plan with
// no config leaves doc as it is.
func mergeComposerSettings(doc []member, planned json.RawMessage) ([]member, error) {
	if planned == nil {
		return doc, nil
	}
	want, err := objectMembers(planned)
	if err != nil {
		return nil, fmt.Errorf("the planned config: %w", err)
	}
	for i, m := range doc {
		if m.key != "config" {
			continue
		}
		have, err := objectMembers(m.value)
		if err != nil {
			return nil, fmt.Errorf("its config is not an object Composer reads (%w); repair it or move it aside, then re-run. Nothing was written", err)
		}
		for _, w := range want {
			have = setMember(have, w, false)
		}
		doc[i].value = joinObject(have)
		return doc, nil
	}
	return append([]member{{"config", planned}}, doc...), nil
}

// objectMembers reads a JSON object's members in the order they are written.
func objectMembers(data []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		if err == nil {
			err = errors.New("the document does not open with {")
		}
		return nil, err
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out = append(out, member{key, v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("text follows the closing }")
	}
	return out, nil
}

func lookup(ms []member, key string) json.RawMessage {
	for _, m := range ms {
		if m.key == key {
			return m.value
		}
	}
	return nil
}

// setMember replaces every member named m.key with m, or adds it first or
// last when there is none.
func setMember(ms []member, m member, first bool) []member {
	found := false
	for i := range ms {
		if ms[i].key == m.key {
			ms[i].value, found = m.value, true
		}
	}
	switch {
	case found:
		return ms
	case first:
		return append([]member{m}, ms...)
	}
	return append(ms, m)
}

func joinObject(ms []member) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(m.key))
		b.WriteByte(':')
		b.Write(m.value)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// indentComposer writes doc as Composer writes config.json: four spaces, a
// space after each colon, a trailing newline. json.Indent keeps every value's
// own escaping, so a string Composer wrote with unescaped slashes stays so.
func indentComposer(doc []member) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, joinObject(doc), "", "    "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

type composerRepo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

// sameComposerRepo reports whether list entry a is bodega's repository b:
// named bodega, the name Composer's own `config -g repositories.bodega`
// looks an entry up by, or the same type at the same URL.
func sameComposerRepo(a, b json.RawMessage) bool {
	var x, y composerRepo
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return x.Name == composerBodegaRepo || x.Type == y.Type && strings.TrimRight(x.URL, "/") == strings.TrimRight(y.URL, "/")
}

// disablesPackagist reports whether a repositories list entry is the
// {"packagist.org": false} form Composer reads as turning Packagist off.
func disablesPackagist(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) != 1 {
		return false
	}
	return isFalse(m[composerPackagist]) || isFalse(m[composerPackagistAlias])
}

func isFalse(v json.RawMessage) bool { return string(bytes.TrimSpace(v)) == "false" }

// ComposerRepos is what a config.json's repositories say about where
// Composer fetches packages from.
type ComposerRepos struct {
	// Bodega is the url of the first composer repository at a /composer
	// route, the form Composer renders, or "" when there is none.
	Bodega string
	// PackagistOff reports whether packagist.org is disabled, in either form
	// Composer reads.
	PackagistOff bool
	// OnPackagist lists the url of every composer repository on
	// packagist.org or a subdomain of it. Composer reads one as Packagist
	// under another name, so it bypasses bodega whatever PackagistOff says.
	OnPackagist []string
}

// ReadComposerRepos reads a Composer config.json's repositories, in the
// object or the list form. A file with no repositories key has none.
func ReadComposerRepos(data []byte) (ComposerRepos, error) {
	var doc struct {
		Repositories json.RawMessage `json:"repositories"`
	}
	var out ComposerRepos
	if err := json.Unmarshal(data, &doc); err != nil {
		return out, err
	}
	var entries []json.RawMessage
	switch trimmed := bytes.TrimSpace(doc.Repositories); {
	case len(trimmed) == 0 || string(trimmed) == "null":
		return out, nil
	case trimmed[0] == '{':
		ms, err := objectMembers(trimmed)
		if err != nil {
			return out, err
		}
		for _, m := range ms {
			if (m.key == composerPackagist || m.key == composerPackagistAlias) && isFalse(m.value) {
				out.PackagistOff = true
				continue
			}
			entries = append(entries, m.value)
		}
	case trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return out, err
		}
	default:
		return out, fmt.Errorf("repositories is %s, not an object or a list", trimmed)
	}
	for _, e := range entries {
		if disablesPackagist(e) {
			out.PackagistOff = true
			continue
		}
		var r composerRepo
		if json.Unmarshal(e, &r) != nil || r.Type != "composer" {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		switch {
		case host == composerPackagist || strings.HasSuffix(host, "."+composerPackagist):
			out.OnPackagist = append(out.OnPackagist, r.URL)
		case out.Bodega == "" && strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/composer"):
			out.Bodega = r.URL
		}
	}
	return out, nil
}

// jsonString is s as a JSON string, with no HTML escaping: Composer reads a
// URL holding & either way, and an operator reading the file should see the
// URL they configured.
func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}
