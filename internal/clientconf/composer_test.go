package clientconf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const composerPlanned = "https://bodega.example.com/composer"

func plannedComposer(t *testing.T) []byte {
	t.Helper()
	return []byte(Composer(testBase).Content)
}

// F95 R2: an existing config.json keeps the operator's auth, platform and
// cache settings, in their order, and gains bodega's repository with
// packagist.org off.
func TestMergeComposerConfigKeepsAuthAndOtherKeys(t *testing.T) {
	existing := `{
  "config": {
    "github-oauth": {"github.com": "ghp_operator"},
    "platform": {"php": "8.3.36"},
    "cache-dir": "/var/cache/composer"
  },
  "repositories": {
    "corp": {"type": "vcs", "url": "https://git.example.com/corp/lib.git"}
  }
}
`
	got, err := MergeComposerConfig([]byte(existing), plannedComposer(t))
	if err != nil {
		t.Fatalf("MergeComposerConfig: %v", err)
	}
	want := `{
    "config": {
        "github-oauth": {
            "github.com": "ghp_operator"
        },
        "platform": {
            "php": "8.3.36"
        },
        "cache-dir": "/var/cache/composer"
    },
    "repositories": {
        "bodega": {
            "type": "composer",
            "url": "https://bodega.example.com/composer"
        },
        "corp": {
            "type": "vcs",
            "url": "https://git.example.com/corp/lib.git"
        },
        "packagist.org": false
    }
}
`
	if string(got) != want {
		t.Errorf("merged =\n%s\nwant\n%s", got, want)
	}
	again, err := MergeComposerConfig(got, plannedComposer(t))
	if err != nil || string(again) != string(got) {
		t.Errorf("a second merge changed the file (err %v):\n%s", err, again)
	}
}

// A bodega repository at an older URL is updated in place, and a packagist.org
// set true is set false, without moving either.
func TestMergeComposerConfigUpdatesInPlace(t *testing.T) {
	existing := `{"repositories":{"packagist.org":true,"bodega":{"type":"composer","url":"http://old.example/composer"}},"config":{"secure-http":false}}`
	got, err := MergeComposerConfig([]byte(existing), plannedComposer(t))
	if err != nil {
		t.Fatal(err)
	}
	var members []member
	if members, err = objectMembers(got); err != nil {
		t.Fatal(err)
	}
	repos, _ := objectMembers(lookup(members, "repositories"))
	var keys []string
	for _, m := range repos {
		keys = append(keys, m.key)
	}
	if !slices.Equal(keys, []string{"packagist.org", "bodega"}) || string(repos[0].value) != "false" || !strings.Contains(string(repos[1].value), composerPlanned) {
		t.Errorf("repositories = %s, want packagist.org false then bodega at %s, in their old order", lookup(members, "repositories"), composerPlanned)
	}
	var cfg bytes.Buffer
	if err := json.Compact(&cfg, lookup(members, "config")); err != nil || cfg.String() != `{"secure-http":false}` {
		t.Errorf("config = %s, want it kept", lookup(members, "config"))
	}
}

// The list form, which Composer 2.10's config -g writes, gets bodega first,
// named as Composer names list entries, and {"packagist.org": false} last,
// with any earlier copy of either dropped and the operator's entries kept
// between.
func TestMergeComposerConfigListForm(t *testing.T) {
	existing := `{"repositories":[{"packagist.org":false},{"type":"composer","url":"https://bodega.example.com/composer/"},{"name":"bodega","type":"composer","url":"http://old/composer"},{"type":"path","url":"../lib"}]}`
	got, err := MergeComposerConfig([]byte(existing), plannedComposer(t))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Repositories []map[string]any `json:"repositories"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Repositories
	if len(r) != 3 || r[0]["url"] != composerPlanned || r[0]["name"] != "bodega" || r[1]["type"] != "path" || r[2]["packagist.org"] != false {
		t.Errorf("repositories = %v, want bodega, the path repository, then packagist.org false", r)
	}
}

func TestMergeComposerConfigEmptyAndRefused(t *testing.T) {
	if got, err := MergeComposerConfig([]byte(" \n"), plannedComposer(t)); err != nil || string(got) != string(plannedComposer(t)) {
		t.Errorf("an empty file merged to %q (err %v), want the planned file", got, err)
	}
	if got, err := MergeComposerConfig([]byte(`{"config":{}}`), plannedComposer(t)); err != nil || !strings.Contains(string(got), `"packagist.org": false`) {
		t.Errorf("a file with no repositories merged to %s (err %v), want them added", got, err)
	}
	for _, bad := range []string{`{"config":`, `[1]`, `{"a":1} {"b":2}`, `{"repositories":"https://repo.packagist.org"}`} {
		if got, err := MergeComposerConfig([]byte(bad), plannedComposer(t)); err == nil {
			t.Errorf("%s merged to %s, want a refusal", bad, got)
		}
	}
}

// F95 R1, R2 through NewChange: the plan's composer record is merged, so an
// auth key the operator keeps in config.json survives an apply.
func TestNewChangeMergesComposerConfig(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".config/composer/config.json")
	writeFile(t, path, `{"config":{"http-basic":{"repo.example.com":{"username":"u","password":"p"}}}}`)
	content := plannedComposer(t)
	c, err := NewChange(PlanRecord{System: "composer", Path: "~/.config/composer/config.json", SHA256: sha(content)}, content, home)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c.New), `"password": "p"`) || !strings.Contains(string(c.New), composerPlanned) {
		t.Errorf("New =\n%s\nwant the http-basic entry kept beside bodega's repository", c.New)
	}
	writeFile(t, path, `{"repositories": nul}`)
	if _, err := NewChange(PlanRecord{System: "composer", Path: "~/.config/composer/config.json", SHA256: sha(content)}, content, home); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("NewChange over unreadable JSON = %v, want a refusal naming %s", err, path)
	}
}

func TestComposerHomeResolvesAsComposerDoes(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	dirs := func(ds ...string) func(string) bool { return func(p string) bool { return slices.Contains(ds, p) } }
	for _, c := range []struct {
		name    string
		vars    map[string]string
		environ []string
		isDir   func(string) bool
		want    string
	}{
		{"COMPOSER_HOME wins", map[string]string{"COMPOSER_HOME": "/srv/composer"}, nil, dirs("/etc/xdg"), "/srv/composer"},
		{"xdg, nothing created yet", nil, nil, dirs("/etc/xdg"), "/home/u/.config/composer"},
		{"xdg, legacy dir exists", nil, nil, dirs("/etc/xdg", "/home/u/.composer"), "/home/u/.composer"},
		{"XDG_CONFIG_HOME", map[string]string{"XDG_CONFIG_HOME": "/x"}, []string{"XDG_CONFIG_HOME=/x"}, dirs(), "/x/composer"},
		{"no xdg: ~/.config/composer is ignored", nil, nil, dirs("/home/u/.config/composer"), "/home/u/.composer"},
	} {
		if got := ComposerHome(env(c.vars), c.environ, "/home/u/", c.isDir); got != c.want {
			t.Errorf("%s: ComposerHome = %q, want %q", c.name, got, c.want)
		}
	}
	if got := ComposerHome(env(nil), nil, "", dirs()); got != "" {
		t.Errorf("no HOME and no COMPOSER_HOME resolved %q, want empty", got)
	}
}

func TestReadComposerRepos(t *testing.T) {
	for _, c := range []struct {
		doc  string
		want ComposerRepos
	}{
		{Composer(testBase).Content, ComposerRepos{Bodega: composerPlanned, PackagistOff: true}},
		{`{"config":{}}`, ComposerRepos{}},
		{`{"repositories":[{"type":"composer","url":"https://b/composer/"},{"packagist":false}]}`, ComposerRepos{Bodega: "https://b/composer/", PackagistOff: true}},
		{`{"repositories":{"mirror":{"type":"composer","url":"https://repo.packagist.org"},"packagist.org":false}}`,
			ComposerRepos{PackagistOff: true, OnPackagist: []string{"https://repo.packagist.org"}}},
	} {
		got, err := ReadComposerRepos([]byte(c.doc))
		if err != nil || got.Bodega != c.want.Bodega || got.PackagistOff != c.want.PackagistOff || !slices.Equal(got.OnPackagist, c.want.OnPackagist) {
			t.Errorf("ReadComposerRepos(%s) = %+v, %v; want %+v", c.doc, got, err, c.want)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// An http:// base sets secure-http false, without which Composer refuses the
// repository; the merge sets it inside an existing config object and keeps
// that object's other keys. An https:// base leaves an operator's own
// secure-http as it was.
func TestComposerPlaintextBaseSetsSecureHTTP(t *testing.T) {
	plain := []byte(Composer("http://bodega.lan:8080").Content)
	var doc struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(plain, &doc); err != nil || doc.Config["secure-http"] != false {
		t.Fatalf("http base rendered %s (err %v), want secure-http false", plain, err)
	}
	if strings.Contains(string(plannedComposer(t)), "secure-http") {
		t.Errorf("https base rendered secure-http:\n%s", plannedComposer(t))
	}
	got, err := MergeComposerConfig([]byte(`{"config":{"process-timeout":600,"secure-http":true}}`), plain)
	if err != nil {
		t.Fatal(err)
	}
	doc.Config = nil
	if err := json.Unmarshal(got, &doc); err != nil || doc.Config["secure-http"] != false || doc.Config["process-timeout"] != float64(600) {
		t.Errorf("merged %s (err %v), want secure-http false beside process-timeout", got, err)
	}
	got, err = MergeComposerConfig([]byte(`{"config":{"secure-http":false}}`), plannedComposer(t))
	if err != nil || !strings.Contains(string(got), `"secure-http": false`) {
		t.Errorf("an https merge changed the operator's secure-http: %s (err %v)", got, err)
	}
	if _, err := MergeComposerConfig([]byte(`{"config":[]}`), plain); err == nil {
		t.Error("a config that is not an object merged, want a refusal")
	}
}
