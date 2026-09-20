package tui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// The three emitters an operator copies from, on one non-default suite, in
// both signing states. Every wrong sources line this repository shipped passed
// a test that injected the value the emitter got wrong: the scheme, the suite,
// the trust option. So these assert the finished string, character for
// character, and nothing here injects one.
const (
	wantUnsignedLine = "deb [trusted=yes] https://bodega.example.com/apt/ jammy main"
	wantSignedLine   = "deb [signed-by=/etc/apt/keyrings/bodega-archive-keyring.gpg] https://bodega.example.com/apt/ jammy main"
)

// aptLineConfig is the one deployment all six strings describe: published at a
// name a proxy owns, serving a suite that is not the historical "noble"
// literal, holding one package.
func aptLineConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		AptCodename: "jammy",
		AptSuites:   []string{"jammy"},
		PublicURL:   "https://bodega.example.com",
		StoragePath: t.TempDir(),
	}
}

func aptLineStore(t *testing.T) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "pkg-a", manifest.VersionEntry{
		Version:  "1.0",
		Suites:   []string{"jammy"},
		Metadata: map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	return store
}

// installKey writes a usable signing key where both the server and the pane
// look for one. The credentials directory is first in aptsign's search order,
// so it steers both without touching the host.
func installKey(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)
	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := kr.WritePrivate(filepath.Join(dir, aptsign.KeyFileName)); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
}

// statusOneLine is the string /api/v1/status hands the web page and any other
// API consumer. The status handler answers 503 without a storage backend and
// still renders the apt block, so the body is read whatever the code.
func statusOneLine(t *testing.T, cfg *config.Config, store *manifest.Store) string {
	t.Helper()
	srv := server.New(cfg, store, storage.NewSingle(storage.NewMemory()), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Apt json.RawMessage `json:"apt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	var apt struct {
		Sources []struct {
			Suite   string `json:"suite"`
			OneLine string `json:"one_line"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(body.Apt, &apt); err != nil {
		t.Fatalf("decode apt block: %v", err)
	}
	if len(apt.Sources) == 0 {
		t.Fatal("/api/v1/status carries no sources block")
	}
	return apt.Sources[0].OneLine
}

// The key column wraps a two-word label onto its own row, so the line is
// anchored on "line:" rather than the whole label.
var paneSourcesLine = regexp.MustCompile(`line: *(deb [^\n]*)`)

// paneOneLine renders the details pane for the apt entry and reads the line
// back out of it, rather than calling the renderer directly: the pane is what
// the operator selects text from, and a correct renderer wired to the wrong
// argument is one of the defects this covers.
func paneOneLine(t *testing.T, cfg *config.Config, store *manifest.Store) string {
	t.Helper()
	d := newDetailsModel(store, cfg)
	d.SetSize(200, 40)
	d.SetNode(&TreeNode{Name: "pkg-a", EntryType: manifest.TypeApt, Version: "1.0"})
	m := paneSourcesLine.FindStringSubmatch(stripANSI(d.View()))
	if m == nil {
		t.Fatalf("details pane rendered no sources line:\n%s", stripANSI(d.View()))
	}
	return strings.TrimSpace(m[1])
}

var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiEscape.ReplaceAllString(s, "") }

// TestSourcesLineIsTheSameStringEverywhere pins all six.
func TestSourcesLineIsTheSameStringEverywhere(t *testing.T) {
	for _, tc := range []struct {
		name string
		sign bool
		want string
	}{
		{"unsigned", false, wantUnsignedLine},
		{"signed", true, wantSignedLine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An absent credentials directory is what makes the unsigned case
			// unsigned; TestMain already steered the system path away.
			t.Setenv(aptsign.CredentialsEnv, t.TempDir())
			if tc.sign {
				installKey(t)
			}
			cfg := aptLineConfig(t)
			store := aptLineStore(t)

			if got := statusOneLine(t, cfg, store); got != tc.want {
				t.Errorf("/api/v1/status one_line:\n got %q\nwant %q", got, tc.want)
			}
			if got := paneOneLine(t, cfg, store); got != tc.want {
				t.Errorf("TUI pane sources line:\n got %q\nwant %q", got, tc.want)
			}
			if got := pageOneLine(t, cfg, store); got != tc.want {
				t.Errorf("web page sources line:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// pageFuncs are the page's whole contribution to the apt line: which
// server-rendered block an entry uses, and reading one_line off it. Everything
// else in the stanza is composed on the server, which is the point — the page
// printed a literal "noble" and derived a scheme from location.protocol for as
// long as it composed its own.
var pageFuncs = []string{"clientBase", "aptSourcesFor", "getClientUrl"}

// extractJSFunc pulls one top-level function out of the served page by
// matching braces from its declaration. Running the whole script is not an
// option: it ends in init() and two document.addEventListener calls, so it
// needs a DOM before it will reach the four lines under test.
func extractJSFunc(t *testing.T, page, name string) string {
	t.Helper()
	start := strings.Index(page, "function "+name+"(")
	if start < 0 {
		t.Fatalf("served page defines no %s(); the apt line is composed somewhere this test cannot see", name)
	}
	depth := 0
	for i := start; i < len(page); i++ {
		switch page[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return page[start : i+1]
			}
		}
	}
	t.Fatalf("unbalanced braces in %s()", name)
	return ""
}

// servedPage is the HTML a browser gets, read back off the listener rather
// than off disk: the file is embedded, and a page that stopped being served
// would still pass a test that read the source tree.
func servedPage(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read page: %v", err)
	}
	return string(body)
}

// pageOneLine runs the page's own selection against the server's own status
// body and returns the string it would put in the Sources line field.
//
// It needs a JS engine, and the gate has none: adding one to go.mod to
// exercise four lines costs more than it settles. Where node is on PATH — this
// project's CI image and any machine with a front-end toolchain — the string
// is asserted like the other two. Where it is not, TestPageComposesNoLine
// still holds the page to emitting the server's string verbatim, which is the
// property that makes the assertion transitive.
func pageOneLine(t *testing.T, cfg *config.Config, store *manifest.Store) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not on PATH; the page's rendered string is unasserted here — see TestPageComposesNoLine")
	}

	srv := server.New(cfg, store, storage.NewSingle(storage.NewMemory()), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	page := servedPage(t, ts)
	statusJSON := rawStatus(t, ts)

	var script strings.Builder
	script.WriteString("const location = {origin: 'http://unused.invalid'};\n")
	script.WriteString("const serverApt = " + statusJSON + ".apt;\n")
	for _, fn := range pageFuncs {
		script.WriteString(extractJSFunc(t, page, fn) + "\n")
	}
	script.WriteString("process.stdout.write(getClientUrl('apt', {name: 'pkg-a', suites: ['jammy']}));\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "page.js")
	if err := os.WriteFile(path, []byte(script.String()), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), node, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return string(out)
}

func rawStatus(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return string(body)
}

// TestPageComposesNoLine holds the page to reading the server's string rather
// than building one, which is what makes the status assertion above cover the
// page on a machine with no JS engine. Each literal named here was in the page
// and each produced a command that fails: "noble" on a jammy instance, http://
// behind a TLS-terminating proxy, and [trusted=yes] against a signed archive.
func TestPageComposesNoLine(t *testing.T) {
	srv := server.New(aptLineConfig(t), aptLineStore(t), storage.NewSingle(storage.NewMemory()), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	page := servedPage(t, ts)

	// The comment above aptSourcesFor names all three; strip comments so the
	// history does not read as a live literal.
	code := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(page, "")
	for _, banned := range []string{"trusted=yes", "signed-by=", "location.protocol", "'noble'", `"noble"`} {
		if strings.Contains(code, banned) {
			t.Errorf("served page composes %q of its own; the line must come from /api/v1/status", banned)
		}
	}

	apt := extractJSFunc(t, page, "getClientUrl")
	if !strings.Contains(apt, "src.one_line") {
		t.Error("getClientUrl no longer returns the server-rendered one_line for apt")
	}
}

// writeKeyAt installs a key file at path with the given mode, returning the
// keyring so a caller can derive a public-only export from it.
func writeKeyAt(t *testing.T, path string, mode os.FileMode) *aptsign.KeyRing {
	t.Helper()
	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := kr.WritePrivate(path); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return kr
}

// TestPaneFollowsTheKeyOnDisk drives the one input that decides which form the
// pane emits. Every earlier test injected the bool, so nothing exercised the
// function that produces it — and the function accepted keys the server does
// not, which is the direction that hurts: the pane prints Signed-By: against
// an archive with no signature, and apt update fails outright rather than
// falling back.
func TestPaneFollowsTheKeyOnDisk(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, keyPath string)
		want  string
	}{
		{
			name:  "no key installed",
			setup: func(*testing.T, string) {},
			want:  wantUnsignedLine,
		},
		{
			name:  "usable key",
			setup: func(t *testing.T, p string) { writeKeyAt(t, p, 0o600) },
			want:  wantSignedLine,
		},
		{
			// aptsign refuses a key any other account can copy. The server is
			// then unsigned, so the pane must be too.
			name:  "key readable beyond its owner",
			setup: func(t *testing.T, p string) { writeKeyAt(t, p, 0o644) },
			want:  wantUnsignedLine,
		},
		{
			// The public half alone signs nothing. It parses, which is what
			// made a check that stopped at "the file is a key" wrong.
			name: "public half exported by mistake",
			setup: func(t *testing.T, p string) {
				kr := writeKeyAt(t, p, 0o600)
				pub, err := kr.PublicKey()
				if err != nil {
					t.Fatalf("PublicKey: %v", err)
				}
				if err := os.WriteFile(p, pub, 0o600); err != nil {
					t.Fatalf("write public key: %v", err)
				}
			},
			want: wantUnsignedLine,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(aptsign.CredentialsEnv, dir)
			tc.setup(t, filepath.Join(dir, aptsign.KeyFileName))

			if got := paneOneLine(t, aptLineConfig(t), aptLineStore(t)); got != tc.want {
				t.Errorf("pane line:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The pane reads a file; the server holds a signer that outlives it, because a
// reload never takes signing away. Nothing here can close that gap, so the
// pane says which of the two it is describing and where to read the other.
func TestPaneSaysItReadsTheKeyOnDisk(t *testing.T) {
	d := newDetailsModel(aptLineStore(t), aptLineConfig(t))
	d.SetSize(400, 40)
	d.SetNode(&TreeNode{Name: "pkg-a", EntryType: manifest.TypeApt, Version: "1.0"})
	view := stripANSI(d.View())
	if !strings.Contains(view, "not from the running server") {
		t.Errorf("pane describes the key on disk as if it were the server's state:\n%s", view)
	}
	if !strings.Contains(view, "/api/v1/status") {
		t.Errorf("pane does not say where the server's own state is readable:\n%s", view)
	}
}

// A key generated while the TUI is open was invisible until restart, so the
// pane went on offering [trusted=yes] for an archive that had started signing.
func TestPaneRereadsTheKeyOnRefresh(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)

	cfg := aptLineConfig(t)
	d := newDetailsModel(aptLineStore(t), cfg)
	if d.aptSigned {
		t.Fatal("no key installed but the pane reports signed")
	}
	writeKeyAt(t, filepath.Join(dir, aptsign.KeyFileName), 0o600)
	d.refreshAptSigning()
	if !d.aptSigned {
		t.Error("a key generated while the pane was open stayed invisible")
	}
}

// TestPaneNamesOnlyAServedSuite. An entry naming a suite outside apt_suites
// reaches no index, so a line pointing at it 404s and apt reports "Unable to
// locate package" — indistinguishable from a typo in the name. The web UI
// matches against the server's own blocks and cannot name an unserved suite;
// this is the same rule on the Go side.
func TestPaneNamesOnlyAServedSuite(t *testing.T) {
	cfg := &config.Config{
		AptCodename: "noble",
		AptSuites:   []string{"noble", "jammy"},
		PublicURL:   "https://bodega.example.com",
		StoragePath: t.TempDir(),
	}
	for _, tc := range []struct {
		name   string
		suites []string
		want   string
	}{
		{"served suite is used", []string{"jammy"}, "jammy"},
		{"unserved suite falls back to the first served", []string{"bookworm"}, "noble"},
		{"first served of several", []string{"bookworm", "jammy"}, "jammy"},
		{"no suites means the default", nil, "noble"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pm := &manifest.PackageManifest{
				Name:     "pkg-a",
				Versions: []manifest.VersionEntry{{Version: "1.0", Suites: tc.suites}},
			}
			if got := aptSourcesSuite(cfg, pm); got != tc.want {
				t.Errorf("suite = %q, want %q", got, tc.want)
			}
			line := aptSources(cfg, pm, false).OneLine
			if !strings.Contains(line, " "+tc.want+" main") {
				t.Errorf("line names the wrong suite: %q", line)
			}
		})
	}

	// Nothing served at all is the one case with no honest answer, and a
	// placeholder is better than a literal the server does not answer for.
	bare := &config.Config{PublicURL: "https://bodega.example.com", StoragePath: t.TempDir()}
	if got := aptSources(bare, nil, false).Suite; got != aptsources.PlaceholderSuite {
		t.Errorf("suite = %q, want the placeholder", got)
	}
}
