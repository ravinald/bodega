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
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// The four places an operator copies the apt stanza from, on one non-default
// suite, in both signing states. Every wrong sources line this repository
// shipped passed a test that injected the value the emitter got wrong: the
// scheme, the suite, the trust option. So these assert the finished string,
// character for character, and nothing here injects one.
const (
	wantUnsignedStanza = "Types: deb\nURIs: https://bodega.example.com/apt/\nSuites: jammy\nComponents: main\nTrusted: yes"
	wantSignedStanza   = "Types: deb\nURIs: https://bodega.example.com/apt/\nSuites: jammy\nComponents: main\nSigned-By: /etc/apt/keyrings/bodega-archive-keyring.gpg"
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

// getJSON reads one API route off a server built on cfg and store. The status
// handler answers 503 without a storage backend and still renders the apt
// block, so the body is read whatever the code.
func getJSON(t *testing.T, cfg *config.Config, store *manifest.Store, route string, into any) string {
	t.Helper()
	srv := server.New(cfg, store, storage.NewSingle(storage.NewMemory()), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+route, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", route, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", route, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decode %s: %v\n%s", route, err, body)
	}
	return string(body)
}

// statusStanza is the stanza /api/v1/status hands any API consumer.
func statusStanza(t *testing.T, cfg *config.Config, store *manifest.Store) string {
	t.Helper()
	var body struct {
		Apt struct {
			Sources []struct {
				Deb822 string `json:"deb822"`
			} `json:"sources"`
		} `json:"apt"`
	}
	getJSON(t, cfg, store, "/api/v1/status", &body)
	if len(body.Apt.Sources) == 0 {
		t.Fatal("/api/v1/status carries no sources block")
	}
	return body.Apt.Sources[0].Deb822
}

// packageClientConfig is client_config off the package route, which is what
// the web page renders, and the raw body for a caller that hands it to the
// page's own script.
func packageClientConfig(t *testing.T, cfg *config.Config, store *manifest.Store, typ, name string) ([]clientconf.File, string) {
	t.Helper()
	var body struct {
		ClientConfig []clientconf.File `json:"client_config"`
	}
	raw := getJSON(t, cfg, store, "/api/v1/packages/"+typ+"/"+name, &body)
	return body.ClientConfig, raw
}

// paneStanza renders the details pane for the apt entry and reads the stanza
// back out of it, rather than calling the renderer directly: the pane is what
// the operator selects text from, and a correct renderer wired to the wrong
// argument is one of the defects this covers. stanzaField writes the first
// line after the label and each further line on a row of its own.
func paneStanza(t *testing.T, cfg *config.Config, store *manifest.Store) string {
	t.Helper()
	d := newDetailsModel(store, cfg)
	d.SetSize(200, 40)
	d.SetNode(&TreeNode{Name: "pkg-a", EntryType: manifest.TypeApt, Version: "1.0"})
	lines := strings.Split(stripANSI(d.View()), "\n")
	for i, l := range lines {
		at := strings.Index(l, "Types: deb")
		if at < 0 || !strings.Contains(l[:at], "Sources:") {
			continue
		}
		out := []string{strings.TrimSpace(l[at:])}
		for _, next := range lines[i+1:] {
			v := strings.TrimSpace(next)
			if len(next) <= at || strings.TrimSpace(next[:at]) != "" || v == "" {
				break
			}
			out = append(out, v)
		}
		return strings.Join(out, "\n")
	}
	t.Fatalf("details pane rendered no sources stanza:\n%s", stripANSI(d.View()))
	return ""
}

var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiEscape.ReplaceAllString(s, "") }

// TestSourcesLineIsTheSameStringEverywhere pins all four.
func TestSourcesLineIsTheSameStringEverywhere(t *testing.T) {
	for _, tc := range []struct {
		name string
		sign bool
		want string
	}{
		{"unsigned", false, wantUnsignedStanza},
		{"signed", true, wantSignedStanza},
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

			if got := statusStanza(t, cfg, store); got != tc.want {
				t.Errorf("/api/v1/status deb822:\n got %q\nwant %q", got, tc.want)
			}
			if got := paneStanza(t, cfg, store); got != tc.want {
				t.Errorf("TUI pane sources stanza:\n got %q\nwant %q", got, tc.want)
			}
			files, _ := packageClientConfig(t, cfg, store, manifest.TypeApt, "pkg-a")
			if len(files) == 0 {
				t.Fatal("GET /api/v1/packages/apt/pkg-a carries no client_config")
			}
			if got := strings.TrimRight(files[0].Content, "\n"); got != tc.want {
				t.Errorf("package client_config:\n got %q\nwant %q", got, tc.want)
			}
			if got := pageStanza(t, cfg, store); got != tc.want {
				t.Errorf("web page sources stanza:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// pageFuncs are the page's whole contribution to a client line: which of the
// server-rendered files an entry shows. Everything in the file is composed on
// the server, which is the point: the page printed a literal "noble" and
// derived a scheme from location.protocol for as long as it composed its own.
var pageFuncs = []string{"entryScopes", "pickClientFiles"}

// extractJSFunc pulls one top-level function out of the served page by
// matching braces from its declaration. Running the whole script is not an
// option: it ends in init() and two document.addEventListener calls, so it
// needs a DOM before it will reach the lines under test.
func extractJSFunc(t *testing.T, page, name string) string {
	t.Helper()
	start := strings.Index(page, "function "+name+"(")
	if start < 0 {
		t.Fatalf("served page defines no %s(); the client line is picked somewhere this test cannot see", name)
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

// pageStanza runs the page's own selection against the package route's own
// body and returns the content it would put in the Sources field.
//
// It needs a JS engine, and the gate has none: adding one to go.mod to
// exercise a dozen lines costs more than it settles. Where node is on PATH,
// this project's CI image and any machine with a front-end toolchain, the
// string is asserted like the other three. Where it is not,
// TestPageComposesNoLine still holds the page to rendering the server's
// content verbatim, which is the property that makes the assertion transitive.
func pageStanza(t *testing.T, cfg *config.Config, store *manifest.Store) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not on PATH; the page's rendered string is unasserted here, see TestPageComposesNoLine")
	}

	srv := server.New(cfg, store, storage.NewSingle(storage.NewMemory()), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	page := servedPage(t, ts)
	_, raw := packageClientConfig(t, cfg, store, manifest.TypeApt, "pkg-a")

	var script strings.Builder
	for _, fn := range pageFuncs {
		script.WriteString(extractJSFunc(t, page, fn) + "\n")
	}
	script.WriteString("const files = (" + raw + ").client_config;\n")
	script.WriteString("process.stdout.write(pickClientFiles('apt', {name: 'pkg-a', version: '1.0', suites: ['jammy']}, files)[0].content.replace(/\\n$/, ''));\n")

	path := filepath.Join(t.TempDir(), "page.js")
	if err := os.WriteFile(path, []byte(script.String()), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	out, err := exec.CommandContext(t.Context(), node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return string(out)
}

// TestPageComposesNoLine holds the page to rendering the server's content
// rather than building its own, which is what makes the API assertion above
// cover the page on a machine with no JS engine. Each literal named here was
// in the page and each produced a command that fails: "noble" on a jammy
// instance, http:// behind a TLS-terminating proxy, and [trusted=yes] against
// a signed archive.
func TestPageComposesNoLine(t *testing.T) {
	srv := server.New(aptLineConfig(t), aptLineStore(t), storage.NewSingle(storage.NewMemory()), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	page := servedPage(t, ts)

	code := regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(page, "")
	for _, banned := range []string{"trusted=yes", "signed-by=", "location.protocol", "'noble'", `"noble"`, "getClientUrl"} {
		if strings.Contains(code, banned) {
			t.Errorf("served page composes %q of its own; client lines come from client_config", banned)
		}
	}

	render := extractJSFunc(t, page, "clientConfigHtml")
	if !strings.Contains(render, "f.content") {
		t.Error("clientConfigHtml no longer renders the server's content")
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
			want:  wantUnsignedStanza,
		},
		{
			name:  "usable key",
			setup: func(t *testing.T, p string) { writeKeyAt(t, p, 0o600) },
			want:  wantSignedStanza,
		},
		{
			// aptsign refuses a key any other account can copy. The server is
			// then unsigned, so the pane must be too.
			name:  "key readable beyond its owner",
			setup: func(t *testing.T, p string) { writeKeyAt(t, p, 0o644) },
			want:  wantUnsignedStanza,
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
			want: wantUnsignedStanza,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(aptsign.CredentialsEnv, dir)
			tc.setup(t, filepath.Join(dir, aptsign.KeyFileName))

			if got := paneStanza(t, aptLineConfig(t), aptLineStore(t)); got != tc.want {
				t.Errorf("pane stanza:\n got %q\nwant %q", got, tc.want)
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
	d.refreshSigningKeys()
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

// The TUI links a binary to its stored name, and the server has to keep
// serving that name whatever it looks like: one ending in "~" and hex digits,
// whether it came from the url or an explicit filename, and one carrying the
// url's userinfo, which the read API publishes under an alias instead. Each is
// fetched for real, then requested at the TUI's own link through the server's
// own handler, beside the link the public manifest gives the web UI.
func TestBinaryClientURLReachesTheFetchedArtifact(t *testing.T) {
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{filepath.Join(t.TempDir(), "pepper")}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); ok && (user != "audit-user" || password != "audit-secret") {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("FETCHED-ELF"))
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")
	tag32 := strings.Repeat("0123456789abcdef", 2)
	for label, ve := range map[string]manifest.VersionEntry{
		"url-derived":    {Version: "1.0.0", URL: upstream.URL + "/tool~0123456789abcdef"},
		"explicit":       {Version: "1.0.0", URL: upstream.URL + "/download", Filename: "tool~0123456789abcdef"},
		"url-derived-32": {Version: "1.0.0", URL: upstream.URL + "/tool~" + tag32},
		"explicit-32":    {Version: "1.0.0", URL: upstream.URL + "/download", Filename: "tool~" + tag32},
		"userinfo":       {Version: "1.0.0", URL: "http://audit-user:audit-secret@" + host},
	} {
		t.Run(label, func(t *testing.T) {
			cfg := aptLineConfig(t)
			store := manifest.NewLocalStore(t.TempDir())
			objects := storage.NewMemory()
			if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", ve); err != nil {
				t.Fatal(err)
			}
			buildCfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
			if sum := builder.FetchBinaries(buildCfg, store, "tool"); sum.Total != 1 || sum.Failures != 0 {
				t.Fatalf("fetch: %+v", sum)
			}
			for _, p := range builder.BinaryArtifactPaths(buildCfg, store, "tool") {
				data, err := os.ReadFile(p.Local)
				if err != nil {
					t.Fatal(err)
				}
				if err := objects.Put(t.Context(), p.ObjectKey, data); err != nil {
					t.Fatal(err)
				}
			}
			srv := server.New(cfg, store, storage.NewSingle(objects), ":0", nil)
			get := func(target string) (int, string) {
				rr := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
				return rr.Code, rr.Body.String()
			}

			link := clientLine(cfg, store, manifest.TypeBinary, "tool")
			if code, body := get(link); code != http.StatusOK || body != "FETCHED-ELF" {
				t.Errorf("TUI link %s = %d %q, want the fetched bytes", link, code, body)
			}

			// The web page renders client_config off the package route.
			pcode, pbody := get("/api/v1/packages/binary/tool")
			var pkg struct {
				ClientConfig []clientconf.File `json:"client_config"`
			}
			if err := json.Unmarshal([]byte(pbody), &pkg); pcode != http.StatusOK || err != nil || len(pkg.ClientConfig) == 0 {
				t.Fatalf("package route: %d %v %s", pcode, err, pbody)
			}
			if web := pkg.ClientConfig[0].Content; web != link {
				t.Errorf("web link %q differs from the TUI link %q", web, link)
			}

			code, body := get("/api/v1/packages/binary/tool/1.0.0")
			if code != http.StatusOK {
				t.Fatalf("read: %d %s", code, body)
			}
			var pm manifest.PackageManifest
			if err := json.Unmarshal([]byte(body), &pm); err != nil {
				t.Fatal(err)
			}
			fn := pm.Versions[0].Filename
			if fn == "" {
				parts := strings.Split(pm.Versions[0].URL, "/")
				fn = parts[len(parts)-1]
			}
			if code, body := get("/binaries/tool/1.0.0/" + fn); code != http.StatusOK || body != "FETCHED-ELF" {
				t.Errorf("public manifest link %s = %d %q, want the fetched bytes", fn, code, body)
			}
		})
	}
}

// An operator who copies a published alias into another entry's explicit
// filename stores that entry under a spelling the server reads as the first
// entry's alias. The TUI links the copy by its own alias instead, minted with
// the server's pepper, so the link reaches the copy and never the original;
// the original's link, and the copy's link from the public manifest, keep
// reaching their own bytes whichever entry comes first and after the original
// is removed.
func TestBinaryClientURLNeverReachesAnotherEntry(t *testing.T) {
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{filepath.Join(t.TempDir(), "pepper")}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	serve := func(body string) string {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(up.Close)
		return up.URL
	}
	original := manifest.VersionEntry{Version: "1.0.0", URL: serve("ORIGINAL-ELF") + "/tool"}
	copyURL := serve("COPIED-ELF") + "/copy"

	cfg := aptLineConfig(t)
	store := manifest.NewLocalStore(t.TempDir())
	objects := storage.NewMemory()
	srv := server.New(cfg, store, storage.NewSingle(objects), ":0", nil)
	get := func(target string) (int, string) {
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		return rr.Code, rr.Body.String()
	}
	fetch := func(versions ...manifest.VersionEntry) {
		t.Helper()
		if err := store.SavePackage(t.Context(), &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "tool", Versions: versions}); err != nil {
			t.Fatal(err)
		}
		buildCfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
		if sum := builder.FetchBinaries(buildCfg, store, "tool"); sum.Failures != 0 {
			t.Fatalf("fetch: %+v", sum)
		}
		for _, p := range builder.BinaryArtifactPaths(buildCfg, store, "tool") {
			data, err := os.ReadFile(p.Local)
			if err != nil {
				t.Fatal(err)
			}
			if err := objects.Put(t.Context(), p.ObjectKey, data); err != nil {
				t.Fatal(err)
			}
		}
	}
	// published returns the public manifest's link for every entry, as the
	// web UI builds it.
	published := func() []string {
		t.Helper()
		code, body := get("/api/v1/packages/binary/tool")
		if code != http.StatusOK {
			t.Fatalf("read: %d %s", code, body)
		}
		var pm manifest.PackageManifest
		if err := json.Unmarshal([]byte(body), &pm); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, ve := range pm.Versions {
			fn := ve.Filename
			if fn == "" {
				parts := strings.Split(ve.URL, "/")
				fn = parts[len(parts)-1]
			}
			out = append(out, "/binaries/tool/1.0.0/"+fn)
		}
		return out
	}

	// The original is published under its stored name, so an alias has to
	// come from an entry that needs one: a url with userinfo and no path.
	aliased := manifest.VersionEntry{Version: "1.0.0", URL: strings.Replace(serve("ALIASED-ELF"), "http://", "http://audit-user:audit-secret@", 1)}
	fetch(aliased, original)
	alias := strings.TrimPrefix(published()[0], "/binaries/tool/1.0.0/")
	if !manifest.IsBinaryAlias(alias) {
		t.Fatalf("a url with no path is published as %q, not an alias", alias)
	}
	copied := manifest.VersionEntry{Version: "1.0.0", URL: copyURL, Filename: alias}

	for _, tc := range []struct {
		label    string
		versions []manifest.VersionEntry
		want     []string
	}{
		{"copy first", []manifest.VersionEntry{copied, aliased, original}, []string{"COPIED-ELF", "ALIASED-ELF", "ORIGINAL-ELF"}},
		{"copy last", []manifest.VersionEntry{original, aliased, copied}, []string{"ORIGINAL-ELF", "ALIASED-ELF", "COPIED-ELF"}},
		{"aliased entry removed", []manifest.VersionEntry{copied, original}, []string{"COPIED-ELF", "ORIGINAL-ELF"}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			fetch(tc.versions...)
			link := clientLine(cfg, store, manifest.TypeBinary, "tool")
			if link == "" {
				t.Errorf("the TUI offers no link for %+v", tc.versions[0])
			} else if code, body := get(strings.TrimPrefix(link, "https://bodega.example.com")); code != http.StatusOK || body != tc.want[0] {
				t.Errorf("TUI link %s = %d %q, want %q", link, code, body, tc.want[0])
			}
			for i, path := range published() {
				if code, body := get(path); code != http.StatusOK || body != tc.want[i] {
					t.Errorf("public link %s = %d %q, want %q", path, code, body, tc.want[i])
				}
			}
			code, body := get("/binaries/tool/1.0.0/" + alias)
			if tc.label == "aliased entry removed" {
				if code != http.StatusNotFound {
					t.Errorf("the removed entry's alias = %d %q, want 404", code, body)
				}
			} else if body != "ALIASED-ELF" {
				t.Errorf("the alias = %d %q, want the entry it was minted for", code, body)
			}
		})
	}
}

// An entry with no version whose explicit filename starts "~/" is stored as
// binaries/tool/~/tool, and the route reads /binaries/tool/~/tool, three
// segments, as a request for that key rather than as an alias. The entry sits
// on the backend the route falls back to, so a TUI that cannot read the
// pepper links it by its stored name and still gets the link.
func TestBinaryClientURLKeepsATildeStoredName(t *testing.T) {
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{filepath.Join(t.TempDir(), "pepper")}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("FETCHED-ELF"))
	}))
	defer upstream.Close()

	cfg := aptLineConfig(t)
	store := manifest.NewLocalStore(t.TempDir())
	objects := storage.NewMemory()
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", manifest.VersionEntry{URL: upstream.URL + "/tool", Filename: "~/tool"}); err != nil {
		t.Fatal(err)
	}
	buildCfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
	if sum := builder.FetchBinaries(buildCfg, store, "tool"); sum.Total != 1 || sum.Failures != 0 {
		t.Fatalf("fetch: %+v", sum)
	}
	for _, p := range builder.BinaryArtifactPaths(buildCfg, store, "tool") {
		data, err := os.ReadFile(p.Local)
		if err != nil {
			t.Fatal(err)
		}
		if err := objects.Put(t.Context(), p.ObjectKey, data); err != nil {
			t.Fatal(err)
		}
	}
	srv := server.New(cfg, store, storage.NewSingle(objects), ":0", nil)
	audit.DefaultPepperPaths = []string{filepath.Join(t.TempDir(), "absent")}

	link := clientLine(cfg, store, manifest.TypeBinary, "tool")
	if link == "" {
		t.Fatal("the TUI offers no link for an entry stored as ~/tool")
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(link, "https://bodega.example.com"), nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "FETCHED-ELF" {
		t.Errorf("TUI link %s = %d %q, want the fetched bytes", link, rr.Code, rr.Body)
	}
}

// The same stored name recorded on another backend. /binaries/tool/~/tool
// parses as version "~", which no entry has, so the route serves it from the
// type's backend, where other bytes sit under that key. The TUI links the
// entry by the alias the read API publishes when it can read the pepper, and
// offers no link when it cannot, rather than the stored name.
func TestBinaryClientURLKeepsATildeStoredNameOnItsBackend(t *testing.T) {
	prev := audit.DefaultPepperPaths
	pepper := filepath.Join(t.TempDir(), "pepper")
	audit.DefaultPepperPaths = []string{pepper}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("FETCHED-ELF"))
	}))
	defer upstream.Close()

	cfg := aptLineConfig(t)
	cfg.StorageBackend = "local"
	cfg.StoragePath = t.TempDir()
	cfg.StorageBackends = map[string]config.StorageSpec{"other": {Driver: "local", Path: t.TempDir()}}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := stores.ByName("other")
	if err != nil {
		t.Fatal(err)
	}
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "tool", manifest.VersionEntry{URL: upstream.URL + "/tool", Filename: "~/tool", Storage: "other"}); err != nil {
		t.Fatal(err)
	}
	buildCfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
	if sum := builder.FetchBinaries(buildCfg, store, "tool"); sum.Total != 1 || sum.Failures != 0 {
		t.Fatalf("fetch: %+v", sum)
	}
	for _, p := range builder.BinaryArtifactPaths(buildCfg, store, "tool") {
		data, err := os.ReadFile(p.Local)
		if err != nil {
			t.Fatal(err)
		}
		if err := objects.Put(t.Context(), p.ObjectKey, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := stores.Default().Put(t.Context(), "binaries/tool/~/tool", []byte("WRONG-BACKEND-ELF")); err != nil {
		t.Fatal(err)
	}
	srv := server.New(cfg, store, stores, ":0", nil)

	link := clientLine(cfg, store, manifest.TypeBinary, "tool")
	if link == "" {
		t.Fatal("the TUI offers no link for an entry stored as ~/tool on another backend")
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(link, "https://bodega.example.com"), nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "FETCHED-ELF" {
		t.Errorf("TUI link %s = %d %q, want the fetched bytes", link, rr.Code, rr.Body)
	}

	audit.DefaultPepperPaths = []string{filepath.Join(t.TempDir(), "absent")}
	if link := clientLine(cfg, store, manifest.TypeBinary, "tool"); link != "" {
		t.Errorf("with no pepper the TUI links %s, want no link", link)
	}
}
