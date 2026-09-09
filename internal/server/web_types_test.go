package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// webIndex returns the embedded page as the server serves it. Nothing else in
// the tree reads the asset back, which is how a seven-type list shipped past a
// green gate: //go:embed compiles whatever is on disk without inspecting it.
func webIndex(t *testing.T) string {
	t.Helper()
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded web/index.html: %v", err)
	}
	return string(b)
}

var (
	reTypeIcons = regexp.MustCompile(`(?s)const typeIcons = \{(.*?)\}`)
	reBarColors = regexp.MustCompile(`(?s)var barColors = \{(.*?)\}`)
	reObjectKey = regexp.MustCompile(`(\w+)\s*:`)
	reTypeRule  = regexp.MustCompile(`\.type-([a-z0-9_-]+)\s*\{`)
	// getClientUrl's body, up to the first closing brace in column 0. Every
	// brace inside the function is indented, so that is its end.
	reClientURLFn = regexp.MustCompile(`(?s)\nfunction getClientUrl\(.*?\n\}`)
	reSwitchCase  = regexp.MustCompile(`case '([a-z0-9_-]+)':`)
	// The .field .val rule, excluding its .yes/.no/.url modifiers.
	reFieldValRule = regexp.MustCompile(`(?s)\.field \.val\s*\{(.*?)\}`)
)

func objectKeys(t *testing.T, re *regexp.Regexp, src, what string) map[string]bool {
	t.Helper()
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("web/index.html: no %s object literal found; the test's regexp and the page have drifted", what)
	}
	keys := map[string]bool{}
	for _, k := range reObjectKey.FindAllStringSubmatch(m[1], -1) {
		keys[k[1]] = true
	}
	return keys
}

// TestWebUICoversEveryKnownType pins the page's three presentation tables to
// manifest.AllTypes. Each named seven of eight, and each fails differently and
// quietly: typeIcons renders the string "undefined" for a type it has no
// letter for, barColors falls back to the accent color so every unnamed type
// shares one bar color, and a missing .type-<name> rule inherits whatever
// color surrounds it. Asserted against AllTypes rather than a list of this
// test's own, because a second list is the defect being fixed.
func TestWebUICoversEveryKnownType(t *testing.T) {
	src := webIndex(t)

	icons := objectKeys(t, reTypeIcons, src, "typeIcons")
	colors := objectKeys(t, reBarColors, src, "barColors")

	rules := map[string]bool{}
	for _, m := range reTypeRule.FindAllStringSubmatch(src, -1) {
		rules[m[1]] = true
	}
	if len(rules) == 0 {
		t.Fatal("web/index.html: no .type-<name> CSS rules found; the test's regexp and the page have drifted")
	}

	for _, typ := range manifest.AllTypes {
		t.Run(typ, func(t *testing.T) {
			if !icons[typ] {
				t.Errorf("typeIcons has no %q key, so the group header renders the string \"undefined\" as its icon", typ)
			}
			if !colors[typ] {
				t.Errorf("barColors has no %q key, so its dashboard bar falls back to the accent color it shares with every other unnamed type", typ)
			}
			if !rules[typ] {
				t.Errorf("no .type-%s CSS rule, so the icon inherits the surrounding color instead of its own", typ)
			}
		})
	}
}

// TestWebUIEnvelopesCarryCargo drives the page's own two inputs with a crate
// and an npm package stored. A Go test cannot run the page's JavaScript, so
// the assertion is on the envelopes it renders from: /api/v1/packages must
// carry the crate under a cargo key, entry_count must count it, and the sum
// the header renders must equal the total across the groups the render loop
// produces. That last equality is #280: the header summed entry_count over
// every type while the loop rendered a hand-maintained seven, so the count in
// the header exceeded the entries below it by exactly the crates.
func TestWebUIEnvelopesCarryCargo(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	for typ, name := range map[string]string{manifest.TypeCargo: "time", manifest.TypeNpm: "left-pad"} {
		pm := &manifest.PackageManifest{
			ConfigVersion: manifest.CurrentConfigVersion,
			Name:          name,
			Type:          typ,
			Versions:      []manifest.VersionEntry{{Version: "1.0.0"}},
		}
		if err := s.store.SavePackage(t.Context(), pm); err != nil {
			t.Fatalf("seed %s/%s: %v", typ, name, err)
		}
	}

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	get := func(path string, into any) {
		t.Helper()
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200; body: %s", path, resp.StatusCode, body)
		}
		if err := json.Unmarshal(body, into); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}

	var envelope map[string][]struct {
		Name string `json:"name"`
	}
	get("/api/v1/packages", &envelope)
	crates, ok := envelope["cargo"]
	if !ok {
		t.Fatal("GET /api/v1/packages: no cargo key, so the page has nothing to render the crate from")
	}
	if len(crates) != 1 || crates[0].Name != "time" {
		t.Errorf("GET /api/v1/packages: cargo = %+v, want the one stored crate", crates)
	}

	var status struct {
		EntryCount map[string]int `json:"entry_count"`
	}
	get("/api/v1/status", &status)
	if status.EntryCount["cargo"] != 1 {
		t.Errorf("GET /api/v1/status: entry_count[cargo] = %d, want 1", status.EntryCount["cargo"])
	}

	// Both sides here are package counts: entry_count is len(ListPackages),
	// and each /api/v1/packages value is the list the page groups by type. The
	// tree's own totals are version entries, a different quantity, asserted
	// against the rendered page in TestWebUIRendersEveryServedType. What #280
	// broke is membership, which is what the key check below catches.
	header := 0
	for typ, n := range status.EntryCount {
		header += n
		if _, ok := envelope[typ]; !ok {
			t.Errorf("entry_count counts %q, which /api/v1/packages has no key for, so the header counts a group the tree cannot render", typ)
		}
	}
	served := 0
	for _, pkgs := range envelope {
		served += len(pkgs)
	}
	if header != served {
		t.Errorf("entry_count totals %d packages against %d in /api/v1/packages; the header counts packages the page is never handed", header, served)
	}
}

// domStub is the smallest DOM the embedded page's script touches. It exists so
// the render loop and the permalink guard are asserted by running them rather
// than by matching their source, which is the only way a claim about what an
// operator sees in a browser is falsifiable.
const domStub = `
class El {
  constructor(tag) {
    this.tagName = tag; this.className = ''; this.style = {}; this.childNodes = [];
    this.textContent = ''; this.title = ''; this.value = ''; this._html = '';
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = v; if (v === '') this.childNodes = []; }
  appendChild(c) { this.childNodes.push(c); return c; }
  addEventListener() {}
  setAttribute() {}
  querySelector() { return null; }
  closest() { return null; }
}
const __els = {};
globalThis.document = {
  documentElement: new El('html'),
  body: new El('body'),
  getElementById(id) { return __els[id] || (__els[id] = new El('div')); },
  createElement(tag) { return new El(tag); },
  addEventListener() {},
  querySelectorAll() { return []; },
};
globalThis.localStorage = { getItem() { return null; }, setItem() {} };
globalThis.location = { hash: process.env.HARNESS_HASH || '', origin: 'http://127.0.0.1', protocol: 'http:' };
const __base = process.env.HARNESS_BASE;
const __canned = JSON.parse(process.env.HARNESS_CANNED || '{}');
const __realFetch = globalThis.fetch;
globalThis.fetch = async function(url) {
  if (__base) return __realFetch(__base + url);
  for (const path of Object.keys(__canned)) {
    if (url.startsWith(path)) return { ok: true, json: async () => __canned[path] };
  }
  return { ok: false, json: async () => null };
};
`

// harnessProbe runs after the page's own script, in its scope, so it can read
// the top-level `let` bindings the script never exports.
const harnessProbe = `
globalThis.__probe = async function() {
  await init();
  const tree = document.getElementById('tree');
  const groups = tree.childNodes.map(g => {
    const h = g.childNodes[0]._html;
    const type = (h.match(/<span>([^<]*)\/<\/span>/) || [])[1];
    const icon = (h.match(/<span class="icon type-([^"]*)">([^<]*)<\/span>/) || []);
    return { type: type, iconClass: icon[1], icon: icon[2], count: Number((h.match(/\((\d+)\)/) || [])[1]) };
  });
  await showDashboard();
  const bars = document.getElementById('detail')._html
    .split('dash-bar-row').slice(1)
    .map(s => ({ label: (s.match(/dash-bar-label">([^<]*)</) || [])[1], color: (s.match(/background:([^"]*)"/) || [])[1] }));
  return {
    groups: groups,
    bars: bars,
    statusText: document.getElementById('status-text').textContent,
    expandedGroups: Array.from(expandedGroups),
    renderTypes: renderTypes(Object.keys(allData || {})),
  };
};
__probe().then(r => console.log(JSON.stringify(r))).catch(e => { console.error(e); process.exit(1); });
`

type probeGroup struct {
	Type      string `json:"type"`
	IconClass string `json:"iconClass"`
	Icon      string `json:"icon"`
	Count     int    `json:"count"`
}

type probeResult struct {
	Groups []probeGroup `json:"groups"`
	Bars   []struct {
		Label string `json:"label"`
		Color string `json:"color"`
	} `json:"bars"`
	StatusText     string   `json:"statusText"`
	ExpandedGroups []string `json:"expandedGroups"`
	RenderTypes    []string `json:"renderTypes"`
}

// runPage evaluates the embedded page's script under domStub with the given
// hash fragment and canned envelopes, and reports what rendered.
func runPage(t *testing.T, hash string, canned map[string]any) probeResult {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		// A developer without node still gets the rest of the suite. CI is the
		// one place where a skip here would be indistinguishable from a pass,
		// so on a runner it is a failure: GitHub's ubuntu images ship node,
		// and the day one stops, this says so rather than going quiet.
		if os.Getenv("CI") != "" {
			t.Fatal("node not on PATH; the page's own JavaScript went unexercised on a CI runner")
		}
		t.Skip("node not on PATH; the page's own JavaScript cannot be executed here")
	}

	src := webIndex(t)
	start, end := strings.Index(src, "<script>"), strings.LastIndex(src, "</script>")
	if start < 0 || end < 0 {
		t.Fatal("web/index.html: no <script> block found")
	}
	script := src[start+len("<script>") : end]
	// The page calls init() on load. Dropping that call hands the harness the
	// only invocation, so nothing renders concurrently with the assertions.
	script = strings.Replace(script, "\ninit();\n", "\n", 1)

	path := filepath.Join(t.TempDir(), "page.cjs")
	if err := os.WriteFile(path, []byte(domStub+script+harnessProbe), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	cannedJSON, err := json.Marshal(canned)
	if err != nil {
		t.Fatalf("marshal canned envelopes: %v", err)
	}
	cmd := exec.Command(node, path)
	cmd.Env = append(os.Environ(), "HARNESS_HASH="+hash, "HARNESS_CANNED="+string(cannedJSON))
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("run page: %v\n%s", err, stderr)
	}

	var got probeResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode probe output %q: %v", out, err)
	}
	return got
}

// cannedEnvelopes builds the three responses the page fetches, one key per
// named type, in the shape the server emits. counts is packages per type, and
// package i of a type carries i+1 versions so that entry_count (packages) and
// the tree (version entries) come apart wherever a type holds more than one
// package. The second return is the version-entry total per type, so a caller
// asserts what the tree lists without restating that rule as a second list.
func cannedEnvelopes(counts map[string]int) (map[string]any, map[string]int) {
	packages := map[string]any{}
	entryCount := map[string]int{}
	byType := map[string]any{}
	entries := map[string]int{}
	for typ, n := range counts {
		pkgs := []any{}
		for i := 0; i < n; i++ {
			versions := []any{}
			for v := 0; v <= i; v++ {
				versions = append(versions, map[string]any{"version": fmt.Sprintf("%d.0.0", v+1)})
			}
			pkgs = append(pkgs, map[string]any{
				"name":     fmt.Sprintf("%s-pkg-%d", typ, i),
				"versions": versions,
			})
			entries[typ] += len(versions)
		}
		packages[typ] = pkgs
		entryCount[typ] = n
		byType[typ] = map[string]any{"packages": n}
	}
	return map[string]any{
		"/api/v1/packages": packages,
		"/api/v1/status":   map[string]any{"entry_count": entryCount},
		"/api/v1/metrics":  map[string]any{"global": map[string]any{}, "by_type": byType},
	}, entries
}

// TestWebUIRendersEveryServedType runs the page's script against an envelope
// carrying a type typeOrder does not name. The literal used to be the render
// set, so a crate the read API answered for was invisible in the browser.
func TestWebUIRendersEveryServedType(t *testing.T) {
	counts := map[string]int{"apt": 1, "npm": 1, "cargo": 1, "nuget": 2}
	canned, entries := cannedEnvelopes(counts)
	got := runPage(t, "", canned)

	rendered := map[string]probeGroup{}
	for _, g := range got.Groups {
		rendered[g.Type] = g
	}
	for _, typ := range []string{"apt", "npm", "cargo", "nuget"} {
		if _, ok := rendered[typ]; !ok {
			t.Errorf("no %q group rendered, though the server sent the key; groups: %+v", typ, got.Groups)
		}
	}
	if g := rendered["cargo"]; g.Icon != "C" || g.IconClass != "cargo" {
		t.Errorf("cargo group icon = %q class %q, want \"C\" and \"cargo\"", g.Icon, g.IconClass)
	}
	// A type with no icon row renders its first letter, never "undefined".
	if g := rendered["nuget"]; g.Icon != "N" {
		t.Errorf("nuget group icon = %q, want the fallback \"N\"", g.Icon)
	}

	// typeOrder decides order and never membership: the types it names lead,
	// the rest follow.
	if want := []string{"apt", "npm", "cargo", "nuget"}; !equalStrings(got.RenderTypes, want) {
		t.Errorf("render order = %v, want %v", got.RenderTypes, want)
	}

	// The header states both quantities: entry_count's package total, and a
	// version total the page sums from the same entriesForType the groups
	// render. The seed gives package i of a type i+1 versions, so the two
	// differ here (5 packages, 6 versions) and neither can stand in for the
	// other. The version half equals the tree total by construction, which is
	// why it is asserted rather than sampled: a header computed from
	// entry_count instead, or an entriesForType that stops at one version per
	// package, fails this. #280 broke membership, caught per type below.
	packages, treeEntries, total := 0, 0, 0
	for _, g := range got.Groups {
		total += g.Count
	}
	for typ, n := range counts {
		packages += n
		treeEntries += entries[typ]
		g, ok := rendered[typ]
		if !ok {
			continue // already reported as a group the server sent and the page dropped
		}
		if g.Count != entries[typ] {
			t.Errorf("%s group lists %d entries, want the %d versions the server sent", typ, g.Count, entries[typ])
		}
	}
	if want := fmt.Sprintf("%d packages, %d versions", packages, treeEntries); got.StatusText != want || total != treeEntries {
		t.Errorf("header %q over groups totalling %d entries, want %q over %d; either the header counts a quantity the tree does not list, or a group lists fewer entries than the server sent", got.StatusText, total, want, treeEntries)
	}

	bars := map[string]string{}
	for _, b := range got.Bars {
		bars[b.Label] = b.Color
	}
	if bars["cargo"] != "#d75fd7" {
		t.Errorf("cargo dashboard bar color = %q, want its own #d75fd7 rather than the shared fallback", bars["cargo"])
	}
	if _, ok := bars["nuget"]; !ok {
		t.Errorf("no nuget dashboard bar, though by_type carried it; bars: %v", bars)
	}
}

// TestWebUIRejectsUnservedPermalinkType feeds the permalink parser a type the
// server never sent. parts[0] reached expandedGroups unchecked and the group
// header interpolated it into innerHTML with no escaping; only the render loop
// being driven by a literal kept it off the page, and requirement 1 rewrote
// exactly that loop.
func TestWebUIRejectsUnservedPermalinkType(t *testing.T) {
	const payload = `<img src=x onerror=alert(1)>`
	canned, _ := cannedEnvelopes(map[string]int{"apt": 1, "cargo": 1})
	got := runPage(t, "#"+payload+"/pkg/1.0.0", canned)

	if len(got.ExpandedGroups) != 0 {
		t.Errorf("expandedGroups = %v, want empty: a permalink type the server never sent must not reach it", got.ExpandedGroups)
	}
	for _, g := range got.Groups {
		if strings.Contains(g.Type, "img") || strings.Contains(g.IconClass, "img") {
			t.Errorf("rendered a group for the permalink type: %+v", g)
		}
	}
	if want := []string{"apt", "cargo"}; !equalStrings(got.RenderTypes, want) {
		t.Errorf("render set = %v, want %v: the render set comes from the server and nowhere else", got.RenderTypes, want)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestWebClientInstructionCoversEveryKnownType pins getClientUrl's switch to
// manifest.AllTypes. The function shipped with seven arms and fell through to
// "" for the eighth, and showEntry drops the row when the string is empty, so
// a crate's detail panel was the one panel of eight with nothing to copy. The
// switch is read out of the embedded asset for the same reason the tables
// above are: //go:embed compiles the page without inspecting it.
func TestWebClientInstructionCoversEveryKnownType(t *testing.T) {
	src := webIndex(t)

	body := reClientURLFn.FindString(src)
	if body == "" {
		t.Fatal("web/index.html: no getClientUrl function found; the test's regexp and the page have drifted")
	}
	cases := map[string]bool{}
	for _, m := range reSwitchCase.FindAllStringSubmatch(body, -1) {
		cases[m[1]] = true
	}
	if len(cases) == 0 {
		t.Fatal("web/index.html: getClientUrl has no case labels; the test's regexp and the page have drifted")
	}

	for _, typ := range manifest.AllTypes {
		if !cases[typ] {
			t.Errorf("getClientUrl has no case for %q, so it falls through to \"\" and the detail panel drops the client-instruction row entirely", typ)
		}
	}
}

// TestWebMultiLineClientInstructionWraps guards the CSS the moment a client
// instruction stops being one line. cargo's is a three-line registry stanza,
// and .field .val shipped with no white-space declaration, so the browser
// collapsed it to a single line: the copy affordance handed over legal TOML
// while the text on screen was a parse error, which is the worse half to get
// wrong because retyping it is what docs/USAGE.md invites. text-align comes
// with it because #detail computes to center, which every one-line value in
// the pane's history hid. Conditional on a newline actually being in a case
// body, so a page whose instructions are all single lines needs neither.
func TestWebMultiLineClientInstructionWraps(t *testing.T) {
	src := webIndex(t)

	body := reClientURLFn.FindString(src)
	if body == "" {
		t.Fatal("web/index.html: no getClientUrl function found; the test's regexp and the page have drifted")
	}
	if !strings.Contains(body, `\n`) {
		t.Skip("no getClientUrl case emits a newline, so the pane has no multi-line value to wrap")
	}

	m := reFieldValRule.FindStringSubmatch(src)
	if m == nil {
		t.Fatal("web/index.html: no .field .val rule found; the test's regexp and the page have drifted")
	}
	decls := m[1]
	for _, want := range []string{"white-space: pre-wrap", "text-align: left"} {
		if !strings.Contains(decls, want) {
			t.Errorf(".field .val does not declare %q, so a client instruction carrying a newline renders as one line: {%s}", want, decls)
		}
	}
}
