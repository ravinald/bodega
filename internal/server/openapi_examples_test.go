package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ravinald/bodega/internal/audit"
)

const walkthroughBase = "https://bodega.example.com"

func loadOpenAPI(t *testing.T) *openapi3.T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(raw)
	if err != nil {
		t.Fatalf("api/openapi.yaml does not load as OpenAPI: %v", err)
	}
	return doc
}

// validateExamples holds every example and examples value in the document to
// the schema it sits under. kin-openapi's own validation decides what matches;
// its error names the path and method, or the component, of the first miss.
func validateExamples(doc *openapi3.T) error {
	return doc.Validate(context.Background(), openapi3.EnableExamplesValidation())
}

func TestOpenAPIExamplesMatchTheirSchemas(t *testing.T) {
	if err := validateExamples(loadOpenAPI(t)); err != nil {
		t.Fatalf("an example in api/openapi.yaml does not match its schema: %v", err)
	}

	// Each case breaks one example where the document carries one, so a
	// position the validation stopped reading fails here rather than passing
	// every example unread.
	cases := []struct {
		name    string
		breakIt func(*openapi3.T)
		names   []string
	}{
		{
			name: "a request body's example",
			breakIt: func(d *openapi3.T) {
				d.Paths.Find("/api/v1/tokens").Post.RequestBody.Value.Content["application/json"].Example = map[string]any{"label": 7, "scope": "read"}
			},
			names: []string{"/api/v1/tokens", "POST"},
		},
		{
			name: "a response's example",
			breakIt: func(d *openapi3.T) {
				d.Paths.Find("/api/v1/status").Get.Responses.Value("200").Value.Content["application/json"].Example = map[string]any{"healthy": "yes"}
			},
			names: []string{"/api/v1/status", "GET"},
		},
		{
			name: "a shared example a response names",
			breakIt: func(d *openapi3.T) {
				d.Components.Examples["LodashHidden"].Value.Value = map[string]any{"name": "lodash", "type": "not-a-type"}
			},
			names: []string{"/api/v1/packages/{type}/{name}/hide", "PATCH"},
		},
		{
			name: "a schema property's example",
			breakIt: func(d *openapi3.T) {
				d.Components.Schemas["PolicyRule"].Value.Properties["RegistryType"].Value.Example = 12
			},
			names: []string{"PolicyRule"},
		},
		{
			name: "a parameter's example",
			breakIt: func(d *openapi3.T) {
				d.Components.Parameters["ClientRelease"].Value.Schema.Value.Example = "fourteen"
			},
			names: []string{"ClientRelease"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := loadOpenAPI(t)
			tc.breakIt(doc)
			err := validateExamples(doc)
			if err == nil {
				t.Fatalf("%s that does not match its schema passed validation", tc.name)
			}
			for _, want := range tc.names {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the failure does not name %q, so nobody can find the example: %v", want, err)
				}
			}
		})
	}
}

type walkthroughCall struct {
	method, path string
	query        url.Values
	op           *openapi3.Operation
	template     string
}

var (
	fencedBlock = regexp.MustCompile("(?s)```[a-z]*\n(.*?)```")
	curlMethod  = regexp.MustCompile(`-X ([A-Z]+)`)
	curlURL     = regexp.MustCompile(`https?://[^\s"']+`)
	tokenScope  = regexp.MustCompile(`bodega token generate \S+(?: expiry \S+)? --scope (\S+)`)
)

// firstRequests is the walkthrough section of the introduction, up to the next
// heading of its level.
func firstRequests(t *testing.T, doc *openapi3.T) string {
	t.Helper()
	_, section, ok := strings.Cut(doc.Info.Description, "\n## First requests\n")
	if !ok {
		t.Fatal(`info.description has no "## First requests" section`)
	}
	if i := strings.Index(section, "\n## "); i >= 0 {
		section = section[:i]
	}
	return section
}

// matchOperation finds the documented path a concrete request path fits,
// preferring the template with the most literal segments, so
// /api/v1/packages/import is the import route and not a package type.
func matchOperation(doc *openapi3.T, method, path string) (*openapi3.Operation, string, map[string]string) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var (
		best     *openapi3.Operation
		bestTmpl string
		bestVars map[string]string
		bestLit  = -1
	)
	for tmpl, item := range doc.Paths.Map() {
		parts := strings.Split(strings.Trim(tmpl, "/"), "/")
		if len(parts) != len(segs) {
			continue
		}
		vars, lit, ok := map[string]string{}, 0, true
		for i, p := range parts {
			switch {
			case strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}"):
				vars[strings.Trim(p, "{}")] = segs[i]
			case p == segs[i]:
				lit++
			default:
				ok = false
			}
		}
		if op := item.GetOperation(method); ok && op != nil && lit > bestLit {
			best, bestTmpl, bestVars, bestLit = op, tmpl, vars, lit
		}
	}
	return best, bestTmpl, bestVars
}

func walkthroughCalls(t *testing.T, doc *openapi3.T) []walkthroughCall {
	t.Helper()
	var calls []walkthroughCall
	for _, block := range fencedBlock.FindAllStringSubmatch(firstRequests(t, doc), -1) {
		cmd := strings.ReplaceAll(block[1], "\\\n", " ")
		if !strings.HasPrefix(strings.TrimSpace(cmd), "curl ") {
			continue
		}
		method := http.MethodGet
		if m := curlMethod.FindStringSubmatch(cmd); m != nil {
			method = m[1]
		}
		raw := curlURL.FindString(cmd)
		if !strings.HasPrefix(raw, walkthroughBase+"/") {
			t.Errorf("the walkthrough request %q is not against the placeholder base URL %s", strings.TrimSpace(cmd), walkthroughBase)
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Errorf("the walkthrough URL %q does not parse: %v", raw, err)
			continue
		}
		op, tmpl, vars := matchOperation(doc, method, u.Path)
		if op == nil {
			t.Errorf("the walkthrough calls %s %s, and the document describes no such operation", method, u.Path)
			continue
		}
		declared := map[string]*openapi3.Parameter{}
		for _, p := range op.Parameters {
			declared[p.Value.In+":"+p.Value.Name] = p.Value
		}
		for name, value := range vars {
			p := declared["path:"+name]
			if p == nil {
				t.Errorf("%s %s: the path names {%s}, which %s does not declare", method, tmpl, name, op.OperationID)
				continue
			}
			if err := p.Schema.Value.VisitJSON(pathValue(p.Schema.Value, value)); err != nil {
				t.Errorf("%s %s: the walkthrough's {%s} is %q, which %s does not accept: %v", method, u.Path, name, value, op.OperationID, err)
			}
		}
		for name, values := range u.Query() {
			p := declared["query:"+name]
			if p == nil {
				t.Errorf("%s %s: the walkthrough sends ?%s=, a parameter %s does not declare", method, u.Path, name, op.OperationID)
				continue
			}
			if err := p.Schema.Value.VisitJSON(values[0]); err != nil {
				t.Errorf("%s %s: ?%s=%s is not a value %s accepts: %v", method, u.Path, name, values[0], op.OperationID, err)
			}
		}
		calls = append(calls, walkthroughCall{method: method, path: u.Path, query: u.Query(), op: op, template: tmpl})
	}
	return calls
}

// pathValue reads a path segment as the type its parameter declares, so an
// integer id is checked as an integer.
func pathValue(s *openapi3.Schema, raw string) any {
	if s.Type != nil && s.Type.Is("integer") {
		var n float64
		for _, r := range raw {
			if r < '0' || r > '9' {
				return raw
			}
			n = n*10 + float64(r-'0')
		}
		return n
	}
	return raw
}

func TestOpenAPIIntroductionTeachesTheAPI(t *testing.T) {
	doc := loadOpenAPI(t)
	intro := doc.Info.Description
	for _, section := range [][2]string{
		{"when to use the API rather than the CLI or the TUI", "## When to use it"},
		{"the TUI", "`bodega shell`"},
		{"the base URL section", "## Base URL"},
		{"the setting the base URL is", "`public_url`"},
		{"the placeholder base URL", walkthroughBase},
		{"the authentication section", "## Authentication"},
		{"the rule for when a request must authenticate", "`admin_permit_cidr`"},
		{"the command that mints a credential", "bodega token generate {label} --scope {scopes}"},
		{"the header a credential travels in", "Authorization: Bearer"},
		{"the OIDC exchange", "`POST /api/v1/auth/exchange`"},
		{"the error section", "## Errors"},
		{"the Error body", "`Error` schema"},
		{"the text/plain refusals", "`text/plain`"},
		{"the /client/ refusals", "`/client/`"},
		{"the walkthrough", "## First requests"},
	} {
		what, want := section[0], section[1]
		if !strings.Contains(intro, want) {
			t.Errorf("info.description does not cover %s: it lacks %q", what, want)
		}
	}
	for _, scope := range []string{audit.ScopeRead, audit.ScopeWrite, audit.ScopeAdmin, audit.ScopeApprove, audit.ScopeSuperadmin, audit.ScopeInventory} {
		if !strings.Contains(intro, "| `"+scope+"` |") {
			t.Errorf("info.description's scope table has no row for %q", scope)
		}
	}
	for _, status := range []string{"400", "401", "403", "404", "409"} {
		if !strings.Contains(intro, "| `"+status+"` |") {
			t.Errorf("info.description's status table has no row for %s", status)
		}
	}

	calls := walkthroughCalls(t, doc)
	var got []string
	for _, c := range calls {
		got = append(got, c.op.OperationID)
	}
	for _, want := range []string{"healthz", "getStatus", "listPackagesByType", "getPackageVersion", "listQueue", "approveQueue", "toggleHiddenVersion"} {
		if !slices.Contains(got, want) {
			t.Errorf("the walkthrough has no request for %s; it calls %v", want, got)
		}
	}

	// The token the walkthrough mints has to reach every request that follows
	// it, by the server's own rule for what each route needs.
	m := tokenScope.FindStringSubmatch(firstRequests(t, doc))
	if m == nil {
		t.Fatal("the walkthrough mints no token with bodega token generate ... --scope")
	}
	scopes, err := audit.ParseScopes(m[1])
	if err != nil {
		t.Fatalf("the walkthrough's --scope %q is not a scope list bodega accepts: %v", m[1], err)
	}
	for _, c := range calls {
		need, typ := routeScope(httptest.NewRequest(c.method, c.path, nil))
		if len(need) == 0 {
			continue
		}
		if !slices.ContainsFunc(need, func(n string) bool { return scopes.Allows(n, typ) }) {
			t.Errorf("the walkthrough's token holds %q, which does not reach %s %s: the route needs %v for type %q", m[1], c.method, c.path, need, typ)
		}
	}

	for _, tag := range doc.Tags {
		if !strings.Contains(tag.Description, "](../docs/usage/") {
			t.Errorf("tag %q does not link the docs/usage.md section that explains it by its path on the site, relative to /api/", tag.Name)
		}
		if len(strings.Fields(tag.Description)) < 15 {
			t.Errorf("tag %q describes itself in %d words; say what an operator uses the group for", tag.Name, len(strings.Fields(tag.Description)))
		}
	}
}

// Every mutation, and every request the walkthrough makes, shows a reader what
// to send and what comes back.
func TestOpenAPIMutationsAndWalkthroughCarryExamples(t *testing.T) {
	doc := loadOpenAPI(t)
	walked := map[string]bool{}
	for _, c := range walkthroughCalls(t, doc) {
		walked[c.op.OperationID] = true
	}
	shown := func(m *openapi3.MediaType) bool { return m.Example != nil || len(m.Examples) > 0 }
	checked := 0
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			mutation := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
			if !mutation && !walked[op.OperationID] {
				continue
			}
			checked++
			if op.RequestBody != nil {
				for media, m := range op.RequestBody.Value.Content {
					if !shown(m) {
						t.Errorf("%s (%s %s) has no example of its %s request body", op.OperationID, method, path, media)
					}
				}
			}
			success := 0
			for code, res := range op.Responses.Map() {
				if !strings.HasPrefix(code, "2") {
					continue
				}
				success++
				for media, m := range res.Value.Content {
					if !shown(m) {
						t.Errorf("%s (%s %s) has no example of its %s %s response", op.OperationID, method, path, code, media)
					}
				}
			}
			if success == 0 {
				t.Errorf("%s (%s %s) documents no success response", op.OperationID, method, path)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d operations were held to an example; the document or this test lost its mutations", checked)
	}
}
