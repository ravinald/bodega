package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureSpec = `
openapi: "3.0.3"
info:
  title: widget API
  description: Widgets, for the test.
  version: 9.8.7
servers:
  - url: https://widgets.example.com
    description: The operator's base URL
tags:
  - name: widgets
    description: Widget operations
paths:
  /widgets/{id}:
    post:
      summary: Replace a widget
      description: Writes the widget at /srv/<name>.json and returns it.
      operationId: replaceWidget
      tags: [widgets]
      security:
        - bearerAuth: []
      parameters:
        - $ref: "#/components/parameters/WidgetID"
        - name: dry_run
          in: query
          description: Validate without writing
          schema:
            type: boolean
            default: false
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/Widget"
      responses:
        "200":
          description: The widget as stored
          content:
            application/json:
              schema:
                type: object
                properties:
                  widget:
                    $ref: "#/components/schemas/Widget"
                  warnings:
                    type: array
                    items:
                      type: string
        "404":
          $ref: "#/components/responses/NotFound"
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      description: An API token
  parameters:
    WidgetID:
      name: id
      in: path
      required: true
      description: The widget's id
      schema:
        type: integer
  responses:
    NotFound:
      description: No such widget
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/Problem"
  schemas:
    Widget:
      type: object
      required: [name]
      properties:
        name:
          type: string
          description: What the widget is called
        color:
          type: string
          enum: [red, blue]
    Problem:
      type: object
      properties:
        error:
          type: string
`

func renderFixture(t *testing.T, spec string) map[string]string {
	t.Helper()
	pages, err := renderAPI([]byte(spec), "/")
	if err != nil {
		t.Fatalf("renderAPI: %v", err)
	}
	bodies := map[string]string{}
	for _, p := range pages {
		bodies[p.Out] = string(p.Body)
	}
	return bodies
}

func wantAll(t *testing.T, name, body string, wants map[string]string) {
	t.Helper()
	for what, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %s: no %q in\n%s", name, what, want, body)
		}
	}
}

func TestRenderAPIFixture(t *testing.T) {
	bodies := renderFixture(t, fixtureSpec)

	wantAll(t, "the tag page", bodies["api/widgets.html"], map[string]string{
		"the operation heading":          `<h2 id="replaceWidget">Replace a widget</h2>`,
		"the method and path":            `<span class="api-method api-post">POST</span> <code>/widgets/{id}</code>`,
		"the description's placeholder":  `/srv/&lt;name&gt;.json`,
		"the path parameter":             `<tr><td><code>id</code></td><td>path</td><td>integer</td><td>yes</td><td><p>The widget's id</p>`,
		"the query parameter":            `<tr><td><code>dry_run</code></td><td>query</td><td>boolean</td><td>no</td><td><p>Validate without writing</p>`,
		"the query parameter's default":  `Default <code>false</code>.`,
		"the request body":               `<h3 id="replaceWidget-request-body">Request body</h3>` + "\n<p>The body is required.</p>",
		"the request body's $ref link":   `<p><code>application/json</code> <span class="api-type"><a href="/api/schemas.html#Widget">Widget</a></span></p>`,
		"the 200 response":               `<dt><code>200</code></dt>` + "\n<dd><p>The widget as stored</p>",
		"the 200 response's inline body": `<li><code>warnings</code> <span class="api-type">array of string</span>`,
		"the 404 response":               `<dt><code>404</code></dt>` + "\n<dd><p>No such widget</p>",
		"the 404 response's $ref link":   `<a href="/api/schemas.html#Problem">Problem</a>`,
		"the authentication link":        `<a href="/api/#auth-bearerAuth">`,
	})
	wantAll(t, "the index", bodies["api/index.html"], map[string]string{
		"the tag":             `<h2 id="tag-widgets"><a href="/api/widgets.html">Widgets</a></h2>`,
		"the tag's operation": `<td><code>/widgets/{id}</code></td><td><a href="/api/widgets.html#replaceWidget">Replace a widget</a></td>`,
		"the version":         `<code>9.8.7</code>`,
		"the server":          `<code>https://widgets.example.com</code>: the operator&#39;s base URL.`,
		"the security scheme": `<dt id="auth-bearerAuth">`,
	})
	wantAll(t, "the schemas page", bodies["api/schemas.html"], map[string]string{
		"the Widget section":    `<h2 id="Widget">Widget</h2>`,
		"the required property": `<li><code>name</code> <span class="api-type">string</span> <span class="api-required">required</span>`,
		"the enum":              `One of <code>red</code>, <code>blue</code>.`,
	})
}

func writeBodies(t *testing.T, bodies map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for out, body := range bodies {
		write(filepath.Join(dir, out), []byte(body))
	}
	return dir
}

func TestDanglingRefFailsTheBuild(t *testing.T) {
	if broken := checkLinks(writeBodies(t, renderFixture(t, fixtureSpec)), "/"); broken != 0 {
		t.Fatalf("the fixture has %d broken links before any $ref is broken, want 0", broken)
	}

	dangling := strings.Replace(fixtureSpec, `$ref: "#/components/schemas/Problem"`, `$ref: "#/components/schemas/Gone"`, 1)
	if broken := checkLinks(writeBodies(t, renderFixture(t, dangling)), "/"); broken != 1 {
		t.Errorf("a $ref to a schema the document lacks left %d broken links, want 1", broken)
	}

	for name, ref := range map[string]string{
		"parameter": "#/components/parameters/WidgetID",
		"response":  "#/components/responses/NotFound",
	} {
		spec := strings.Replace(fixtureSpec, ref+`"`, ref+`Gone"`, 1)
		_, err := renderAPI([]byte(spec), "/")
		if err == nil || !strings.Contains(err.Error(), "Gone") || !strings.Contains(err.Error(), "POST /widgets/{id}") {
			t.Errorf("a dangling %s $ref: err = %v, want one naming the operation and the $ref", name, err)
		}
	}
}

// The whole site, built from this checkout the way deploy.py builds it.
func TestBuildPublishesAPIReference(t *testing.T) {
	dir := t.TempDir()
	coverage := filepath.Join(dir, "coverage.json")
	write(coverage, []byte(`{"revision":"abc","evaluatedAt":"2026-01-01T00:00:00Z","summary":"s","packages":[{"id":"apt","verdict":"Ready","reason":"r","coverage":"90%","features":[{"label":"L","description":"D","value":"yes"}]}]}`))
	out := filepath.Join(dir, "site")
	if broken := build("..", out, ".", "v0.0.0-test", strings.Repeat("0", 40), "/", coverage); broken != 0 {
		t.Fatalf("the site has %d broken internal links, want 0", broken)
	}
	page := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("the build wrote no %s: %v", name, err)
		}
		return string(b)
	}

	spec, err := renderAPI(read("..", "api/openapi.yaml"), "/")
	if err != nil {
		t.Fatal(err)
	}
	index := page("api/index.html")
	for _, p := range spec[1:] {
		page(p.Out)
		if href := `href="/` + p.Out + `"`; !strings.Contains(index, href) {
			t.Errorf("api/index.html does not link %s", p.Out)
		}
	}
	if len(spec) < 3 {
		t.Fatalf("api/openapi.yaml rendered %d pages, want the index, a page per tag and the schemas", len(spec))
	}

	wantAll(t, "api/index.html", index, map[string]string{
		"the navigation entry, marked current": `<a href="/api/" class="here">API</a>`,
		"the contents column":                  `<aside class="contents"`,
		"its own entry in the contents column": `<a href="/api/" aria-current="page">API reference</a>`,
	})
	wantAll(t, "the front page", page("index.html"), map[string]string{"the navigation entry": `<a href="/api/">API</a>`})
	wantAll(t, "the docs index", page("docs/index.html"), map[string]string{
		"the API reference group": `<h2>API reference</h2>`,
		"the API reference":       `<a href="/api/">API reference</a>`,
		"a tag page":              `<a href="/` + spec[1].Out + `">`,
	})

	usage, err := os.ReadFile(filepath.Join("..", "docs", "usage.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(usage), "[API reference](../api/openapi.yaml)") {
		t.Error("docs/usage.md should link api/openapi.yaml as the API reference: that link is the raw YAML on GitHub and the rendered page on the site")
	}
	wantAll(t, "the REST API usage page", page("docs/usage/rest-api.html"), map[string]string{
		"the rendered API reference": `documented in the <a href="/api/">API reference</a>`,
	})
}
