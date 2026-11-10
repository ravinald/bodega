package main

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/yuin/goldmark/ast"
	"gopkg.in/yaml.v3"
)

// apiSpec is the part of an OpenAPI 3.0 document the reference renders. A
// keyword it does not name (headers, links, callbacks, discriminator) is read
// past rather than refused, so the page omits it.
type apiSpec struct {
	Info struct {
		Title, Description, Version string
	}
	Servers []struct {
		URL         string `yaml:"url"`
		Description string
	}
	Tags []struct {
		Name, Description string
	}
	Paths      ordered[apiPath]
	Components struct {
		Schemas         map[string]*apiSchema
		Parameters      map[string]apiParameter
		Responses       map[string]apiResponse
		SecuritySchemes map[string]struct {
			Type, Scheme, Description string
		} `yaml:"securitySchemes"`
	}
}

// ordered is a mapping that keeps the document's key order, which is the order
// the author chose for paths and properties and the order a reader expects.
type ordered[V any] struct {
	keys []string
	vals map[string]V
}

func (o *ordered[V]) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping", n.Line)
	}
	o.vals = map[string]V{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		var v V
		if err := n.Content[i+1].Decode(&v); err != nil {
			return err
		}
		o.keys = append(o.keys, n.Content[i].Value)
		o.vals[n.Content[i].Value] = v
	}
	return nil
}

type apiPath struct {
	Parameters                                   []apiParameter
	Get, Put, Post, Delete, Patch, Head, Options *apiOperation
}

type apiOperation struct {
	Summary, Description string
	OperationID          string `yaml:"operationId"`
	Tags                 []string
	Parameters           []apiParameter
	RequestBody          *struct {
		Description string
		Required    bool
		Content     map[string]apiMedia
	} `yaml:"requestBody"`
	Responses map[string]apiResponse
	Security  []map[string][]string
}

type apiParameter struct {
	Ref         string `yaml:"$ref"`
	Name, In    string
	Required    bool
	Description string
	Schema      *apiSchema
}

type apiResponse struct {
	Ref         string `yaml:"$ref"`
	Description string
	Content     map[string]apiMedia
}

type apiMedia struct{ Schema *apiSchema }

type apiSchema struct {
	Ref                  string `yaml:"$ref"`
	Type, Format         string
	Description          string
	Nullable             bool
	Enum                 []any
	Default              any
	Items                *apiSchema
	Properties           ordered[*apiSchema]
	Required             []string
	AdditionalProperties yaml.Node    `yaml:"additionalProperties"`
	AllOf                []*apiSchema `yaml:"allOf"`
	OneOf                []*apiSchema `yaml:"oneOf"`
	AnyOf                []*apiSchema `yaml:"anyOf"`
}

// valueSchema is the schema of a map's values, or nil when
// additionalProperties is absent or a bare boolean.
func (s *apiSchema) valueSchema() *apiSchema {
	if s.AdditionalProperties.Kind != yaml.MappingNode {
		return nil
	}
	var v apiSchema
	if err := s.AdditionalProperties.Decode(&v); err != nil {
		return nil
	}
	return &v
}

const (
	apiDir        = "api/"
	apiSchemasOut = apiDir + "schemas.html"
	schemaRef     = "#/components/schemas/"
)

type apiRenderer struct {
	spec apiSpec
	base string
}

type apiCall struct {
	method, path string
	op           *apiOperation
	shared       []apiParameter
}

func (c apiCall) id() string {
	if c.op.OperationID != "" {
		return c.op.OperationID
	}
	return slug(c.method + "-" + strings.ReplaceAll(c.path, "/", "-"))
}

// renderAPI turns an OpenAPI document into the pages under /api/: the index,
// one page per tag, and the schemas every $ref links to. A $ref to a schema
// the document lacks still renders as a link, so checkLinks reports it with
// the page it sits on; a $ref to a missing parameter or response has nothing
// to link to and is an error here.
func renderAPI(src []byte, base string) ([]*page, error) {
	a := &apiRenderer{base: base}
	if err := yaml.Unmarshal(src, &a.spec); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(a.spec.Paths.keys) == 0 {
		return nil, fmt.Errorf("the document has no paths, so there is no reference to render")
	}

	var tagNames []string
	tagText := map[string]string{}
	byTag := map[string][]apiCall{}
	for _, t := range a.spec.Tags {
		tagNames = append(tagNames, t.Name)
		tagText[t.Name] = t.Description
	}
	for _, p := range a.spec.Paths.keys {
		item := a.spec.Paths.vals[p]
		for _, m := range []struct {
			name string
			op   *apiOperation
		}{{"GET", item.Get}, {"HEAD", item.Head}, {"POST", item.Post}, {"PUT", item.Put}, {"PATCH", item.Patch}, {"DELETE", item.Delete}, {"OPTIONS", item.Options}} {
			if m.op == nil {
				continue
			}
			opTags := m.op.Tags
			if len(opTags) == 0 {
				opTags = []string{"other"}
			}
			for _, t := range opTags {
				if _, seen := byTag[t]; !seen {
					if _, declared := tagText[t]; !declared {
						tagNames = append(tagNames, t)
						tagText[t] = ""
					}
				}
				byTag[t] = append(byTag[t], apiCall{m.name, p, m.op, item.Parameters})
			}
		}
	}

	e := template.HTMLEscapeString
	tagOut := map[string]string{}
	for _, t := range tagNames {
		out := apiDir + slug(t) + ".html"
		if slug(t) == "" || out == apiSchemasOut || out == apiDir+"index.html" {
			return nil, fmt.Errorf("tag %q has no page name of its own: rename it", t)
		}
		for other, o := range tagOut {
			if o == out {
				return nil, fmt.Errorf("tags %q and %q both render to %s: rename one", other, t, out)
			}
		}
		tagOut[t] = out
	}

	var idx strings.Builder
	title := a.spec.Info.Title
	if title == "" {
		title = "API reference"
	}
	fmt.Fprintf(&idx, "<h1>API reference</h1>\n%s", a.markdown(a.spec.Info.Description))
	fmt.Fprintf(&idx, "<p>This page describes %s version <code>%s</code>.", e(title), e(a.spec.Info.Version))
	for _, s := range a.spec.Servers {
		fmt.Fprintf(&idx, " Paths are relative to <code>%s</code>: %s.", e(s.URL), e(lowerFirst(strings.TrimSuffix(s.Description, "."))))
	}
	fmt.Fprintf(&idx, " Request and response bodies are described under <a href=\"%s%s\">Schemas</a>.</p>\n", base, apiSchemasOut)
	if len(a.spec.Components.SecuritySchemes) > 0 {
		idx.WriteString("<h2 id=\"authentication\">Authentication</h2>\n<dl>\n")
		for _, name := range sortedKeys(a.spec.Components.SecuritySchemes) {
			s := a.spec.Components.SecuritySchemes[name]
			fmt.Fprintf(&idx, "<dt id=\"auth-%s\"><code>%s</code> <span class=\"api-type\">%s</span></dt><dd>%s</dd>\n", e(name), e(name), e(strings.TrimSpace(s.Type+" "+s.Scheme)), a.markdown(s.Description))
		}
		idx.WriteString("</dl>\n")
	}

	pages := []*page{nil}
	for _, t := range tagNames {
		calls := byTag[t]
		if len(calls) == 0 {
			continue
		}
		href := base + tagOut[t]
		fmt.Fprintf(&idx, "<h2 id=\"tag-%s\"><a href=\"%s\">%s</a></h2>\n%s", slug(t), href, e(capitalize(t)), a.markdown(tagText[t]))
		idx.WriteString("<div class=\"table\"><table class=\"api\"><thead><tr><th>Method</th><th>Path</th><th>Summary</th></tr></thead><tbody>\n")

		var b strings.Builder
		fmt.Fprintf(&b, "<h1>%s</h1>\n%s", e(capitalize(t)), a.markdown(tagText[t]))
		for _, c := range calls {
			fmt.Fprintf(&idx, "<tr><td>%s</td><td><code>%s</code></td><td><a href=\"%s#%s\">%s</a></td></tr>\n", method(c.method), e(c.path), href, e(c.id()), e(c.op.Summary))
			if err := a.operation(&b, c); err != nil {
				return nil, fmt.Errorf("%s %s: %w", c.method, c.path, err)
			}
		}
		idx.WriteString("</tbody></table></div>\n")
		pages = append(pages, a.page(tagOut[t], capitalize(t), b.String()))
	}
	pages[0] = a.page(apiDir+"index.html", "API reference", idx.String())

	var sch strings.Builder
	sch.WriteString("<h1>Schemas</h1>\n<p>The request and response bodies the API reference links to, by name.</p>\n")
	for _, name := range sortedKeys(a.spec.Components.Schemas) {
		s := a.spec.Components.Schemas[name]
		fmt.Fprintf(&sch, "<h2 id=\"%s\">%s</h2>\n", e(name), e(name))
		if s == nil {
			continue
		}
		fmt.Fprintf(&sch, "<p><span class=\"api-type\">%s</span></p>\n%s%s", a.typeOf(s), a.markdown(s.Description), a.members(s))
	}
	return append(pages, a.page(apiSchemasOut, "Schemas", sch.String())), nil
}

func (a *apiRenderer) page(out, title, body string) *page {
	return &page{Src: "api/openapi.yaml", Out: out, Title: title, Kind: "doc", Body: template.HTML(body)}
}

func (a *apiRenderer) operation(b *strings.Builder, c apiCall) error {
	e := template.HTMLEscapeString
	title := c.op.Summary
	if title == "" {
		title = c.method + " " + c.path
	}
	fmt.Fprintf(b, "<h2 id=\"%s\">%s</h2>\n<p class=\"api-call\">%s <code>%s</code></p>\n", e(c.id()), e(title), method(c.method), e(c.path))
	b.WriteString(a.markdown(c.op.Description))
	if len(c.op.Security) > 0 {
		var names []string
		for _, req := range c.op.Security {
			for _, name := range sortedKeys(req) {
				names = append(names, fmt.Sprintf("<a href=\"%s%s#auth-%s\"><code>%s</code></a>", a.base, apiDir, e(name), e(name)))
			}
		}
		fmt.Fprintf(b, "<p>Authentication: %s.</p>\n", strings.Join(names, " or "))
	}

	var params []apiParameter
	for _, p := range append(append([]apiParameter{}, c.shared...), c.op.Parameters...) {
		if p.Ref != "" {
			name := strings.TrimPrefix(p.Ref, "#/components/parameters/")
			resolved, ok := a.spec.Components.Parameters[name]
			if !ok || name == p.Ref {
				return fmt.Errorf("parameter $ref %q names nothing under components.parameters", p.Ref)
			}
			p = resolved
		}
		params = append(params, p)
	}
	if len(params) > 0 {
		fmt.Fprintf(b, "<h3 id=\"%s-parameters\">Parameters</h3>\n<div class=\"table\"><table class=\"api\"><thead><tr><th>Name</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr></thead><tbody>\n", e(c.id()))
		for _, p := range params {
			required := "no"
			if p.Required {
				required = "yes"
			}
			fmt.Fprintf(b, "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s%s</td></tr>\n", e(p.Name), e(p.In), a.typeOf(p.Schema), required, a.markdown(p.Description), a.constraints(p.Schema))
		}
		b.WriteString("</tbody></table></div>\n")
	}

	if rb := c.op.RequestBody; rb != nil {
		need := "optional"
		if rb.Required {
			need = "required"
		}
		fmt.Fprintf(b, "<h3 id=\"%s-request-body\">Request body</h3>\n<p>The body is %s.</p>\n%s%s", e(c.id()), need, a.markdown(rb.Description), a.content(rb.Content))
	}

	fmt.Fprintf(b, "<h3 id=\"%s-responses\">Responses</h3>\n<dl class=\"api-responses\">\n", e(c.id()))
	for _, status := range sortedKeys(c.op.Responses) {
		r := c.op.Responses[status]
		if r.Ref != "" {
			name := strings.TrimPrefix(r.Ref, "#/components/responses/")
			resolved, ok := a.spec.Components.Responses[name]
			if !ok || name == r.Ref {
				return fmt.Errorf("response %s $ref %q names nothing under components.responses", status, r.Ref)
			}
			r = resolved
		}
		fmt.Fprintf(b, "<dt><code>%s</code></dt>\n<dd>%s%s</dd>\n", e(status), a.markdown(r.Description), a.content(r.Content))
	}
	b.WriteString("</dl>\n")
	return nil
}

func (a *apiRenderer) content(content map[string]apiMedia) string {
	var b strings.Builder
	for _, mediaType := range sortedKeys(content) {
		s := content[mediaType].Schema
		fmt.Fprintf(&b, "<p><code>%s</code>", template.HTMLEscapeString(mediaType))
		if s != nil {
			fmt.Fprintf(&b, " <span class=\"api-type\">%s</span>", a.typeOf(s))
		}
		b.WriteString("</p>\n")
		if s != nil {
			b.WriteString(a.members(s))
		}
	}
	return b.String()
}

// typeOf names a schema in one line: a link for a $ref, the element type for
// an array or a map, and the JSON type otherwise.
func (a *apiRenderer) typeOf(s *apiSchema) string {
	e := template.HTMLEscapeString
	if s == nil {
		return "any"
	}
	if s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, schemaRef)
		return fmt.Sprintf("<a href=\"%s%s#%s\">%s</a>", a.base, apiSchemasOut, e(name), e(name))
	}
	for _, combo := range []struct {
		parts []*apiSchema
		word  string
	}{{s.AllOf, " and "}, {s.OneOf, " or "}, {s.AnyOf, " or "}} {
		if len(combo.parts) > 0 {
			var names []string
			for _, part := range combo.parts {
				names = append(names, a.typeOf(part))
			}
			return strings.Join(names, combo.word) + nullable(s)
		}
	}
	t := s.Type
	switch {
	case t == "array":
		t = "array of " + a.typeOf(s.Items)
	case s.valueSchema() != nil:
		t = "map of string to " + a.typeOf(s.valueSchema())
	case t == "" && len(s.Properties.keys) > 0:
		t = "object"
	case t == "":
		t = "any"
	default:
		t = e(t)
	}
	if s.Format != "" {
		t += " (" + e(s.Format) + ")"
	}
	return t + nullable(s)
}

func nullable(s *apiSchema) string {
	if s.Nullable {
		return ", nullable"
	}
	return ""
}

// constraints lists what a value is limited to beyond its type.
func (a *apiRenderer) constraints(s *apiSchema) string {
	if s == nil {
		return ""
	}
	e := template.HTMLEscapeString
	var parts []string
	if len(s.Enum) > 0 {
		var vals []string
		for _, v := range s.Enum {
			vals = append(vals, "<code>"+e(fmt.Sprint(v))+"</code>")
		}
		parts = append(parts, "One of "+strings.Join(vals, ", ")+".")
	}
	if s.Default != nil {
		parts = append(parts, "Default <code>"+e(fmt.Sprint(s.Default))+"</code>.")
	}
	if len(parts) == 0 {
		return ""
	}
	return "<p class=\"api-limits\">" + strings.Join(parts, " ") + "</p>"
}

// members lists an object's properties, and under each the properties of any
// object it holds inline. A $ref is not opened: its link is the way in.
func (a *apiRenderer) members(s *apiSchema) string {
	if s == nil || s.Ref != "" {
		return ""
	}
	e := template.HTMLEscapeString
	var b strings.Builder
	if len(s.Properties.keys) > 0 {
		required := map[string]bool{}
		for _, name := range s.Required {
			required[name] = true
		}
		b.WriteString("<ul class=\"api-members\">\n")
		for _, name := range s.Properties.keys {
			p := s.Properties.vals[name]
			fmt.Fprintf(&b, "<li><code>%s</code> <span class=\"api-type\">%s</span>", e(name), a.typeOf(p))
			if required[name] {
				b.WriteString(" <span class=\"api-required\">required</span>")
			}
			if p != nil {
				b.WriteString(a.markdown(p.Description) + a.constraints(p) + a.members(p))
			}
			b.WriteString("</li>\n")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString(a.members(s.Items) + a.members(s.valueSchema()))
	for _, parts := range [][]*apiSchema{s.AllOf, s.OneOf, s.AnyOf} {
		for _, part := range parts {
			b.WriteString(a.members(part))
		}
	}
	return b.String()
}

// markdown renders a description. The document writes placeholders such as
// <codename> in running text, which Markdown reads as HTML tags and a browser
// would then hide, so anything parsed as raw HTML is written back as text.
func (a *apiRenderer) markdown(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	src := []byte(s)
	doc := parse(src)
	var raw []ast.Node
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering && (n.Kind() == ast.KindRawHTML || n.Kind() == ast.KindHTMLBlock) {
			raw = append(raw, n)
		}
		return ast.WalkContinue, nil
	})
	for _, n := range raw {
		var text bytes.Buffer
		var replacement ast.Node
		switch n := n.(type) {
		case *ast.RawHTML:
			for i := 0; i < n.Segments.Len(); i++ {
				seg := n.Segments.At(i)
				text.Write(seg.Value(src))
			}
			replacement = ast.NewString(append([]byte(nil), text.Bytes()...))
		case *ast.HTMLBlock:
			for i := 0; i < n.Lines().Len(); i++ {
				seg := n.Lines().At(i)
				text.Write(seg.Value(src))
			}
			p := ast.NewParagraph()
			p.AppendChild(p, ast.NewString(bytes.TrimSpace(text.Bytes())))
			replacement = p
		}
		n.Parent().ReplaceChild(n.Parent(), n, replacement)
	}
	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, src, doc); err != nil {
		return "<p>" + template.HTMLEscapeString(s) + "</p>\n"
	}
	return buf.String()
}

func method(m string) string {
	return fmt.Sprintf("<span class=\"api-method api-%s\">%s</span>", strings.ToLower(m), m)
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
