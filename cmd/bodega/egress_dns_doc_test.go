package main

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The registry names docs/threat-model.md tells an operator to refuse in DNS
// must cover every host a built-in upstream default fetches from, or a new
// default ships with a block list that quietly lets it through. Both forms
// the page gives, the RPZ zone and the plain list, are checked.
func TestThreatModelDNSListCoversBuiltInUpstreams(t *testing.T) {
	cfg := loadFrom(t, `{}`)
	hosts := map[string]string{
		"gomod_upstream":     cfg.GomodUpstream,
		"npm_upstream":       cfg.NpmUpstream,
		"pypi_upstream":      cfg.PypiUpstream,
		"cargo_upstream":     cfg.CargoUpstream,
		"cargo_dl_upstream":  cfg.CargoDLUpstream,
		"distfiles_upstream": cfg.DistfilesUpstream,
		// Not a config key: PyPI's simple index links every file here, and
		// the pypi proxy follows those links.
		"pypi files": "https://files.pythonhosted.org/",
	}

	raw, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	section := string(raw)
	if i := strings.Index(section, "#### Registry names in DNS"); i >= 0 {
		section = section[i:]
	} else {
		t.Fatal(`docs/threat-model.md has no "#### Registry names in DNS" section; the heading moved`)
	}
	lists := map[string][]string{
		"RPZ zone":   fenced(t, section, "zone", func(l string) string { return strings.TrimSuffix(strings.Fields(l)[0], ".") }),
		"plain list": fenced(t, section, "text", strings.TrimSpace),
	}

	for key, raw := range hosts {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			t.Fatalf("%s default %q has no host", key, raw)
		}
		host := strings.ToLower(u.Hostname())
		for form, names := range lists {
			if !coveredBy(host, names) {
				t.Errorf("%s fetches from %s, which the threat model's DNS %s does not name", key, host, form)
			}
		}
	}
}

// fenced returns the non-empty lines of the first code block in doc fenced
// with lang, each passed through name.
func fenced(t *testing.T, doc, lang string, name func(string) string) []string {
	t.Helper()
	m := regexp.MustCompile("(?s)```" + lang + "\n(.*?)```").FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("no ```%s block in the DNS section", lang)
	}
	var out []string
	for _, l := range strings.Split(m[1], "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.ToLower(name(l)))
		}
	}
	return out
}

// coveredBy reports whether host is one of names, or under a "*." wildcard
// among them. A wildcard does not cover its apex, as in RPZ.
func coveredBy(host string, names []string) bool {
	for _, n := range names {
		if n == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(n, "*."); ok && strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
