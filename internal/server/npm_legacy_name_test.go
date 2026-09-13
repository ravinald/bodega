package server

import (
	"encoding/json"
	"testing"
)

// The version-manifest route's path is "<pkg>/<version>", and preferring the
// document's own name hid that: a legacy uppercase name fails npm's pattern,
// so the fallback put the version segment inside the composed prefix and every
// dist.tarball on that route pointed where bodega 404s.
//
// npm install never reads this endpoint, so no client install broke. What
// broke is anything reading /npm/{pkg}/{version} directly, which is what #248
// added the top-level dist walk to cover.
func TestNpmPackageFromPath(t *testing.T) {
	cases := []struct{ path, want string }{
		{"lodash", "lodash"},
		{"JSONStream", "JSONStream"},
		{"lodash/4.17.21", "lodash"},
		{"JSONStream/1.3.5", "JSONStream"},
		{"@sindresorhus/is", "@sindresorhus/is"},
		{"@sindresorhus/is/5.6.0", "@sindresorhus/is"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := npmPackageFromPath(tc.path); got != tc.want {
				t.Errorf("npmPackageFromPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// The composed tarball has to be a path handleNpm can serve: it splits the
// request on "/-/", so a version segment ahead of that separator makes the
// package "JSONStream/1.3.5" and the filename prefix "1.3.5-", which
// npmVersionFromTarball cannot read.
func TestRewritePacksTheTarballWhereHandleNpmCanFindIt(t *testing.T) {
	const upstream = `{
	  "name": "JSONStream",
	  "version": "1.3.5",
	  "dist": {"tarball": "https://registry.npmjs.org/JSONStream/-/JSONStream-1.3.5.tgz"}
	}`

	got, err := rewriteNpmPackument([]byte(upstream), "http://bodega.example/npm", "JSONStream/1.3.5")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	var doc struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("parse rewritten: %v", err)
	}

	const want = "http://bodega.example/npm/JSONStream/-/JSONStream-1.3.5.tgz"
	if doc.Dist.Tarball != want {
		t.Errorf("dist.tarball = %q, want %q", doc.Dist.Tarball, want)
	}
}

// An upstream that is trusted for the bytes and answers /npm/victim with a
// different name moved every rewritten URL onto that name's route, and bodega
// then applied its hidden-version and constraint policy instead of the
// requested package's. The pattern stopped path syntax, not substitution: the
// substituted name is a legal one.
func TestRewriteIgnoresANameTheUpstreamSubstitutes(t *testing.T) {
	const substituted = `{
	  "name": "other",
	  "versions": {"1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/other/-/other-1.0.0.tgz"}}}
	}`

	got, err := rewriteNpmPackument([]byte(substituted), "http://bodega.example/npm", "victim")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("parse rewritten: %v", err)
	}

	const want = "http://bodega.example/npm/victim/-/other-1.0.0.tgz"
	if got := doc.Versions["1.0.0"].Dist.Tarball; got != want {
		t.Errorf("dist.tarball = %q, want %q; the upstream chose bodega's route", got, want)
	}
}
