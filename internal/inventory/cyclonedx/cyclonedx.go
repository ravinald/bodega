// Package cyclonedx is the built-in inventory source: a push source that
// accepts a CycloneDX 1.5 or 1.6 JSON document from a host holding an
// inventory-scoped token. It needs no vendor tool, so it exercises the whole
// inventory frame on its own, and anything that emits CycloneDX (syft over a
// disk snapshot, for one) can feed it.
package cyclonedx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
)

// TypeName is the inventory_sources "type" this package registers.
const TypeName = "cyclonedx"

// DefaultMaxBodyBytes caps one document. A full image SBOM with hashes runs
// to a few MiB; 32 MiB leaves room without letting one request hold an
// unbounded buffer.
const DefaultMaxBodyBytes int64 = 32 << 20

// RoutePath is the push route below /api/v1/inventory/sources/{instance}/.
const RoutePath = "bom"

func init() { inventory.Register(TypeName, newSource) }

// Source is one configured CycloneDX instance.
type Source struct {
	maxBody int64
}

func newSource(_ string, s *inventory.Settings) (inventory.Source, error) {
	maxBody, err := s.Int64("max_body_bytes", DefaultMaxBodyBytes)
	if err != nil {
		return nil, err
	}
	if maxBody <= 0 {
		return nil, s.Errorf("max_body_bytes", "want a positive byte count, got %d", maxBody)
	}
	return &Source{maxBody: maxBody}, nil
}

func (*Source) Type() string         { return TypeName }
func (*Source) Mode() inventory.Mode { return inventory.ModePush }
func (*Source) Capabilities() []inventory.Capability {
	return []inventory.Capability{inventory.CapInventory}
}

// Routes registers the one route a host posts its document to.
func (s *Source) Routes() []inventory.Route {
	return []inventory.Route{{Method: http.MethodPost, Path: RoutePath, MaxBody: s.maxBody}}
}

// Authenticate accepts only an inventory-scoped token with an identity
// binding. The bound identity is the external id, and since the token
// binding already ties the credential to that host, the source writes the
// host mapping itself.
//
// A full-scope token is refused here too: an admin credential copied onto a
// host to post its inventory would be an admin credential on that host.
func (*Source) Authenticate(r *http.Request, creds inventory.Credentials) (inventory.Principal, error) {
	tok, err := creds.Token(r)
	if err != nil {
		return inventory.Principal{}, err
	}
	if tok.Scope != audit.ScopeInventory {
		return inventory.Principal{}, &inventory.AuthError{
			Status: http.StatusForbidden, Reason: audit.DenialTokenScope,
			Message: fmt.Sprintf("token scope %q cannot post to %s; mint one with: bodega token create <label> --scope inventory", tok.Scope, r.URL.Path),
		}
	}
	if tok.Identity == "" {
		return inventory.Principal{}, &inventory.AuthError{
			Status: http.StatusForbidden, Reason: audit.DenialClientUnidentified,
			Message: fmt.Sprintf("token %s is bound to no identity, so its reports would name no host; bind it with: bodega identity bind token %s <identity>", tok.ID, tok.ID),
		}
	}
	return inventory.Principal{ExternalID: tok.Identity, Identity: tok.Identity}, nil
}

type bom struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Components []component `json:"components"`
}

type component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Hashes  []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	ExternalReferences []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"externalReferences"`
	Evidence struct {
		Occurrences []struct {
			Location string `json:"location"`
		} `json:"occurrences"`
	} `json:"evidence"`
	Components []component `json:"components"`
}

// Normalize maps one CycloneDX document to a single report for externalID.
func (*Source) Normalize(doc []byte, externalID string) (inventory.Batch, error) {
	var b bom
	dec := json.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&b); err != nil {
		return inventory.Batch{}, fmt.Errorf("not a CycloneDX JSON document: %w", err)
	}
	if b.BOMFormat != "CycloneDX" {
		return inventory.Batch{}, fmt.Errorf("bomFormat is %q, want \"CycloneDX\"", b.BOMFormat)
	}
	if b.SpecVersion != "1.5" && b.SpecVersion != "1.6" {
		return inventory.Batch{}, fmt.Errorf("specVersion %q is not supported (want 1.5 or 1.6)", b.SpecVersion)
	}
	rep := inventory.Report{ExternalID: externalID}
	if b.Metadata.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339, b.Metadata.Timestamp)
		if err != nil {
			return inventory.Batch{}, fmt.Errorf("metadata.timestamp %q is not RFC 3339", b.Metadata.Timestamp)
		}
		rep.ObservedAt = ts
	}
	var walk func([]component)
	walk = func(cs []component) {
		for _, c := range cs {
			if c.Name != "" {
				rep.Components = append(rep.Components, toComponent(c))
			}
			walk(c.Components)
		}
	}
	walk(b.Components)
	return inventory.Batch{Reports: []inventory.Report{rep}}, nil
}

func toComponent(c component) inventory.Component {
	out := inventory.Component{Name: c.Name, Version: c.Version, PURL: c.PURL, Ecosystem: inventory.EcosystemOther}
	if c.PURL != "" {
		purlType, qualifiers := parsePURL(c.PURL)
		if eco, ok := purlEcosystems[purlType]; ok {
			out.Ecosystem = eco
		}
		out.Origin = firstNonEmpty(qualifiers.Get("repository_url"), qualifiers.Get("download_url"))
	}
	if out.Origin == "" {
		for _, ref := range c.ExternalReferences {
			if ref.Type == "distribution" && ref.URL != "" {
				out.Origin = ref.URL
				break
			}
		}
	}
	if len(c.Evidence.Occurrences) > 0 {
		out.Path = c.Evidence.Occurrences[0].Location
	}
	out.DigestAlgorithm, out.DigestValue = pickDigest(c)
	return out
}

// purlEcosystems maps a purl type to the bodega type that serves it. A purl
// type bodega serves nothing for lands in "other".
var purlEcosystems = map[string]string{
	"deb":     manifest.TypeApt,
	"pypi":    manifest.TypePypi,
	"npm":     manifest.TypeNpm,
	"cargo":   manifest.TypeCargo,
	"golang":  manifest.TypeGomod,
	"helm":    manifest.TypeHelm,
	"freebsd": manifest.TypeFreeBSD,
}

// parsePURL returns a package URL's type and qualifiers. Name and version
// come from the component's own fields, so nothing else is parsed.
func parsePURL(p string) (string, url.Values) {
	rest, ok := strings.CutPrefix(p, "pkg:")
	if !ok {
		return "", url.Values{}
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	typ, _, _ := strings.Cut(strings.TrimLeft(rest, "/"), "/")
	q, err := url.ParseQuery(query)
	if err != nil {
		q = url.Values{}
	}
	return strings.ToLower(typ), q
}

// digestPreference orders the CycloneDX hash algorithms by strength, so a
// component carrying several records its strongest.
var digestPreference = []string{"SHA-512", "SHA-384", "SHA-256", "SHA3-512", "SHA3-384", "SHA3-256", "BLAKE3", "BLAKE2b-512", "SHA-1", "MD5"}

func pickDigest(c component) (alg, value string) {
	for _, want := range digestPreference {
		for _, h := range c.Hashes {
			if strings.EqualFold(h.Alg, want) && h.Content != "" {
				return normalizeAlg(h.Alg), strings.ToLower(h.Content)
			}
		}
	}
	return "", ""
}

// normalizeAlg spells an algorithm the way bodega's checksum table does:
// "SHA-256" becomes "sha256".
func normalizeAlg(a string) string {
	return strings.ToLower(strings.ReplaceAll(a, "-", ""))
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
